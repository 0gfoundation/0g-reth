//! EVM config for vanilla ethereum.
//!
//! # Revm features
//!
//! This crate does __not__ enforce specific revm features such as `blst` or `c-kzg`, which are
//! critical for revm's evm internals, it is the responsibility of the implementer to ensure the
//! proper features are selected.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{borrow::Cow, sync::Arc};
use alloy_consensus::{Header, Transaction};
use alloy_eips::merge::SLOT_DURATION_SECS;
use alloy_evm::{
    eth::{EthBlockExecutionCtx, EthBlockExecutorFactory, EthTxResult},
    EthEvmFactory, FromRecoveredTx, FromTxWithEncoded,
};
use alloy_primitives::{Address, B256};
#[cfg(feature = "jit")]
use core::any::Any;
use core::{any::TypeId, convert::Infallible, fmt::Debug};
use reth_chainspec::{ChainSpec, EthChainSpec, MAINNET};
use reth_ethereum_primitives::{Block, EthPrimitives, TransactionSigned};
use reth_evm::{
    eth::NextEvmEnvAttributes, precompiles::PrecompilesMap, ConfigureEvm, EvmEnv, EvmFactory,
    HaltReasonFor, JitBackend, NextBlockEnvAttributes, SenderRecoveryCache, TransactionEnvMut,
    TxExecutionResultFor,
};
use reth_primitives_traits::{SealedBlock, SealedHeader};
use revm::{
    context::{result::ResultAndState, BlockEnv},
    primitives::hardfork::SpecId,
};

#[cfg(feature = "std")]
use reth_evm::{ConfigureEngineEvm, ExecutableTxIterator};
#[allow(unused_imports)]
use {
    alloy_eips::Decodable2718,
    alloy_primitives::{Bytes, U256},
    alloy_rpc_types_engine::ExecutionData,
    reth_chainspec::EthereumHardforks,
    reth_evm::{EvmEnvFor, ExecutionCtxFor},
    reth_primitives_traits::{constants::MAX_TX_GAS_LIMIT_OSAKA, SignedTransaction, TxTy},
    reth_storage_errors::any::AnyError,
    revm::context::CfgEnv,
    revm::context_interface::block::BlobExcessGasAndPrice,
};

pub use alloy_evm::EthEvm;

mod config;
use alloy_evm::eth::spec::EthExecutorSpec;
pub use config::{revm_spec, revm_spec_by_timestamp_and_block_number};
use reth_ethereum_forks::Hardforks;

/// Helper type with backwards compatible methods to obtain Ethereum executor
/// providers.
#[doc(hidden)]
pub mod execute {
    use crate::EthEvmConfig;

    #[deprecated(note = "Use `EthEvmConfig` instead")]
    pub type EthExecutorProvider = EthEvmConfig;
}

/// 0G: decode a CL-emitted `BridgeRequests` SSZ blob into ABI calldata for
/// `Bridge.parkRemoteMessages(InboundMessage[])`, stamping `fee_recipient` onto every message.
///
/// Shared by all three execution-context constructors so build (`context_for_next_block`),
/// verify (`context_for_payload`) and replay (`context_for_block`) produce byte-identical
/// calldata from the same blob: `fee_recipient` is the block coinbase on every path
/// (`attrs.suggested_fee_recipient` is sealed into `header.beneficiary`, which is what
/// `payload.fee_recipient()` and `header.beneficiary()` read back).
///
/// Decoding errors degrade to `None` (system call skipped) — a malformed blob would already
/// have failed CL-side payload validation upstream, and treating it as a hard error here would
/// prevent the EL from making progress at all.
fn bridge_calldata_from_ssz(
    chain_id: u64,
    raw: &[u8],
    fee_recipient: alloy_primitives::Address,
    path: &'static str,
) -> Option<Bytes> {
    match reth_0g_bridge::decode_bridge_messages(raw) {
        Ok(msgs) => {
            let cd = reth_0g_bridge::encode_park_remote_messages_calldata(
                &msgs,
                chain_id,
                fee_recipient,
            );
            tracing::debug!(
                target: "0g::evm::bridge",
                ssz_len = raw.len(),
                msg_count = msgs.len(),
                calldata_len = cd.len(),
                ?fee_recipient,
                path,
                "decoded bridge SSZ to parkRemoteMessages calldata"
            );
            Some(cd)
        }
        Err(err) => {
            tracing::warn!(
                target: "0g::evm::bridge",
                ?err,
                ssz_len = raw.len(),
                path,
                "failed to decode bridge SSZ blob — system call will be skipped"
            );
            None
        }
    }
}

mod build;
pub use build::EthBlockAssembler;

mod receipt;
pub use receipt::RethReceiptBuilder;

#[cfg(feature = "test-utils")]
mod test_utils;
#[cfg(feature = "test-utils")]
pub use test_utils::*;

pub mod factory;

/// Ethereum-related EVM configuration.
#[derive(Debug, Clone)]
pub struct EthEvmConfig<C = ChainSpec, EvmFactory = EthEvmFactory> {
    /// Inner [`EthBlockExecutorFactory`].
    pub executor_factory: EthBlockExecutorFactory<RethReceiptBuilder, Arc<C>, EvmFactory>,
    /// Ethereum block assembler.
    pub block_assembler: EthBlockAssembler<C>,
    /// Cache of recovered transaction senders, if enabled.
    pub sender_recovery_cache: Option<SenderRecoveryCache>,
}

impl EthEvmConfig {
    /// Creates a new Ethereum EVM configuration for the ethereum mainnet.
    pub fn mainnet() -> Self {
        Self::ethereum(MAINNET.clone())
    }
}

impl<ChainSpec> EthEvmConfig<ChainSpec> {
    /// Creates a new Ethereum EVM configuration with the given chain spec.
    pub fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self::ethereum(chain_spec)
    }

    /// Creates a new Ethereum EVM configuration.
    pub fn ethereum(chain_spec: Arc<ChainSpec>) -> Self {
        Self::new_with_evm_factory(chain_spec, EthEvmFactory::default())
    }
}

impl<ChainSpec, EvmFactory> EthEvmConfig<ChainSpec, EvmFactory> {
    /// Creates a new Ethereum EVM configuration with the given chain spec and EVM factory.
    pub fn new_with_evm_factory(chain_spec: Arc<ChainSpec>, evm_factory: EvmFactory) -> Self {
        Self {
            block_assembler: EthBlockAssembler::new(chain_spec.clone()),
            sender_recovery_cache: None,
            executor_factory: EthBlockExecutorFactory::new(
                RethReceiptBuilder::default(),
                chain_spec,
                evm_factory,
            ),
        }
    }

    /// Returns the chain spec associated with this configuration.
    pub const fn chain_spec(&self) -> &Arc<ChainSpec> {
        self.executor_factory.spec()
    }

    /// Uses the provided sender recovery cache.
    pub fn with_sender_recovery_cache(mut self, cache: SenderRecoveryCache) -> Self {
        self.sender_recovery_cache = Some(cache);
        self
    }
}

impl<ChainSpec, EvmF> ConfigureEvm for EthEvmConfig<ChainSpec, EvmF>
where
    ChainSpec: EthExecutorSpec + EthChainSpec<Header = Header> + Hardforks + 'static,
    EvmF: EvmFactory<
            Tx: TransactionEnvMut
                    + FromRecoveredTx<TransactionSigned>
                    + FromTxWithEncoded<TransactionSigned>,
            Spec = SpecId,
            BlockEnv = BlockEnv,
            Precompiles = PrecompilesMap,
        > + Clone
        + Debug
        + Send
        + Sync
        + Unpin
        + 'static,
{
    type Primitives = EthPrimitives;
    type Error = Infallible;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory = EthBlockExecutorFactory<RethReceiptBuilder, Arc<ChainSpec>, EvmF>;
    type BlockAssembler = EthBlockAssembler<ChainSpec>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.executor_factory
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.block_assembler
    }

    fn with_jit_support_enabled(self, enabled: bool) -> Self
    where
        Self: Sized,
    {
        #[cfg(feature = "jit")]
        {
            let mut this = self;
            let mut evm_factory = this.executor_factory.evm_factory().clone();
            if let Some(factory) =
                (&mut evm_factory as &mut dyn Any).downcast_mut::<factory::RethEvmFactory>()
            {
                factory.set_jit_support(enabled);
            }
            this.executor_factory = EthBlockExecutorFactory::new(
                *this.executor_factory.receipt_builder(),
                this.executor_factory.spec().clone(),
                evm_factory,
            );
            this
        }

        #[cfg(not(feature = "jit"))]
        {
            let _ = enabled;
            self
        }
    }

    fn jit_backend(&self) -> Option<&dyn JitBackend> {
        #[cfg(feature = "jit")]
        if let Some(factory) = (self.executor_factory.evm_factory() as &dyn Any)
            .downcast_ref::<factory::RethEvmFactory>()
        {
            return Some(factory);
        }

        None
    }

    fn evm_env(&self, header: &Header) -> Result<EvmEnv<SpecId>, Self::Error> {
        Ok(EvmEnv::for_eth_block(
            header,
            self.chain_spec(),
            self.chain_spec().chain().id(),
            self.chain_spec().blob_params_at_timestamp(header.timestamp),
        ))
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &NextBlockEnvAttributes,
    ) -> Result<EvmEnv, Self::Error> {
        Ok(EvmEnv::for_eth_next_block(
            parent,
            NextEvmEnvAttributes {
                timestamp: attributes.timestamp,
                suggested_fee_recipient: attributes.suggested_fee_recipient,
                prev_randao: attributes.prev_randao,
                gas_limit: attributes.gas_limit,
                slot_number: attributes.slot_number,
            },
            self.chain_spec().next_block_base_fee(parent, attributes.timestamp).unwrap_or_default(),
            self.chain_spec(),
            self.chain_spec().chain().id(),
            self.chain_spec().blob_params_at_timestamp(attributes.timestamp),
        ))
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<Block>,
    ) -> Result<EthBlockExecutionCtx<'a>, Self::Error> {
        // 0G: replay (pipeline `ExecutionStage`, engine-tree downloaded blocks,
        // `reth stage run` / `re-execute`, ExEx backfill) sources the CL-determined bridge
        // blob from the block body, where the build path (`EthBlockAssembler`) and the verify
        // path (`ensure_well_formed_payload`) sealed it verbatim. This is what lets a node
        // that never saw the CL's newPayload — e.g. a devp2p-backfilling follower — execute
        // `parkRemoteMessages` and re-emit the 0xf0 requests entry byte-identically, so its
        // post-state root matches the sealed header. Pre-Bridge blocks carry `None` and this
        // reduces to the historical no-op behavior.
        //
        // `fee_recipient` is `header.beneficiary()`: byte-equal to the build path's
        // `attrs.suggested_fee_recipient` (the proposer sealed that address into the header
        // coinbase) and the verify path's `payload.fee_recipient()`.
        //
        // reth-v2.8.1 migration: the original called `block.header().beneficiary()` through the
        // `BlockHeader` trait, which this file no longer imports upstream; the `Header` field is
        // read directly (same as `timestamp` below).
        let bridge_request = block.body().bridge_requests.as_ref().and_then(|raw| {
            bridge_calldata_from_ssz(
                self.chain_spec().chain().id(),
                raw,
                block.header().beneficiary,
                "context_for_block (replay)",
            )
            .map(Cow::Owned)
        });
        let bridge_request_raw = block.body().bridge_requests.as_ref().map(Cow::Borrowed);

        Ok(EthBlockExecutionCtx {
            tx_count_hint: Some(block.transaction_count()),
            parent_hash: block.header().parent_hash,
            parent_beacon_block_root: block.header().parent_beacon_block_root,
            ommers: &block.body().ommers,
            withdrawals: block.body().withdrawals.as_ref().map(|w| Cow::Borrowed(w.as_slice())),
            slashed: block.body().slashed.as_ref().map(Cow::Borrowed),
            // reth-v2.8.1 migration: the original called `block.header().timestamp()` through the
            // `BlockHeader` trait, which this file no longer imports upstream; the `Header` field
            // is read directly, like the neighbouring fields.
            timestamp: block.header().timestamp,
            bridge_request,
            bridge_request_raw,
            extra_data: block.header().extra_data.clone(),
            slot_number: block.header().slot_number,
        })
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<EthBlockExecutionCtx<'_>, Self::Error> {
        // 0G: decode the SSZ `BridgeRequests` blob the CL forwarded via
        // `engine_forkchoiceUpdatedV4.payloadAttributes.bridgeRequests` and re-encode it as
        // ABI calldata for `Bridge.parkRemoteMessages(InboundMessage[])`. Fork-activation
        // and bridge-address gating happen inside
        // `system_calls::bridge::transact_bridge_contract_call`; if either is closed, the
        // calldata is computed but never executed (still cheap — a few KB encode).
        // Decoding errors degrade to `None` (no system call); a malformed blob would have
        // failed CL-side payload validation upstream, but treating it as a build-time hard
        // error would prevent the EL from making any progress at all.
        // 0G bridge fee path: the same address that the EVM will use as `block.coinbase` —
        // post-MinerReward fork, CL writes `withdrawals[0].Address` (proposer's withdrawal
        // address) into `attrs.suggested_fee_recipient`. We thread this into every
        // `InboundMessage.feeRecipient` so the dest-chain Bridge can pay the per-message fee
        // to the dest-block proposer. The verifier path in `context_for_payload` sources the
        // identical address from `payload.beneficiary` (the block-header coinbase), giving
        // build/verify byte-equal calldata.
        let fee_recipient = attributes.suggested_fee_recipient;
        let bridge_calldata = attributes.bridge_request.as_ref().and_then(|raw| {
            bridge_calldata_from_ssz(
                self.chain_spec().chain().id(),
                raw,
                fee_recipient,
                "context_for_next_block (build)",
            )
            .map(Cow::Owned)
        });

        // 0G: Forward the original SSZ blob unchanged so `EthBlockExecutor::finish` can append
        // it as the `0xf0` entry of the EIP-7685 requests list. This is what makes the proposer-
        // built sealed `block.header.requests_hash` cover the bridge entry — a precondition for
        // the CL's re-assembled block hash to match `payload.block_hash`. The bytes pass through
        // verbatim (no decode → re-encode) so proposer and verifier emit byte-equal
        // `executionRequests` lists.
        let bridge_request_raw = attributes.bridge_request.clone().map(Cow::Owned);
        tracing::debug!(
            target: "0g::evm::bridge",
            has_calldata = bridge_calldata.is_some(),
            has_raw = bridge_request_raw.is_some(),
            "context_for_next_block: bridge ctx populated"
        );

        Ok(EthBlockExecutionCtx {
            tx_count_hint: None,
            parent_hash: parent.hash(),
            parent_beacon_block_root: attributes.parent_beacon_block_root,
            ommers: &[],
            withdrawals: attributes.withdrawals.map(|w| Cow::Owned(w.into_inner())),
            slashed: None,
            timestamp: attributes.timestamp,
            bridge_request: bridge_calldata,
            bridge_request_raw,
            extra_data: attributes.extra_data,
            slot_number: attributes.slot_number,
        })
    }

    fn reuses_prewarm_results(&self) -> bool {
        // Custom factories may change transaction validation or read state outside the database.
        let factory = TypeId::of::<EvmF>();
        factory == TypeId::of::<EthEvmFactory>() ||
            factory == TypeId::of::<factory::RethEvmFactory>()
    }

    fn prewarm_tx_result(
        &self,
        tx: &TransactionSigned,
        result: ResultAndState<HaltReasonFor<Self>>,
    ) -> Option<TxExecutionResultFor<Self>> {
        Some(EthTxResult {
            result,
            blob_gas_used: tx.blob_gas_used().unwrap_or_default(),
            tx_type: tx.tx_type(),
            // reth-v2.8.1 migration: this code is new upstream after reth 1.8.1. The alloy-evm
            // fork this commit pins (`6b65ec86`, replayed as `6e150fa0`) carries the transaction
            // gas limit in `EthTxResult` so that `commit_transaction` can apply the 80% minimum
            // gas used; it is filled from the same transaction, as alloy-evm does when executing.
            tx_gas_limit: tx.gas_limit(),
        })
    }

    fn speculative_next_evm_env(
        &self,
        parent: &SealedHeader,
        beneficiary: Address,
    ) -> Option<EvmEnv> {
        let Ok(evm_env) = self.next_evm_env(
            parent,
            &NextBlockEnvAttributes {
                timestamp: parent.timestamp + SLOT_DURATION_SECS,
                suggested_fee_recipient: beneficiary,
                prev_randao: B256::ZERO,
                gas_limit: parent.gas_limit,
                parent_beacon_block_root: None,
                withdrawals: None,
                extra_data: Bytes::new(),
                slot_number: None,
                // reth-v2.8.1 migration: upstream-new speculative env for prewarming; 880ce24ad
                // added `bridge_request` to these attributes, and a guessed next block carries
                // no CL bridge blob. Only the EVM env is derived from it.
                bridge_request: None,
            },
        );
        Some(evm_env)
    }
}

#[cfg(feature = "std")]
impl<ChainSpec, EvmF> ConfigureEngineEvm<ExecutionData> for EthEvmConfig<ChainSpec, EvmF>
where
    ChainSpec: EthExecutorSpec + EthChainSpec<Header = Header> + Hardforks + 'static,
    EvmF: EvmFactory<
            Tx: TransactionEnvMut
                    + FromRecoveredTx<TransactionSigned>
                    + FromTxWithEncoded<TransactionSigned>,
            Spec = SpecId,
            BlockEnv = BlockEnv,
            Precompiles = PrecompilesMap,
        > + Clone
        + Debug
        + Send
        + Sync
        + Unpin
        + 'static,
{
    fn evm_env_for_payload(&self, payload: &ExecutionData) -> Result<EvmEnvFor<Self>, Self::Error> {
        let timestamp = payload.payload.timestamp();
        let block_number = payload.payload.block_number();

        let blob_params = self.chain_spec().blob_params_at_timestamp(timestamp);
        let spec =
            revm_spec_by_timestamp_and_block_number(self.chain_spec(), timestamp, block_number);

        // configure evm env based on parent block
        let mut cfg_env = CfgEnv::new()
            .with_chain_id(self.chain_spec().chain().id())
            .with_spec_and_mainnet_gas_params(spec);

        if let Some(blob_params) = &blob_params {
            cfg_env.set_max_blobs_per_tx(blob_params.max_blobs_per_tx);
        }

        if self.chain_spec().is_osaka_active_at_timestamp(timestamp) {
            cfg_env.tx_gas_limit_cap = Some(MAX_TX_GAS_LIMIT_OSAKA);
        }

        // derive the EIP-4844 blob fees from the header's `excess_blob_gas` and the current
        // blobparams
        let blob_excess_gas_and_price =
            payload.payload.excess_blob_gas().zip(blob_params).map(|(excess_blob_gas, params)| {
                let blob_gasprice = params.calc_blob_fee(excess_blob_gas);
                BlobExcessGasAndPrice { excess_blob_gas, blob_gasprice }
            });

        let block_env = BlockEnv {
            number: U256::from(block_number),
            beneficiary: payload.payload.fee_recipient(),
            timestamp: U256::from(timestamp),
            difficulty: if spec >= SpecId::MERGE {
                U256::ZERO
            } else {
                payload.payload.as_v1().prev_randao.into()
            },
            prevrandao: (spec >= SpecId::MERGE).then(|| payload.payload.as_v1().prev_randao),
            gas_limit: payload.payload.gas_limit(),
            basefee: payload.payload.saturated_base_fee_per_gas(),
            blob_excess_gas_and_price,
            slot_num: payload.payload.as_v4().map(|v4| v4.slot_number).unwrap_or_default(),
        };

        Ok(EvmEnv { cfg_env, block_env })
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a ExecutionData,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        // 0G bridge: extract the EIP-7685 type-`0xf0` entry, if any, and produce ABI calldata
        // for `Bridge.parkRemoteMessages`. We do NOT enforce fork-activation here — the
        // actual gating happens inside `system_calls::bridge::transact_bridge_contract_call`,
        // which checks `is_bridge_active_at_timestamp` and `bridge_contract_address`.
        // Decoding errors from CL-emitted bytes degrade to `None` (no system call); a
        // misbehaving CL would already have failed payload validation upstream.
        // Locate the `0xf0` entry once and reuse for both fields below.
        let sidecar_requests_count = payload.sidecar.requests().map_or(0, |r| r.iter().count());
        // Keep the full `&Bytes` entry (incl. type byte) so the raw field below is a zero-copy
        // refcounted slice rather than a fresh allocation; strip the type byte per use.
        let bridge_entry: Option<&Bytes> = payload
            .sidecar
            .requests()
            .and_then(|reqs| reth_0g_bridge::find_bridge_entry(reqs.iter()));

        // 0G bridge fee path: source the dest-block coinbase from the payload's fee_recipient
        // (== block-header `beneficiary` post-merge). This is byte-equal to the build path's
        // `attrs.suggested_fee_recipient` because the proposer pinned that address into the
        // header it sealed, and we don't recompute it here. Calldata produced on this path
        // matches the proposer's calldata byte-for-byte.
        let fee_recipient = payload.payload.fee_recipient();
        let bridge_calldata: Option<Cow<'a, Bytes>> = bridge_entry
            .map(|entry| &entry[1..])
            .and_then(|raw| {
                bridge_calldata_from_ssz(
                    self.chain_spec().chain().id(),
                    raw,
                    fee_recipient,
                    "context_for_payload (verify)",
                )
            })
            .map(Cow::Owned);

        // 0G: Carry the same raw SSZ bytes the CL emitted in the 0xf0 entry. On the verifier
        // path `EthBlockExecutor::finish` re-pushes them so its returned `requests` matches
        // the proposer-built sealed header's `requests_hash`. Bytes go through verbatim to
        // preserve byte-equality between proposer and verifier `executionRequests` lists.
        // Zero-copy: `Bytes::slice` is a refcounted view into the sidecar entry, not a memcpy of
        // the (up to ~13 KB at the message cap) SSZ body on every newPayload.
        let bridge_request_raw: Option<Cow<'a, Bytes>> =
            bridge_entry.map(|entry| Cow::Owned(entry.slice(1..)));

        tracing::debug!(
            target: "0g::evm::bridge",
            sidecar_requests_count,
            has_bridge_entry = bridge_entry.is_some(),
            has_calldata = bridge_calldata.is_some(),
            has_raw = bridge_request_raw.is_some(),
            "context_for_payload: bridge ctx populated"
        );

        Ok(EthBlockExecutionCtx {
            tx_count_hint: Some(payload.payload.transactions().len()),
            parent_hash: payload.parent_hash(),
            parent_beacon_block_root: payload.sidecar.parent_beacon_block_root(),
            ommers: &[],
            withdrawals: payload.payload.withdrawals().map(|w| Cow::Borrowed(w.as_slice())),
            slashed: payload
                .payload
                .slashed()
                .filter(|s| !s.is_empty())
                .map(|s| Cow::Owned(s.to_vec().into())),
            timestamp: payload.payload.timestamp(),
            bridge_request: bridge_calldata,
            bridge_request_raw,
            extra_data: payload.payload.as_v1().extra_data.clone(),
            slot_number: payload.payload.as_v4().map(|v4| v4.slot_number),
        })
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &ExecutionData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        let txs = payload.payload.transactions().clone();
        let sender_recovery_cache = self.sender_recovery_cache.clone();
        let convert = move |tx: Bytes| {
            let tx =
                TxTy::<Self::Primitives>::decode_2718_exact(tx.as_ref()).map_err(AnyError::new)?;
            let signer = if let Some(cache) = &sender_recovery_cache {
                cache.recover(&tx)
            } else {
                tx.try_recover()
            }
            .map_err(AnyError::new)?;
            Ok::<_, AnyError>(tx.with_signer(signer))
        };

        Ok((txs, convert))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header;
    use alloy_evm::{
        eth::{EthEvm, EthEvmContext},
        Database,
    };
    use alloy_genesis::Genesis;
    use reth_chainspec::{Chain, ChainSpec};
    use reth_evm::{execute::ProviderError, EvmEnv};
    use revm::{
        context::{
            result::{EVMError, HaltReason},
            BlockEnv, CfgEnv, TxEnv,
        },
        database::CacheDB,
        database_interface::{DBErrorMarker, EmptyDBTyped},
        inspector::NoOpInspector,
        Inspector,
    };

    #[test]
    fn test_fill_cfg_and_block_env() {
        // Create a default header
        let header = Header::default();

        // Build the ChainSpec for Ethereum mainnet, activating London, Paris, and Shanghai
        // hardforks
        let chain_spec = ChainSpec::builder()
            .chain(Chain::mainnet())
            .genesis(Genesis::default())
            .london_activated()
            .paris_activated()
            .shanghai_activated()
            .build();

        // Use the `EthEvmConfig` to fill the `cfg_env` and `block_env` based on the ChainSpec,
        // Header, and total difficulty
        let EvmEnv { cfg_env, .. } =
            EthEvmConfig::new(Arc::new(chain_spec.clone())).evm_env(&header).unwrap();

        // Assert that the chain ID in the `cfg_env` is correctly set to the chain ID of the
        // ChainSpec
        assert_eq!(cfg_env.chain_id, chain_spec.chain().id());
    }

    #[test]
    fn test_evm_with_env_default_spec() {
        let evm_config = EthEvmConfig::mainnet();

        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        let evm_env = EvmEnv::default();

        let evm = evm_config.evm_with_env(db, evm_env.clone());

        // Check that the EVM environment
        assert_eq!(evm.block, evm_env.block_env);
        assert_eq!(evm.cfg, evm_env.cfg_env);
    }

    #[test]
    fn test_evm_with_env_custom_cfg() {
        let evm_config = EthEvmConfig::mainnet();

        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        // Create a custom configuration environment with a chain ID of 111
        let cfg = CfgEnv::default().with_chain_id(111);

        let evm_env = EvmEnv { cfg_env: cfg.clone(), ..Default::default() };

        let evm = evm_config.evm_with_env(db, evm_env);

        // Check that the EVM environment is initialized with the custom environment
        assert_eq!(evm.cfg, cfg);
    }

    #[test]
    fn test_evm_with_env_custom_block_and_tx() {
        let evm_config = EthEvmConfig::mainnet();

        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        // Create customs block and tx env
        let block = BlockEnv {
            basefee: 1000,
            gas_limit: 10_000_000,
            number: U256::from(42),
            ..Default::default()
        };

        let evm_env = EvmEnv { block_env: block, ..Default::default() };

        let evm = evm_config.evm_with_env(db, evm_env.clone());

        // Verify that the block and transaction environments are set correctly
        assert_eq!(evm.block, evm_env.block_env);

        // Default spec ID
        assert_eq!(evm.cfg.spec, SpecId::default());
    }

    #[test]
    fn test_evm_with_spec_id() {
        let evm_config = EthEvmConfig::mainnet();

        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        let evm_env = EvmEnv {
            cfg_env: CfgEnv::new().with_spec_and_mainnet_gas_params(SpecId::PETERSBURG),
            ..Default::default()
        };

        let evm = evm_config.evm_with_env(db, evm_env);

        // Check that the spec ID is setup properly
        assert_eq!(evm.cfg.spec, SpecId::PETERSBURG);
    }

    #[test]
    fn test_evm_with_env_and_default_inspector() {
        let evm_config = EthEvmConfig::mainnet();
        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        let evm_env = EvmEnv::default();

        let evm = evm_config.evm_with_env_and_inspector(db, evm_env.clone(), NoOpInspector {});

        // Check that the EVM environment is set to default values
        assert_eq!(evm.block, evm_env.block_env);
        assert_eq!(evm.cfg, evm_env.cfg_env);
    }

    #[test]
    fn test_evm_with_env_inspector_and_custom_cfg() {
        let evm_config = EthEvmConfig::mainnet();
        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        let cfg_env = CfgEnv::default().with_chain_id(111);
        let block = BlockEnv::default();
        let evm_env = EvmEnv { cfg_env: cfg_env.clone(), block_env: block };

        let evm = evm_config.evm_with_env_and_inspector(db, evm_env, NoOpInspector {});

        // Check that the EVM environment is set with custom configuration
        assert_eq!(evm.cfg, cfg_env);
        assert_eq!(evm.cfg.spec, SpecId::default());
    }

    #[test]
    fn test_evm_with_env_inspector_and_custom_block_tx() {
        let evm_config = EthEvmConfig::mainnet();
        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        // Create custom block and tx environment
        let block = BlockEnv {
            basefee: 1000,
            gas_limit: 10_000_000,
            number: U256::from(42),
            ..Default::default()
        };
        let evm_env = EvmEnv { block_env: block, ..Default::default() };

        let evm = evm_config.evm_with_env_and_inspector(db, evm_env.clone(), NoOpInspector {});

        // Verify that the block and transaction environments are set correctly
        assert_eq!(evm.block, evm_env.block_env);
        assert_eq!(evm.cfg.spec, SpecId::default());
    }

    #[test]
    fn test_evm_with_env_inspector_and_spec_id() {
        let evm_config = EthEvmConfig::mainnet();
        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        let evm_env = EvmEnv {
            cfg_env: CfgEnv::new().with_spec_and_mainnet_gas_params(SpecId::PETERSBURG),
            ..Default::default()
        };

        let evm = evm_config.evm_with_env_and_inspector(db, evm_env.clone(), NoOpInspector {});

        // Check that the spec ID is set properly
        assert_eq!(evm.block, evm_env.block_env);
        assert_eq!(evm.cfg, evm_env.cfg_env);
        assert_eq!(evm.tx, Default::default());
    }

    #[test]
    fn test_reuses_prewarm_results_only_for_known_factories() {
        assert!(EthEvmConfig::mainnet().reuses_prewarm_results());
        assert!(EthEvmConfig::new_with_evm_factory(
            MAINNET.clone(),
            factory::RethEvmFactory::default()
        )
        .reuses_prewarm_results());

        #[derive(Debug, Clone)]
        struct CustomFactory(EthEvmFactory);

        impl EvmFactory for CustomFactory {
            type Evm<DB: Database, I: Inspector<Self::Context<DB>>> =
                EthEvm<DB, I, Self::Precompiles>;
            type Context<DB: Database> = EthEvmContext<DB>;
            type Tx = TxEnv;
            type Error<DBError: DBErrorMarker> = EVMError<DBError>;
            type HaltReason = HaltReason;
            type Spec = SpecId;
            type BlockEnv = BlockEnv;
            type Precompiles = PrecompilesMap;

            fn create_evm<DB: Database>(
                &self,
                db: DB,
                input: EvmEnv,
            ) -> Self::Evm<DB, NoOpInspector> {
                self.0.create_evm(db, input)
            }

            fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
                &self,
                db: DB,
                input: EvmEnv,
                inspector: I,
            ) -> Self::Evm<DB, I> {
                self.0.create_evm_with_inspector(db, input, inspector)
            }
        }

        assert!(!EthEvmConfig::new_with_evm_factory(
            MAINNET.clone(),
            CustomFactory(EthEvmFactory::default())
        )
        .reuses_prewarm_results());
    }

    #[cfg(feature = "jit")]
    #[test]
    fn test_jit_support_downcast_updates_reth_factory() {
        let evm_config = EthEvmConfig::new_with_evm_factory(
            MAINNET.clone(),
            factory::RethEvmFactory::disabled(),
        );

        assert!(evm_config.jit_backend().is_some());
        assert!(!evm_config.executor_factory.evm_factory().jit_support_enabled());

        let evm_config = evm_config.with_jit_support();
        assert!(evm_config.executor_factory.evm_factory().jit_support_enabled());

        let evm_config = evm_config.with_jit_support_enabled(false);
        assert!(!evm_config.executor_factory.evm_factory().jit_support_enabled());
    }

    #[cfg(feature = "jit")]
    #[test]
    fn test_jit_support_downcast_ignores_plain_factory() {
        let evm_config = EthEvmConfig::mainnet();

        assert!(evm_config.jit_backend().is_none());

        let evm_config = evm_config.with_jit_support();
        assert!(evm_config.jit_backend().is_none());
    }
}
