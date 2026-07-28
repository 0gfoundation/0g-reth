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
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{borrow::Cow, sync::Arc, vec, vec::Vec};
use alloy_consensus::{BlockHeader, Header};
use alloy_eips::Decodable2718;
pub use alloy_evm::EthEvm;
use alloy_evm::{
    eth::{EthBlockExecutionCtx, EthBlockExecutorFactory},
    EthEvmFactory, FromRecoveredTx, FromTxWithEncoded,
};
use alloy_primitives::{Bytes, U256};
use alloy_rpc_types_engine::ExecutionData;
use core::{convert::Infallible, fmt::Debug};
use reth_chainspec::{ChainSpec, EthChainSpec, EthereumHardforks, MAINNET};
use reth_ethereum_primitives::{Block, EthPrimitives, TransactionSigned};
use reth_evm::{
    precompiles::PrecompilesMap, ConfigureEngineEvm, ConfigureEvm, EvmEnv, EvmEnvFor, EvmFactory,
    ExecutableTxIterator, ExecutionCtxFor, NextBlockEnvAttributes, TransactionEnv,
};
use reth_primitives_traits::{
    constants::MAX_TX_GAS_LIMIT_OSAKA, transaction::recover::recover_signers, SealedBlock,
    SealedHeader, SignedTransaction, TxTy,
};
use reth_storage_errors::any::AnyError;
use revm::{
    context::{BlockEnv, CfgEnv},
    context_interface::block::BlobExcessGasAndPrice,
    primitives::hardfork::SpecId,
};

mod config;
use alloy_eips::{eip1559::INITIAL_BASE_FEE, eip7840::BlobParams};
use alloy_evm::eth::spec::EthExecutorSpec;
pub use config::{revm_spec, revm_spec_by_timestamp_and_block_number};
use reth_ethereum_forks::{EthereumHardfork, Hardforks};

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

/// Ethereum-related EVM configuration.
#[derive(Debug, Clone)]
pub struct EthEvmConfig<C = ChainSpec, EvmFactory = EthEvmFactory> {
    /// Inner [`EthBlockExecutorFactory`].
    pub executor_factory: EthBlockExecutorFactory<RethReceiptBuilder, Arc<C>, EvmFactory>,
    /// Ethereum block assembler.
    pub block_assembler: EthBlockAssembler<C>,
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

    /// Sets the extra data for the block assembler.
    pub fn with_extra_data(mut self, extra_data: Bytes) -> Self {
        self.block_assembler.extra_data = extra_data;
        self
    }
}

impl<ChainSpec, EvmF> ConfigureEvm for EthEvmConfig<ChainSpec, EvmF>
where
    ChainSpec: EthExecutorSpec + EthChainSpec<Header = Header> + Hardforks + 'static,
    EvmF: EvmFactory<
            Tx: TransactionEnv
                    + FromRecoveredTx<TransactionSigned>
                    + FromTxWithEncoded<TransactionSigned>,
            Spec = SpecId,
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

    fn evm_env(&self, header: &Header) -> EvmEnv {
        let blob_params = self.chain_spec().blob_params_at_timestamp(header.timestamp);
        let spec = config::revm_spec(self.chain_spec(), header);

        // configure evm env based on parent block
        let mut cfg_env =
            CfgEnv::new().with_chain_id(self.chain_spec().chain().id()).with_spec(spec);

        if let Some(blob_params) = &blob_params {
            cfg_env.set_max_blobs_per_tx(blob_params.max_blobs_per_tx);
        }

        if self.chain_spec().is_osaka_active_at_timestamp(header.timestamp) {
            cfg_env.tx_gas_limit_cap = Some(MAX_TX_GAS_LIMIT_OSAKA);
        }

        // derive the EIP-4844 blob fees from the header's `excess_blob_gas` and the current
        // blobparams
        let blob_excess_gas_and_price =
            header.excess_blob_gas.zip(blob_params).map(|(excess_blob_gas, params)| {
                let blob_gasprice = params.calc_blob_fee(excess_blob_gas);
                BlobExcessGasAndPrice { excess_blob_gas, blob_gasprice }
            });

        let block_env = BlockEnv {
            number: U256::from(header.number()),
            beneficiary: header.beneficiary(),
            timestamp: U256::from(header.timestamp()),
            difficulty: if spec >= SpecId::MERGE { U256::ZERO } else { header.difficulty() },
            prevrandao: if spec >= SpecId::MERGE { header.mix_hash() } else { None },
            gas_limit: header.gas_limit(),
            basefee: header.base_fee_per_gas().unwrap_or_default(),
            blob_excess_gas_and_price,
        };

        EvmEnv { cfg_env, block_env }
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &NextBlockEnvAttributes,
    ) -> Result<EvmEnv, Self::Error> {
        // ensure we're not missing any timestamp based hardforks
        let chain_spec = self.chain_spec();
        let blob_params = chain_spec.blob_params_at_timestamp(attributes.timestamp);
        let spec_id = revm_spec_by_timestamp_and_block_number(
            chain_spec,
            attributes.timestamp,
            parent.number() + 1,
        );

        // configure evm env based on parent block
        let mut cfg =
            CfgEnv::new().with_chain_id(self.chain_spec().chain().id()).with_spec(spec_id);

        if let Some(blob_params) = &blob_params {
            cfg.set_max_blobs_per_tx(blob_params.max_blobs_per_tx);
        }

        if self.chain_spec().is_osaka_active_at_timestamp(attributes.timestamp) {
            cfg.tx_gas_limit_cap = Some(MAX_TX_GAS_LIMIT_OSAKA);
        }

        // if the parent block did not have excess blob gas (i.e. it was pre-cancun), but it is
        // cancun now, we need to set the excess blob gas to the default value(0)
        let blob_excess_gas_and_price = parent
            .maybe_next_block_excess_blob_gas(blob_params)
            .or_else(|| (spec_id == SpecId::CANCUN).then_some(0))
            .map(|excess_blob_gas| {
                let blob_gasprice =
                    blob_params.unwrap_or_else(BlobParams::cancun).calc_blob_fee(excess_blob_gas);
                BlobExcessGasAndPrice { excess_blob_gas, blob_gasprice }
            });

        let mut basefee = chain_spec.next_block_base_fee(parent, attributes.timestamp);

        let mut gas_limit = attributes.gas_limit;

        // If we are on the London fork boundary, we need to multiply the parent's gas limit by the
        // elasticity multiplier to get the new gas limit.
        if self.chain_spec().fork(EthereumHardfork::London).transitions_at_block(parent.number + 1)
        {
            let elasticity_multiplier = self
                .chain_spec()
                .base_fee_params_at_timestamp(attributes.timestamp)
                .elasticity_multiplier;

            // multiply the gas limit by the elasticity multiplier
            gas_limit *= elasticity_multiplier as u64;

            // set the base fee to the initial base fee from the EIP-1559 spec
            basefee = Some(INITIAL_BASE_FEE)
        }

        let block_env = BlockEnv {
            number: U256::from(parent.number + 1),
            beneficiary: attributes.suggested_fee_recipient,
            timestamp: U256::from(attributes.timestamp),
            difficulty: U256::ZERO,
            prevrandao: Some(attributes.prev_randao),
            gas_limit,
            // calculate basefee based on parent block's gas usage
            basefee: basefee.unwrap_or_default(),
            // calculate excess gas based on parent block's blob gas usage
            blob_excess_gas_and_price,
        };

        Ok((cfg, block_env).into())
    }

    fn context_for_block<'a>(&self, block: &'a SealedBlock<Block>) -> EthBlockExecutionCtx<'a> {
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
        let bridge_request = block.body().bridge_requests.as_ref().and_then(|raw| {
            bridge_calldata_from_ssz(
                self.chain_spec().chain().id(),
                raw,
                block.header().beneficiary(),
                "context_for_block (replay)",
            )
            .map(Cow::Owned)
        });
        let bridge_request_raw = block.body().bridge_requests.as_ref().map(Cow::Borrowed);

        EthBlockExecutionCtx {
            parent_hash: block.header().parent_hash,
            parent_beacon_block_root: block.header().parent_beacon_block_root,
            ommers: &block.body().ommers,
            withdrawals: block.body().withdrawals.as_ref().map(Cow::Borrowed),
            slashed: block.body().slashed.as_ref().map(Cow::Borrowed),
            timestamp: block.header().timestamp(),
            bridge_request,
            bridge_request_raw,
        }
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> EthBlockExecutionCtx<'_> {
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

        EthBlockExecutionCtx {
            parent_hash: parent.hash(),
            parent_beacon_block_root: attributes.parent_beacon_block_root,
            ommers: &[],
            withdrawals: attributes.withdrawals.map(Cow::Owned),
            slashed: None,
            timestamp: attributes.timestamp,
            bridge_request: bridge_calldata,
            bridge_request_raw,
        }
    }
}

impl<ChainSpec, EvmF> ConfigureEngineEvm<ExecutionData> for EthEvmConfig<ChainSpec, EvmF>
where
    ChainSpec: EthExecutorSpec + EthChainSpec<Header = Header> + Hardforks + 'static,
    EvmF: EvmFactory<
            Tx: TransactionEnv
                    + FromRecoveredTx<TransactionSigned>
                    + FromTxWithEncoded<TransactionSigned>,
            Spec = SpecId,
            Precompiles = PrecompilesMap,
        > + Clone
        + Debug
        + Send
        + Sync
        + Unpin
        + 'static,
{
    fn evm_env_for_payload(&self, payload: &ExecutionData) -> EvmEnvFor<Self> {
        let timestamp = payload.payload.timestamp();
        let block_number = payload.payload.block_number();

        let blob_params = self.chain_spec().blob_params_at_timestamp(timestamp);
        let spec =
            revm_spec_by_timestamp_and_block_number(self.chain_spec(), timestamp, block_number);

        // configure evm env based on parent block
        let mut cfg_env =
            CfgEnv::new().with_chain_id(self.chain_spec().chain().id()).with_spec(spec);

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
        };

        EvmEnv { cfg_env, block_env }
    }

    fn context_for_payload<'a>(&self, payload: &'a ExecutionData) -> ExecutionCtxFor<'a, Self> {
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

        EthBlockExecutionCtx {
            parent_hash: payload.parent_hash(),
            parent_beacon_block_root: payload.sidecar.parent_beacon_block_root(),
            ommers: &[],
            withdrawals: payload.payload.withdrawals().map(|w| Cow::Owned(w.clone().into())),
            slashed: payload
                .payload
                .slashed()
                .filter(|s| !s.is_empty())
                .map(|s| Cow::Owned(s.to_vec().into())),
            timestamp: payload.payload.timestamp(),
            bridge_request: bridge_calldata,
            bridge_request_raw,
        }
    }

    fn tx_iterator_for_payload(&self, payload: &ExecutionData) -> impl ExecutableTxIterator<Self> {
        // Recover the payload's tx signers in parallel, up front — rather than lazily, one tx at
        // a time, on the single feeder thread that streams txs to the executor. Sender recovery
        // is pure per-tx secp256k1 (~40-90µs/tx) with no state dependency, so it parallelizes
        // freely. `recover_signers` calls the *identical* `recover_signer()` the old per-tx
        // `try_recover()` used, so recovered senders are byte-identical (consensus-neutral); under
        // the node's `reth-primitives-traits/rayon` feature it fans the work across the rayon pool
        // and collapses to sequential otherwise. Decoding stays sequential (cheap; recovery is the
        // cost). This removes the per-tx recv-wait in which the executor was parked waiting for the
        // single recovery thread — the dominant term in the on-chain execution segment.
        let decoded = payload
            .payload
            .transactions()
            .iter()
            .map(|tx| {
                TxTy::<Self::Primitives>::decode_2718_exact(tx.as_ref()).map_err(AnyError::new)
            })
            .collect::<Result<Vec<TxTy<Self::Primitives>>, AnyError>>();

        // On any decode/recover failure, yield a single leading Err: the block is rejected
        // wholesale either way, matching the old per-tx short-circuit's verdict (nothing is
        // committed unless the whole block validates).
        let recovered: Vec<Result<_, AnyError>> = match decoded {
            Ok(txs) => match recover_signers(&txs).map_err(AnyError::new) {
                Ok(signers) => txs
                    .into_iter()
                    .zip(signers)
                    .map(|(tx, signer)| Ok(tx.with_signer(signer)))
                    .collect(),
                Err(e) => vec![Err(e)],
            },
            Err(e) => vec![Err(e)],
        };
        recovered.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header;
    use alloy_genesis::Genesis;
    use reth_chainspec::{Chain, ChainSpec};
    use reth_evm::{execute::ProviderError, EvmEnv};
    use revm::{
        context::{BlockEnv, CfgEnv},
        database::CacheDB,
        database_interface::EmptyDBTyped,
        inspector::NoOpInspector,
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
            EthEvmConfig::new(Arc::new(chain_spec.clone())).evm_env(&header);

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
            cfg_env: CfgEnv::new().with_spec(SpecId::CONSTANTINOPLE),
            ..Default::default()
        };

        let evm = evm_config.evm_with_env(db, evm_env);

        // Check that the spec ID is setup properly
        assert_eq!(evm.cfg.spec, SpecId::CONSTANTINOPLE);
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
            cfg_env: CfgEnv::new().with_spec(SpecId::CONSTANTINOPLE),
            ..Default::default()
        };

        let evm = evm_config.evm_with_env_and_inspector(db, evm_env.clone(), NoOpInspector {});

        // Check that the spec ID is set properly
        assert_eq!(evm.block, evm_env.block_env);
        assert_eq!(evm.cfg, evm_env.cfg_env);
        assert_eq!(evm.tx, Default::default());
    }
}
