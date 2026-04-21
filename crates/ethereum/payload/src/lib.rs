//! A basic Ethereum payload builder implementation.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![allow(clippy::useless_let_if_seq)]

use alloy_consensus::Transaction;
use alloy_primitives::{Address, B256, U256};
use alloy_rlp::Encodable;
use reth_basic_payload_builder::{
    is_better_payload, BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadBuilder,
    PayloadConfig,
};
use reth_chainspec::{ChainSpecProvider, EthChainSpec, EthereumHardforks};
use reth_consensus_common::validation::MAX_RLP_BLOCK_SIZE;
use reth_errors::ConsensusError;
use reth_ethereum_primitives::{EthPrimitives, TransactionSigned};
use reth_evm::{
    execute::{BlockBuilder, BlockBuilderOutcome},
    ConfigureEvm, Evm, NextBlockEnvAttributes,
};
use reth_evm_ethereum::EthEvmConfig;
use reth_payload_builder::{BlobSidecars, EthBuiltPayload, EthPayloadBuilderAttributes};
use reth_payload_builder_primitives::PayloadBuilderError;
use reth_payload_primitives::PayloadBuilderAttributes;
use reth_revm::{database::StateProviderDatabase, db::State};
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{
    error::{Eip4844PoolTransactionError, InvalidPoolTransactionError},
    BestTransactions, BestTransactionsAttributes, PoolTransaction, TransactionPool,
    ValidPoolTransaction,
};
use revm::{context_interface::Block as _, precompile::perp_dex::PERP_DEX_ADDRESS};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tracing::{debug, trace, warn};

mod config;
pub use config::*;

pub mod validator;
pub use validator::EthereumExecutionPayloadValidator;

type BestTransactionsIter<Pool> = Box<
    dyn BestTransactions<Item = Arc<ValidPoolTransaction<<Pool as TransactionPool>::Transaction>>>,
>;

/// Ethereum payload builder
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthereumPayloadBuilder<Pool, Client, EvmConfig = EthEvmConfig> {
    /// Client providing access to node state.
    client: Client,
    /// Transaction pool.
    pool: Pool,
    /// The type responsible for creating the evm.
    evm_config: EvmConfig,
    /// Payload builder configuration.
    builder_config: EthereumBuilderConfig,
}

impl<Pool, Client, EvmConfig> EthereumPayloadBuilder<Pool, Client, EvmConfig> {
    /// `EthereumPayloadBuilder` constructor.
    pub const fn new(
        client: Client,
        pool: Pool,
        evm_config: EvmConfig,
        builder_config: EthereumBuilderConfig,
    ) -> Self {
        Self { client, pool, evm_config, builder_config }
    }
}

// Default implementation of [PayloadBuilder] for unit type
impl<Pool, Client, EvmConfig> PayloadBuilder for EthereumPayloadBuilder<Pool, Client, EvmConfig>
where
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec: EthereumHardforks> + Clone,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>,
{
    type Attributes = EthPayloadBuilderAttributes;
    type BuiltPayload = EthBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<EthPayloadBuilderAttributes, EthBuiltPayload>,
    ) -> Result<BuildOutcome<EthBuiltPayload>, PayloadBuilderError> {
        default_ethereum_payload(
            self.evm_config.clone(),
            self.client.clone(),
            self.pool.clone(),
            self.builder_config.clone(),
            args,
            |attributes| self.pool.best_transactions_with_attributes(attributes),
        )
    }

    fn on_missing_payload(
        &self,
        _args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> MissingPayloadBehaviour<Self::BuiltPayload> {
        if self.builder_config.await_payload_on_missing {
            MissingPayloadBehaviour::AwaitInProgress
        } else {
            MissingPayloadBehaviour::RaceEmptyPayload
        }
    }

    fn build_empty_payload(
        &self,
        config: PayloadConfig<Self::Attributes>,
    ) -> Result<EthBuiltPayload, PayloadBuilderError> {
        let args = BuildArguments::new(Default::default(), config, Default::default(), None);

        default_ethereum_payload(
            self.evm_config.clone(),
            self.client.clone(),
            self.pool.clone(),
            self.builder_config.clone(),
            args,
            |attributes| self.pool.best_transactions_with_attributes(attributes),
        )?
        .into_payload()
        .ok_or_else(|| PayloadBuilderError::MissingPayload)
    }
}

/// Constructs an Ethereum transaction payload using the best transactions from the pool.
///
/// Given build arguments including an Ethereum client, transaction pool,
/// and configuration, this function creates a transaction payload. Returns
/// a result indicating success with the payload or an error in case of failure.
#[inline]
pub fn default_ethereum_payload<EvmConfig, Client, Pool, F>(
    evm_config: EvmConfig,
    client: Client,
    pool: Pool,
    builder_config: EthereumBuilderConfig,
    args: BuildArguments<EthPayloadBuilderAttributes, EthBuiltPayload>,
    best_txs: F,
) -> Result<BuildOutcome<EthBuiltPayload>, PayloadBuilderError>
where
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec: EthereumHardforks>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>,
    F: FnOnce(BestTransactionsAttributes) -> BestTransactionsIter<Pool>,
{
    let BuildArguments { mut cached_reads, config, cancel, best_payload } = args;
    let PayloadConfig { parent_header, attributes } = config;

    let state_provider = client.state_by_block_hash(parent_header.hash())?;
    let state = StateProviderDatabase::new(&state_provider);
    let mut db =
        State::builder().with_database(cached_reads.as_db_mut(state)).with_bundle_update().build();

    let mut builder = evm_config
        .builder_for_next_block(
            &mut db,
            &parent_header,
            NextBlockEnvAttributes {
                timestamp: attributes.timestamp(),
                suggested_fee_recipient: attributes.suggested_fee_recipient(),
                prev_randao: attributes.prev_randao(),
                gas_limit: builder_config.gas_limit(parent_header.gas_limit),
                parent_beacon_block_root: attributes.parent_beacon_block_root(),
                withdrawals: Some(attributes.withdrawals().clone()),
            },
        )
        .map_err(PayloadBuilderError::other)?;

    let chain_spec = client.chain_spec();

    debug!(target: "payload_builder", id=%attributes.id, parent_header = ?parent_header.hash(), parent_number = parent_header.number, "building new payload");
    let mut cumulative_gas_used = 0;
    let block_gas_limit: u64 = builder.evm_mut().block().gas_limit;
    let base_fee = builder.evm_mut().block().basefee;

    let blob_gasprice =
        builder.evm_mut().block().blob_gasprice().map(|gasprice| gasprice as u64);
    let mut total_fees = U256::ZERO;

    // Track cumulative gas cost per sender to prevent insufficient balance issues
    // when multiple transactions from the same sender are included in the block
    let mut sender_cumulative_gas_cost: HashMap<Address, U256> = HashMap::new();

    builder.apply_pre_execution_changes().map_err(|err| {
        warn!(target: "payload_builder", %err, "failed to apply pre-execution changes");
        PayloadBuilderError::Internal(err.into())
    })?;

    // initialize empty blob sidecars at first. If cancun is active then this will be populated by
    // blob sidecars if any.
    let mut blob_sidecars = BlobSidecars::Empty;

    let mut block_blob_count = 0u64;
    let mut block_transactions_rlp_length = 0usize;

    let blob_params = chain_spec.blob_params_at_timestamp(attributes.timestamp);
    let max_blob_count =
        blob_params.as_ref().map(|params| params.max_blob_count).unwrap_or_default();

    let is_osaka = chain_spec.is_osaka_active_at_timestamp(attributes.timestamp);

    // PerpDEX-priority gating: on blocks where `target_block % perpdex_modulus != 0`, pack
    // PerpDEX-targeted transactions first and use a second pass to fill remaining gas with
    // non-PerpDEX traffic. `perpdex_modulus == 0` (or target % modulus == 0) disables the gating.
    let target_block = parent_header.number + 1;
    let perpdex_modulus = builder_config.perpdex_modulus;
    let is_open_block = perpdex_modulus == 0 || target_block % perpdex_modulus == 0;
    let withdrawals_rlp_length = attributes.withdrawals().length();
    let mut included_hashes: HashSet<B256> = HashSet::new();

    // Outcome of attempting to include one transaction. Caller applies `mark_invalid`
    // / `skip_blobs` to the iterator based on the result; the closure itself does not
    // see the iterator so the pass-1 / pass-2 loops can supply different iterators.
    enum PackOutcome {
        Included { saturated_blobs: bool },
        Invalid(InvalidPoolTransactionError),
        Cancelled,
    }

    // All mutable per-block state is captured by `&mut` here. Both passes call this closure;
    // we wrap both loops in a block so the closure drops before `builder.finish(...)` runs.
    {
        let mut try_pack = |pool_tx: Arc<ValidPoolTransaction<Pool::Transaction>>|
            -> Result<PackOutcome, PayloadBuilderError> {
            // ensure we still have capacity for this transaction
            if cumulative_gas_used + pool_tx.gas_limit() > block_gas_limit {
                return Ok(PackOutcome::Invalid(InvalidPoolTransactionError::ExceedsGasLimit(
                    pool_tx.gas_limit(),
                    block_gas_limit,
                )));
            }

            // check if the job was cancelled, if so we can exit early
            if cancel.is_cancelled() {
                return Ok(PackOutcome::Cancelled);
            }

            // convert tx to a signed transaction
            let tx = pool_tx.to_consensus();

            let estimated_block_size_with_tx = block_transactions_rlp_length +
                tx.inner().length() +
                withdrawals_rlp_length +
                1024; // 1Kb of overhead for the block header

            if is_osaka && estimated_block_size_with_tx > MAX_RLP_BLOCK_SIZE {
                return Ok(PackOutcome::Invalid(InvalidPoolTransactionError::OversizedData(
                    estimated_block_size_with_tx,
                    MAX_RLP_BLOCK_SIZE,
                )));
            }

            // There's only limited amount of blob space available per block, so we need to check
            // if the EIP-4844 can still fit in the block
            let mut blob_tx_sidecar = None;
            if let Some(blob_tx) = tx.as_eip4844() {
                let tx_blob_count = blob_tx.tx().blob_versioned_hashes.len() as u64;

                if block_blob_count + tx_blob_count > max_blob_count {
                    trace!(target: "payload_builder", tx=?tx.hash(), ?block_blob_count, "skipping blob transaction because it would exceed the max blob count per block");
                    return Ok(PackOutcome::Invalid(InvalidPoolTransactionError::Eip4844(
                        Eip4844PoolTransactionError::TooManyEip4844Blobs {
                            have: block_blob_count + tx_blob_count,
                            permitted: max_blob_count,
                        },
                    )));
                }

                let blob_sidecar_result = 'sidecar: {
                    let Some(sidecar) =
                        pool.get_blob(*tx.hash()).map_err(PayloadBuilderError::other)?
                    else {
                        break 'sidecar Err(Eip4844PoolTransactionError::MissingEip4844BlobSidecar)
                    };

                    if is_osaka {
                        if sidecar.is_eip7594() {
                            Ok(sidecar)
                        } else {
                            Err(Eip4844PoolTransactionError::UnexpectedEip4844SidecarAfterOsaka)
                        }
                    } else if sidecar.is_eip4844() {
                        Ok(sidecar)
                    } else {
                        Err(Eip4844PoolTransactionError::UnexpectedEip7594SidecarBeforeOsaka)
                    }
                };

                blob_tx_sidecar = match blob_sidecar_result {
                    Ok(sidecar) => Some(sidecar),
                    Err(error) => {
                        return Ok(PackOutcome::Invalid(InvalidPoolTransactionError::Eip4844(
                            error,
                        )));
                    }
                };
            }

            // Use gas limit instead of executing transaction
            let gas_used = pool_tx.gas_limit();

            // Calculate the maximum gas cost for this transaction
            let max_fee_per_gas = tx.max_fee_per_gas();
            let max_priority_fee_per_gas = tx.max_priority_fee_per_gas().unwrap_or(0);
            let effective_gas_price = (U256::from(base_fee) + U256::from(max_priority_fee_per_gas))
                .min(U256::from(max_fee_per_gas));
            let tx_max_cost = U256::from(gas_used) * effective_gas_price;

            // Get sender address
            let sender = pool_tx.sender();

            // Calculate total cumulative cost for this sender including this transaction
            let current_cumulative_cost =
                sender_cumulative_gas_cost.get(&sender).copied().unwrap_or(U256::ZERO);
            let new_cumulative_cost = current_cumulative_cost + tx_max_cost + tx.value();

            // Check if sender has sufficient balance for cumulative gas costs
            // Query sender balance from the state provider
            if let Ok(Some(sender_account)) = state_provider.basic_account(&sender) {
                let sender_balance = sender_account.balance;

                if sender_balance < new_cumulative_cost {
                    trace!(
                        target: "payload_builder",
                        ?tx,
                        ?sender,
                        sender_balance = ?sender_balance,
                        required_cost = ?new_cumulative_cost,
                        cumulative_cost = ?current_cumulative_cost,
                        "skipping transaction: insufficient balance for cumulative gas costs"
                    );
                    return Ok(PackOutcome::Invalid(InvalidPoolTransactionError::ExceedsFeeCap {
                        max_tx_fee_wei: new_cumulative_cost.try_into().unwrap_or(u128::MAX),
                        tx_fee_cap_wei: sender_balance.try_into().unwrap_or(u128::MAX),
                    }));
                }
            }

            // Add transaction to block without execution
            builder.add_transaction_without_execution(tx.clone());

            // Update sender's cumulative gas cost
            sender_cumulative_gas_cost.insert(sender, new_cumulative_cost);

            // add to the total blob gas used if the transaction successfully executed
            let mut saturated_blobs = false;
            if let Some(blob_tx) = tx.as_eip4844() {
                block_blob_count += blob_tx.tx().blob_versioned_hashes.len() as u64;

                // if we've reached the max blob count, we can skip blob txs entirely
                if block_blob_count == max_blob_count {
                    saturated_blobs = true;
                }
            }

            block_transactions_rlp_length += tx.inner().length();

            // update and add to total fees
            let miner_fee = tx
                .effective_tip_per_gas(base_fee)
                .expect("fee is always valid; execution succeeded");
            total_fees += U256::from(miner_fee) * U256::from(gas_used);
            cumulative_gas_used += gas_used;

            // Add blob tx sidecar to the payload.
            if let Some(sidecar) = blob_tx_sidecar {
                blob_sidecars.push_sidecar_variant(sidecar.as_ref().clone());
            }

            Ok(PackOutcome::Included { saturated_blobs })
        };

        // Pass 1: on closed blocks, pack only PerpDEX txs (deferring everything else via
        // `mark_invalid`, which cascades their same-sender descendants out of this iterator
        // only — the pool itself is unaffected). On open blocks, pack everything normally.
        let mut best_txs_pass1 =
            best_txs(BestTransactionsAttributes::new(base_fee, blob_gasprice));
        while let Some(pool_tx) = best_txs_pass1.next() {
            if !is_open_block && pool_tx.to() != Some(PERP_DEX_ADDRESS) {
                best_txs_pass1
                    .mark_invalid(&pool_tx, InvalidPoolTransactionError::Underpriced);
                continue;
            }
            match try_pack(pool_tx.clone())? {
                PackOutcome::Included { saturated_blobs } => {
                    if !is_open_block {
                        included_hashes.insert(*pool_tx.hash());
                    }
                    if saturated_blobs {
                        best_txs_pass1.skip_blobs();
                    }
                }
                PackOutcome::Invalid(err) => {
                    best_txs_pass1.mark_invalid(&pool_tx, err);
                }
                PackOutcome::Cancelled => return Ok(BuildOutcome::Cancelled),
            }
        }

        // Pass 2 (closed blocks only): fill remaining gas with non-PerpDEX txs as filler.
        // A fresh pool iterator is required because pass 1 cascaded them out of `best_txs_pass1`.
        // Already-packed hashes are skipped silently — `next()` has already advanced the
        // sender's internal nonce cursor, so skipping with `continue` leaves pass 2 in the
        // correct state to yield the sender's next-nonce tx.
        if !is_open_block {
            let mut best_txs_pass2 = pool.best_transactions_with_attributes(
                BestTransactionsAttributes::new(base_fee, blob_gasprice),
            );
            while let Some(pool_tx) = best_txs_pass2.next() {
                if included_hashes.contains(pool_tx.hash()) {
                    continue;
                }
                match try_pack(pool_tx.clone())? {
                    PackOutcome::Included { saturated_blobs } => {
                        if saturated_blobs {
                            best_txs_pass2.skip_blobs();
                        }
                    }
                    PackOutcome::Invalid(err) => {
                        best_txs_pass2.mark_invalid(&pool_tx, err);
                    }
                    PackOutcome::Cancelled => return Ok(BuildOutcome::Cancelled),
                }
            }
        }
    }

    // check if we have a better block
    if !is_better_payload(best_payload.as_ref(), total_fees) {
        // Release db
        drop(builder);
        // can skip building the block
        return Ok(BuildOutcome::Aborted { fees: total_fees, cached_reads })
    }

    let BlockBuilderOutcome { execution_result, block, .. } = builder.finish(&state_provider)?;

    let requests = chain_spec
        .is_prague_active_at_timestamp(attributes.timestamp)
        .then_some(execution_result.requests);

    let sealed_block = Arc::new(block.sealed_block().clone());
    debug!(target: "payload_builder", id=%attributes.id, sealed_block_header = ?sealed_block.sealed_header(), "sealed built block");

    if is_osaka && sealed_block.rlp_length() > MAX_RLP_BLOCK_SIZE {
        return Err(PayloadBuilderError::other(ConsensusError::BlockTooLarge {
            rlp_length: sealed_block.rlp_length(),
            max_rlp_length: MAX_RLP_BLOCK_SIZE,
        }));
    }

    let payload = EthBuiltPayload::new(attributes.id, sealed_block, total_fees, requests)
        // add blob sidecars from the executed txs
        .with_sidecars(blob_sidecars);

    Ok(BuildOutcome::Better { payload, cached_reads })
}
