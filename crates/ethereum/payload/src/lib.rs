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
use reth_primitives_traits::transaction::error::InvalidTransactionError;
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

    let blob_gasprice = builder.evm_mut().block().blob_gasprice().map(|gasprice| gasprice as u64);
    let mut total_fees = U256::ZERO;

    // Track cumulative gas cost per sender to prevent insufficient balance issues
    // when multiple transactions from the same sender are included in the block
    let mut sender_cumulative_gas_cost: HashMap<Address, U256> = HashMap::new();

    // Per-sender committed-account memo (catalog V3). `basic_account` goes straight to the
    // provider — bypassing cached_reads, and caching is disabled on this deployment — so the
    // per-candidate read was a full mdbx round-trip each time. The committed snapshot cannot
    // change within a build job, so one read per sender is exact; `Err` memoizes as `None`
    // (same skip-the-checks behavior as before). Biggest win on relayer-shaped flows
    // (hundreds of txs per sender per block); also dedups across the two modulus passes.
    let mut sender_accounts: HashMap<Address, Option<reth_primitives_traits::Account>> =
        HashMap::new();

    // Track the next nonce expected per sender within this build job. Initialized
    // lazily from chain state on first encounter, then incremented after each
    // accepted tx. Bidirectionally guards against stale (already-mined) and gap
    // (out-of-order independent insertion) tx that the pool iterator can yield
    // under multi-source burst load. See fix/payload-skip-stale-nonce-tx.
    let mut sender_next_nonce: HashMap<Address, u64> = HashMap::new();

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
    let is_open_block = builder_config.is_open_block(target_block);
    let withdrawals_rlp_length = attributes.withdrawals().length();
    let mut included_hashes: HashSet<B256> = HashSet::new();

    // Outcome of attempting to include one transaction. Caller applies `mark_invalid`
    // / `skip_blobs` to the iterator based on the result; the closure itself does not
    // see the iterator so the pass-1 / pass-2 loops can supply different iterators.
    enum PackOutcome {
        Included { saturated_blobs: bool },
        Invalid(InvalidPoolTransactionError),
        Skip,
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
            // Query sender balance from the state provider (memoized per sender — V3)
            let sender_account = *sender_accounts
                .entry(sender)
                .or_insert_with(|| state_provider.basic_account(&sender).ok().flatten());
            if let Some(sender_account) = sender_account {
                let sender_balance = sender_account.balance;

                // Bidirectional nonce guard. The pool iterator's independent set
                // can be wrong in two directions when 0g's delay-execution path
                // skips EVM enforcement:
                //   * stale (pool_tx.nonce < expected): pool snapshot lagged
                //   * gap   (pool_tx.nonce > expected): out-of-order arrival
                // Either case would produce an invalid block at NewPayload.
                let expected_nonce =
                    *sender_next_nonce.entry(sender).or_insert(sender_account.nonce);
                if pool_tx.nonce() < expected_nonce {
                    warn!(
                        target: "payload_builder",
                        ?sender,
                        pool_tx_nonce = pool_tx.nonce(),
                        expected = expected_nonce,
                        tx_hash = ?tx.hash(),
                        "STALE_TX_IN_BUILD skipping stale (already-mined) tx"
                    );
                    return Ok(PackOutcome::Skip);
                }
                if pool_tx.nonce() > expected_nonce {
                    warn!(
                        target: "payload_builder",
                        ?sender,
                        pool_tx_nonce = pool_tx.nonce(),
                        expected = expected_nonce,
                        tx_hash = ?tx.hash(),
                        "GAP_TX_IN_BUILD skipping gap-nonce tx; sender invalidated for this build"
                    );
                    return Ok(PackOutcome::Invalid(InvalidPoolTransactionError::Consensus(
                        InvalidTransactionError::NonceNotConsistent {
                            tx: pool_tx.nonce(),
                            state: expected_nonce,
                        },
                    )));
                }

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

            // Advance the in-build expected nonce so subsequent txs from this
            // sender are checked against the post-tx position.
            sender_next_nonce.insert(sender, pool_tx.nonce() + 1);

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
        let mut best_txs_pass1 = best_txs(BestTransactionsAttributes::new(base_fee, blob_gasprice));
        while let Some(pool_tx) = best_txs_pass1.next() {
            if !is_open_block && pool_tx.to() != Some(PERP_DEX_ADDRESS) {
                best_txs_pass1.mark_invalid(&pool_tx, InvalidPoolTransactionError::Underpriced);
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
                PackOutcome::Skip => {}
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
                    PackOutcome::Skip => {}
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

/// Iterator-pattern tests.
///
/// These tests do NOT go through `default_ethereum_payload`. They run the same two-pass
/// filter/skip pattern against a synthetic `BestTransactions` iterator, whose cascade
/// semantics on `mark_invalid` mirror what the real Reth pool provides. The goal is to
/// verify that the pattern itself (pass-1 filter + `mark_invalid`, pass-2 hash-skip) is
/// correct, independent of the payload builder's block-assembly concerns.
#[cfg(test)]
mod iter_pattern_tests {
    use super::*;
    use alloy_primitives::{Address, TxKind};
    use reth_transaction_pool::{
        test_utils::{MockTransaction, MockTransactionFactory, MockValidTx},
        BestTransactions,
    };
    use std::collections::VecDeque;

    /// Synthetic `BestTransactions` iterator. `mark_invalid` removes the named tx *and* any
    /// descendant (same sender, higher nonce) from the remaining queue — matching the real
    /// Reth iterator's cascade behavior.
    struct MockBestTxs {
        queue: VecDeque<Arc<MockValidTx>>,
        mark_invalid_calls: Vec<B256>,
    }

    impl MockBestTxs {
        fn new(txs: Vec<Arc<MockValidTx>>) -> Self {
            Self { queue: txs.into_iter().collect(), mark_invalid_calls: vec![] }
        }
    }

    impl Iterator for MockBestTxs {
        type Item = Arc<MockValidTx>;
        fn next(&mut self) -> Option<Self::Item> {
            self.queue.pop_front()
        }
    }

    impl BestTransactions for MockBestTxs {
        fn mark_invalid(
            &mut self,
            tx: &Self::Item,
            _kind: reth_transaction_pool::error::InvalidPoolTransactionError,
        ) {
            self.mark_invalid_calls.push(*tx.hash());
            let sender = tx.sender();
            let nonce = tx.nonce();
            // Cascade: drop this sender's descendants (same sender, nonce >= given).
            self.queue.retain(|other| other.sender() != sender || other.nonce() < nonce);
        }
        fn no_updates(&mut self) {}
        fn set_skip_blobs(&mut self, _skip: bool) {}
    }

    fn with_to(mut tx: MockTransaction, to: Address) -> MockTransaction {
        match &mut tx {
            MockTransaction::Legacy { to: t, .. } |
            MockTransaction::Eip1559 { to: t, .. } |
            MockTransaction::Eip2930 { to: t, .. } => {
                *t = TxKind::Call(to);
            }
            MockTransaction::Eip4844 { to: t, .. } | MockTransaction::Eip7702 { to: t, .. } => {
                *t = to;
            }
        }
        tx
    }

    fn mk(
        factory: &mut MockTransactionFactory,
        sender: Address,
        nonce: u64,
        to: Address,
    ) -> Arc<MockValidTx> {
        let tx = MockTransaction::eip1559().with_sender(sender).with_nonce(nonce);
        factory.validated_arc(with_to(tx, to))
    }

    /// Run the pass-1 loop exactly as `default_ethereum_payload` does on a closed block:
    /// a non-PerpDEX tx is `mark_invalid`'d and skipped; a `PerpDEX` tx is included and its
    /// hash recorded. Returns `(included_hashes, mark_invalid_calls)`.
    fn run_pass_1(mut iter: MockBestTxs) -> (Vec<B256>, Vec<B256>) {
        let mut included = Vec::new();
        while let Some(pool_tx) = iter.next() {
            if pool_tx.to() != Some(PERP_DEX_ADDRESS) {
                iter.mark_invalid(
                    &pool_tx,
                    reth_transaction_pool::error::InvalidPoolTransactionError::Underpriced,
                );
                continue;
            }
            included.push(*pool_tx.hash());
        }
        (included, iter.mark_invalid_calls)
    }

    /// Run the pass-2 loop exactly as `default_ethereum_payload` does: skip already-included
    /// hashes via `continue`, include everything else. Returns the ordered list of included.
    fn run_pass_2(iter: MockBestTxs, already_included: &[B256]) -> Vec<B256> {
        let already: std::collections::HashSet<B256> = already_included.iter().copied().collect();
        let mut out = Vec::new();
        for pool_tx in iter {
            if already.contains(pool_tx.hash()) {
                continue;
            }
            out.push(*pool_tx.hash());
        }
        out
    }

    #[test]
    fn pass_1_cascades_non_perpdex_same_sender() {
        // Sender A has one PerpDEX tx; sender B has two consecutive non-PerpDEX txs.
        // Pass 1 should include A's tx, mark_invalid B's nonce-0 (which cascades out B's nonce-1),
        // and yield no more.
        let mut f = MockTransactionFactory::default();
        let a = Address::random();
        let b = Address::random();
        let other = Address::from([0x99; 20]);

        let a_perp = mk(&mut f, a, 0, PERP_DEX_ADDRESS);
        let b_0 = mk(&mut f, b, 0, other);
        let b_1 = mk(&mut f, b, 1, other);

        let iter = MockBestTxs::new(vec![a_perp.clone(), b_0.clone(), b_1]);
        let (included, invalidated) = run_pass_1(iter);

        assert_eq!(included, vec![*a_perp.hash()], "only PerpDEX tx should be included");
        assert_eq!(
            invalidated,
            vec![*b_0.hash()],
            "only b_0 is explicitly mark_invalid'd; b_1 is cascaded out silently"
        );
    }

    #[test]
    fn pass_2_fresh_iterator_recovers_deferred_txs() {
        // After pass 1 dropped B's txs into the ether, pass 2 uses a fresh iterator over the
        // same pool contents. B's non-PerpDEX txs must be visible again and includable in
        // nonce order.
        let mut f = MockTransactionFactory::default();
        let a = Address::random();
        let b = Address::random();
        let other = Address::from([0x99; 20]);

        let a_perp = mk(&mut f, a, 0, PERP_DEX_ADDRESS);
        let b_0 = mk(&mut f, b, 0, other);
        let b_1 = mk(&mut f, b, 1, other);

        let iter1 = MockBestTxs::new(vec![a_perp.clone(), b_0.clone(), b_1.clone()]);
        let (included, _) = run_pass_1(iter1);

        // Pass 2 sees a *fresh* iterator built from the same pool snapshot (all three txs).
        let iter2 = MockBestTxs::new(vec![a_perp, b_0.clone(), b_1.clone()]);
        let out = run_pass_2(iter2, &included);

        assert_eq!(
            out,
            vec![*b_0.hash(), *b_1.hash()],
            "pass 2 must recover both of B's non-PerpDEX txs (a_perp skipped via hash-set)"
        );
    }

    #[test]
    fn pass_2_hash_skip_preserves_nonce_advance() {
        // Sender S has [perpdex @ N=0, other @ N=1]. Pass 1 includes the perpdex tx.
        // Pass 2 sees both; silently `continue`-ing on the pre-included perpdex tx must
        // leave S's nonce-1 tx yieldable (no cascade).
        let mut f = MockTransactionFactory::default();
        let s = Address::random();
        let other = Address::from([0x99; 20]);

        let s_0_perp = mk(&mut f, s, 0, PERP_DEX_ADDRESS);
        let s_1_other = mk(&mut f, s, 1, other);

        let iter1 = MockBestTxs::new(vec![s_0_perp.clone(), s_1_other.clone()]);
        let (included, _) = run_pass_1(iter1);
        assert_eq!(included, vec![*s_0_perp.hash()]);

        let iter2 = MockBestTxs::new(vec![s_0_perp, s_1_other.clone()]);
        let out = run_pass_2(iter2, &included);

        assert_eq!(
            out,
            vec![*s_1_other.hash()],
            "pass 2 `continue` on hash-match must NOT cascade out s_1_other"
        );
    }

    #[test]
    fn mixed_sender_pass_2_respects_nonce_order() {
        // Sender S has [other @ N=0, perpdex @ N=1]. Pass 1's perpdex filter rejects
        // S's nonce-0, cascading the perpdex @ nonce-1 out of iter1. Pass 2 sees both
        // fresh and packs them in nonce order — this is the critical "mixed sender" case
        // called out in the design.
        let mut f = MockTransactionFactory::default();
        let s = Address::random();
        let other = Address::from([0x99; 20]);

        let s_0_other = mk(&mut f, s, 0, other);
        let s_1_perp = mk(&mut f, s, 1, PERP_DEX_ADDRESS);

        let iter1 = MockBestTxs::new(vec![s_0_other.clone(), s_1_perp.clone()]);
        let (included, invalidated) = run_pass_1(iter1);

        assert!(included.is_empty(), "pass 1 includes nothing: perpdex @ N=1 is cascaded out");
        assert_eq!(invalidated, vec![*s_0_other.hash()]);

        let iter2 = MockBestTxs::new(vec![s_0_other.clone(), s_1_perp.clone()]);
        let out = run_pass_2(iter2, &included);

        assert_eq!(
            out,
            vec![*s_0_other.hash(), *s_1_perp.hash()],
            "pass 2 must yield both in nonce order; perpdex @ N=1 must NOT come before other @ N=0"
        );
    }
}

/// End-to-end tests for `default_ethereum_payload`.
///
/// These tests exercise the full function (pool iterator → two-pass packing → builder assembly)
/// against a minimal `MockEthProvider` + `EthEvmConfig`. They rely on `MockTransaction`'s
/// `Recovered<TransactionSigned>` conversion, which uses `Signature::test_signature()`, so
/// the harness cannot execute transactions on a real EVM — we exercise the **selection**
/// path (which txs enter the builder queue) and short-circuit via `BuildOutcome::Aborted`
/// when `total_fees` come out as 0 / the baseline payload wins.
#[cfg(test)]
mod end_to_end_tests {
    use super::*;
    use alloy_consensus::Header;
    use alloy_primitives::{Address, TxKind, B256};
    use alloy_rpc_types_engine::PayloadAttributes;
    use reth_basic_payload_builder::{BuildArguments, PayloadConfig};
    use reth_chainspec::MAINNET;
    use reth_evm_ethereum::EthEvmConfig;
    use reth_primitives_traits::SealedHeader;
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_revm::cancelled::CancelOnDrop;
    use reth_transaction_pool::{
        test_utils::{testing_pool, MockTransaction, TestPool},
        TransactionOrigin, TransactionPool,
    };

    fn with_to_addr(mut tx: MockTransaction, to: Address) -> MockTransaction {
        match &mut tx {
            MockTransaction::Legacy { to: t, .. } |
            MockTransaction::Eip1559 { to: t, .. } |
            MockTransaction::Eip2930 { to: t, .. } => {
                *t = TxKind::Call(to);
            }
            MockTransaction::Eip4844 { to: t, .. } | MockTransaction::Eip7702 { to: t, .. } => {
                *t = to;
            }
        }
        tx
    }

    /// Mint a funded sender in the provider and return a simple Eip1559 mock tx from them.
    fn funded_tx(
        provider: &MockEthProvider,
        sender: Address,
        nonce: u64,
        to: Address,
        priority: u128,
    ) -> MockTransaction {
        provider.add_account(sender, ExtendedAccount::new(nonce, U256::from(u128::MAX)));
        let tx = MockTransaction::eip1559()
            .with_sender(sender)
            .with_nonce(nonce)
            .with_gas_limit(21_000)
            .with_priority_fee(priority)
            .with_max_fee(priority + 1_000_000_000);
        with_to_addr(tx, to)
    }

    fn build(
        provider: MockEthProvider,
        pool: TestPool,
        modulus: u64,
        parent_number: u64,
    ) -> Result<BuildOutcome<EthBuiltPayload>, PayloadBuilderError> {
        let chain_spec = MAINNET.clone();

        let parent = Header {
            number: parent_number,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
            // Pick a timestamp well past Prague/Cancun so hardfork checks settle
            // deterministically on the Prague side of things.
            timestamp: 1_900_000_000,
            ..Default::default()
        };
        let sealed_parent = Arc::new(SealedHeader::seal_slow(parent));

        let attributes = EthPayloadBuilderAttributes::new(
            sealed_parent.hash(),
            PayloadAttributes {
                timestamp: sealed_parent.timestamp + 12,
                prev_randao: B256::ZERO,
                suggested_fee_recipient: Address::ZERO,
                withdrawals: Some(vec![]),
                parent_beacon_block_root: Some(B256::ZERO),
            },
        );

        let config = PayloadConfig { parent_header: sealed_parent, attributes };
        let args = BuildArguments {
            cached_reads: Default::default(),
            config,
            cancel: CancelOnDrop::default(),
            best_payload: None,
        };

        let pool_for_factory = pool.clone();
        default_ethereum_payload(
            EthEvmConfig::new(chain_spec),
            provider,
            pool,
            EthereumBuilderConfig::new().with_perpdex_modulus(modulus),
            args,
            move |attrs| pool_for_factory.best_transactions_with_attributes(attrs),
        )
    }

    /// Pull the body transactions out of a `BuildOutcome::Better` payload; panic otherwise.
    fn tx_hashes(outcome: BuildOutcome<EthBuiltPayload>) -> Vec<B256> {
        match outcome {
            BuildOutcome::Better { payload, .. } => {
                payload.block().body().transactions.iter().map(|t| *t.hash()).collect()
            }
            other => panic!("expected Better, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn empty_pool_produces_empty_block() {
        // Regression: no txs, no panic. With `best_payload = None`, `is_better_payload`
        // returns true unconditionally, so the builder finalizes an empty block.
        let provider = MockEthProvider::default();
        let pool = testing_pool();

        let out = build(provider, pool, /* modulus= */ 0, /* parent_number= */ 0).unwrap();
        assert!(tx_hashes(out).is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn modulus_zero_packs_all_txs_single_pass() {
        // With modulus=0 the feature is disabled. Both txs (perpdex + non-perpdex) must
        // appear in the block regardless of target block number — the classic single-pass
        // behavior is preserved.
        let provider = MockEthProvider::default();
        let pool = testing_pool();

        let sender_a = Address::random();
        let sender_b = Address::random();
        let other = Address::from([0x99; 20]);

        let tx_perp = funded_tx(&provider, sender_a, 0, PERP_DEX_ADDRESS, 10);
        let tx_other = funded_tx(&provider, sender_b, 0, other, 20);
        let perp_hash = *tx_perp.hash();
        let other_hash = *tx_other.hash();

        pool.add_transaction(TransactionOrigin::External, tx_perp).await.unwrap();
        pool.add_transaction(TransactionOrigin::External, tx_other).await.unwrap();

        // parent_number=4 → target=5, which is NOT a multiple of 10; but modulus=0
        // forces open-block behavior anyway.
        let hashes =
            tx_hashes(build(provider, pool, /* modulus= */ 0, /* parent_number= */ 4).unwrap());
        assert_eq!(hashes.len(), 2, "modulus=0: both txs must be packed");
        assert!(hashes.contains(&perp_hash));
        assert!(hashes.contains(&other_hash));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn open_block_packs_all_txs() {
        // parent_number=9 → target=10, which IS a multiple of modulus=10. Open-block
        // semantics: no filtering, both txs packed.
        let provider = MockEthProvider::default();
        let pool = testing_pool();

        let sender_a = Address::random();
        let sender_b = Address::random();
        let other = Address::from([0x99; 20]);

        let tx_perp = funded_tx(&provider, sender_a, 0, PERP_DEX_ADDRESS, 10);
        let tx_other = funded_tx(&provider, sender_b, 0, other, 20);

        pool.add_transaction(TransactionOrigin::External, tx_perp).await.unwrap();
        pool.add_transaction(TransactionOrigin::External, tx_other).await.unwrap();

        let hashes =
            tx_hashes(build(provider, pool, /* modulus= */ 10, /* parent_number= */ 9).unwrap());
        assert_eq!(hashes.len(), 2, "target=10 (open): both txs must be packed");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn closed_block_packs_perpdex_first_then_filler() {
        // parent=4 → target=5 (closed). Pool has 1 perpdex + 1 non-perpdex from different
        // senders. Non-perpdex has HIGHER priority fee (20 > 10), so in a single-pass
        // fee-ordered build it would come first — but pass-1 filters it out, pass-2 fills
        // behind. Resulting order in the block: perpdex first, non-perpdex second.
        let provider = MockEthProvider::default();
        let pool = testing_pool();

        let sender_a = Address::random();
        let sender_b = Address::random();
        let other = Address::from([0x99; 20]);

        let tx_perp = funded_tx(&provider, sender_a, 0, PERP_DEX_ADDRESS, 10);
        let tx_other = funded_tx(&provider, sender_b, 0, other, 20);
        let perp_hash = *tx_perp.hash();
        let other_hash = *tx_other.hash();

        pool.add_transaction(TransactionOrigin::External, tx_perp).await.unwrap();
        pool.add_transaction(TransactionOrigin::External, tx_other).await.unwrap();

        let hashes =
            tx_hashes(build(provider, pool, /* modulus= */ 10, /* parent_number= */ 4).unwrap());
        assert_eq!(hashes, vec![perp_hash, other_hash], "perpdex must precede filler");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn closed_block_with_no_perpdex_falls_back_to_filler_only() {
        // No perpdex in pool; pass 1 packs nothing, pass 2 packs the non-perpdex tx as filler.
        let provider = MockEthProvider::default();
        let pool = testing_pool();

        let sender = Address::random();
        let other = Address::from([0x99; 20]);
        let tx_other = funded_tx(&provider, sender, 0, other, 15);
        let other_hash = *tx_other.hash();

        pool.add_transaction(TransactionOrigin::External, tx_other).await.unwrap();

        let hashes =
            tx_hashes(build(provider, pool, /* modulus= */ 10, /* parent_number= */ 4).unwrap());
        assert_eq!(hashes, vec![other_hash], "non-perpdex must survive as pass-2 filler");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn closed_block_mixed_sender_packs_in_nonce_order() {
        // Critical mixed-sender case: sender has [non-perpdex @ N=0, perpdex @ N=1].
        // Pass 1 mark_invalid's N=0 (which cascades N=1 out of pass-1 iter). Pass 2's
        // fresh iterator yields them in nonce order; both packed.
        let provider = MockEthProvider::default();
        let pool = testing_pool();

        let sender = Address::random();
        let other = Address::from([0x99; 20]);
        let tx_n0_other = funded_tx(&provider, sender, 0, other, 10);
        let tx_n1_perp = funded_tx(&provider, sender, 1, PERP_DEX_ADDRESS, 10);
        let n0_hash = *tx_n0_other.hash();
        let n1_hash = *tx_n1_perp.hash();

        pool.add_transaction(TransactionOrigin::External, tx_n0_other).await.unwrap();
        pool.add_transaction(TransactionOrigin::External, tx_n1_perp).await.unwrap();

        let hashes =
            tx_hashes(build(provider, pool, /* modulus= */ 10, /* parent_number= */ 4).unwrap());
        assert_eq!(hashes, vec![n0_hash, n1_hash], "mixed-sender: both in strict nonce order");
    }
}
