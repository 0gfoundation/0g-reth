//! Types and traits for validating blocks and payloads.

use crate::tree::{
    cached_state::CachedStateProvider,
    error::{InsertBlockError, InsertBlockErrorKind, InsertPayloadError},
    executor::WorkloadExecutor,
    instrumented_state::InstrumentedStateProvider,
    parallel_replay::{shadow_parallel_replay, ReplayReadSet},
    payload_processor::PayloadProcessor,
    persistence_state::CurrentPersistenceAction,
    precompile_cache::{CachedPrecompile, CachedPrecompileMetrics, PrecompileCacheMap},
    sparse_trie::StateRootComputeOutcome,
    ConsistentDbView, EngineApiMetrics, EngineApiTreeState, ExecutionEnv, PayloadHandle,
    PersistenceState, PersistingKind, StateProviderBuilder, StateProviderDatabase, TreeConfig,
};
use alloy_consensus::{transaction::Either, BlockHeaderMut};
use alloy_eips::{eip1898::BlockWithParent, NumHash};
use alloy_evm::Evm;
use alloy_primitives::B256;
use reth_chain_state::{
    CanonicalInMemoryState, ExecutedBlock, ExecutedBlockWithTrieUpdates, ExecutedTrieUpdates,
};
use reth_consensus::{ConsensusError, FullConsensus};
use reth_engine_primitives::{
    ConfigureEngineEvm, ExecutableTxIterator, ExecutionPayload, InvalidBlockHook, PayloadValidator,
};
use reth_errors::{BlockExecutionError, ProviderResult};
use reth_evm::{
    block::BlockExecutor, execute::ExecutableTxFor, ConfigureEvm, EvmEnvFor, ExecutionCtxFor,
    SpecFor,
};
use reth_payload_primitives::{
    BuiltPayload, InvalidPayloadAttributesError, NewPayloadError, PayloadTypes,
};
use reth_primitives_traits::{
    AlloyBlockHeader, BlockTy, NodePrimitives, RecoveredBlock, SealedBlock, SealedHeader
};
use reth_provider::{
    AccountReader, BlockExecutionOutput, BlockHashReader, BlockNumReader, BlockReader, DBProvider,
    DatabaseProviderFactory, ExecutionOutcome, HashedPostStateProvider, HeaderProvider,
    ProviderError, StateProvider, StateProviderFactory, StateReader, StateRootProvider,
};
use reth_revm::db::State;
use reth_revm::database::{PerpDb, PerpHandle};
// Off-trie PerpDEX parallel place/cancel engine (catalog #21 step 4b). Gated on revm's perp-parallel
// feature (enabled in the workspace); the orchestration lives in `execute_block` / `perp_parallel_prephase`.
use revm::context::journal::{perp_pool::PerpPool, shared_perp::SharedPerpBook};
use revm::context::{BlockEnv, CfgEnv, Context, ContextTr, Journal, TxEnv};
use revm::context_interface::journaled_state::PerpReplayResult;
use revm::database::EmptyDB;
use revm::precompile::perp_dex::parallel::{
    classify_perp_tx_pending, finalize_pending_classes, transact_block_parallel_logged,
    transact_block_parallel_logged_profiled, transact_block_serial, CancelOutcome, OpResult, PerpOp,
    PendingPerpTx, PerpTxClass, PlaceOutcome,
};
use revm::precompile::perp_dex::PERP_DEX_ADDRESS;
use revm::primitives::hardfork::SpecId;
// Trait methods for classifying perp txs: `.to()`/`.input()` (alloy Transaction) on the signed tx,
// `.tx()`/`.signer()` (alloy_evm RecoveredTx) on the executable tx.
use alloy_consensus::Transaction as _;
use alloy_evm::RecoveredTx as _;
use reth_trie::{updates::TrieUpdates, HashedPostState, KeccakKeyHasher, TrieInput};
use reth_trie_db::DatabaseHashedPostState;
use reth_trie_parallel::root::{ParallelStateRoot, ParallelStateRootError};
use std::{collections::HashMap, sync::Arc, time::Instant};
use tracing::{debug, debug_span, error, info, trace, warn};

/// Context providing access to tree state during validation.
///
/// This context is provided to the [`EngineValidator`] and includes the state of the tree's
/// internals
pub struct TreeCtx<'a, N: NodePrimitives> {
    /// The engine API tree state
    state: &'a mut EngineApiTreeState<N>,
    /// Information about the current persistence state
    persistence: &'a PersistenceState,
    /// Reference to the canonical in-memory state
    canonical_in_memory_state: &'a CanonicalInMemoryState<N>,
}

impl<'a, N: NodePrimitives> std::fmt::Debug for TreeCtx<'a, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TreeCtx")
            .field("state", &"EngineApiTreeState")
            .field("persistence_info", &self.persistence)
            .field("canonical_in_memory_state", &self.canonical_in_memory_state)
            .finish()
    }
}

impl<'a, N: NodePrimitives> TreeCtx<'a, N> {
    /// Creates a new tree context
    pub const fn new(
        state: &'a mut EngineApiTreeState<N>,
        persistence: &'a PersistenceState,
        canonical_in_memory_state: &'a CanonicalInMemoryState<N>,
    ) -> Self {
        Self { state, persistence, canonical_in_memory_state }
    }

    /// Returns a reference to the engine tree state
    pub const fn state(&self) -> &EngineApiTreeState<N> {
        &*self.state
    }

    /// Returns a mutable reference to the engine tree state
    pub const fn state_mut(&mut self) -> &mut EngineApiTreeState<N> {
        self.state
    }

    /// Returns a reference to the persistence info
    pub const fn persistence(&self) -> &PersistenceState {
        self.persistence
    }

    /// Returns a reference to the canonical in-memory state
    pub const fn canonical_in_memory_state(&self) -> &'a CanonicalInMemoryState<N> {
        self.canonical_in_memory_state
    }

    /// Determines the persisting kind for the given block based on persistence info.
    ///
    /// Based on the given header it returns whether any conflicting persistence operation is
    /// currently in progress.
    ///
    /// This is adapted from the `persisting_kind_for` method in `EngineApiTreeHandler`.
    pub fn persisting_kind_for(&self, block: BlockWithParent) -> PersistingKind {
        // Check that we're currently persisting.
        let Some(action) = self.persistence().current_action() else {
            return PersistingKind::NotPersisting
        };
        // Check that the persistince action is saving blocks, not removing them.
        let CurrentPersistenceAction::SavingBlocks { highest } = action else {
            return PersistingKind::PersistingNotDescendant
        };

        // The block being validated can only be a descendant if its number is higher than
        // the highest block persisting. Otherwise, it's likely a fork of a lower block.
        if block.block.number > highest.number &&
            self.state().tree_state.is_descendant(*highest, block)
        {
            return PersistingKind::PersistingDescendant
        }

        // In all other cases, the block is not a descendant.
        PersistingKind::PersistingNotDescendant
    }
}

/// A helper type that provides reusable payload validation logic for network-specific validators.
///
/// This type satisfies [`EngineValidator`] and is responsible for executing blocks/payloads.
///
/// This type contains common validation, execution, and state root computation logic that can be
/// used by network-specific payload validators (e.g., Ethereum, Optimism). It is not meant to be
/// used as a standalone component, but rather as a building block for concrete implementations.
#[derive(derive_more::Debug)]
pub struct BasicEngineValidator<P, Evm, V>
where
    Evm: ConfigureEvm,
{
    /// Provider for database access.
    provider: P,
    /// Consensus implementation for validation.
    consensus: Arc<dyn FullConsensus<Evm::Primitives, Error = ConsensusError>>,
    /// EVM configuration.
    evm_config: Evm,
    /// Configuration for the tree.
    config: TreeConfig,
    /// Payload processor for state root computation.
    payload_processor: PayloadProcessor<Evm>,
    /// Precompile cache map.
    precompile_cache_map: PrecompileCacheMap<SpecFor<Evm>>,
    /// Precompile cache metrics.
    precompile_cache_metrics: HashMap<alloy_primitives::Address, CachedPrecompileMetrics>,
    /// Hook to call when invalid blocks are encountered.
    #[debug(skip)]
    invalid_block_hook: Box<dyn InvalidBlockHook<Evm::Primitives>>,
    /// Metrics for the engine api.
    metrics: EngineApiMetrics,
    /// Validator for the payload.
    validator: V,
    /// Persistent FIFO worker pool for the parallel PerpDEX place/cancel pre-phase (catalog #21 step
    /// 4b), reused across every block. `Arc` so the validator stays cheap to clone.
    perp_pool: Arc<PerpPool>,
    /// Worker count of `perp_pool` (sizes the parallel payload-recovery chunks).
    perp_pool_threads: usize,
    /// tx-hash → already-recovered-sender short-circuit for payload recovery, typically backed by
    /// the node's own mempool (which recovered every tx it validated at ingress). `None` → every
    /// tx takes the full ecrecover path. See [`ConfigureEngineEvm::decode_payload_tx_with_lookup`].
    #[debug(skip)]
    sender_lookup: Option<Arc<reth_evm::SenderLookup>>,
}

impl<N, P, Evm, V> BasicEngineValidator<P, Evm, V>
where
    N: NodePrimitives,
    P: DatabaseProviderFactory<Provider: BlockReader>
        + BlockReader<Header = N::BlockHeader>
        + StateProviderFactory
        + StateReader
        + HashedPostStateProvider
        + Clone
        + 'static,
    Evm: ConfigureEvm<Primitives = N> + 'static,
{
    /// Creates a new `TreePayloadValidator`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: P,
        consensus: Arc<dyn FullConsensus<N, Error = ConsensusError>>,
        evm_config: Evm,
        validator: V,
        config: TreeConfig,
        invalid_block_hook: Box<dyn InvalidBlockHook<N>>,
    ) -> Self {
        let precompile_cache_map = PrecompileCacheMap::default();
        let payload_processor = PayloadProcessor::new(
            WorkloadExecutor::default(),
            evm_config.clone(),
            &config,
            precompile_cache_map.clone(),
        );
        // One persistent worker pool for the parallel PerpDEX pre-phase. `available_parallelism()` is
        // LOGICAL cores (2x physical on an HT box), and the pre-phase is CPU-bound matching/classify
        // that competes with reth's main block-exec thread + tokio + DB — so sizing the pool to all
        // logical cores OVERSUBSCRIBES the physical cores (measured: a perp-free `simple` baseline
        // regressed ~10% purely from the resident pool). Default to half the logical count (≈ physical
        // cores, leaving headroom); override with PERP_POOL_THREADS to sweep the optimum on a box.
        let perp_pool_threads = std::env::var("PERP_POOL_THREADS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n >= 1)
            .unwrap_or_else(|| {
                (std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(8)
                    / 2)
                .max(1)
            });
        let perp_pool = Arc::new(PerpPool::new(perp_pool_threads));
        Self {
            provider,
            consensus,
            evm_config,
            payload_processor,
            precompile_cache_map,
            precompile_cache_metrics: HashMap::new(),
            config,
            invalid_block_hook,
            metrics: EngineApiMetrics::default(),
            validator,
            perp_pool,
            perp_pool_threads,
            sender_lookup: None,
        }
    }

    /// Installs a tx-hash → already-recovered-sender lookup (typically the node's mempool) that
    /// lets payload recovery skip ecrecover on hits. Misses fall back to full recovery, so this
    /// is a pure CPU short-circuit with zero consensus surface.
    pub fn with_sender_lookup(mut self, lookup: Arc<reth_evm::SenderLookup>) -> Self {
        self.sender_lookup = Some(lookup);
        self
    }

    /// Converts a [`BlockOrPayload`] to a recovered block.
    pub fn convert_to_block<T: PayloadTypes<BuiltPayload: BuiltPayload<Primitives = N>>>(
        &self,
        input: BlockOrPayload<T>,
    ) -> Result<RecoveredBlock<N::Block>, NewPayloadError>
    where
        V: PayloadValidator<T, Block = N::Block>,
    {
        match input {
            BlockOrPayload::Payload(payload) => self.validator.ensure_well_formed_payload(payload),
            BlockOrPayload::Block(block) => Ok(block),
        }
    }

    /// Returns EVM environment for the given payload or block.
    pub fn evm_env_for<T: PayloadTypes<BuiltPayload: BuiltPayload<Primitives = N>>>(
        &self,
        input: &BlockOrPayload<T>,
    ) -> EvmEnvFor<Evm>
    where
        V: PayloadValidator<T, Block = N::Block>,
        Evm: ConfigureEngineEvm<T::ExecutionData, Primitives = N>,
    {
        match input {
            BlockOrPayload::Payload(payload) => self.evm_config.evm_env_for_payload(payload),
            BlockOrPayload::Block(block) => self.evm_config.evm_env(block.header()),
        }
    }

    /// Recover-once-and-share (perf lever 1): materialize + sender-recover the input's transactions
    /// ONCE and extract the perp-destined `(calldata, signer)` pairs in the same pass. For a PAYLOAD,
    /// decode + ecrecover (~90µs/tx, previously paid TWICE per block — once by the perp prephase's
    /// serial gather and once by the payload processor's lazy tx stream) run in PARALLEL chunks on
    /// the resident perp pool. For a BLOCK the senders are already recovered — cheap serial
    /// materialization. The returned iterator feeds the payload processor exactly like
    /// [`Self::tx_iterator_for`]; a decode/recovery error surfaces here (the same tx would have
    /// failed the lazy iterator downstream).
    pub fn recovered_txs_for<T: PayloadTypes<BuiltPayload: BuiltPayload<Primitives = N>>>(
        &self,
        input: &BlockOrPayload<T>,
    ) -> Result<
        (impl ExecutableTxIterator<Evm>, Vec<(Vec<u8>, alloy_primitives::Address)>, usize),
        NewPayloadError,
    >
    where
        V: PayloadValidator<T, Block = N::Block>,
        Evm: ConfigureEngineEvm<T::ExecutionData, Primitives = N> + 'static,
    {
        match input {
            BlockOrPayload::Payload(payload) => {
                let encoded = self.evm_config.payload_txs_encoded(payload);
                let n = encoded.len();
                // Mempool-backed sender short-circuit (when installed): wrap it with a per-block
                // hit counter for the PERP_PROF_RECOVER line. A hit skips the ~90µs ecrecover; a
                // miss takes the full path, so the result is identical either way.
                let pool_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let lookup: Option<Arc<reth_evm::SenderLookup>> =
                    self.sender_lookup.clone().map(|l| {
                        let hits = pool_hits.clone();
                        Arc::new(move |h: &B256| {
                            let r = l(h);
                            if r.is_some() {
                                hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            r
                        }) as Arc<reth_evm::SenderLookup>
                    });
                let decode = |cfg: &Evm, tx| match &lookup {
                    Some(l) => cfg.decode_payload_tx_with_lookup(tx, l.as_ref()),
                    None => cfg.decode_payload_tx(tx),
                };
                // Chunked fan-out — per-tx pool tasks would pay more dispatch than work (the #3
                // lesson); ~2 chunks per worker balances tail skew vs dispatch. Small blocks decode
                // inline (the pool round-trip isn't worth it).
                let recovered: Vec<<Evm as ConfigureEngineEvm<T::ExecutionData>>::PayloadTx> =
                    if n <= 32 {
                        encoded
                            .into_iter()
                            .map(|tx| decode(&self.evm_config, tx))
                            .collect::<Result<_, _>>()
                            .map_err(|e| NewPayloadError::Other(Box::new(e)))?
                    } else {
                        let chunk = n.div_ceil(self.perp_pool_threads.max(1) * 2).max(8);
                        let tasks: Vec<_> = encoded
                            .chunks(chunk)
                            .map(|c| {
                                let cfg = self.evm_config.clone();
                                let lookup = lookup.clone();
                                // `Bytes` clones are cheap (Arc-backed); the task must own its
                                // chunk (`run_batch` requires 'static).
                                let c = c.to_vec();
                                move || {
                                    c.into_iter()
                                        .map(|tx| match &lookup {
                                            Some(l) => {
                                                cfg.decode_payload_tx_with_lookup(tx, l.as_ref())
                                            }
                                            None => cfg.decode_payload_tx(tx),
                                        })
                                        .collect::<Result<Vec<_>, _>>()
                                }
                            })
                            .collect();
                        let mut recovered = Vec::with_capacity(n);
                        for chunk in self.perp_pool.run_batch(tasks) {
                            recovered
                                .extend(chunk.map_err(|e| NewPayloadError::Other(Box::new(e)))?);
                        }
                        recovered
                    };
                let pool_hits = pool_hits.load(std::sync::atomic::Ordering::Relaxed);
                let perp_calls = recovered
                    .iter()
                    .filter(|tx| tx.tx().to() == Some(PERP_DEX_ADDRESS))
                    .map(|tx| (tx.tx().input().to_vec(), *tx.signer()))
                    .collect();
                Ok((
                    Either::Left(
                        recovered
                            .into_iter()
                            .map(|tx| Ok::<_, core::convert::Infallible>(Either::Left(tx))),
                    ),
                    perp_calls,
                    pool_hits,
                ))
            }
            BlockOrPayload::Block(block) => {
                let transactions = block.clone_transactions_recovered().collect::<Vec<_>>();
                let perp_calls = transactions
                    .iter()
                    // `Recovered`'s INHERENT accessors (vs the RecoveredTx trait methods the
                    // generic payload arm resolves to): `inner()` for the tx, by-value `signer()`.
                    .filter(|tx| tx.inner().to() == Some(PERP_DEX_ADDRESS))
                    .map(|tx| (tx.inner().input().to_vec(), tx.signer()))
                    .collect();
                Ok((
                    Either::Right(
                        transactions
                            .into_iter()
                            .map(|tx| Ok::<_, core::convert::Infallible>(Either::Right(tx))),
                    ),
                    perp_calls,
                    // Senders came recovered with the block — the lookup never runs here.
                    0,
                ))
            }
        }
    }

    /// Returns a [`ExecutionCtxFor`] for the given payload or block.
    pub fn execution_ctx_for<'a, T: PayloadTypes<BuiltPayload: BuiltPayload<Primitives = N>>>(
        &self,
        input: &'a BlockOrPayload<T>,
    ) -> ExecutionCtxFor<'a, Evm>
    where
        V: PayloadValidator<T, Block = N::Block>,
        Evm: ConfigureEngineEvm<T::ExecutionData, Primitives = N>,
    {
        match input {
            BlockOrPayload::Payload(payload) => self.evm_config.context_for_payload(payload),
            BlockOrPayload::Block(block) => self.evm_config.context_for_block(block),
        }
    }

    /// Handles execution errors by checking if header validation errors should take precedence.
    ///
    /// When an execution error occurs, this function checks if there are any header validation
    /// errors that should be reported instead, as header validation errors have higher priority.
    fn handle_execution_error<T: PayloadTypes<BuiltPayload: BuiltPayload<Primitives = N>>>(
        &self,
        input: BlockOrPayload<T>,
        execution_err: InsertBlockErrorKind,
        parent_block: &SealedHeader<N::BlockHeader>,
    ) -> Result<ExecutedBlockWithTrieUpdates<N>, InsertPayloadError<N::Block>>
    where
        V: PayloadValidator<T, Block = N::Block>,
    {
        debug!(
            target: "engine::tree",
            ?execution_err,
            block = ?input.num_hash(),
            "Block execution failed, checking for header validation errors"
        );

        // If execution failed, we should first check if there are any header validation
        // errors that take precedence over the execution error
        let block = self.convert_to_block(input)?;

        // Validate block consensus rules which includes header validation
        if let Err(consensus_err) = self.validate_block_inner(&block) {
            // Header validation error takes precedence over execution error
            return Err(InsertBlockError::new(block.into_sealed_block(), consensus_err.into()).into())
        }

        // Also validate against the parent
        if let Err(consensus_err) =
            self.consensus.validate_header_against_parent(block.sealed_header(), parent_block)
        {
            // Parent validation error takes precedence over execution error
            return Err(InsertBlockError::new(block.into_sealed_block(), consensus_err.into()).into())
        }

        // No header validation errors, return the original execution error
        Err(InsertBlockError::new(block.into_sealed_block(), execution_err).into())
    }

    /// Validates a block that has already been converted from a payload.
    ///
    /// This method performs:
    /// - Consensus validation
    /// - Block execution
    /// - State root computation
    /// - Fork detection
    pub fn validate_block_with_state<T: PayloadTypes<BuiltPayload: BuiltPayload<Primitives = N>>>(
        &mut self,
        input: BlockOrPayload<T>,
        mut ctx: TreeCtx<'_, N>,
    ) -> ValidationOutcome<N, InsertPayloadError<N::Block>>
    where
        V: PayloadValidator<T, Block = N::Block>,
        Evm: ConfigureEngineEvm<T::ExecutionData, Primitives = N>,
    {
        /// A helper macro that returns the block in case there was an error
        macro_rules! ensure_ok {
            ($expr:expr) => {
                match $expr {
                    Ok(val) => val,
                    Err(e) => {
                        let block = self.convert_to_block(input)?;
                        return Err(
                            InsertBlockError::new(block.into_sealed_block(), e.into()).into()
                        )
                    }
                }
            };
        }

        let parent_hash = input.parent_hash();
        let block_num_hash = input.num_hash();

        trace!(target: "engine::tree", block=?block_num_hash, parent=?parent_hash, "Fetching block state provider");
        let Some(provider_builder) =
            ensure_ok!(self.state_provider_builder(parent_hash, ctx.state()))
        else {
            // this is pre-validated in the tree
            return Err(InsertBlockError::new(
                self.convert_to_block(input)?.into_sealed_block(),
                ProviderError::HeaderNotFound(parent_hash.into()).into(),
            )
            .into())
        };

        let state_provider = ensure_ok!(provider_builder.build());

        // fetch parent block
        let Some(parent_block) = ensure_ok!(self.sealed_header_by_hash(parent_hash, ctx.state()))
        else {
            return Err(InsertBlockError::new(
                self.convert_to_block(input)?.into_sealed_block(),
                ProviderError::HeaderNotFound(parent_hash.into()).into(),
            )
            .into())
        };

        let evm_env = self.evm_env_for(&input);

        let env = ExecutionEnv { evm_env, hash: input.hash(), parent_hash: input.parent_hash() };

        // We only run the parallel state root if we are not currently persisting any blocks or
        // persisting blocks that are all ancestors of the one we are executing.
        //
        // If we're committing ancestor blocks, then: any trie updates being committed are a subset
        // of the in-memory trie updates collected before fetching reverts. So any diff in
        // reverts (pre vs post commit) is already covered by the in-memory trie updates we
        // collect in `compute_state_root_parallel`.
        //
        // See https://github.com/paradigmxyz/reth/issues/12688 for more details
        let persisting_kind = ctx.persisting_kind_for(input.block_with_parent());
        // don't run parallel if state root fallback is set
        let run_parallel_state_root =
            persisting_kind.can_run_parallel_state_root() && !self.config.state_root_fallback();

        // Use state root task only if:
        // 1. No persistence is in progress
        // 2. Config allows it
        // 3. No ancestors with missing trie updates. If any exist, it will mean that every state
        //    root task proof calculation will include a lot of unrelated paths in the prefix sets.
        //    It's cheaper to run a parallel state root that does one walk over trie tables while
        //    accounting for the prefix sets.
        let has_ancestors_with_missing_trie_updates =
            self.has_ancestors_with_missing_trie_updates(input.block_with_parent(), ctx.state());
        let mut use_state_root_task = run_parallel_state_root &&
            self.config.use_state_root_task() &&
            !has_ancestors_with_missing_trie_updates;

        debug!(
            target: "engine::tree",
            block=?block_num_hash,
            run_parallel_state_root,
            has_ancestors_with_missing_trie_updates,
            use_state_root_task,
            config_allows_state_root_task=self.config.use_state_root_task(),
            "Deciding which state root algorithm to run"
        );

        // Recover-once-and-share (perf lever 1): decode + sender-recover every tx ONCE — payload txs
        // in parallel chunks on the perp pool — and extract the perp calls in the same pass. The
        // materialized list feeds the payload processor below (prewarm + the execution's
        // iter_transactions channel) AND the perp prephase, which previously EACH re-ran the
        // ~90µs/tx ecrecover serially.
        let recover_start = std::env::var_os("PERP_PROF").is_some().then(Instant::now);
        let (txs, perp_calls, pool_hits) = self.recovered_txs_for(&input)?;
        if let Some(t) = recover_start {
            // Companion to the PERP_PROF prephase line: the recovery moved OUT of prephase_ms/scan_ms
            // (lever 1), so emit it separately to keep block-time accounting comparable across builds.
            // `pool_hits` = txs whose sender came from the mempool lookup (ecrecover skipped).
            info!(
                target: "engine::tree",
                "PERP_PROF_RECOVER block={} recover_ms={:.3} perp_calls={} pool_hits={}",
                block_num_hash.number,
                t.elapsed().as_secs_f64() * 1e3,
                perp_calls.len(),
                pool_hits
            );
        }
        let mut handle = if use_state_root_task {
            // use background tasks for state root calc
            let consistent_view =
                ensure_ok!(ConsistentDbView::new_with_latest_tip(self.provider.clone()));

            // get allocated trie input if it exists
            let allocated_trie_input = self.payload_processor.take_trie_input();

            // Compute trie input
            let trie_input_start = Instant::now();
            let trie_input = ensure_ok!(self.compute_trie_input(
                persisting_kind,
                ensure_ok!(consistent_view.provider_ro()),
                parent_hash,
                ctx.state(),
                allocated_trie_input,
            ));

            self.metrics
                .block_validation
                .trie_input_duration
                .record(trie_input_start.elapsed().as_secs_f64());

            // Use state root task only if prefix sets are empty, otherwise proof generation is too
            // expensive because it requires walking over the paths in the prefix set in every
            // proof.
            let spawn_payload_processor_start = Instant::now();
            let handle = if trie_input.prefix_sets.is_empty() {
                self.payload_processor.spawn(
                    env.clone(),
                    txs,
                    provider_builder,
                    consistent_view,
                    trie_input,
                    &self.config,
                )
            } else {
                debug!(target: "engine::tree", block=?block_num_hash, "Disabling state root task due to non-empty prefix sets");
                use_state_root_task = false;
                self.payload_processor.spawn_cache_exclusive(env.clone(), txs, provider_builder)
            };

            // record prewarming initialization duration
            self.metrics
                .block_validation
                .spawn_payload_processor
                .record(spawn_payload_processor_start.elapsed().as_secs_f64());
            handle
        } else {
            let prewarming_start = Instant::now();
            let handle =
                self.payload_processor.spawn_cache_exclusive(env.clone(), txs, provider_builder);

            // Record prewarming initialization duration
            self.metrics
                .block_validation
                .spawn_payload_processor
                .record(prewarming_start.elapsed().as_secs_f64());
            handle
        };

        // Use cached state provider before executing, used in execution after prewarming threads
        // complete
        let state_provider = CachedStateProvider::new_with_caches(
            state_provider,
            handle.caches(),
            handle.cache_metrics(),
        );

        // Execute the block and handle any execution errors
        let perp_handle = ctx.canonical_in_memory_state().canonical_perp_handle();
        let output = match if self.config.state_provider_metrics() {
            let state_provider = InstrumentedStateProvider::from_state_provider(&state_provider);
            let result = self.execute_block(
                &state_provider,
                env,
                &input,
                &mut handle,
                perp_handle.clone(),
                perp_calls,
            );
            state_provider.record_total_latency();
            result
        } else {
            self.execute_block(&state_provider, env, &input, &mut handle, perp_handle, perp_calls)
        } {
            Ok(output) => output,
            Err(err) => return self.handle_execution_error(input, err, &parent_block),
        };

        // after executing the block we can stop executing transactions
        handle.stop_prewarming_execution();

        let mut block = self.convert_to_block(input)?;

        // A helper macro that returns the block in case there was an error
        macro_rules! ensure_ok {
            ($expr:expr) => {
                match $expr {
                    Ok(val) => val,
                    Err(e) => return Err(InsertBlockError::new(block.into_sealed_block(), e.into()).into()),
                }
            };
        }

        let post_execution_start = Instant::now();
        trace!(target: "engine::tree", block=?block_num_hash, "Validating block consensus");
        // validate block consensus rules
        ensure_ok!(self.validate_block_inner(&block));

        // now validate against the parent
        if let Err(e) =
            self.consensus.validate_header_against_parent(block.sealed_header(), &parent_block)
        {
            warn!(target: "engine::tree", ?block, "Failed to validate header {} against parent: {e}", block.hash());
            return Err(InsertBlockError::new(block.into_sealed_block(), e.into()).into())
        }

        if let Err(err) = self.consensus.validate_block_post_execution(&mut block, &output) {
            // call post-block hook
            self.on_invalid_block(&parent_block, &block, &output, None, ctx.state_mut());
            return Err(InsertBlockError::new(block.into_sealed_block(), err.into()).into())
        }

        let hashed_state = self.provider.hashed_post_state(&output.state);

        if let Err(err) =
            self.validator.validate_block_post_execution_with_hashed_state(&hashed_state, &block)
        {
            // call post-block hook
            self.on_invalid_block(&parent_block, &block, &output, None, ctx.state_mut());
            return Err(InsertBlockError::new(block.into_sealed_block(), err.into()).into())
        }

        // record post-execution validation duration
        self.metrics
            .block_validation
            .post_execution_validation_duration
            .record(post_execution_start.elapsed().as_secs_f64());

        debug!(target: "engine::tree", block=?block_num_hash, "Calculating block state root");

        let root_time = Instant::now();

        let mut maybe_state_root = None;

        if run_parallel_state_root {
            // if we new payload extends the current canonical change we attempt to use the
            // background task or try to compute it in parallel
            if use_state_root_task {
                debug!(target: "engine::tree", block=?block_num_hash, "Using sparse trie state root algorithm");
                match handle.state_root() {
                    Ok(StateRootComputeOutcome { state_root, trie_updates }) => {
                        let elapsed = root_time.elapsed();
                        info!(target: "engine::tree", ?state_root, ?elapsed, "State root task finished");
                        
                        maybe_state_root = Some((state_root, trie_updates, elapsed))
                        // we double check the state root here for good measure
                        // if state_root == block.header().state_root() {
                        //     maybe_state_root = Some((state_root, trie_updates, elapsed))
                        // } else {
                        //     warn!(
                        //         target: "engine::tree",
                        //         ?state_root,
                        //         block_state_root = ?block.header().state_root(),
                        //         "State root task returned incorrect state root"
                        //     );
                        // }
                    }
                    Err(error) => {
                        debug!(target: "engine::tree", %error, "State root task failed");
                    }
                }
            } else {
                debug!(target: "engine::tree", block=?block_num_hash, "Using parallel state root algorithm");
                match self.compute_state_root_parallel(
                    persisting_kind,
                    block.parent_hash(),
                    &hashed_state,
                    ctx.state(),
                ) {
                    Ok(result) => {
                        info!(
                            target: "engine::tree",
                            block = ?block_num_hash,
                            regular_state_root = ?result.0,
                            "Regular root task finished"
                        );
                        maybe_state_root = Some((result.0, result.1, root_time.elapsed()));
                    }
                    Err(error) => {
                        debug!(target: "engine::tree", %error, "Parallel state root computation failed");
                    }
                }
            }
        }

        let (state_root, trie_output, root_elapsed) = if let Some(maybe_state_root) =
            maybe_state_root
        {
            maybe_state_root
        } else {
            // fallback is to compute the state root regularly in sync
            if self.config.state_root_fallback() {
                debug!(target: "engine::tree", block=?block_num_hash, "Using state root fallback for testing");
            } else {
                warn!(target: "engine::tree", block=?block_num_hash, ?persisting_kind, "Failed to compute state root in parallel");
                self.metrics.block_validation.state_root_parallel_fallback_total.increment(1);
            }

            let (root, updates) =
                ensure_ok!(state_provider.state_root_with_updates(hashed_state.clone()));
            (root, updates, root_time.elapsed())
        };

        self.metrics.block_validation.record_state_root(&trie_output, root_elapsed.as_secs_f64());
        debug!(target: "engine::tree", ?root_elapsed, block=?block_num_hash, "Calculated state root");

        // ensure state root matches
        if state_root != block.header().state_root() {
            // update the `state_root` field and replace `block` with the updated one.
            let mut header = block.header().clone();
            header.set_state_root(state_root);
            let sealed_block = SealedBlock::seal_parts(header, block.body().clone());
            block = RecoveredBlock::new_sealed(sealed_block, block.senders().to_vec());
        }

        // terminate prewarming task with good state output
        handle.terminate_caching(Some(output.state.clone()));

        // If the block doesn't connect to the database tip, we don't save its trie updates, because
        // they may be incorrect as they were calculated on top of the forked block.
        //
        // We also only save trie updates if all ancestors have trie updates, because otherwise the
        // trie updates may be incorrect.
        //
        // Instead, they will be recomputed on persistence.
        let connects_to_last_persisted =
            ensure_ok!(self.block_connects_to_last_persisted(ctx, &block));
        let should_discard_trie_updates =
            !connects_to_last_persisted || has_ancestors_with_missing_trie_updates;
        debug!(
            target: "engine::tree",
            block = ?block_num_hash,
            connects_to_last_persisted,
            has_ancestors_with_missing_trie_updates,
            should_discard_trie_updates,
            "Checking if should discard trie updates"
        );
        let trie_updates = if should_discard_trie_updates {
            ExecutedTrieUpdates::Missing
        } else {
            ExecutedTrieUpdates::Present(Arc::new(trie_output))
        };

        Ok(ExecutedBlockWithTrieUpdates {
            block: ExecutedBlock {
                recovered_block: Arc::new(block),
                execution_output: Arc::new(ExecutionOutcome::from((output, block_num_hash.number))),
                hashed_state: Arc::new(hashed_state),
            },
            trie: trie_updates,
        })
    }

    /// Return sealed block header from database or in-memory state by hash.
    fn sealed_header_by_hash(
        &self,
        hash: B256,
        state: &EngineApiTreeState<N>,
    ) -> ProviderResult<Option<SealedHeader<N::BlockHeader>>> {
        // check memory first
        let header = state.tree_state.sealed_header_by_hash(&hash);

        if header.is_some() {
            Ok(header)
        } else {
            self.provider.sealed_header_by_hash(hash)
        }
    }

    /// Validate if block is correct and satisfies all the consensus rules that concern the header
    /// and block body itself.
    fn validate_block_inner(&self, block: &RecoveredBlock<N::Block>) -> Result<(), ConsensusError> {
        if let Err(e) = self.consensus.validate_header(block.sealed_header()) {
            error!(target: "engine::tree", ?block, "Failed to validate header {}: {e}", block.hash());
            return Err(e)
        }

        if let Err(e) = self.consensus.validate_block_pre_execution(block.sealed_block()) {
            error!(target: "engine::tree", ?block, "Failed to validate block {}: {e}", block.hash());
            return Err(e)
        }

        Ok(())
    }

    /// Step-4b parallel PerpDEX pre-phase: classify the block's top-level `0x…1003` trading calls
    /// (decode CONCURRENTLY on the pool + serial id-finalize, NO matching), run them through the
    /// parallel driver against a fresh shared book, and build the replay vec the serial EVM pass
    /// replays. Returns the per-trading-tx replay results (block order) + the shared book holding
    /// the net off-trie delta. A block with no perp trading txs returns `(empty, None)` → the
    /// caller runs the plain serial path.
    fn perp_parallel_prephase(
        &self,
        // The block's 0x…1003 (calldata, signer) pairs in txn order, pre-extracted by
        // `recovered_txs_for` from the ONCE-recovered tx list (lever 1) — this fn no longer
        // iterates/recovers the block itself, so PERP_PROF's scan_ms is classify+finalize only.
        perp_calls: Vec<(Vec<u8>, alloy_primitives::Address)>,
        block_env: &BlockEnv,
        perp: &PerpHandle,
    ) -> Result<(Vec<PerpReplayResult>, Option<Arc<SharedPerpBook>>), InsertBlockErrorKind> {
        // DEBUG (env PERP_PARALLEL_DISABLE): force the serial fallback for EVERY block — the EVM pass
        // runs the 0x1003 precompile normally (no replay), i.e. pure serial execution. Used to test
        // whether a verifier failure (e.g. matchingPair TRADE_MISMATCH) is parallel-specific or also
        // present in serial. Off by default. NOTE (lever 1): the ONCE-per-block parallel tx recovery
        // in `recovered_txs_for` runs regardless of this flag (it also feeds the payload processor),
        // so DISABLE isolates the perp classify+driver only, not the recovery.
        if std::env::var_os("PERP_PARALLEL_DISABLE").is_some() {
            return Ok((Vec::new(), None));
        }
        // PERP_PROF (catalog #21 instrumentation): start the pre-phase wall clock when profiling is
        // enabled. `None` (the default) makes every profiling touch below a no-op — zero cost off.
        let prephase_start = std::env::var_os("PERP_PROF").is_some().then(Instant::now);
        let book = Arc::new(SharedPerpBook::new());
        let block_env = block_env.clone();
        let block_number = block_env.number; // captured before make_ctx moves block_env (audit logging)
        let perp_for_ctx = perp.clone();
        // Per-slot context factory: a perp-only cold-read DB (matching never touches EVM accounts, so
        // EmptyDB suffices; perp reads resolve through the canonical_perp handle) + the block env +
        // the shared book. The EVM spec is irrelevant to perp matching, so a fixed default is used.
        // The concrete per-slot context type (annotated so closure return-type inference succeeds).
        type PerpSlotCtx = Context<
            BlockEnv,
            TxEnv,
            CfgEnv,
            PerpDb<EmptyDB>,
            Journal<PerpDb<EmptyDB>>,
            (),
        >;
        let make_ctx = move |book: Arc<SharedPerpBook>| -> PerpSlotCtx {
            let db = PerpDb::new(EmptyDB::default(), Some(perp_for_ctx.clone()));
            let mut ctx: PerpSlotCtx = Context::new(db, SpecId::default());
            ctx.block = block_env.clone();
            ctx.journal_mut().set_perp_shared(book);
            ctx
        };

        // A `Trade` feeds the driver (its replay result is filled from the driver outcome below); a
        // `Reject` is replayed as a revert now; non-trading / non-perp calls are skipped (they run
        // normally in the serial EVM pass).
        enum Slot {
            Trade { op_index: usize, success_output: Vec<u8> },
            Reject { output: Vec<u8> },
        }
        // #3 (parallel decode): DECODE + verify the pre-gathered 0x…1003 calls CONCURRENTLY on the
        // resident perp pool (`classify_perp_tx_pending` is read-only — a direct place's order id is
        // DEFERRED), then assign the direct-place ids SERIALLY in txn order
        // (`finalize_pending_classes` — the nonce read-modify-write that cannot race across
        // same-account places). Byte-identical to a serial classify_perp_tx scan.
        //
        // No 0x1003 calls at all → nothing to parallelize; run the plain serial path.
        if perp_calls.is_empty() {
            return Ok((Vec::new(), None));
        }
        // Parallel decode/verify (read-only) on the pool — one fresh cold-read ctx per call.
        let pending: Vec<PendingPerpTx> = {
            let tasks: Vec<_> = perp_calls
                .into_iter()
                .map(|(calldata, signer)| {
                    let make_ctx = make_ctx.clone();
                    let book = book.clone();
                    move || -> Result<PendingPerpTx, _> {
                        let mut ctx = make_ctx(book);
                        classify_perp_tx_pending(&calldata, signer, &mut ctx)
                    }
                })
                .collect();
            self.perp_pool
                .run_batch(tasks)
                .into_iter()
                .collect::<Result<Vec<_>, _>>()
                .map_err(BlockExecutionError::other)?
        };
        // Serial finalize: assign direct-place ids by per-maker nonce sequence in txn order + write
        // each toucher's final nonce to the book (byte-identical to the serial classify scan).
        let mut classify_ctx = make_ctx(book.clone());
        let classes = finalize_pending_classes(pending, &mut classify_ctx)
            .map_err(BlockExecutionError::other)?;

        let mut ops: Vec<PerpOp> = Vec::new();
        let mut slots: Vec<Slot> = Vec::new();
        // A NON-trading 0x1003 call (deposit / withdraw / addMargin / liquidate / updateIndexPrice /
        // …) can change state a later trade depends on (e.g. margin). The parallel pre-phase runs ALL
        // trades upfront against committed state, so it cannot honor an intra-block dependency on such
        // a call. Rather than mis-order, we FALL BACK to full serial for any block containing one (the
        // relayer's trade-only batches still parallelize; mixed blocks stay serial → byte-identical).
        let mut saw_non_trading_perp = false;
        for class in classes {
            match class {
                PerpTxClass::Trade { op, success_output } => {
                    let op_index = ops.len();
                    ops.push(op);
                    slots.push(Slot::Trade { op_index, success_output });
                }
                PerpTxClass::Reject { output } => slots.push(Slot::Reject { output }),
                // A 0x1003 call that is not a trading selector → a non-trading perp call.
                PerpTxClass::NotTrading => saw_non_trading_perp = true,
            }
        }
        // No trades to parallelize, or a non-trading perp call present → run the plain serial path.
        if slots.is_empty() || saw_non_trading_perp {
            return Ok((Vec::new(), None));
        }

        // DEBUG AUDIT (env PERP_PARALLEL_AUDIT): capture a make_ctx clone NOW (before the real run
        // consumes make_ctx). After the real run we re-run the SAME ops SERIALLY and compare the REAL
        // run's captured per-op logs — exactly what phase B re-emits → what the verifier sees — against
        // serial. Comparing the REAL `results` (not a fresh re-run) catches a node-specific
        // non-determinism in the real parallel run that a fresh re-run might not reproduce. Off by
        // default.
        let audit_make = std::env::var_os("PERP_PARALLEL_AUDIT")
            .is_some()
            .then(|| make_ctx.clone());

        // Parallel matching against the shared book (the segmented driver: parallel batches with the
        // contagion floor run serially in place). Results are in `ops` (= txn_id) order, each carrying
        // the EVM logs its matching emitted (the `_logged` variant — the matching runs in throwaway
        // contexts, so the driver drains each op's logs here for the replay to re-emit).
        // PERP_PROF: when set, run the PROFILED driver — identical execution to the plain path, plus a
        // per-block PerpBlockProfile (achieved concurrency §1, classification histogram §A, block
        // totals §H) — and emit one `PERP_PROF …` line to reth.log. Off by default. The profiled call
        // adds one Instant + a few relaxed atomics per op; the plain branch below is unchanged.
        let results = if let Some(pstart) = prephase_start {
            let scan_ns = pstart.elapsed().as_nanos() as u64; // §D: serial classify-scan gate (pre-run)
            let (results, prof) = transact_block_parallel_logged_profiled(
                self.perp_pool.as_ref(),
                &book,
                &ops,
                make_ctx,
            )
            .map_err(BlockExecutionError::other)?;
            let prephase_ns = pstart.elapsed().as_nanos() as u64; // §D: whole pre-phase wall (scan+run)
            info!(
                target: "engine::tree",
                "{}",
                prof.format_prof_line(block_number.saturating_to::<u64>(), prephase_ns, scan_ns)
            );
            results
        } else {
            transact_block_parallel_logged(self.perp_pool.as_ref(), &book, &ops, make_ctx)
                .map_err(BlockExecutionError::other)?
        };

        // AUDIT: compare the REAL run's captured per-op logs against a serial re-run (same cold-read).
        // These logs are what phase B re-emits, so a divergence here = the parallel node's events
        // differ from serial → the bug. Dumps the diverging ops + per-op log counts.
        if let Some(make) = audit_make {
            let sa_book = Arc::new(SharedPerpBook::new());
            match transact_block_serial(&sa_book, &ops, make) {
                Ok(sr) => {
                    let plogs: Vec<_> = results.iter().map(|r| r.logs.clone()).collect();
                    let slogs: Vec<_> = sr.iter().map(|r| r.logs.clone()).collect();
                    if plogs != slogs {
                        error!(
                            target: "perp::audit",
                            block = ?block_number,
                            n_ops = ops.len(),
                            "REAL-RUN PERP LOGS DIVERGE FROM SERIAL — ops follow"
                        );
                        for (i, op) in ops.iter().enumerate() {
                            let pl = plogs.get(i);
                            let sl = slogs.get(i);
                            error!(
                                target: "perp::audit",
                                block = ?block_number,
                                i,
                                op = ?op,
                                diff = (pl != sl),
                                parallel_logs = ?pl,
                                serial_logs = ?sl,
                                "audit op"
                            );
                        }
                    }
                }
                Err(e) => error!(
                    target: "perp::audit",
                    block = ?block_number,
                    err = ?e,
                    "PERP AUDIT serial re-run errored"
                ),
            }
        }

        // Build the replay vec in block order (one entry per trading tx). Each carries the captured
        // logs so the serial replay re-emits the same perp events as serial execution.
        let replay = slots
            .into_iter()
            .map(|slot| match slot {
                Slot::Trade { op_index, success_output } => {
                    let op = &results[op_index];
                    let executed = matches!(
                        op.result,
                        OpResult::Place(PlaceOutcome::Executed)
                            | OpResult::Cancel(CancelOutcome::Executed)
                    );
                    PerpReplayResult {
                        // Driver-reverted (margin / crossing PostOnly / not-cancellable): empty output
                        // (return data is not in the receipts root) + empty logs (rolled back).
                        reverted: !executed,
                        output: if executed { success_output } else { Vec::new() },
                        logs: op.logs.clone(),
                    }
                }
                Slot::Reject { output } => {
                    PerpReplayResult { reverted: true, output, logs: Vec::new() }
                }
            })
            .collect();
        Ok((replay, Some(book)))
    }

    /// Executes a block with the given state provider
    fn execute_block<S, Err, T>(
        &mut self,
        state_provider: S,
        env: ExecutionEnv<Evm>,
        input: &BlockOrPayload<T>,
        // `Clone + Send + 'static` (satisfied by every handle tx type — see
        // `ExecutableTxIterator::Tx` + `TransactionEnv`) lets the A1 shadow clone the block's txs
        // for its parallel workers; the serial path never clones.
        handle: &mut PayloadHandle<impl ExecutableTxFor<Evm> + Clone + Send + 'static, Err>,
        // Off-trie PerpDEX ("PerpState") committed-store read handle; wraps the execution DB in
        // `PerpDb` so the EVM's perp cold-read resolves to `canonical_perp` (off the state trie).
        perp: PerpHandle,
        // The block's perp-destined (calldata, signer) pairs, pre-extracted by
        // `recovered_txs_for` from the ONCE-recovered tx list (lever 1) — the prephase no longer
        // re-decodes/re-recovers the block itself.
        perp_calls: Vec<(Vec<u8>, alloy_primitives::Address)>,
    ) -> Result<BlockExecutionOutput<N::Receipt>, InsertBlockErrorKind>
    where
        S: StateProvider,
        Err: core::error::Error + Send + Sync + 'static,
        V: PayloadValidator<T, Block = N::Block>,
        T: PayloadTypes<BuiltPayload: BuiltPayload<Primitives = N>>,
        Evm: ConfigureEngineEvm<T::ExecutionData, Primitives = N>,
    {
        let num_hash = NumHash::new(env.evm_env.block_env.number.to(), env.hash);

        let span = debug_span!(target: "engine::tree", "execute_block", num = ?num_hash.number, hash = ?num_hash.hash);
        let _enter = span.enter();
        debug!(target: "engine::tree", "Executing block");

        // L2-2 Phase 0 probe (env PERP_SENDER_PREFETCH): best-effort PARALLEL warm-up of the block's
        // perp senders' account state — K scoped threads, each with its OWN state provider (own read
        // view, built on this thread and moved in, so no `P: Sync` bound is needed), values
        // DISCARDED. Zero consensus surface: a stale or missing read just means no warmth. Purpose is
        // twofold: (a) if the EVM pass's per-tx cost is account-read-bound, the serial pass now runs
        // warm; (b) it measures whether PARALLEL state reads amortize or amplify the kernel
        // page/TLB term on this box — the go/no-go datum for full per-sender parallel replay
        // (L2-2 Phase A). Timed to reth.log under PERP_PROF as `PERP_PROF_PREFETCH`.
        if std::env::var_os("PERP_SENDER_PREFETCH").is_some() && !perp_calls.is_empty() {
            let t0 = Instant::now();
            let mut senders: Vec<alloy_primitives::Address> =
                perp_calls.iter().map(|(_, s)| *s).collect();
            senders.sort_unstable();
            senders.dedup();
            let k = self.perp_pool_threads.clamp(1, 16).min(senders.len().max(1));
            let mut providers = Vec::with_capacity(k);
            for _ in 0..k {
                match self.provider.latest() {
                    Ok(sp) => providers.push(sp),
                    Err(_) => break, // best-effort: fewer workers (or none → skip entirely)
                }
            }
            let hits = std::sync::atomic::AtomicUsize::new(0);
            if !providers.is_empty() {
                let chunk = senders.len().div_ceil(providers.len());
                std::thread::scope(|s| {
                    for (sp, ch) in providers.into_iter().zip(senders.chunks(chunk)) {
                        let hits = &hits;
                        s.spawn(move || {
                            let mut n = 0usize;
                            for a in ch {
                                if sp.basic_account(a).ok().flatten().is_some() {
                                    n += 1;
                                }
                            }
                            hits.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                        });
                    }
                });
            }
            if std::env::var_os("PERP_PROF").is_some() {
                info!(
                    target: "engine::tree",
                    "PERP_PROF_PREFETCH block={} senders={} hits={} elapsed_ms={:.3}",
                    num_hash.number,
                    senders.len(),
                    hits.load(std::sync::atomic::Ordering::Relaxed),
                    t0.elapsed().as_secs_f64() * 1e3
                );
            }
        }

        // Step 4b: parallel PerpDEX pre-phase — classify + match this block's trading calls against a
        // shared book BEFORE the serial EVM pass, which then REPLAYS the pre-computed results. `perp`
        // is borrowed here (it is moved into `PerpDb` below). `(empty, None)` for a block with no perp
        // trades → the serial path runs unchanged.
        let n_perp_calls = perp_calls.len();
        let (perp_replay, perp_book) =
            self.perp_parallel_prephase(perp_calls, &env.evm_env.block_env, &perp)?;

        // L2-2 Phase A1 (env PERP_REPLAY_SHADOW): shadow-gate precheck. A parallelized block
        // (`perp_book.is_some()`) has a replay result for EVERY perp call; the remaining gate —
        // every tx in the block IS a perp trading call — is checked below once the tx stream is
        // materialized. Small blocks skip (dispatch would swamp the signal).
        let shadow_replay = (std::env::var_os("PERP_REPLAY_SHADOW").is_some()
            && perp_book.is_some()
            && n_perp_calls >= 64)
            .then(|| perp_replay.clone());

        let mut db = State::builder()
            .with_database(PerpDb::new(StateProviderDatabase::new(&state_provider), Some(perp)))
            .with_bundle_update()
            .without_state_clear()
            .build();

        let evm = self.evm_config.evm_with_env(&mut db, env.evm_env.clone());
        let ctx = self.execution_ctx_for(input);
        let mut executor = self.evm_config.create_executor(evm, ctx);

        if !self.config.precompile_cache_disabled() {
            // Only cache pure precompiles to avoid issues with stateful precompiles
            executor.evm_mut().precompiles_mut().map_pure_precompiles(|address, precompile| {
                let metrics = self
                    .precompile_cache_metrics
                    .entry(*address)
                    .or_insert_with(|| CachedPrecompileMetrics::new_with_address(*address))
                    .clone();
                CachedPrecompile::wrap(
                    precompile,
                    self.precompile_cache_map.cache_for_address(*address),
                    *env.evm_env.spec_id(),
                    Some(metrics),
                )
            });
        }

        let execution_start = Instant::now();
        let state_hook = Box::new(handle.state_hook());
        let output = if let Some(shadow_replay) = shadow_replay {
            // A1 shadow arm: materialize the tx stream first (lever 1 already recovered every tx —
            // the channel only forwards), so the block's txs can be cloned for the shadow workers.
            let collected: Vec<_> = handle.iter_transactions().collect();
            // Final shadow gate: the replay vec is 1:1 with the block's txs (⇒ every tx is a perp
            // trading call — non-perp txs would make it shorter) and the stream carried no error.
            let shadow_txs = (collected.len() == shadow_replay.len())
                .then(|| {
                    collected.iter().filter_map(|r| r.as_ref().ok()).cloned().collect::<Vec<_>>()
                })
                .filter(|txs| txs.len() == shadow_replay.len());
            let output = self.metrics.execute_metered(
                executor,
                collected.into_iter().map(|res| res.map_err(BlockExecutionError::other)),
                state_hook,
                perp_replay,
                perp_book,
            )?;
            // The serial pass stays authoritative; the shadow re-executes the SAME block on the
            // pre-materialized read-set and reports wall time + fail-stop misses + a gas digest.
            // Runs AFTER the serial pass (reads only committed pre-block state, so order is
            // irrelevant to correctness) to keep the measured serial exec window undisturbed.
            if let Some(shadow_txs) = shadow_txs {
                let rs_start = Instant::now();
                let read_set = ReplayReadSet::build(
                    &state_provider,
                    shadow_txs.iter().map(|t| *t.signer()),
                    env.evm_env.block_env.beneficiary,
                    PERP_DEX_ADDRESS,
                );
                let rs_ms = rs_start.elapsed().as_secs_f64() * 1e3;
                match read_set {
                    Some(rs) => {
                        let stats = shadow_parallel_replay(
                            &self.perp_pool,
                            self.perp_pool_threads,
                            &self.evm_config,
                            env.evm_env.clone(),
                            &shadow_txs,
                            &shadow_replay,
                            Arc::new(rs),
                        );
                        let gas_serial = output.result.gas_used;
                        info!(
                            target: "engine::tree",
                            "PERP_PROF_REPLAY_SHADOW block={} n={} tasks={} rs_ms={:.3} wall_ms={:.3} misses={} ok={} reverted={} errors={} gas_shadow={} gas_serial={} gas_match={}",
                            num_hash.number,
                            stats.n_txs,
                            stats.n_tasks,
                            rs_ms,
                            stats.wall_ms,
                            stats.misses,
                            stats.ok,
                            stats.reverted,
                            stats.errors,
                            stats.gas_sum,
                            gas_serial,
                            stats.gas_sum == gas_serial,
                        );
                    }
                    None => info!(
                        target: "engine::tree",
                        "PERP_PROF_REPLAY_SHADOW block={} skipped=readset_build_failed rs_ms={:.3}",
                        num_hash.number,
                        rs_ms,
                    ),
                }
            } else {
                info!(
                    target: "engine::tree",
                    "PERP_PROF_REPLAY_SHADOW block={} skipped=mixed_block_or_stream_error",
                    num_hash.number,
                );
            }
            output
        } else {
            self.metrics.execute_metered(
                executor,
                handle.iter_transactions().map(|res| res.map_err(BlockExecutionError::other)),
                state_hook,
                perp_replay,
                perp_book,
            )?
        };
        let execution_finish = Instant::now();
        let execution_time = execution_finish.duration_since(execution_start);
        debug!(target: "engine::tree", elapsed = ?execution_time, number=?num_hash.number, "Executed block");
        Ok(output)
    }

    /// Compute state root for the given hashed post state in parallel.
    ///
    /// # Returns
    ///
    /// Returns `Ok(_)` if computed successfully.
    /// Returns `Err(_)` if error was encountered during computation.
    /// `Err(ProviderError::ConsistentView(_))` can be safely ignored and fallback computation
    /// should be used instead.
    fn compute_state_root_parallel(
        &self,
        persisting_kind: PersistingKind,
        parent_hash: B256,
        hashed_state: &HashedPostState,
        state: &EngineApiTreeState<N>,
    ) -> Result<(B256, TrieUpdates), ParallelStateRootError> {
        let consistent_view = ConsistentDbView::new_with_latest_tip(self.provider.clone())?;

        let mut input = self.compute_trie_input(
            persisting_kind,
            consistent_view.provider_ro()?,
            parent_hash,
            state,
            None,
        )?;
        // Extend with block we are validating root for.
        input.append_ref(hashed_state);

        ParallelStateRoot::new(consistent_view, input).incremental_root_with_updates()
    }

    /// Checks if the given block connects to the last persisted block, i.e. if the last persisted
    /// block is the ancestor of the given block.
    ///
    /// This checks the database for the actual last persisted block, not [`PersistenceState`].
    fn block_connects_to_last_persisted(
        &self,
        ctx: TreeCtx<'_, N>,
        block: &RecoveredBlock<N::Block>,
    ) -> ProviderResult<bool> {
        let provider = self.provider.database_provider_ro()?;
        let last_persisted_block = provider.best_block_number()?;
        let last_persisted_hash = provider
            .block_hash(last_persisted_block)?
            .ok_or(ProviderError::HeaderNotFound(last_persisted_block.into()))?;
        let last_persisted = NumHash::new(last_persisted_block, last_persisted_hash);

        let parent_num_hash = |hash: B256| -> ProviderResult<NumHash> {
            let parent_num_hash =
                if let Some(header) = ctx.state().tree_state.sealed_header_by_hash(&hash) {
                    Some(header.parent_num_hash())
                } else {
                    provider.sealed_header_by_hash(hash)?.map(|header| header.parent_num_hash())
                };

            parent_num_hash.ok_or(ProviderError::BlockHashNotFound(hash))
        };

        let mut parent_block = block.parent_num_hash();
        while parent_block.number > last_persisted.number {
            parent_block = parent_num_hash(parent_block.hash)?;
        }

        let connects = parent_block == last_persisted;

        debug!(
            target: "engine::tree",
            num_hash = ?block.num_hash(),
            ?last_persisted,
            ?parent_block,
            "Checking if block connects to last persisted block"
        );

        Ok(connects)
    }

    /// Check if the given block has any ancestors with missing trie updates.
    fn has_ancestors_with_missing_trie_updates(
        &self,
        target_header: BlockWithParent,
        state: &EngineApiTreeState<N>,
    ) -> bool {
        // Walk back through the chain starting from the parent of the target block
        let mut current_hash = target_header.parent;
        while let Some(block) = state.tree_state.blocks_by_hash.get(&current_hash) {
            // Check if this block is missing trie updates
            if block.trie.is_missing() {
                return true;
            }

            // Move to the parent block
            current_hash = block.recovered_block().parent_hash();
        }

        false
    }

    /// Creates a `StateProviderBuilder` for the given parent hash.
    ///
    /// This method checks if the parent is in the tree state (in-memory) or persisted to disk,
    /// and creates the appropriate provider builder.
    fn state_provider_builder(
        &self,
        hash: B256,
        state: &EngineApiTreeState<N>,
    ) -> ProviderResult<Option<StateProviderBuilder<N, P>>> {
        if let Some((historical, blocks)) = state.tree_state.blocks_by_hash(hash) {
            debug!(target: "engine::tree", %hash, %historical, "found canonical state for block in memory, creating provider builder");
            // the block leads back to the canonical chain
            return Ok(Some(StateProviderBuilder::new(
                self.provider.clone(),
                historical,
                Some(blocks),
            )))
        }

        // Check if the block is persisted
        if let Some(header) = self.provider.header(&hash)? {
            debug!(target: "engine::tree", %hash, number = %header.number(), "found canonical state for block in database, creating provider builder");
            // For persisted blocks, we create a builder that will fetch state directly from the
            // database
            return Ok(Some(StateProviderBuilder::new(self.provider.clone(), hash, None)))
        }

        debug!(target: "engine::tree", %hash, "no canonical state found for block");
        Ok(None)
    }

    /// Called when an invalid block is encountered during validation.
    fn on_invalid_block(
        &self,
        parent_header: &SealedHeader<N::BlockHeader>,
        block: &RecoveredBlock<N::Block>,
        output: &BlockExecutionOutput<N::Receipt>,
        trie_updates: Option<(&TrieUpdates, B256)>,
        state: &mut EngineApiTreeState<N>,
    ) {
        if state.invalid_headers.get(&block.hash()).is_some() {
            // we already marked this block as invalid
            return
        }
        self.invalid_block_hook.on_invalid_block(parent_header, block, output, trie_updates);
    }

    /// Computes the trie input at the provided parent hash.
    ///
    /// The goal of this function is to take in-memory blocks and generate a [`TrieInput`] that
    /// serves as an overlay to the database blocks.
    ///
    /// It works as follows:
    /// 1. Collect in-memory blocks that are descendants of the provided parent hash using
    ///    [`crate::tree::TreeState::blocks_by_hash`].
    /// 2. If the persistence is in progress, and the block that we're computing the trie input for
    ///    is a descendant of the currently persisting blocks, we need to be sure that in-memory
    ///    blocks are not overlapping with the database blocks that may have been already persisted.
    ///    To do that, we're filtering out in-memory blocks that are lower than the highest database
    ///    block.
    /// 3. Once in-memory blocks are collected and optionally filtered, we compute the
    ///    [`HashedPostState`] from them.
    fn compute_trie_input<TP: DBProvider + BlockNumReader>(
        &self,
        persisting_kind: PersistingKind,
        provider: TP,
        parent_hash: B256,
        state: &EngineApiTreeState<N>,
        allocated_trie_input: Option<TrieInput>,
    ) -> ProviderResult<TrieInput> {
        // get allocated trie input or use a default trie input
        let mut input = allocated_trie_input.unwrap_or_default();

        let best_block_number = provider.best_block_number()?;

        let (mut historical, mut blocks) = state
            .tree_state
            .blocks_by_hash(parent_hash)
            .map_or_else(|| (parent_hash.into(), vec![]), |(hash, blocks)| (hash.into(), blocks));

        // If the current block is a descendant of the currently persisting blocks, then we need to
        // filter in-memory blocks, so that none of them are already persisted in the database.
        if persisting_kind.is_descendant() {
            // Iterate over the blocks from oldest to newest.
            while let Some(block) = blocks.last() {
                let recovered_block = block.recovered_block();
                if recovered_block.number() <= best_block_number {
                    // Remove those blocks that lower than or equal to the highest database
                    // block.
                    blocks.pop();
                } else {
                    // If the block is higher than the best block number, stop filtering, as it's
                    // the first block that's not in the database.
                    break
                }
            }

            historical = if let Some(block) = blocks.last() {
                // If there are any in-memory blocks left after filtering, set the anchor to the
                // parent of the oldest block.
                (block.recovered_block().number() - 1).into()
            } else {
                // Otherwise, set the anchor to the original provided parent hash.
                parent_hash.into()
            };
        }

        if blocks.is_empty() {
            debug!(target: "engine::tree", %parent_hash, "Parent found on disk");
        } else {
            debug!(target: "engine::tree", %parent_hash, %historical, blocks = blocks.len(), "Parent found in memory");
        }

        // Convert the historical block to the block number.
        let block_number = provider
            .convert_hash_or_number(historical)?
            .ok_or_else(|| ProviderError::BlockHashNotFound(historical.as_hash().unwrap()))?;

        // Retrieve revert state for historical block.
        let revert_state = if block_number == best_block_number {
            // We do not check against the `last_block_number` here because
            // `HashedPostState::from_reverts` only uses the database tables, and not static files.
            debug!(target: "engine::tree", block_number, best_block_number, "Empty revert state");
            HashedPostState::default()
        } else {
            let revert_state = HashedPostState::from_reverts::<KeccakKeyHasher>(
                provider.tx_ref(),
                block_number + 1,
            )
            .map_err(ProviderError::from)?;
            debug!(
                target: "engine::tree",
                block_number,
                best_block_number,
                accounts = revert_state.accounts.len(),
                storages = revert_state.storages.len(),
                "Non-empty revert state"
            );
            revert_state
        };
        input.append(revert_state);

        // Extend with contents of parent in-memory blocks.
        input.extend_with_blocks(
            blocks.iter().rev().map(|block| (block.hashed_state(), block.trie_updates())),
        );

        Ok(input)
    }
}

/// Output of block or payload validation.
pub type ValidationOutcome<N, E = InsertPayloadError<BlockTy<N>>> =
    Result<ExecutedBlockWithTrieUpdates<N>, E>;

/// Type that validates the payloads processed by the engine.
///
/// This provides the necessary functions for validating/executing payloads/blocks.
pub trait EngineValidator<
    Types: PayloadTypes,
    N: NodePrimitives = <<Types as PayloadTypes>::BuiltPayload as BuiltPayload>::Primitives,
>: Send + Sync + 'static
{
    /// Validates the payload attributes with respect to the header.
    ///
    /// By default, this enforces that the payload attributes timestamp is greater than the
    /// timestamp according to:
    ///   > 7. Client software MUST ensure that payloadAttributes.timestamp is greater than
    ///   > timestamp
    ///   > of a block referenced by forkchoiceState.headBlockHash.
    ///
    /// See also: <https://github.com/ethereum/execution-apis/blob/main/src/engine/common.md#specification-1>
    fn validate_payload_attributes_against_header(
        &self,
        attr: &Types::PayloadAttributes,
        header: &N::BlockHeader,
    ) -> Result<(), InvalidPayloadAttributesError>;

    /// Ensures that the given payload does not violate any consensus rules that concern the block's
    /// layout.
    ///
    /// This function must convert the payload into the executable block and pre-validate its
    /// fields.
    ///
    /// Implementers should ensure that the checks are done in the order that conforms with the
    /// engine-API specification.
    fn ensure_well_formed_payload(
        &self,
        payload: Types::ExecutionData,
    ) -> Result<RecoveredBlock<N::Block>, NewPayloadError>;

    /// Validates a payload received from engine API.
    fn validate_payload(
        &mut self,
        payload: Types::ExecutionData,
        ctx: TreeCtx<'_, N>,
    ) -> ValidationOutcome<N>;

    /// Validates a block downloaded from the network.
    fn validate_block(
        &mut self,
        block: RecoveredBlock<N::Block>,
        ctx: TreeCtx<'_, N>,
    ) -> ValidationOutcome<N>;
}

impl<N, Types, P, Evm, V> EngineValidator<Types> for BasicEngineValidator<P, Evm, V>
where
    P: DatabaseProviderFactory<Provider: BlockReader>
        + BlockReader<Header = N::BlockHeader>
        + StateProviderFactory
        + StateReader
        + HashedPostStateProvider
        + Clone
        + 'static,
    N: NodePrimitives,
    V: PayloadValidator<Types, Block = N::Block>,
    Evm: ConfigureEngineEvm<Types::ExecutionData, Primitives = N> + 'static,
    Types: PayloadTypes<BuiltPayload: BuiltPayload<Primitives = N>>,
{
    fn validate_payload_attributes_against_header(
        &self,
        attr: &Types::PayloadAttributes,
        header: &N::BlockHeader,
    ) -> Result<(), InvalidPayloadAttributesError> {
        self.validator.validate_payload_attributes_against_header(attr, header)
    }

    fn ensure_well_formed_payload(
        &self,
        payload: Types::ExecutionData,
    ) -> Result<RecoveredBlock<N::Block>, NewPayloadError> {
        let block = self.validator.ensure_well_formed_payload(payload)?;
        Ok(block)
    }

    fn validate_payload(
        &mut self,
        payload: Types::ExecutionData,
        ctx: TreeCtx<'_, N>,
    ) -> ValidationOutcome<N> {
        self.validate_block_with_state(BlockOrPayload::Payload(payload), ctx)
    }

    fn validate_block(
        &mut self,
        block: RecoveredBlock<N::Block>,
        ctx: TreeCtx<'_, N>,
    ) -> ValidationOutcome<N> {
        self.validate_block_with_state(BlockOrPayload::Block(block), ctx)
    }
}

/// Enum representing either block or payload being validated.
#[derive(Debug)]
pub enum BlockOrPayload<T: PayloadTypes> {
    /// Payload.
    Payload(T::ExecutionData),
    /// Block.
    Block(RecoveredBlock<BlockTy<<T::BuiltPayload as BuiltPayload>::Primitives>>),
}

impl<T: PayloadTypes> BlockOrPayload<T> {
    /// Returns the hash of the block.
    pub fn hash(&self) -> B256 {
        match self {
            Self::Payload(payload) => payload.block_hash(),
            Self::Block(block) => block.hash(),
        }
    }

    /// Returns the number and hash of the block.
    pub fn num_hash(&self) -> NumHash {
        match self {
            Self::Payload(payload) => payload.num_hash(),
            Self::Block(block) => block.num_hash(),
        }
    }

    /// Returns the parent hash of the block.
    pub fn parent_hash(&self) -> B256 {
        match self {
            Self::Payload(payload) => payload.parent_hash(),
            Self::Block(block) => block.parent_hash(),
        }
    }

    /// Returns [`BlockWithParent`] for the block.
    pub fn block_with_parent(&self) -> BlockWithParent {
        match self {
            Self::Payload(payload) => payload.block_with_parent(),
            Self::Block(block) => block.block_with_parent(),
        }
    }
}
