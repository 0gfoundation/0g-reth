//! L2-2 Phase A1 — SHADOW parallel replay of the EVM execution pass (measurement/validation only).
//!
//! For an all-perp-trading block the EVM pass is per-sender independent: each replay tx touches
//! ONLY its sender account (+ read-only 0x1003 + the beneficiary, folded at merge in Phase A2), and
//! the perp effects live in the pre-phase book. So the pass can be re-executed in parallel over a
//! PRE-MATERIALIZED read-set — workers run on pure in-memory state (no mdbx, no providers, no
//! kernel page/TLB exposure; the shell-scaling probe's cross-sender scaling applies directly).
//!
//! Phase A1 (this module) is a SHADOW: gated by `PERP_REPLAY_SHADOW`, it executes the whole block
//! in parallel workers and DISCARDS the results — the serial `execute_metered` pass stays
//! authoritative. It reports wall time, read-set misses (must be zero — the fail-stop probe of the
//! read-set claim) and a gas-sum digest to compare against the serial output. Phase A2 promotes the
//! same machinery to the real path behind a deterministic merge.

use alloy_evm::Evm as _;
use alloy_primitives::{Address, B256, KECCAK256_EMPTY};
use reth_evm::{execute::ExecutableTxFor, ConfigureEvm, EvmEnvFor};
use reth_provider::{ProviderError, StateProvider};
use reth_revm::db::CacheDB;
use revm::context_interface::journaled_state::PerpReplayResult;
use revm::{
    bytecode::Bytecode, context::journal::perp_pool::PerpPool, context::result::ExecutionResult,
    state::AccountInfo, DatabaseRef,
};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Instant,
};

/// Pre-materialized closed read-set for one block's replay pass: every account a replay tx may
/// touch, read ONCE through the authoritative state provider on the calling thread. Workers see
/// ONLY this — any access outside it is a fail-stop miss (counted, task aborts), which is exactly
/// the probe for the "replay txs read nothing else" claim.
#[derive(Debug, Default)]
pub(crate) struct ReplayReadSet {
    accounts: HashMap<Address, Option<AccountInfo>>,
    code: HashMap<B256, Bytecode>,
}

impl ReplayReadSet {
    /// Builds the read-set: all tx senders + the 0x1003 precompile account (and its code) + the
    /// block beneficiary. Returns `None` on any provider error (shadow is best-effort).
    pub(crate) fn build<S: StateProvider>(
        provider: &S,
        senders: impl Iterator<Item = Address>,
        beneficiary: Address,
        perp_address: Address,
    ) -> Option<Self> {
        let mut rs = Self::default();
        for addr in senders.chain([beneficiary, perp_address]) {
            if rs.accounts.contains_key(&addr) {
                continue;
            }
            let acct = provider.basic_account(&addr).ok()?;
            let info = acct.map(|a| AccountInfo {
                balance: a.balance,
                nonce: a.nonce,
                code_hash: a.bytecode_hash.unwrap_or(KECCAK256_EMPTY),
                code: None,
            });
            if let Some(info) = &info {
                if info.code_hash != KECCAK256_EMPTY && !rs.code.contains_key(&info.code_hash) {
                    let code = provider.bytecode_by_hash(&info.code_hash).ok()??;
                    rs.code.insert(info.code_hash, code.0);
                }
            }
            rs.accounts.insert(addr, info);
        }
        Some(rs)
    }
}

/// Read-only DB over the read-set; anything outside is a counted fail-stop miss. Wrapped in a
/// per-worker `CacheDB` overlay for same-sender nonce/balance sequencing.
#[derive(Debug, Clone)]
struct ReadSetDb {
    rs: Arc<ReplayReadSet>,
    misses: Arc<AtomicUsize>,
}

impl ReadSetDb {
    fn miss<T>(&self) -> Result<T, ProviderError> {
        self.misses.fetch_add(1, Ordering::Relaxed);
        Err(ProviderError::UnsupportedProvider)
    }
}

impl DatabaseRef for ReadSetDb {
    type Error = ProviderError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        match self.rs.accounts.get(&address) {
            Some(info) => Ok(info.clone()),
            None => self.miss(),
        }
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if code_hash == KECCAK256_EMPTY {
            return Ok(Bytecode::default());
        }
        match self.rs.code.get(&code_hash) {
            Some(c) => Ok(c.clone()),
            None => self.miss(),
        }
    }

    fn storage_ref(
        &self,
        _address: Address,
        _index: alloy_primitives::U256,
    ) -> Result<alloy_primitives::U256, Self::Error> {
        // A replay tx executes no bytecode → any storage read is outside the claimed read-set.
        self.miss()
    }

    fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
        self.miss()
    }
}

/// Aggregate outcome of one shadow run (logged by the caller under PERP_PROF).
#[derive(Debug, Default)]
pub(crate) struct ShadowStats {
    pub n_txs: usize,
    pub n_tasks: usize,
    pub wall_ms: f64,
    pub gas_sum: u64,
    pub ok: usize,
    pub reverted: usize,
    pub errors: usize,
    pub misses: usize,
}

/// Groups tx indices by sender (order preserved within a sender), then packs whole groups into
/// `~2×threads` balanced tasks (greedy by size) — whole-group placement keeps same-sender nonce
/// sequences on one worker; chunked tasks avoid per-tx dispatch overhead.
fn plan_tasks(senders: &[Address], threads: usize) -> Vec<Vec<usize>> {
    let mut group_of: HashMap<Address, usize> = HashMap::new();
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for (i, s) in senders.iter().enumerate() {
        match group_of.get(s) {
            Some(&g) => groups[g].push(i),
            None => {
                group_of.insert(*s, groups.len());
                groups.push(vec![i]);
            }
        }
    }
    let n_tasks = (threads * 2).clamp(1, groups.len().max(1));
    let mut tasks: Vec<Vec<usize>> = vec![Vec::new(); n_tasks];
    let mut load = vec![0usize; n_tasks];
    // Largest groups first onto the least-loaded task.
    let mut order: Vec<usize> = (0..groups.len()).collect();
    order.sort_by_key(|&g| core::cmp::Reverse(groups[g].len()));
    for g in order {
        let t = (0..n_tasks).min_by_key(|&t| load[t]).unwrap_or(0);
        load[t] += groups[g].len();
        tasks[t].extend(&groups[g]);
    }
    tasks.retain(|t| !t.is_empty());
    tasks
}

/// Runs the shadow parallel replay. Caller has already verified the gates (all txs are perp
/// trading calls, `replay.len() == txs.len()`, threshold, env). Results are discarded; only stats
/// return. Deterministic per task (each task's txs execute in block order within the task).
///
/// Each task receives OWNED clones of its txs + replay slice (built here on the calling thread) —
/// the handle's tx type guarantees `Clone + Send + 'static` but not `Sync`, so no cross-thread
/// sharing of the tx list itself.
pub(crate) fn shadow_parallel_replay<C, Tx>(
    pool: &PerpPool,
    threads: usize,
    evm_config: &C,
    evm_env: EvmEnvFor<C>,
    txs: &[Tx],
    replay: &[PerpReplayResult],
    read_set: Arc<ReplayReadSet>,
) -> ShadowStats
where
    C: ConfigureEvm + 'static,
    Tx: ExecutableTxFor<C> + Clone + Send + 'static,
{
    let senders: Vec<Address> = txs.iter().map(|t| *t.signer()).collect();
    let tasks = plan_tasks(&senders, threads.max(1));
    let misses = Arc::new(AtomicUsize::new(0));

    let t0 = Instant::now();
    let jobs: Vec<_> = tasks
        .iter()
        .map(|indices| {
            // Owned per-task slices, in the task's execution order: the txs it runs and the replay
            // results its journal pops (the per-worker queue replaces the global block-order cursor).
            let task_txs: Vec<Tx> = indices.iter().map(|&i| txs[i].clone()).collect();
            let task_replay: Vec<PerpReplayResult> =
                indices.iter().map(|&i| replay[i].clone()).collect();
            let cfg = evm_config.clone();
            let env = evm_env.clone();
            let db = ReadSetDb { rs: read_set.clone(), misses: misses.clone() };
            move || -> (u64, usize, usize, usize) {
                let mut evm = cfg.evm_with_env(CacheDB::new(db), env);
                evm.set_perp_replay(task_replay);
                let (mut gas, mut ok, mut rev, mut errs) = (0u64, 0usize, 0usize, 0usize);
                for tx in &task_txs {
                    match evm.transact_commit(tx.to_tx_env()) {
                        Ok(res) => {
                            gas += res.gas_used();
                            match res {
                                ExecutionResult::Success { .. } => ok += 1,
                                _ => rev += 1,
                            }
                        }
                        Err(_) => {
                            // Fail-stop for this task (read-set miss or exec error): remaining txs
                            // of the task are skipped; the miss counter attributes it.
                            errs += 1;
                            break;
                        }
                    }
                }
                (gas, ok, rev, errs)
            }
        })
        .collect();
    let n_tasks = jobs.len();
    let results = pool.run_batch(jobs);
    let wall_ms = t0.elapsed().as_secs_f64() * 1e3;

    let mut stats = ShadowStats {
        n_txs: txs.len(),
        n_tasks,
        wall_ms,
        misses: misses.load(Ordering::Relaxed),
        ..Default::default()
    };
    for (gas, ok, rev, errs) in results {
        stats.gas_sum += gas;
        stats.ok += ok;
        stats.reverted += rev;
        stats.errors += errs;
    }
    stats
}
