use crate::primitives::alloy_primitives::{BlockNumber, StorageKey, StorageValue};
use alloy_primitives::{Address, B256, U256};
use core::ops::{Deref, DerefMut};
use reth_primitives_traits::Account;
use reth_storage_api::{AccountReader, BlockHashReader, BytecodeReader, StateProvider};
use reth_storage_errors::provider::{ProviderError, ProviderResult};
use revm::{bytecode::Bytecode, state::AccountInfo, Database, DatabaseRef};

/// A helper trait responsible for providing state necessary for EVM execution.
///
/// This serves as the data layer for [`Database`].
pub trait EvmStateProvider: Send + Sync {
    /// Get basic account information.
    ///
    /// Returns [`None`] if the account doesn't exist.
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>>;

    /// Get the hash of the block with the given number. Returns [`None`] if no block with this
    /// number exists.
    fn block_hash(&self, number: BlockNumber) -> ProviderResult<Option<B256>>;

    /// Get account code by hash.
    fn bytecode_by_hash(
        &self,
        code_hash: &B256,
    ) -> ProviderResult<Option<reth_primitives_traits::Bytecode>>;

    /// Get storage of the given account.
    fn storage(
        &self,
        account: Address,
        storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>>;
}

// Blanket implementation of EvmStateProvider for any type that implements StateProvider.
impl<T: StateProvider> EvmStateProvider for T {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        <T as AccountReader>::basic_account(self, address)
    }

    fn block_hash(&self, number: BlockNumber) -> ProviderResult<Option<B256>> {
        <T as BlockHashReader>::block_hash(self, number)
    }

    fn bytecode_by_hash(
        &self,
        code_hash: &B256,
    ) -> ProviderResult<Option<reth_primitives_traits::Bytecode>> {
        <T as BytecodeReader>::bytecode_by_hash(self, code_hash)
    }

    fn storage(
        &self,
        account: Address,
        storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        <T as StateProvider>::storage(self, account, storage_key)
    }
}

/// A [Database] and [`DatabaseRef`] implementation that uses [`EvmStateProvider`] as the underlying
/// data source.
#[derive(Clone)]
pub struct StateProviderDatabase<DB>(pub DB);

impl<DB> StateProviderDatabase<DB> {
    /// Create new State with generic `StateProvider`.
    pub const fn new(db: DB) -> Self {
        Self(db)
    }

    /// Consume State and return inner `StateProvider`.
    pub fn into_inner(self) -> DB {
        self.0
    }
}

impl<DB> core::fmt::Debug for StateProviderDatabase<DB> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StateProviderDatabase").finish_non_exhaustive()
    }
}

impl<DB> AsRef<DB> for StateProviderDatabase<DB> {
    fn as_ref(&self) -> &DB {
        self
    }
}

impl<DB> Deref for StateProviderDatabase<DB> {
    type Target = DB;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<DB> DerefMut for StateProviderDatabase<DB> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<DB: EvmStateProvider> Database for StateProviderDatabase<DB> {
    type Error = ProviderError;

    /// Retrieves basic account information for a given address.
    ///
    /// Returns `Ok` with `Some(AccountInfo)` if the account exists,
    /// `None` if it doesn't, or an error if encountered.
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.basic_ref(address)
    }

    /// Retrieves the bytecode associated with a given code hash.
    ///
    /// Returns `Ok` with the bytecode if found, or the default bytecode otherwise.
    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.code_by_hash_ref(code_hash)
    }

    /// Retrieves the storage value at a specific index for a given address.
    ///
    /// Returns `Ok` with the storage value, or the default value if not found.
    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.storage_ref(address, index)
    }

    /// Retrieves the block hash for a given block number.
    ///
    /// Returns `Ok` with the block hash if found, or the default hash otherwise.
    /// Note: It safely casts the `number` to `u64`.
    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.block_hash_ref(number)
    }
}

impl<DB: EvmStateProvider> DatabaseRef for StateProviderDatabase<DB> {
    type Error = <Self as Database>::Error;

    /// Retrieves basic account information for a given address.
    ///
    /// Returns `Ok` with `Some(AccountInfo)` if the account exists,
    /// `None` if it doesn't, or an error if encountered.
    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.basic_account(&address)?.map(Into::into))
    }

    /// Retrieves the bytecode associated with a given code hash.
    ///
    /// Returns `Ok` with the bytecode if found, or the default bytecode otherwise.
    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(self.bytecode_by_hash(&code_hash)?.unwrap_or_default().0)
    }

    /// Retrieves the storage value at a specific index for a given address.
    ///
    /// Returns `Ok` with the storage value, or the default value if not found.
    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        Ok(self.0.storage(address, B256::new(index.to_be_bytes()))?.unwrap_or_default())
    }

    /// Retrieves the block hash for a given block number.
    ///
    /// Returns `Ok` with the block hash if found, or the default hash otherwise.
    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        // Get the block hash or default hash with an attempt to convert U256 block number to u64
        Ok(self.0.block_hash(number)?.unwrap_or_default())
    }
}

/// Cloneable read handle to the off-trie PerpDEX canonical store ("PerpState").
///
/// The same `Arc` is shared with `reth_chain_state::CanonicalInMemoryState::canonical_perp`; it
/// maps a domain key to its committed orderbook blob (empty/absent => no committed value).
#[cfg(feature = "std")]
pub type PerpHandle =
    std::sync::Arc<parking_lot::RwLock<alloy_primitives::map::HashMap<B256, alloc::vec::Vec<u8>>>>;

/// Wraps a [`Database`]/[`DatabaseRef`] so off-trie PerpDEX cold reads resolve to the committed
/// `canonical_perp` store, while all trie-backed reads forward unchanged to the inner database.
///
/// This is the read counterpart of revm's journal perp section: when the EVM's `perp_load` misses
/// the in-block overlay, revm calls [`Database::perp_storage`], which resolves here to the
/// committed off-trie store instead of returning empty. The perp store is intentionally NOT in the
/// state trie, so it is served from this side channel rather than via [`Database::storage`].
#[cfg(feature = "std")]
#[derive(Clone)]
pub struct PerpDb<DB> {
    inner: DB,
    perp: PerpHandle,
}

#[cfg(feature = "std")]
impl<DB> PerpDb<DB> {
    /// Wraps `inner`, serving perp cold reads from the shared `canonical_perp` handle.
    pub const fn new(inner: DB, perp: PerpHandle) -> Self {
        Self { inner, perp }
    }

    /// Consumes the wrapper, returning the inner database.
    pub fn into_inner(self) -> DB {
        self.inner
    }

    #[inline]
    fn perp_get(&self, key: B256) -> alloc::vec::Vec<u8> {
        self.perp.read().get(&key).cloned().unwrap_or_default()
    }
}

#[cfg(feature = "std")]
impl<DB> core::fmt::Debug for PerpDb<DB> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PerpDb").finish_non_exhaustive()
    }
}

#[cfg(feature = "std")]
impl<DB: Database> Database for PerpDb<DB> {
    type Error = DB::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.inner.basic(address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.inner.code_by_hash(code_hash)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.inner.storage(address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.inner.block_hash(number)
    }

    /// Off-trie PerpDEX cold read: resolves from the committed `canonical_perp` store.
    fn perp_storage(&mut self, key: B256) -> Result<alloc::vec::Vec<u8>, Self::Error> {
        Ok(self.perp_get(key))
    }
}

#[cfg(feature = "std")]
impl<DB: DatabaseRef> DatabaseRef for PerpDb<DB> {
    type Error = DB::Error;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.inner.basic_ref(address)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.inner.code_by_hash_ref(code_hash)
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.inner.storage_ref(address, index)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.inner.block_hash_ref(number)
    }

    /// Off-trie PerpDEX cold read: resolves from the committed `canonical_perp` store.
    fn perp_storage_ref(&self, key: B256) -> Result<alloc::vec::Vec<u8>, Self::Error> {
        Ok(self.perp_get(key))
    }
}
