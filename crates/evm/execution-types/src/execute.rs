use revm::context_interface::journaled_state::PerpDelta;
use revm::database::BundleState;

pub use alloy_evm::block::BlockExecutionResult;

/// [`BlockExecutionResult`] combined with state.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    derive_more::AsRef,
    derive_more::AsMut,
    derive_more::Deref,
    derive_more::DerefMut,
)]
pub struct BlockExecutionOutput<T> {
    /// All the receipts of the transactions in the block.
    #[as_ref]
    #[as_mut]
    #[deref]
    #[deref_mut]
    pub result: BlockExecutionResult<T>,
    /// The changed state of the block after execution.
    pub state: BundleState,
    /// Net off-trie PerpDEX writes ("PerpState") harvested during block execution, if any.
    /// Carried alongside `state` but deliberately NOT folded into the bundle / state trie.
    pub perp: Option<PerpDelta>,
}
