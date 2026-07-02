use crate::{execute::ExecutableTxFor, ConfigureEvm, EvmEnvFor, ExecutionCtxFor};
use alloc::vec::Vec;
use alloy_primitives::Bytes;
use reth_storage_errors::any::AnyError;

/// [`ConfigureEvm`] extension providing methods for executing payloads.
pub trait ConfigureEngineEvm<ExecutionData>: ConfigureEvm {
    /// The recovered executable transaction type a decoded payload transaction yields (the item
    /// type of [`Self::tx_iterator_for_payload`]).
    type PayloadTx: ExecutableTxFor<Self> + Clone + Send + 'static;

    /// Returns an [`EvmEnvFor`] for the given payload.
    fn evm_env_for_payload(&self, payload: &ExecutionData) -> EvmEnvFor<Self>;

    /// Returns an [`ExecutionCtxFor`] for the given payload.
    fn context_for_payload<'a>(&self, payload: &'a ExecutionData) -> ExecutionCtxFor<'a, Self>;

    /// The payload's raw EIP-2718 encoded transactions, in block order (cheap `Bytes` clones).
    fn payload_txs_encoded(&self, payload: &ExecutionData) -> Vec<Bytes>;

    /// Decodes + sender-recovers ONE encoded payload transaction. Pure CPU and thread-safe — the
    /// unit the engine fans out over a worker pool to recover a whole payload in PARALLEL
    /// (ecrecover dominates at ~90µs/tx serial); also the body of the serial
    /// [`Self::tx_iterator_for_payload`].
    fn decode_payload_tx(&self, encoded: Bytes) -> Result<Self::PayloadTx, AnyError>;

    /// Returns an [`ExecutableTxIterator`] for the given payload.
    fn tx_iterator_for_payload(&self, payload: &ExecutionData) -> impl ExecutableTxIterator<Self>;
}

/// Iterator over executable transactions.
pub trait ExecutableTxIterator<Evm: ConfigureEvm>:
    Iterator<Item = Result<Self::Tx, Self::Error>> + Send + 'static
{
    /// The executable transaction type iterator yields.
    type Tx: ExecutableTxFor<Evm> + Clone + Send + 'static;
    /// Errors that may occur while recovering or decoding transactions.
    type Error: core::error::Error + Send + Sync + 'static;
}

impl<Evm: ConfigureEvm, Tx, Err, T> ExecutableTxIterator<Evm> for T
where
    Tx: ExecutableTxFor<Evm> + Clone + Send + 'static,
    Err: core::error::Error + Send + Sync + 'static,
    T: Iterator<Item = Result<Tx, Err>> + Send + 'static,
{
    type Tx = Tx;
    type Error = Err;
}
