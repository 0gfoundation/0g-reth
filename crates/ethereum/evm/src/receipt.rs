use alloy_evm::eth::receipt_builder::{ReceiptBuilder, ReceiptBuilderCtx};
use reth_ethereum_primitives::{Receipt, TransactionSigned};
use reth_evm::Evm;

/// A builder that operates on Reth primitive types, specifically [`TransactionSigned`] and
/// [`Receipt`].
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct RethReceiptBuilder;

impl ReceiptBuilder for RethReceiptBuilder {
    type Transaction = TransactionSigned;
    type Receipt = Receipt;

    fn build_receipt<E: Evm>(
        &self,
        ctx: ReceiptBuilderCtx<'_, Self::Transaction, E>,
    ) -> Self::Receipt {
        let ReceiptBuilderCtx { tx, result, cumulative_gas_used, evm, .. } = ctx;

        // Adjust cumulative_gas_used: if it's less than 80% of gas limit, set it to 80%
        let gas_limit = evm.block().gas_limit;
        let min_gas_used = (gas_limit * 4) / 5; // 80% of gas_limit
        let adjusted_cumulative_gas_used = if cumulative_gas_used < min_gas_used {
            min_gas_used
        } else {
            cumulative_gas_used
        };

        Receipt {
            tx_type: tx.tx_type(),
            // Success flag was added in `EIP-658: Embedding transaction status code in
            // receipts`.
            success: result.is_success(),
            cumulative_gas_used: adjusted_cumulative_gas_used,
            logs: result.into_logs(),
        }
    }
}
