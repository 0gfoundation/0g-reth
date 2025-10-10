use alloc::vec::Vec;
use alloy_consensus::{proofs::calculate_receipt_root, BlockHeader, BlockHeaderMut, TxReceipt};
use alloy_eips::Encodable2718;
use alloy_primitives::{Bloom, Bytes, B256};
use reth_chainspec::EthereumHardforks;
use reth_consensus::ConsensusError;
use reth_execution_types::BlockExecutionResult;
use reth_primitives_traits::{
    receipt::gas_spent_by_transactions, Block, GotExpected, Receipt, RecoveredBlock, SealedBlock,
};

/// Validate a block with regard to execution results:
///
/// - Compares the receipts root in the block header to the block body
/// - Compares the gas used in the block header to the actual gas usage after execution
/// - Compares the computed Block Access List Hash to the value in the header if Amsterdam is active
///
/// If `receipt_root_bloom` is provided, the pre-computed receipt root and logs bloom are used
/// instead of computing them from the receipts.
pub fn validate_block_post_execution<B, R, ChainSpec>(
    block: &mut RecoveredBlock<B>,
    chain_spec: &ChainSpec,
    result: &BlockExecutionResult<R>,
    receipt_root_bloom: Option<(B256, Bloom)>,
    block_access_list_hash: Option<B256>,
) -> Result<(), ConsensusError>
where
    B: Block,
    R: Receipt,
    ChainSpec: EthereumHardforks,
{
    validate_block_post_execution_with_bal_hashes(
        block,
        chain_spec,
        result,
        receipt_root_bloom,
        block_access_list_hash,
        false,
    )
}

/// Validate a block with regard to execution results, optionally allowing pre-Amsterdam BAL hashes.
// reth-v2.8.1 migration: upstream moved the body of `validate_block_post_execution` into this
// function, so the 0G change of `block` to `&mut` (the block is re-sealed with the computed
// header values below) is applied here too.
pub(crate) fn validate_block_post_execution_with_bal_hashes<B, R, ChainSpec>(
    block: &mut RecoveredBlock<B>,
    chain_spec: &ChainSpec,
    result: &BlockExecutionResult<R>,
    receipt_root_bloom: Option<(B256, Bloom)>,
    block_access_list_hash: Option<B256>,
    allow_bal_hashes: bool,
) -> Result<(), ConsensusError>
where
    B: Block,
    R: Receipt,
    ChainSpec: EthereumHardforks,
{
    let mut header = block.header().clone();
    // Check if gas used matches the value set in header.
    // reth-v2.8.1 migration: the original compared the header with the last receipt's
    // `cumulative_gas_used` and wrote that value into `header` before returning the error.
    // Upstream now compares with `result.gas_used` (since EIP-8037 the block gas is no longer the
    // receipts' cumulative gas). This commit's receipt builder raises the receipts' cumulative
    // gas to 80% of the block gas limit, so the two differ here; the receipts' value is kept so
    // the comparison and the value written are the ones the original used.
    let cumulative_gas_used =
        result.receipts.last().map(|receipt| receipt.cumulative_gas_used()).unwrap_or(0);
    if block.header().gas_used() != cumulative_gas_used {
        header.set_gas_used(cumulative_gas_used);
        return Err(ConsensusError::BlockGasUsed {
            gas: GotExpected { got: cumulative_gas_used, expected: block.header().gas_used() },
            gas_spent_by_tx: gas_spent_by_transactions(&result.receipts),
        })
    }

    // Before Byzantium, receipts contained state root that would mean that expensive
    // operation as hashing that is required for state root got calculated in every
    // transaction This was replaced with is_success flag.
    // See more about EIP here: https://eips.ethereum.org/EIPS/eip-658
    if chain_spec.is_byzantium_active_at_block(block.header().number()) {
        // reth-v2.8.1 migration: upstream can pass a `receipt_root_bloom` already computed from
        // the same receipts (the engine computes it in a background task); the original only
        // computed it here. Use the pre-computed value when given, otherwise compute it as the
        // original did; either way the values are written to `header` instead of compared.
        let (receipts_root, logs_bloom) = if let Some(root_bloom) = receipt_root_bloom {
            root_bloom
        } else {
            // Calculate receipts root and logs bloom from receipts
            let receipts_with_bloom =
                result.receipts.iter().map(TxReceipt::with_bloom_ref).collect::<Vec<_>>();
            let receipts_root = calculate_receipt_root(&receipts_with_bloom);
            let logs_bloom =
                receipts_with_bloom.iter().fold(Bloom::ZERO, |bloom, r| bloom | r.bloom_ref());
            (receipts_root, logs_bloom)
        };

        // Set the calculated values to header
        header.set_receipts_root(receipts_root);
        header.set_logs_bloom(logs_bloom);
    }

    // Validate that the header requests hash matches the calculated requests hash
    if chain_spec.is_prague_active_at_timestamp(block.header().timestamp()) {
        let Some(header_requests_hash) = block.header().requests_hash() else {
            return Err(ConsensusError::RequestsHashMissing)
        };
        let requests_hash = result.requests.requests_hash();
        header.set_requests_hash(Some(requests_hash));
    }

    // Validate that the header block access list hash matches the calculated block access list hash
    let is_allowed_pre_amsterdam_bal_hash = allow_bal_hashes &&
        !chain_spec.is_amsterdam_active_at_timestamp(block.header().timestamp()) &&
        block.header().block_access_list_hash().is_some();

    let is_amsterdam = chain_spec.is_amsterdam_active_at_timestamp(block.header().timestamp());
    if is_amsterdam && block_access_list_hash.is_none() {
        return Err(ConsensusError::BlockAccessListHashMissing)
    }

    if (is_amsterdam || is_allowed_pre_amsterdam_bal_hash) &&
        let Some(block_access_list_hash) = block_access_list_hash
    {
        let block_bal_hash = block.header().block_access_list_hash().unwrap_or_default();
        if block_access_list_hash != block_bal_hash {
            return Err(ConsensusError::BlockAccessListHashMismatch(
                GotExpected::new(block_access_list_hash, block_bal_hash).into(),
            ))
        }
    }

    let sealed_block = SealedBlock::seal_parts(header, block.body().clone());
    *block = RecoveredBlock::new_sealed(sealed_block, block.senders().to_vec());

    Ok(())
}

/// Calculate the receipts root, and compare it against the expected receipts root and logs
/// bloom.
pub fn verify_receipts<R: Receipt>(
    expected_receipts_root: B256,
    expected_logs_bloom: Bloom,
    receipts: &[R],
) -> Result<(), ConsensusError> {
    // Calculate receipts root.
    let receipts_with_bloom = receipts.iter().map(TxReceipt::with_bloom_ref).collect::<Vec<_>>();
    let receipts_root = calculate_receipt_root(&receipts_with_bloom);

    // Calculate header logs bloom.
    let logs_bloom = receipts_with_bloom.iter().fold(Bloom::ZERO, |bloom, r| bloom | r.bloom_ref());

    compare_receipts_root_and_logs_bloom(
        receipts_root,
        logs_bloom,
        expected_receipts_root,
        expected_logs_bloom,
    )
}

/// Compare the calculated receipts root with the expected receipts root, also compare
/// the calculated logs bloom with the expected logs bloom.
pub fn compare_receipts_root_and_logs_bloom(
    calculated_receipts_root: B256,
    calculated_logs_bloom: Bloom,
    expected_receipts_root: B256,
    expected_logs_bloom: Bloom,
) -> Result<(), ConsensusError> {
    if calculated_receipts_root != expected_receipts_root {
        return Err(ConsensusError::BodyReceiptRootDiff(
            GotExpected { got: calculated_receipts_root, expected: expected_receipts_root }.into(),
        ))
    }

    if calculated_logs_bloom != expected_logs_bloom {
        return Err(ConsensusError::BodyBloomLogDiff(
            GotExpected { got: calculated_logs_bloom, expected: expected_logs_bloom }.into(),
        ))
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    use alloy_primitives::b256;
    use reth_ethereum_primitives::Receipt;

    #[test]
    fn test_verify_receipts_success() {
        // Create a vector of 5 default Receipt instances
        let receipts: Vec<Receipt> = vec![Receipt::default(); 5];

        // Compare against expected values
        assert!(verify_receipts(
            b256!("0x61353b4fb714dc1fccacbf7eafc4273e62f3d1eed716fe41b2a0cd2e12c63ebc"),
            Bloom::ZERO,
            &receipts
        )
        .is_ok());
    }

    #[test]
    fn test_verify_receipts_incorrect_root() {
        // Generate random expected values to produce a failure
        let expected_receipts_root = B256::random();
        let expected_logs_bloom = Bloom::random();

        // Create a vector of 5 random Receipt instances
        let receipts: Vec<Receipt> = vec![Receipt::default(); 5];

        assert!(verify_receipts(expected_receipts_root, expected_logs_bloom, &receipts).is_err());
    }

    #[test]
    fn test_compare_receipts_root_and_logs_bloom_success() {
        let calculated_receipts_root = B256::random();
        let calculated_logs_bloom = Bloom::random();

        let expected_receipts_root = calculated_receipts_root;
        let expected_logs_bloom = calculated_logs_bloom;

        assert!(compare_receipts_root_and_logs_bloom(
            calculated_receipts_root,
            calculated_logs_bloom,
            expected_receipts_root,
            expected_logs_bloom
        )
        .is_ok());
    }

    #[test]
    fn test_compare_receipts_root_failure() {
        let calculated_receipts_root = B256::random();
        let calculated_logs_bloom = Bloom::random();

        let expected_receipts_root = B256::random();
        let expected_logs_bloom = calculated_logs_bloom;

        assert!(matches!(
            compare_receipts_root_and_logs_bloom(
                calculated_receipts_root,
                calculated_logs_bloom,
                expected_receipts_root,
                expected_logs_bloom
            ).unwrap_err(),
            ConsensusError::BodyReceiptRootDiff(diff)
                if diff.got == calculated_receipts_root && diff.expected == expected_receipts_root
        ));
    }

    #[test]
    fn test_compare_log_bloom_failure() {
        let calculated_receipts_root = B256::random();
        let calculated_logs_bloom = Bloom::random();

        let expected_receipts_root = calculated_receipts_root;
        let expected_logs_bloom = Bloom::random();

        assert!(matches!(
            compare_receipts_root_and_logs_bloom(
                calculated_receipts_root,
                calculated_logs_bloom,
                expected_receipts_root,
                expected_logs_bloom
            ).unwrap_err(),
            ConsensusError::BodyBloomLogDiff(diff)
                if diff.got == calculated_logs_bloom && diff.expected == expected_logs_bloom
        ));
    }
}
