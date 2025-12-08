use alloc::vec::Vec;
use alloy_consensus::{proofs::calculate_receipt_root, BlockHeader, BlockHeaderMut, TxReceipt};
use alloy_eips::Encodable2718;
use alloy_primitives::{Bloom, Bytes, B256};
use reth_chainspec::EthereumHardforks;
use reth_consensus::ConsensusError;
use reth_execution_types::BlockExecutionResult;
use reth_primitives_traits::{Block, GotExpected, Receipt, RecoveredBlock, SealedBlock};

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
    B::Header: BlockHeaderMut,
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
    B::Header: BlockHeaderMut,
    R: Receipt,
    ChainSpec: EthereumHardforks,
{
    let mut header = block.header().clone();

    // Print each receipt during cumulative_gas_used calculation
    tracing::info!(
        target: "consensus::validation",
        block_number = block.header().number(),
        receipts_count = result.receipts.len(),
        "Starting to process receipts for cumulative_gas_used calculation"
    );

    for (idx, receipt) in result.receipts.iter().enumerate() {
        tracing::info!(
            target: "consensus::validation",
            block_number = block.header().number(),
            receipt_index = idx,
            cumulative_gas_used = receipt.cumulative_gas_used(),
            success = receipt.status(),
            "Receipt details during cumulative_gas_used calculation"
        );
    }

    tracing::info!(
        target: "consensus::validation",
        block_number = block.header().number(),
        final_cumulative_gas_used = result.gas_used,
        header_gas_used = block.header().gas_used(),
        "Final cumulative_gas_used calculation complete"
    );

    // Check if gas used matches the value set in header.
    if block.header().gas_used() != result.gas_used {
        // Update header with actual gas used from execution
        // This is expected because proposal uses gas_limit while validation uses actual execution result
        header.set_gas_used(result.gas_used);
        tracing::info!(
            target: "consensus::validation",
            block_number = block.header().number(),
            block_hash = ?block.hash(),
            proposal_gas = block.header().gas_used(),
            actual_gas = result.gas_used,
            "Updating header gas_used with actual execution result"
        );
        // Do not return error - header will be updated and re-signed
    }

    // Before Byzantium, receipts contained state root that would mean that expensive
    // operation as hashing that is required for state root got calculated in every
    // transaction This was replaced with is_success flag.
    // See more about EIP here: https://eips.ethereum.org/EIPS/eip-658
    if chain_spec.is_byzantium_active_at_block(block.header().number()) {
        let (receipts_root, logs_bloom) = if let Some(root_bloom) = receipt_root_bloom {
            root_bloom
        } else {
            let receipts = result.receipts.iter().map(TxReceipt::with_bloom_ref).collect::<Vec<_>>();
            let receipts_root = calculate_receipt_root(&receipts);
            let logs_bloom = receipts.iter().fold(Bloom::ZERO, |bloom, receipt| {
                bloom | receipt.bloom_ref()
            });
            (receipts_root, logs_bloom)
        };

        header.set_receipts_root(receipts_root);
        header.set_logs_bloom(logs_bloom);
    }

    // Validate that the header requests hash matches the calculated requests hash
    if chain_spec.is_prague_active_at_timestamp(block.header().timestamp()) {
        let Some(_) = block.header().requests_hash() else {
            return Err(ConsensusError::RequestsHashMissing)
        };
        let requests_hash = result.requests.requests_hash();
        header.set_requests_hash(Some(requests_hash));
    }

    // Validate that the header block access list hash matches the calculated block access list hash
    let is_allowed_pre_amsterdam_bal_hash = allow_bal_hashes &&
        !chain_spec.is_amsterdam_active_at_timestamp(block.header().timestamp()) &&
        block.header().block_access_list_hash().is_some();

    if (chain_spec.is_amsterdam_active_at_timestamp(block.header().timestamp()) ||
        is_allowed_pre_amsterdam_bal_hash) &&
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
fn verify_receipts<R: Receipt>(
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
fn compare_receipts_root_and_logs_bloom(
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
    use alloy_primitives::{b256, hex};
    use reth_ethereum_primitives::Receipt;

    #[test]
    fn test_verify_receipts_success() {
        // Create a vector of 5 default Receipt instances
        let receipts: Vec<Receipt> = vec![Receipt::default(); 5];

        // Compare against expected values
        assert!(verify_receipts(
            b256!("0x61353b4fb714dc1fccacbf7eafc4273e62f3d1eed716fe41b2a0cd2e12c63ebc"),
            Bloom::from(hex!("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
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
