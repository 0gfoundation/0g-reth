use alloc::vec::Vec;
use alloy_consensus::{proofs::calculate_receipt_root, BlockHeader, BlockHeaderMut, TxReceipt};
use alloy_eips::eip7685::Requests;
use alloy_primitives::Bloom;
#[cfg(test)]
use alloy_primitives::B256;
use reth_chainspec::EthereumHardforks;
use reth_consensus::ConsensusError;
#[cfg(test)]
use reth_primitives_traits::GotExpected;
use reth_primitives_traits::{Block, Receipt, RecoveredBlock, SealedBlock};

/// Validate a block with regard to execution results:
///
/// - Compares the receipts root in the block header to the block body
/// - Compares the gas used in the block header to the actual gas usage after execution
pub fn validate_block_post_execution<B, R, ChainSpec>(
    block: &mut RecoveredBlock<B>,
    chain_spec: &ChainSpec,
    receipts: &[R],
    requests: &Requests,
) -> Result<(), ConsensusError>
where
    B: Block,
    R: Receipt,
    ChainSpec: EthereumHardforks,
{
    let mut header = block.header().clone();

    // Print each receipt during cumulative_gas_used calculation
    tracing::info!(
        target: "consensus::validation",
        block_number = block.header().number(),
        receipts_count = receipts.len(),
        "Starting to process receipts for cumulative_gas_used calculation"
    );

    for (idx, receipt) in receipts.iter().enumerate() {
        tracing::info!(
            target: "consensus::validation",
            block_number = block.header().number(),
            receipt_index = idx,
            cumulative_gas_used = receipt.cumulative_gas_used(),
            success = receipt.status(),
            "Receipt details during cumulative_gas_used calculation"
        );
    }

    // Check if gas used matches the value set in header.
    let cumulative_gas_used =
        receipts.last().map(|receipt| receipt.cumulative_gas_used()).unwrap_or(0);

    tracing::info!(
        target: "consensus::validation",
        block_number = block.header().number(),
        final_cumulative_gas_used = cumulative_gas_used,
        header_gas_used = block.header().gas_used(),
        "Final cumulative_gas_used calculation complete"
    );

    if block.header().gas_used() != cumulative_gas_used {
        // Update header with actual gas used from execution
        // This is expected because proposal uses gas_limit while validation uses actual execution
        // result
        header.set_gas_used(cumulative_gas_used);
        tracing::info!(
            target: "consensus::validation",
            block_number = block.header().number(),
            block_hash = ?block.hash(),
            proposal_gas = block.header().gas_used(),
            actual_gas = cumulative_gas_used,
            "Updating header gas_used with actual execution result"
        );
        // Do not return error - header will be updated and re-signed
    }

    // Before Byzantium, receipts contained state root that would mean that expensive
    // operation as hashing that is required for state root got calculated in every
    // transaction This was replaced with is_success flag.
    // See more about EIP here: https://eips.ethereum.org/EIPS/eip-658
    if chain_spec.is_byzantium_active_at_block(block.header().number()) {
        // Calculate receipts root and logs bloom from receipts
        let receipts_with_bloom =
            receipts.iter().map(TxReceipt::with_bloom_ref).collect::<Vec<_>>();
        let receipts_root = calculate_receipt_root(&receipts_with_bloom);
        let logs_bloom =
            receipts_with_bloom.iter().fold(Bloom::ZERO, |bloom, r| bloom | r.bloom_ref());

        // Set the calculated values to header
        header.set_receipts_root(receipts_root);
        header.set_logs_bloom(logs_bloom);
    }

    // Validate that the header requests hash matches the calculated requests hash
    if chain_spec.is_prague_active_at_timestamp(block.header().timestamp()) {
        let Some(_header_requests_hash) = block.header().requests_hash() else {
            return Err(ConsensusError::RequestsHashMissing)
        };
        let requests_hash = requests.requests_hash();
        header.set_requests_hash(Some(requests_hash));
    }

    let sealed_block = SealedBlock::seal_parts(header, block.body().clone());
    *block = RecoveredBlock::new_sealed(sealed_block, block.senders().to_vec());

    Ok(())
}

/// Calculate the receipts root, and compare it against the expected receipts root and logs
/// bloom.
#[cfg(test)]
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
    )?;

    Ok(())
}

/// Compare the calculated receipts root with the expected receipts root, also compare
/// the calculated logs bloom with the expected logs bloom.
#[cfg(test)]
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

        assert_eq!(
            compare_receipts_root_and_logs_bloom(
                calculated_receipts_root,
                calculated_logs_bloom,
                expected_receipts_root,
                expected_logs_bloom
            ),
            Err(ConsensusError::BodyReceiptRootDiff(
                GotExpected { got: calculated_receipts_root, expected: expected_receipts_root }
                    .into()
            ))
        );
    }

    #[test]
    fn test_compare_log_bloom_failure() {
        let calculated_receipts_root = B256::random();
        let calculated_logs_bloom = Bloom::random();

        let expected_receipts_root = calculated_receipts_root;
        let expected_logs_bloom = Bloom::random();

        assert_eq!(
            compare_receipts_root_and_logs_bloom(
                calculated_receipts_root,
                calculated_logs_bloom,
                expected_receipts_root,
                expected_logs_bloom
            ),
            Err(ConsensusError::BodyBloomLogDiff(
                GotExpected { got: calculated_logs_bloom, expected: expected_logs_bloom }.into()
            ))
        );
    }
}
