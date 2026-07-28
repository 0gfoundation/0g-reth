use alloc::{sync::Arc, vec::Vec};
use alloy_consensus::{
    proofs::{self, calculate_receipt_root},
    Block, BlockBody, BlockHeader, Header, Transaction, TxReceipt, EMPTY_OMMER_ROOT_HASH,
};
use alloy_eips::merge::BEACON_NONCE;
use alloy_evm::{
    block::BlockExecutorFactory,
    eth::{spec::EthExecutorSpec, EthBlockExecutionCtx},
};
use alloy_primitives::Bytes;
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_evm::execute::{BlockAssembler, BlockAssemblerInput, BlockExecutionError};
use reth_execution_types::BlockExecutionResult;
use reth_primitives_traits::{logs_bloom, Receipt, SignedTransaction};

/// Block builder for Ethereum.
#[derive(Debug, Clone)]
pub struct EthBlockAssembler<ChainSpec = reth_chainspec::ChainSpec> {
    /// The chainspec.
    pub chain_spec: Arc<ChainSpec>,
    /// Extra data to use for the blocks.
    pub extra_data: Bytes,
}

impl<ChainSpec> EthBlockAssembler<ChainSpec> {
    /// Creates a new [`EthBlockAssembler`].
    pub fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { chain_spec, extra_data: Default::default() }
    }
}

impl<F, ChainSpec> BlockAssembler<F> for EthBlockAssembler<ChainSpec>
where
    F: for<'a> BlockExecutorFactory<
        ExecutionCtx<'a> = EthBlockExecutionCtx<'a>,
        Transaction: SignedTransaction,
        Receipt: Receipt,
    >,
    ChainSpec: EthChainSpec + EthereumHardforks + EthExecutorSpec,
{
    type Block = Block<F::Transaction>;

    fn assemble_block(
        &self,
        input: BlockAssemblerInput<'_, '_, F>,
    ) -> Result<Self::Block, BlockExecutionError> {
        let BlockAssemblerInput {
            evm_env,
            execution_ctx: ctx,
            parent,
            transactions,
            output: BlockExecutionResult { receipts, requests, gas_used },
            state_root,
            ..
        } = input;

        let timestamp = evm_env.block_env.timestamp.saturating_to();

        let transactions_root = proofs::calculate_transaction_root(&transactions);
        let receipts_root = calculate_receipt_root(
            &receipts.iter().map(|r| r.with_bloom_ref()).collect::<Vec<_>>(),
        );
        let logs_bloom = logs_bloom(receipts.iter().flat_map(|r| r.logs()));

        // 0G: seal the CL-forwarded bridge SSZ blob (if any) into the built block's body so
        // the proposer's own stored block carries the same bytes every verifier will persist
        // from the newPayload sidecar — and so any later replay of this block re-executes the
        // park system call and re-emits the 0xf0 requests entry byte-identically. Fork-gated
        // as belt-and-braces: pre-Bridge attributes can never carry a blob (FCU V4 is itself
        // fork-gated), so pre-Bridge bodies stay `None` and their encoding is unchanged.
        // `None` post-Bridge is still allowed here because locally-built pending blocks (RPC
        // `pending` simulation) have no CL attributes; such blocks are never gossiped or
        // validated network-side.
        let bridge_requests = self
            .chain_spec
            .is_bridge_active_at_timestamp(timestamp)
            .then(|| ctx.bridge_request_raw.as_deref().cloned())
            .flatten();

        let withdrawals = self
            .chain_spec
            .is_shanghai_active_at_timestamp(timestamp)
            .then(|| ctx.withdrawals.map(|w| w.into_owned()).unwrap_or_default());

        let withdrawals_root =
            withdrawals.as_deref().map(|w| proofs::calculate_withdrawals_root(w));
        let requests_hash = self
            .chain_spec
            .is_prague_active_at_timestamp(timestamp)
            .then(|| requests.requests_hash());

        let mut excess_blob_gas = None;
        let mut blob_gas_used = None;

        // only determine cancun fields when active
        if self.chain_spec.is_cancun_active_at_timestamp(timestamp) {
            blob_gas_used =
                Some(transactions.iter().map(|tx| tx.blob_gas_used().unwrap_or_default()).sum());
            excess_blob_gas = if self.chain_spec.is_cancun_active_at_timestamp(parent.timestamp) {
                parent.maybe_next_block_excess_blob_gas(
                    self.chain_spec.blob_params_at_timestamp(timestamp),
                )
            } else {
                // for the first post-fork block, both parent.blob_gas_used and
                // parent.excess_blob_gas are evaluated as 0
                Some(
                    alloy_eips::eip7840::BlobParams::cancun()
                        .next_block_excess_blob_gas_osaka(0, 0, 0),
                )
            };
        }

        let header = Header {
            parent_hash: ctx.parent_hash,
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: evm_env.block_env.beneficiary,
            state_root,
            transactions_root,
            receipts_root,
            withdrawals_root,
            logs_bloom,
            timestamp,
            mix_hash: evm_env.block_env.prevrandao.unwrap_or_default(),
            nonce: BEACON_NONCE.into(),
            base_fee_per_gas: Some(evm_env.block_env.basefee),
            number: evm_env.block_env.number.saturating_to(),
            gas_limit: evm_env.block_env.gas_limit,
            difficulty: evm_env.block_env.difficulty,
            gas_used: *gas_used,
            extra_data: self.extra_data.clone(),
            parent_beacon_block_root: ctx.parent_beacon_block_root,
            blob_gas_used,
            excess_blob_gas,
            requests_hash,
        };

        Ok(Block {
            header,
            body: BlockBody {
                transactions,
                ommers: Default::default(),
                withdrawals,
                slashed: None,
                bridge_requests,
            },
        })
    }
}
