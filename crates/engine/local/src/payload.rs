//! The implementation of the [`PayloadAttributesBuilder`] for the
//! [`LocalMiner`](super::LocalMiner).

use alloy_primitives::{Address, B256};
use reth_chainspec::EthereumHardforks;
use reth_ethereum_engine_primitives::EthPayloadAttributes;
use reth_payload_primitives::PayloadAttributesBuilder;
use std::sync::Arc;

/// The attributes builder for local Ethereum payload.
#[derive(Debug)]
#[non_exhaustive]
pub struct LocalPayloadAttributesBuilder<ChainSpec> {
    /// The chainspec
    pub chain_spec: Arc<ChainSpec>,
}

impl<ChainSpec> LocalPayloadAttributesBuilder<ChainSpec> {
    /// Creates a new instance of the builder.
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { chain_spec }
    }
}

impl<ChainSpec> PayloadAttributesBuilder<EthPayloadAttributes>
    for LocalPayloadAttributesBuilder<ChainSpec>
where
    ChainSpec: Send + Sync + EthereumHardforks + 'static,
{
    fn build(&self, timestamp: u64) -> EthPayloadAttributes {
        EthPayloadAttributes::new(
            alloy_rpc_types_engine::PayloadAttributes {
                timestamp,
                prev_randao: B256::random(),
                suggested_fee_recipient: Address::random(),
                withdrawals: self
                    .chain_spec
                    .is_shanghai_active_at_timestamp(timestamp)
                    .then(Default::default),
                parent_beacon_block_root: self
                    .chain_spec
                    .is_cancun_active_at_timestamp(timestamp)
                    .then(B256::random),
            },
            // Local mining (dev-only) does not poll a foreign EL for bridge messages.
            // Post-Bridge-fork the EL validator will refuse the resulting V4 attrs because
            // `bridge_requests` is `None`; production 0G nodes drive payload building from
            // CometBFT (`engine_forkchoiceUpdatedV4` from CL), not from `LocalMiner`.
            None,
        )
    }
}

#[cfg(feature = "op")]
impl<ChainSpec> PayloadAttributesBuilder<op_alloy_rpc_types_engine::OpPayloadAttributes>
    for LocalPayloadAttributesBuilder<ChainSpec>
where
    ChainSpec: Send + Sync + EthereumHardforks + 'static,
{
    fn build(&self, timestamp: u64) -> op_alloy_rpc_types_engine::OpPayloadAttributes {
        let eth: EthPayloadAttributes = self.build(timestamp);
        op_alloy_rpc_types_engine::OpPayloadAttributes {
            payload_attributes: eth.inner,
            // Add dummy system transaction
            transactions: Some(vec![
                reth_optimism_chainspec::constants::TX_SET_L1_BLOCK_OP_MAINNET_BLOCK_124665056
                    .into(),
            ]),
            no_tx_pool: None,
            gas_limit: None,
            eip_1559_params: None,
            min_base_fee: None,
        }
    }
}
