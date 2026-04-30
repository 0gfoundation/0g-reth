//! Validates execution payload wrt Ethereum Execution Engine API version.

use alloy_evm::eth::spec::EthExecutorSpec;
use alloy_rpc_types_engine::ExecutionData;
pub use alloy_rpc_types_engine::{
    ExecutionPayloadEnvelopeV2, ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4,
    ExecutionPayloadV1,
};
pub use reth_ethereum_engine_primitives::EthPayloadAttributes;
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_engine_primitives::{EngineApiValidator, PayloadValidator};
use reth_ethereum_payload_builder::EthereumExecutionPayloadValidator;
use reth_ethereum_primitives::Block;
use reth_node_api::PayloadTypes;
use reth_payload_primitives::{
    validate_execution_requests, validate_version_specific_fields, EngineApiMessageVersion,
    EngineObjectValidationError, NewPayloadError, PayloadOrAttributes,
};
use reth_primitives_traits::RecoveredBlock;
use std::sync::Arc;

/// Errors returned when validating the post-Bridge `bridgeRequests` extension on
/// `engine_forkchoiceUpdated{V3,V4}` payload attributes.
#[derive(Debug, thiserror::Error)]
pub enum BridgeAttributesError {
    /// V1/V2/V3 attributes carried `bridgeRequests` — field is only valid on V4.
    #[error("bridgeRequests is only valid on engine_forkchoiceUpdatedV4")]
    FieldOnlyValidOnV4,
    /// V4 attributes were missing `bridgeRequests` (post-Bridge fork it's required, even when
    /// the SSZ list is empty: CL emits a 4-byte empty-list sentinel).
    #[error("bridgeRequests is required on engine_forkchoiceUpdatedV4 post-Bridge fork")]
    MissingBridgeRequests,
}

/// Validator for the ethereum engine API.
#[derive(Debug, Clone)]
pub struct EthereumEngineValidator<ChainSpec = reth_chainspec::ChainSpec> {
    inner: EthereumExecutionPayloadValidator<ChainSpec>,
}

impl<ChainSpec> EthereumEngineValidator<ChainSpec> {
    /// Instantiates a new validator.
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { inner: EthereumExecutionPayloadValidator::new(chain_spec) }
    }

    /// Returns the chain spec used by the validator.
    #[inline]
    fn chain_spec(&self) -> &ChainSpec {
        self.inner.chain_spec()
    }
}

impl<ChainSpec, Types> PayloadValidator<Types> for EthereumEngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
    Types: PayloadTypes<ExecutionData = ExecutionData>,
{
    type Block = Block;

    fn ensure_well_formed_payload(
        &self,
        payload: ExecutionData,
    ) -> Result<RecoveredBlock<Self::Block>, NewPayloadError> {
        let sealed_block = self.inner.ensure_well_formed_payload(payload)?;
        sealed_block.try_recover().map_err(|e| NewPayloadError::Other(e.into()))
    }
}

impl<ChainSpec, Types> EngineApiValidator<Types> for EthereumEngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + EthExecutorSpec + 'static,
    Types: PayloadTypes<PayloadAttributes = EthPayloadAttributes, ExecutionData = ExecutionData>,
{
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, Types::ExecutionData, EthPayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        payload_or_attrs
            .execution_requests()
            .map(|requests| validate_execution_requests(requests))
            .transpose()?;

        validate_version_specific_fields(self.chain_spec(), version, payload_or_attrs)
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &EthPayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        // 0G Bridge fork: gate `bridgeRequests` and method-version against the chain spec.
        //
        //   * V3 + Bridge active at this timestamp → reject (CL must use V4 post-fork)
        //   * V4 + Bridge inactive                → reject (V4 only valid post-fork)
        //   * V4 + Bridge active                  → require non-nil `bridgeRequests`
        //   * V1/V2/V3 with `bridgeRequests` set  → reject (field is V4-only)
        let bridge_active =
            self.chain_spec().is_bridge_active_at_timestamp(attributes.inner.timestamp);
        match version {
            EngineApiMessageVersion::V1
            | EngineApiMessageVersion::V2
            | EngineApiMessageVersion::V3 => {
                if attributes.bridge_requests.is_some() {
                    return Err(EngineObjectValidationError::invalid_params(
                        BridgeAttributesError::FieldOnlyValidOnV4,
                    ));
                }
                if version == EngineApiMessageVersion::V3 && bridge_active {
                    return Err(EngineObjectValidationError::UnsupportedFork);
                }
            }
            EngineApiMessageVersion::V4 => {
                if !bridge_active {
                    return Err(EngineObjectValidationError::UnsupportedFork);
                }
                if attributes.bridge_requests.is_none() {
                    return Err(EngineObjectValidationError::invalid_params(
                        BridgeAttributesError::MissingBridgeRequests,
                    ));
                }
            }
            EngineApiMessageVersion::V5 => {
                // V5 is reserved for Osaka — we don't implement the bridge<>osaka interaction
                // here. If/when 0G adopts Osaka, the post-Bridge attribute must continue to
                // carry `bridgeRequests`; for now V5 is rejected for consistency with how the
                // outer trait validator would handle it.
                return Err(EngineObjectValidationError::UnsupportedFork);
            }
        }

        validate_version_specific_fields(
            self.chain_spec(),
            version,
            PayloadOrAttributes::<Types::ExecutionData, EthPayloadAttributes>::PayloadAttributes(
                attributes,
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Bytes, B256};
    use reth_chainspec::{ChainHardforks, ChainSpec, EthereumHardfork, ForkCondition, Hardfork};
    use reth_ethereum_engine_primitives::{EthEngineTypes, EthPayloadAttributes};
    use std::sync::Arc;

    /// Build a chain spec with the requested cancun, prague, and bridge activation timestamps.
    fn spec_with_bridge(bridge_activation_time: u64) -> Arc<ChainSpec> {
        // Cancun + Prague active from genesis so V3/V4 timestamp gating doesn't trigger for
        // free; bridge fork is what we toggle.
        let hardforks = ChainHardforks::new(vec![
            (EthereumHardfork::Shanghai.boxed(), ForkCondition::Timestamp(0)),
            (EthereumHardfork::Cancun.boxed(), ForkCondition::Timestamp(0)),
            (EthereumHardfork::Prague.boxed(), ForkCondition::Timestamp(0)),
        ]);
        Arc::new(ChainSpec {
            hardforks,
            bridge_activation_time,
            ..ChainSpec::default()
        })
    }

    fn well_formed_attrs(timestamp: u64, bridge: Option<Bytes>) -> EthPayloadAttributes {
        EthPayloadAttributes::new(
            alloy_rpc_types_engine::PayloadAttributes {
                timestamp,
                prev_randao: B256::ZERO,
                suggested_fee_recipient: Address::ZERO,
                withdrawals: Some(vec![]),
                parent_beacon_block_root: Some(B256::ZERO),
            },
            bridge,
        )
    }

    fn validate(
        spec: Arc<ChainSpec>,
        version: EngineApiMessageVersion,
        attrs: &EthPayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        let validator: EthereumEngineValidator<ChainSpec> = EthereumEngineValidator::new(spec);
        EngineApiValidator::<EthEngineTypes>::ensure_well_formed_attributes(
            &validator, version, attrs,
        )
    }

    #[test]
    fn v3_with_bridge_active_is_unsupported_fork() {
        // Bridge active at t=0 -> CL must use V4. V3 must reject.
        let spec = spec_with_bridge(1);
        let attrs = well_formed_attrs(100, None);
        let err = validate(spec, EngineApiMessageVersion::V3, &attrs).unwrap_err();
        assert!(matches!(err, EngineObjectValidationError::UnsupportedFork), "got {err:?}");
    }

    #[test]
    fn v3_with_bridge_inactive_is_accepted() {
        // Bridge never activates (sentinel 0). V3 stays valid.
        let spec = spec_with_bridge(0);
        let attrs = well_formed_attrs(100, None);
        validate(spec, EngineApiMessageVersion::V3, &attrs).expect("V3 accepted pre-bridge");
    }

    #[test]
    fn v4_without_bridge_active_is_unsupported_fork() {
        // V4 issued before fork activates -> reject.
        let spec = spec_with_bridge(1_000_000);
        let attrs = well_formed_attrs(100, Some(Bytes::from_static(&[0, 0, 0, 0])));
        let err = validate(spec, EngineApiMessageVersion::V4, &attrs).unwrap_err();
        assert!(matches!(err, EngineObjectValidationError::UnsupportedFork), "got {err:?}");
    }

    #[test]
    fn v4_with_bridge_active_requires_bridge_requests() {
        // V4 + active fork + missing bridgeRequests -> invalid params.
        let spec = spec_with_bridge(1);
        let attrs = well_formed_attrs(100, None);
        let err = validate(spec, EngineApiMessageVersion::V4, &attrs).unwrap_err();
        assert!(matches!(err, EngineObjectValidationError::InvalidParams(_)), "got {err:?}");
    }

    #[test]
    fn v4_with_bridge_active_and_bytes_passes() {
        let spec = spec_with_bridge(1);
        let attrs = well_formed_attrs(100, Some(Bytes::from_static(&[0, 0, 0, 0])));
        validate(spec, EngineApiMessageVersion::V4, &attrs).expect("V4 happy path");
    }

    #[test]
    fn v3_with_bridge_requests_field_set_is_invalid_params() {
        // Pre-Bridge node accidentally sending bridgeRequests on V3 must be rejected so a
        // misconfigured CL can't sneak the field through the older method version.
        let spec = spec_with_bridge(0);
        let attrs = well_formed_attrs(100, Some(Bytes::from_static(&[0, 0, 0, 0])));
        let err = validate(spec, EngineApiMessageVersion::V3, &attrs).unwrap_err();
        assert!(matches!(err, EngineObjectValidationError::InvalidParams(_)), "got {err:?}");
    }
}
