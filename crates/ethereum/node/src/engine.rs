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
    /// V4 `bridgeRequests` blob failed SSZ decode or violated a post-decode invariant
    /// (per-block message cap, mode byte). The inner [`reth_0g_bridge::BridgeDecodeError`]
    /// carries the specific reason.
    #[error("bridgeRequests failed validation: {0}")]
    InvalidBridgeRequests(#[from] reth_0g_bridge::BridgeDecodeError),
}

/// Errors returned when validating the post-Bridge `0xf0` request entry on
/// `engine_newPayloadV4` execution payloads.
///
/// These surface ahead of execution so a malformed or absent bridge entry results in a
/// specific, actionable error rather than a generic `PayloadBlockHashMismatch` further down
/// the pipeline. Without these the failure mode is "silently skip the bridge system call but
/// still seal a `requests_hash` covering the malformed entry" → bridge state diverges from
/// network without any visible reject. Empirically this guards against CL↔EL schema drift: the
/// `0xf0` entry must be appended into the requests list *before* the sealed header's
/// `requests_hash` is computed, otherwise the CL's re-assembled block hash disagrees with the
/// payload's `block_hash` and the block is rejected — a failure these checks surface up front
/// instead of as a downstream `PayloadBlockHashMismatch`.
#[derive(Debug, thiserror::Error)]
pub enum BridgePayloadError {
    /// `bridge_active_at_timestamp(payload.timestamp)` returned true but the payload's
    /// `executionRequests` carries no `0xf0` entry. The CL must always emit a `0xf0` entry
    /// post-Bridge — even for an empty bridge-messages list the SSZ empty-list sentinel is a
    /// 4-byte payload, so absence indicates a CL bug or version mismatch.
    #[error(
        "post-Bridge `engine_newPayloadV4` payload is missing the required 0xf0 entry in \
         executionRequests"
    )]
    MissingBridgeEntry,
    /// `0xf0` entry was present but its SSZ body failed to decode. Indicates CL emission bug,
    /// cross-language schema drift (Rust ↔ Go layout disagreement), or wire corruption.
    /// Surfacing the inner `BridgeDecodeError` (which carries the SSZ-decode reason — wrong
    /// length, malformed offset, invalid mode byte, etc.) lets operators triage the root cause
    /// in seconds instead of correlating with `tracing::warn!` logs after the fact.
    #[error("post-Bridge `engine_newPayloadV4` payload 0xf0 entry SSZ decode failed: {0}")]
    BridgeDecodeFailure(#[from] reth_0g_bridge::BridgeDecodeError),
    /// `bridge_active_at_timestamp(payload.timestamp)` returned false but the payload's
    /// `executionRequests` carries a `0xf0` entry. Pre-Bridge the CL never emits a `0xf0`
    /// entry, so its presence indicates a buggy/byzantine CL or a fork-time misconfiguration
    /// — accepting it would commit a `requests_hash` covering a request type this node treats
    /// as undefined, without ever executing the bridge system call.
    #[error(
        "pre-Bridge `engine_newPayload` payload carries an unexpected 0xf0 entry in \
         executionRequests"
    )]
    UnexpectedBridgeEntry,
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
    ChainSpec: EthChainSpec + EthereumHardforks + EthExecutorSpec + 'static,
    Types: PayloadTypes<ExecutionData = ExecutionData>,
{
    type Block = Block;

    fn ensure_well_formed_payload(
        &self,
        payload: ExecutionData,
    ) -> Result<RecoveredBlock<Self::Block>, NewPayloadError> {
        // 0G Bridge fork: when Bridge is active at `payload.timestamp`, the executionRequests
        // list MUST contain exactly one `0xf0` entry AND its SSZ body MUST decode successfully.
        //
        // Without this check two byzantine/buggy CL behaviours silently freeze bridge state on
        // the local node (`requests_hash` stays self-consistent so the block accepts, but the
        // bridge system call never executes):
        //   1. CL omits the `0xf0` entry entirely → `context_for_payload` finds no entry, sets
        //      `bridge_request_raw = None`, `EthBlockExecutor::finish` skips the push, sealed
        //      `requests_hash` matches the (entry-less) wire bytes by accident.
        //   2. CL emits a `0xf0` entry whose SSZ body is malformed → `context_for_payload`'s
        //      `decode_bridge_messages` returns `Err`, `bridge_request = None` (no system call)
        //      but `bridge_request_raw = Some(raw)` so the malformed bytes still get pushed
        //      into requests verbatim; `requests_hash` matches the wire bytes again.
        //
        // Both routes accept the block but stop processing bridge messages. The fix surfaces
        // each as a specific [`BridgePayloadError`] before execution, aligning the failure
        // mode with how the standard EIP-7685 request types (0x00/0x01/0x02) fail loudly when
        // their EL derivation fails — but here the source of truth is the CL bytes, so the
        // check happens at payload validation.
        let timestamp = payload.payload.timestamp();
        if self.chain_spec().is_bridge_active_at_timestamp(timestamp) {
            let bridge_entry = payload
                .sidecar
                .requests()
                .and_then(|reqs| {
                    reqs.iter().find(|r| r.first() == Some(&reth_0g_bridge::BRIDGE_REQUEST_TYPE))
                })
                .map(|entry| entry.as_ref());

            match bridge_entry {
                Some(entry) => {
                    reth_0g_bridge::decode_bridge_messages(&entry[1..]).map_err(|e| {
                        NewPayloadError::Other(BridgePayloadError::from(e).into())
                    })?;
                }
                None => {
                    return Err(NewPayloadError::Other(
                        BridgePayloadError::MissingBridgeEntry.into(),
                    ));
                }
            }
        } else if payload.sidecar.requests().is_some_and(|reqs| {
            reqs.iter().any(|r| r.first() == Some(&reth_0g_bridge::BRIDGE_REQUEST_TYPE))
        }) {
            // Mirror image of the post-fork checks: pre-Bridge the CL never emits a `0xf0`
            // entry, so one showing up here must be rejected rather than sealed into
            // `requests_hash` as an opaque blob. Pre-Prague payloads (V3 and earlier) have no
            // executionRequests sidecar at all — `requests()` returns `None` and this check is
            // a no-op for them.
            return Err(NewPayloadError::Other(BridgePayloadError::UnexpectedBridgeEntry.into()));
        }

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
        // SCOPE: this gate runs only on FCUs that carry payload attributes (build
        // requests) — a `forkchoiceUpdated{V3,V4}` with `payloadAttributes = null`
        // (a plain head/finality update) never reaches here, so it is NOT
        // method-version-gated against the fork. That is deliberate and benign: a
        // no-attrs FCU builds no payload, decodes no `bridgeRequests`, and runs no
        // bridge system call, so its method version has no consensus/state effect,
        // and leaving head-update FCUs version-lenient matches upstream reth's
        // handling of every fork. The build path below — the only path that touches
        // bridge state — is fully gated.
        //
        //   * V3 + Bridge active at this timestamp → reject (CL must use V4 post-fork)
        //   * V4 + Bridge inactive                → reject (V4 only valid post-fork)
        //   * V4 + Bridge active                  → require non-nil `bridgeRequests` that decodes
        //     (SSZ + cap + mode-byte checks)
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
                match &attributes.bridge_requests {
                    None => {
                        return Err(EngineObjectValidationError::invalid_params(
                            BridgeAttributesError::MissingBridgeRequests,
                        ));
                    }
                    Some(blob) => {
                        // Decode + cap-validate the SSZ blob at FCU time. The payload builder
                        // decodes the same blob later but degrades decode failures to "skip the
                        // bridge system call" so block production can still make progress —
                        // rejecting here instead surfaces a malformed or over-cap blob to the
                        // CL as an immediate InvalidParams response rather than a silently
                        // bridge-less block.
                        reth_0g_bridge::decode_bridge_messages(blob).map_err(|e| {
                            EngineObjectValidationError::invalid_params(
                                BridgeAttributesError::InvalidBridgeRequests(e),
                            )
                        })?;
                    }
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
        // Empty-list SSZ sentinel (4-byte LE offset = 4) — what the CL emits for a block with
        // no bridge messages. Must decode cleanly and pass.
        let attrs = well_formed_attrs(100, Some(Bytes::from_static(&[0x04, 0x00, 0x00, 0x00])));
        validate(spec, EngineApiMessageVersion::V4, &attrs).expect("V4 happy path");
    }

    /// V4 + active fork + `bridgeRequests` blob that fails SSZ decode (truncated offset
    /// prefix) → InvalidParams at FCU time, instead of the payload builder later degrading
    /// the decode failure into a silently bridge-less block.
    #[test]
    fn v4_with_malformed_bridge_requests_is_invalid_params() {
        let spec = spec_with_bridge(1);
        let attrs = well_formed_attrs(100, Some(Bytes::from_static(&[0xff, 0xff])));
        let err = validate(spec, EngineApiMessageVersion::V4, &attrs).unwrap_err();
        assert!(matches!(err, EngineObjectValidationError::InvalidParams(_)), "got {err:?}");
    }

    /// V4 + active fork + structurally valid SSZ blob carrying one message more than the
    /// per-block cap → InvalidParams (the cap is a consensus parameter; an over-cap blob is a
    /// CL bug and must reject, not build).
    #[test]
    fn v4_with_over_cap_bridge_requests_is_invalid_params() {
        let spec = spec_with_bridge(1);

        // Hand-built BridgeRequests SSZ container: 4-byte LE offset prefix (= 4) followed by
        // N fixed-size 105-byte BridgeMessage bodies (layout locked by the byte-level fixture
        // test in the 0g-bridge crate).
        let n = reth_0g_bridge::MAX_BRIDGE_MESSAGES_PER_BLOCK + 1;
        let mut blob: Vec<u8> = vec![0x04, 0x00, 0x00, 0x00];
        for nonce in 0..n as u64 {
            blob.extend_from_slice(&16700u64.to_le_bytes()); // src_chain_id
            blob.extend_from_slice(&16702u64.to_le_bytes()); // dst_chain_id
            blob.extend_from_slice(&nonce.to_le_bytes()); // nonce
            blob.extend_from_slice(&[0x01; 20]); // local_token
            blob.extend_from_slice(&[0x02; 20]); // recipient
            blob.extend_from_slice(&[0; 32]); // amount (BE-zero)
            blob.push(0x00); // mode = LockRelease
            blob.extend_from_slice(&0u64.to_le_bytes()); // src_block
        }
        assert_eq!(blob.len(), 4 + n * 105, "fixture builder mismatch");

        let attrs = well_formed_attrs(100, Some(Bytes::from(blob)));
        let err = validate(spec, EngineApiMessageVersion::V4, &attrs).unwrap_err();
        assert!(matches!(err, EngineObjectValidationError::InvalidParams(_)), "got {err:?}");
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

    /// V3 + bridge fork active + `bridge_requests = Some(...)` is a malformed combination — the
    /// CL is both using the wrong method version (should be V4) AND attaching a V4-only field.
    /// Two errors apply here; the validator returns the `FieldOnlyValidOnV4` `InvalidParams`
    /// first (it's checked before the V3+active `UnsupportedFork` branch). Either error is a
    /// reject and the CL would correct course on retry, but lock the actual returned variant
    /// here so future reorderings of the validator branches are explicit.
    #[test]
    fn v3_with_bridge_active_and_bridge_requests_returns_invalid_params() {
        let spec = spec_with_bridge(1); // bridge active at t=1
        let attrs = well_formed_attrs(100, Some(Bytes::from_static(&[0, 0, 0, 0])));
        let err = validate(spec, EngineApiMessageVersion::V3, &attrs).unwrap_err();
        assert!(
            matches!(err, EngineObjectValidationError::InvalidParams(_)),
            "V3 + bridge_active + bridge_requests=Some should reject as InvalidParams \
             (FieldOnlyValidOnV4 takes precedence over UnsupportedFork in the current branch \
              order); got {err:?}"
        );
    }

    // -------- ensure_well_formed_payload — Bridge 0xf0 entry validation --------
    //
    // Cases under test (matching `BridgePayloadError` variants):
    //   * bridge_active + no 0xf0 entry        → `MissingBridgeEntry`           (Q1)
    //   * bridge_active + malformed 0xf0 SSZ   → `BridgeDecodeFailure(...)`     (Q2)
    //   * bridge_inactive + no 0xf0 entry      → check skipped (current behaviour preserved)
    //   * bridge_inactive + 0xf0 entry present → `UnexpectedBridgeEntry`
    //
    // These tests construct only the failure paths (the check returns `Err` before
    // `self.inner.ensure_well_formed_payload` runs, so a minimal synthetic payload suffices —
    // no need to build a fully-valid sealed block). The happy-path success cases are exercised
    // end-to-end by integration tests (3-chain devnet 11-scenario suite) which prove that
    // legitimate empty- and non-empty-bridge payloads pass this gate.

    use alloy_rpc_types_engine::{
        CancunPayloadFields, ExecutionPayloadSidecar, ExecutionPayloadV3, PraguePayloadFields,
    };
    use reth_engine_primitives::PayloadValidator;
    use reth_ethereum_primitives::{Block, BlockBody};

    fn make_payload(timestamp: u64, requests: Vec<Bytes>) -> ExecutionData {
        let header = alloy_consensus::Header {
            beneficiary: Address::ZERO,
            timestamp,
            number: 1,
            excess_blob_gas: Some(0),
            blob_gas_used: Some(0),
            parent_beacon_block_root: Some(B256::ZERO),
            withdrawals_root: Some(B256::ZERO),
            ..Default::default()
        };
        let block = Block {
            header,
            body: BlockBody { withdrawals: Some(Default::default()), ..Default::default() },
        };
        let block_hash = block.header.hash_slow();
        let payload = ExecutionPayloadV3::from_block_unchecked(block_hash, &block);

        let mut req_list = alloy_eips::eip7685::Requests::default();
        for r in requests {
            req_list.push_request(r);
        }
        let sidecar = ExecutionPayloadSidecar::v4(
            CancunPayloadFields { versioned_hashes: vec![], parent_beacon_block_root: B256::ZERO },
            PraguePayloadFields { requests: req_list.into() },
        );
        ExecutionData { payload: payload.into(), sidecar }
    }

    fn validate_payload(
        spec: Arc<ChainSpec>,
        payload: ExecutionData,
    ) -> Result<(), NewPayloadError> {
        let validator: EthereumEngineValidator<ChainSpec> = EthereumEngineValidator::new(spec);
        <EthereumEngineValidator<ChainSpec> as PayloadValidator<EthEngineTypes>>::
            ensure_well_formed_payload(&validator, payload)
            .map(|_| ())
    }

    /// Q1: bridge-active payload without a 0xf0 entry must be rejected with the dedicated
    /// `MissingBridgeEntry` error — *not* a generic block-hash-mismatch much later in the
    /// pipeline. A CL bug that drops the 0xf0 emission would otherwise silently freeze bridge
    /// state on the local node.
    #[test]
    fn bridge_active_payload_missing_0xf0_entry_returns_missing_entry_error() {
        let spec = spec_with_bridge(1); // bridge active at t=1
        // executionRequests carries the standard EIP-7685 entries but no 0xf0.
        let payload = make_payload(
            100,
            vec![
                Bytes::from_static(&[0x00, 0xDE, 0xAD, 0xBE, 0xEF]), // deposit (fake body)
                Bytes::from_static(&[0x01, 0xAB]),                   // withdrawal (fake body)
            ],
        );
        let err = validate_payload(spec, payload).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("missing the required 0xf0 entry"),
            "expected MissingBridgeEntry error, got: {msg}",
        );
    }

    /// Q2: bridge-active payload with a 0xf0 entry whose SSZ body fails to decode must be
    /// rejected with the dedicated `BridgeDecodeFailure` error carrying the inner SSZ error
    /// (length / offset / mode byte / etc.). Operators see the actual root cause in the engine
    /// API response instead of having to correlate with `tracing::warn!` logs.
    #[test]
    fn bridge_active_payload_malformed_0xf0_returns_decode_error() {
        let spec = spec_with_bridge(1);
        // 0xf0 type byte + SSZ body that's too short to be a valid BridgeRequests container
        // (the container needs at least the 4-byte offset prefix for the empty-list sentinel).
        let payload = make_payload(
            100,
            vec![Bytes::from_static(&[0xf0, 0xff, 0xff])], // truncated offset prefix
        );
        let err = validate_payload(spec, payload).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("0xf0 entry SSZ decode failed"),
            "expected BridgeDecodeFailure error, got: {msg}",
        );
    }

    /// 0xf0 with a Container shape that *would* decode but carries an out-of-range `mode` byte
    /// (only 0/1 are valid) must still fail decode validation. Ensures the check covers the
    /// full `decode_bridge_messages` invariants — including the post-SSZ-decode mode-byte
    /// sanity pass — not just structural SSZ shape.
    ///
    /// SSZ bytes hand-crafted to avoid adding `ethereum_ssz` as a dep of `reth-node-ethereum`:
    /// the layout (109 bytes = 4-byte offset prefix + 105-byte `BridgeMessage` body) is locked
    /// by the byte-level fixture test in `0g-bridge/src/decode.rs`. Byte 100 of the body
    /// (= overall offset 4 + 96 = 100) is the `mode` field.
    #[test]
    fn bridge_active_payload_invalid_mode_byte_in_0xf0_returns_decode_error() {
        let spec = spec_with_bridge(1);
        let mut entry: Vec<u8> = vec![0xf0]; // EIP-7685 type byte
        entry.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]); // SSZ list offset prefix
        entry.extend_from_slice(&16700u64.to_le_bytes()); // src_chain_id
        entry.extend_from_slice(&16702u64.to_le_bytes()); // dst_chain_id
        entry.extend_from_slice(&1u64.to_le_bytes()); // nonce
        entry.extend_from_slice(&[0x01; 20]); // local_token
        entry.extend_from_slice(&[0x02; 20]); // recipient
        entry.extend_from_slice(&[0; 32]); // amount (BE-zero)
        entry.push(0xFF); // mode = invalid
        entry.extend_from_slice(&0u64.to_le_bytes()); // src_block
        assert_eq!(entry.len(), 1 + 4 + 105, "fixture builder mismatch");

        let payload = make_payload(100, vec![Bytes::from(entry)]);
        let err = validate_payload(spec, payload).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("0xf0 entry SSZ decode failed"),
            "expected BridgeDecodeFailure error from invalid mode byte, got: {msg}",
        );
    }

    /// Pre-Bridge (bridge_activation_time = 0, fork inactive): the gate is bypassed so payloads
    /// without 0xf0 must NOT trip the new check. Locks the invariant that this validation only
    /// applies to bridge-active payloads. Inner validator may still reject for unrelated
    /// reasons — we only care that the error (if any) is NOT a `BridgePayloadError`.
    #[test]
    fn bridge_inactive_payload_skips_0xf0_check() {
        let spec = spec_with_bridge(0); // bridge inactive forever
        let payload = make_payload(100, vec![]); // no requests at all
        let result = validate_payload(spec, payload);
        if let Err(err) = result {
            let msg = format!("{err}");
            assert!(
                !msg.contains("0xf0 entry") && !msg.contains("MissingBridgeEntry"),
                "pre-Bridge payload must not hit the bridge entry check; got: {msg}",
            );
        }
    }

    /// Pre-Bridge payload that DOES carry a 0xf0 entry must be hard-rejected with
    /// `UnexpectedBridgeEntry` — pre-fork the CL never emits one, so its presence is a
    /// buggy/byzantine CL or a fork-time misconfiguration. Without the reject, the entry would
    /// be sealed into `requests_hash` as an opaque blob with no bridge system call executed.
    #[test]
    fn bridge_inactive_payload_with_0xf0_entry_is_rejected() {
        let spec = spec_with_bridge(0); // bridge inactive forever
        // Forged 0xf0 entry with a perfectly valid empty-list SSZ body — validity of the body
        // is irrelevant pre-fork, presence alone must reject.
        let payload = make_payload(
            100,
            vec![Bytes::from_static(&[0xf0, 0x04, 0x00, 0x00, 0x00])],
        );
        let err = validate_payload(spec, payload).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unexpected 0xf0 entry"),
            "expected UnexpectedBridgeEntry error, got: {msg}",
        );
    }

    /// Same as above but with the fork configured in the future (rather than disabled via the
    /// `0` sentinel): a 0xf0 entry showing up before the activation timestamp must reject.
    #[test]
    fn bridge_pre_activation_payload_with_0xf0_entry_is_rejected() {
        let spec = spec_with_bridge(1_000_000); // bridge activates later
        let payload = make_payload(
            100, // timestamp < activation
            vec![Bytes::from_static(&[0xf0, 0x04, 0x00, 0x00, 0x00])],
        );
        let err = validate_payload(spec, payload).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unexpected 0xf0 entry"),
            "expected UnexpectedBridgeEntry error, got: {msg}",
        );
    }
}
