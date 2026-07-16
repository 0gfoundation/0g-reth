//! Contains types required for building a payload.

use alloc::{sync::Arc, vec::Vec};
use alloy_eips::{
    eip4844::BlobTransactionSidecar,
    eip4895::Withdrawal,
    eip7594::{BlobTransactionSidecarEip7594, BlobTransactionSidecarVariant},
    eip7685::Requests,
};
use alloy_primitives::{Bytes, B256, U256};
use alloy_rpc_types_engine::{
    BlobsBundleV1, BlobsBundleV2, CancunPayloadFields, ExecutionData, ExecutionPayload,
    ExecutionPayloadEnvelopeV2, ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4,
    ExecutionPayloadEnvelopeV5, ExecutionPayloadEnvelopeV6, ExecutionPayloadFieldV2,
    ExecutionPayloadSidecar, ExecutionPayloadV1, ExecutionPayloadV3, ExecutionPayloadV4,
    PayloadAttributes as InnerPayloadAttributes, PayloadId, PraguePayloadFields,
};
use reth_ethereum_primitives::EthPrimitives;
use reth_payload_primitives::{payload_id as upstream_payload_id, BuiltPayload, PayloadAttributes};
use reth_primitives_traits::{NodePrimitives, RecoveredBlock, SealedBlock};

use crate::BuiltPayloadConversionError;

/// Ethereum payload attributes accepted on `engine_forkchoiceUpdated{V1..V4}`.
///
/// Wraps the standard [`alloy_rpc_types_engine::PayloadAttributes`] with an optional 0G
/// `bridgeRequests` SSZ blob. Pre-Bridge-fork the field MUST be `None` and CL MUST use V3 or
/// earlier; post-Bridge-fork the field MUST be `Some(bytes)` (where `bytes` is the
/// SSZ-encoded `BridgeRequests` struct — possibly an empty list, but **never** `None`) and
/// CL MUST use V4. The blob is forwarded verbatim into the next block's
/// `executionRequests` `0xf0` entry; the `0xf0` type byte sits in the private 0G namespace
/// (`0xf0..=0xfe`) to avoid colliding with future Ethereum upstream request types.
//
// reth-v2.8.1 migration: 880ce24ad replaced this crate's re-export of alloy's
// `PayloadAttributes` (as `EthPayloadAttributes`) with this wrapper. Upstream (#23202) since
// dropped `EthPayloadBuilderAttributes`, the 0G type that also carried `bridge_requests`, and
// moved `payload_id` to `reth_payload_primitives`; the payload builder now receives these
// attributes directly, so the wrapper alone carries the blob.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthPayloadAttributes {
    /// Standard Ethereum engine payload attributes (`timestamp`, `prevRandao`,
    /// `suggestedFeeRecipient`, `withdrawals`, `parentBeaconBlockRoot`). `flatten`d so the
    /// JSON shape on the wire matches `engine_forkchoiceUpdatedV3` byte-for-byte when no
    /// bridge field is present.
    #[serde(flatten)]
    pub inner: InnerPayloadAttributes,
    /// 0G: SSZ-encoded `BridgeRequests` blob (CL → EL).
    ///
    /// Required (non-null) on `engine_forkchoiceUpdatedV4`; absent (skipped on serialize and
    /// defaulted to `None` on deserialize) on V1/V2/V3. The EL passes the bytes through to
    /// the resulting block's executionRequests `0xf0` entry without recomputing them so the
    /// proposer's and the verifier's `requestsHash` are byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_requests: Option<Bytes>,
}

impl EthPayloadAttributes {
    /// Build a [`EthPayloadAttributes`] from the standard Ethereum payload attributes plus
    /// an optional 0G bridge SSZ blob.
    pub const fn new(inner: InnerPayloadAttributes, bridge_requests: Option<Bytes>) -> Self {
        Self { inner, bridge_requests }
    }
}

impl From<InnerPayloadAttributes> for EthPayloadAttributes {
    fn from(inner: InnerPayloadAttributes) -> Self {
        Self::new(inner, None)
    }
}

impl core::ops::Deref for EthPayloadAttributes {
    type Target = InnerPayloadAttributes;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl core::ops::DerefMut for EthPayloadAttributes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

// reth-v2.8.1 migration: 880ce24ad implemented `timestamp`, `withdrawals` and
// `parent_beacon_block_root`, the trait's methods then. Upstream's trait now also requires
// `payload_id` (moved here from the builder attributes) and `slot_number`, and has
// `target_gas_limit`; they read the inner attributes like upstream's impl for alloy's type.
impl PayloadAttributes for EthPayloadAttributes {
    fn payload_id(&self, parent_hash: &B256) -> PayloadId {
        payload_id(parent_hash, self)
    }

    fn timestamp(&self) -> u64 {
        self.inner.timestamp
    }

    fn withdrawals(&self) -> Option<&Vec<Withdrawal>> {
        self.inner.withdrawals.as_ref()
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.inner.parent_beacon_block_root
    }

    fn slot_number(&self) -> Option<u64> {
        self.inner.slot_number
    }

    fn target_gas_limit(&self) -> Option<u64> {
        self.inner.target_gas_limit
    }
}

/// Generates the payload id for the configured payload from the [`EthPayloadAttributes`].
///
/// Returns an 8-byte identifier by hashing the payload components with sha256 hash. Post-Bridge
/// the SSZ blob attached on `engine_forkchoiceUpdatedV4.payloadAttributes.bridgeRequests` is
/// folded into the hash so two FCUs that differ only in bridge content yield distinct payload
/// ids.
//
// reth-v2.8.1 migration: 880ce24ad appended `bridge_requests` to the sha256 input of the
// `payload_id` that lived in this file. Upstream (#23202) moved that function to
// `reth_payload_primitives::payload_id` (which now also hashes `slot_number` and
// `target_gas_limit`), so the upstream id is taken as is and, only when bridge bytes are present,
// hashed again together with them (same as the reth v2.4.1 migration). Without bridge bytes the id
// is upstream's, as before; with them it still differs per blob, but is not the same 8 bytes the
// original computed. The id is opaque to the CL, which only echoes it back to `getPayload`.
pub fn payload_id(parent: &B256, attributes: &EthPayloadAttributes) -> PayloadId {
    let id = upstream_payload_id(parent, &attributes.inner);
    let Some(bridge_requests) = &attributes.bridge_requests else { return id };

    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(id.0.as_slice());
    hasher.update(bridge_requests);
    let out = hasher.finalize();

    #[allow(deprecated)] // generic-array 0.14 deprecated
    PayloadId::new(out.as_slice()[..8].try_into().expect("sufficient length"))
}

/// Contains the built payload.
///
/// According to the [engine API specification](https://github.com/ethereum/execution-apis/blob/main/src/engine/README.md) the execution layer should build the initial version of the payload with an empty transaction set and then keep update it in order to maximize the revenue.
///
/// This struct represents a single built block at a point in time. The payload building process
/// creates a sequence of these payloads, starting with an empty block and progressively including
/// more transactions.
#[derive(Debug, Clone)]
pub struct EthBuiltPayload<N: NodePrimitives = EthPrimitives> {
    /// The built block
    pub(crate) block: Arc<RecoveredBlock<N::Block>>,
    /// The fees of the block
    pub(crate) fees: U256,
    /// The blobs, proofs, and commitments in the block. If the block is pre-cancun, this will be
    /// empty.
    pub(crate) sidecars: BlobSidecars,
    /// The requests of the payload
    pub(crate) requests: Option<Requests>,
    /// The block access list of the payload
    pub(crate) block_access_list: Option<Bytes>,
}

// === impl BuiltPayload ===

impl<N: NodePrimitives> EthBuiltPayload<N> {
    /// Initializes the payload with the given initial block
    ///
    /// Caution: This does not set any [`BlobSidecars`].
    pub const fn new(
        block: Arc<RecoveredBlock<N::Block>>,
        fees: U256,
        requests: Option<Requests>,
        block_access_list: Option<Bytes>,
    ) -> Self {
        Self { block, fees, requests, sidecars: BlobSidecars::Empty, block_access_list }
    }

    /// Returns the built block(sealed)
    pub fn block(&self) -> &SealedBlock<N::Block> {
        self.block.sealed_block()
    }

    /// Returns the built block with recovered senders.
    pub fn recovered_block(&self) -> &RecoveredBlock<N::Block> {
        &self.block
    }

    /// Returns the built block with shared ownership.
    pub const fn block_arc(&self) -> &Arc<RecoveredBlock<N::Block>> {
        &self.block
    }

    /// Consumes the payload and returns the built block with shared ownership.
    pub fn into_block_arc(self) -> Arc<RecoveredBlock<N::Block>> {
        self.block
    }

    /// Fees of the block
    pub const fn fees(&self) -> U256 {
        self.fees
    }

    /// Returns the blob sidecars.
    pub const fn sidecars(&self) -> &BlobSidecars {
        &self.sidecars
    }

    /// Sets blob transactions sidecars on the payload.
    pub fn with_sidecars(mut self, sidecars: impl Into<BlobSidecars>) -> Self {
        self.sidecars = sidecars.into();
        self
    }
}

impl EthBuiltPayload {
    /// Try converting built payload into [`ExecutionPayloadEnvelopeV3`].
    ///
    /// Returns an error if the payload contains non EIP-4844 sidecar.
    pub fn try_into_v3(self) -> Result<ExecutionPayloadEnvelopeV3, BuiltPayloadConversionError> {
        let Self { block, fees, sidecars, .. } = self;

        let blobs_bundle = match sidecars {
            BlobSidecars::Empty => BlobsBundleV1::empty(),
            BlobSidecars::Eip4844(sidecars) => BlobsBundleV1::from(sidecars),
            BlobSidecars::Eip7594(_) => {
                return Err(BuiltPayloadConversionError::UnexpectedEip7594Sidecars)
            }
        };

        Ok(ExecutionPayloadEnvelopeV3 {
            execution_payload: ExecutionPayloadV3::from_block_unchecked(
                block.hash(),
                &Arc::unwrap_or_clone(block).into_block(),
            ),
            block_value: fees,
            // From the engine API spec:
            //
            // > Client software **MAY** use any heuristics to decide whether to set
            // `shouldOverrideBuilder` flag or not. If client software does not implement any
            // heuristic this flag **SHOULD** be set to `false`.
            //
            // Spec:
            // <https://github.com/ethereum/execution-apis/blob/fe8e13c288c592ec154ce25c534e26cb7ce0530d/src/engine/cancun.md#specification-2>
            should_override_builder: false,
            blobs_bundle,
        })
    }

    /// Try converting built payload into [`ExecutionPayloadEnvelopeV4`].
    ///
    /// Returns an error if the payload contains non EIP-4844 sidecar.
    pub fn try_into_v4(
        mut self,
    ) -> Result<ExecutionPayloadEnvelopeV4, BuiltPayloadConversionError> {
        let execution_requests = self.requests.take().unwrap_or_default();
        Ok(ExecutionPayloadEnvelopeV4 { execution_requests, envelope_inner: self.try_into()? })
    }

    /// Try converting built payload into [`ExecutionPayloadEnvelopeV5`].
    pub fn try_into_v5(self) -> Result<ExecutionPayloadEnvelopeV5, BuiltPayloadConversionError> {
        let Self { block, fees, sidecars, requests, .. } = self;

        let blobs_bundle = match sidecars {
            BlobSidecars::Empty => BlobsBundleV2::empty(),
            BlobSidecars::Eip7594(sidecars) => BlobsBundleV2::from(sidecars),
            BlobSidecars::Eip4844(_) => {
                return Err(BuiltPayloadConversionError::UnexpectedEip4844Sidecars)
            }
        };

        Ok(ExecutionPayloadEnvelopeV5 {
            execution_payload: ExecutionPayloadV3::from_block_unchecked(
                block.hash(),
                &Arc::unwrap_or_clone(block).into_block(),
            ),
            block_value: fees,
            // From the engine API spec:
            //
            // > Client software **MAY** use any heuristics to decide whether to set
            // `shouldOverrideBuilder` flag or not. If client software does not implement any
            // heuristic this flag **SHOULD** be set to `false`.
            //
            // Spec:
            // <https://github.com/ethereum/execution-apis/blob/fe8e13c288c592ec154ce25c534e26cb7ce0530d/src/engine/cancun.md#specification-2>
            should_override_builder: false,
            blobs_bundle,
            execution_requests: requests.unwrap_or_default(),
        })
    }

    /// Try converting built payload into [`ExecutionPayloadEnvelopeV6`].
    ///
    /// Returns an error if the block access list is missing, as it's required for V6 envelopes.
    pub fn try_into_v6(self) -> Result<ExecutionPayloadEnvelopeV6, BuiltPayloadConversionError> {
        let Self { block, fees, sidecars, requests, block_access_list, .. } = self;

        let block_access_list =
            block_access_list.ok_or(BuiltPayloadConversionError::MissingBlockAccessList)?;

        let blobs_bundle = match sidecars {
            BlobSidecars::Empty => BlobsBundleV2::empty(),
            BlobSidecars::Eip7594(sidecars) => BlobsBundleV2::from(sidecars),
            BlobSidecars::Eip4844(_) => {
                return Err(BuiltPayloadConversionError::UnexpectedEip4844Sidecars)
            }
        };
        Ok(ExecutionPayloadEnvelopeV6 {
            execution_payload: ExecutionPayloadV4::from_block_unchecked_with_bal(
                block.hash(),
                &Arc::unwrap_or_clone(block).into_block(),
                block_access_list,
            ),
            block_value: fees,
            // From the engine API spec:
            //
            // > Client software **MAY** use any heuristics to decide whether to set
            // `shouldOverrideBuilder` flag or not. If client software does not implement any
            // heuristic this flag **SHOULD** be set to `false`.
            //
            // Spec:
            // <https://github.com/ethereum/execution-apis/blob/fe8e13c288c592ec154ce25c534e26cb7ce0530d/src/engine/cancun.md#specification-2>
            should_override_builder: false,
            blobs_bundle,
            execution_requests: requests.unwrap_or_default(),
        })
    }

    /// Converts built payload into [`ExecutionData`].
    pub fn into_execution_data(self) -> ExecutionData {
        let Self { block, requests, block_access_list, .. } = self;
        let block_hash = block.hash();
        let block = Arc::unwrap_or_clone(block).into_block();

        let (payload, sidecar) = ExecutionPayload::from_block_unchecked_with_extras(
            block_hash,
            &block,
            block_access_list,
        );

        let sidecar = if let Some(requests) = requests {
            block.header.parent_beacon_block_root.map_or(sidecar, |parent_beacon_block_root| {
                ExecutionPayloadSidecar::v4(
                    CancunPayloadFields {
                        parent_beacon_block_root,
                        versioned_hashes: block
                            .body
                            .blob_versioned_hashes_iter()
                            .copied()
                            .collect(),
                    },
                    PraguePayloadFields::new(requests),
                )
            })
        } else {
            sidecar
        };

        ExecutionData::new(payload, sidecar)
    }
}

impl<N: NodePrimitives> BuiltPayload for EthBuiltPayload<N> {
    type Primitives = N;

    fn block(&self) -> &SealedBlock<N::Block> {
        self.block.sealed_block()
    }

    fn fees(&self) -> U256 {
        self.fees
    }

    fn block_access_list(&self) -> Option<&Bytes> {
        self.block_access_list.as_ref()
    }

    fn requests(&self) -> Option<Requests> {
        self.requests.clone()
    }
}

// V1 engine_getPayloadV1 response
impl From<EthBuiltPayload> for ExecutionPayloadV1 {
    fn from(value: EthBuiltPayload) -> Self {
        Self::from_block_unchecked(
            value.block().hash(),
            &Arc::unwrap_or_clone(value.block).into_block(),
        )
    }
}

// V2 engine_getPayloadV2 response
impl From<EthBuiltPayload> for ExecutionPayloadEnvelopeV2 {
    fn from(value: EthBuiltPayload) -> Self {
        let EthBuiltPayload { block, fees, .. } = value;

        Self {
            block_value: fees,
            execution_payload: ExecutionPayloadFieldV2::from_block_unchecked(
                block.hash(),
                &Arc::unwrap_or_clone(block).into_block(),
            ),
        }
    }
}

impl TryFrom<EthBuiltPayload> for ExecutionPayloadEnvelopeV3 {
    type Error = BuiltPayloadConversionError;

    fn try_from(value: EthBuiltPayload) -> Result<Self, Self::Error> {
        value.try_into_v3()
    }
}

impl TryFrom<EthBuiltPayload> for ExecutionPayloadEnvelopeV4 {
    type Error = BuiltPayloadConversionError;

    fn try_from(value: EthBuiltPayload) -> Result<Self, Self::Error> {
        value.try_into_v4()
    }
}

impl TryFrom<EthBuiltPayload> for ExecutionPayloadEnvelopeV5 {
    type Error = BuiltPayloadConversionError;

    fn try_from(value: EthBuiltPayload) -> Result<Self, Self::Error> {
        value.try_into_v5()
    }
}

impl TryFrom<EthBuiltPayload> for ExecutionPayloadEnvelopeV6 {
    type Error = BuiltPayloadConversionError;

    fn try_from(value: EthBuiltPayload) -> Result<Self, Self::Error> {
        value.try_into_v6()
    }
}

impl From<EthBuiltPayload> for ExecutionData {
    fn from(value: EthBuiltPayload) -> Self {
        value.into_execution_data()
    }
}

#[cfg(feature = "std")]
impl From<EthBuiltPayload> for reth_engine_primitives::BigBlockData<ExecutionData> {
    fn from(_value: EthBuiltPayload) -> Self {
        unreachable!("payload building is not supported for big blocks");
    }
}

/// An enum representing blob transaction sidecars belonging to [`EthBuiltPayload`].
#[derive(Clone, Default, Debug)]
pub enum BlobSidecars {
    /// No sidecars (default).
    #[default]
    Empty,
    /// EIP-4844 style sidecars.
    Eip4844(Vec<BlobTransactionSidecar>),
    /// EIP-7594 style sidecars.
    Eip7594(Vec<BlobTransactionSidecarEip7594>),
}

impl BlobSidecars {
    /// Create new EIP-4844 style sidecars.
    pub const fn eip4844(sidecars: Vec<BlobTransactionSidecar>) -> Self {
        Self::Eip4844(sidecars)
    }

    /// Create new EIP-7594 style sidecars.
    pub const fn eip7594(sidecars: Vec<BlobTransactionSidecarEip7594>) -> Self {
        Self::Eip7594(sidecars)
    }

    /// Push EIP-4844 blob sidecar. Ignores the item if sidecars already contain EIP-7594 sidecars.
    pub fn push_eip4844_sidecar(&mut self, sidecar: BlobTransactionSidecar) {
        match self {
            Self::Empty => {
                *self = Self::Eip4844(Vec::from([sidecar]));
            }
            Self::Eip4844(sidecars) => {
                sidecars.push(sidecar);
            }
            Self::Eip7594(_) => {}
        }
    }

    /// Push EIP-7594 blob sidecar. Ignores the item if sidecars already contain EIP-4844 sidecars.
    pub fn push_eip7594_sidecar(&mut self, sidecar: BlobTransactionSidecarEip7594) {
        match self {
            Self::Empty => {
                *self = Self::Eip7594(Vec::from([sidecar]));
            }
            Self::Eip7594(sidecars) => {
                sidecars.push(sidecar);
            }
            Self::Eip4844(_) => {}
        }
    }

    /// Push a [`BlobTransactionSidecarVariant`]. Ignores the item if sidecars already contain the
    /// opposite type.
    pub fn push_sidecar_variant(&mut self, sidecar: BlobTransactionSidecarVariant) {
        match sidecar {
            BlobTransactionSidecarVariant::Eip4844(sidecar) => {
                self.push_eip4844_sidecar(sidecar);
            }
            BlobTransactionSidecarVariant::Eip7594(sidecar) => {
                self.push_eip7594_sidecar(sidecar);
            }
        }
    }
}

impl From<Vec<BlobTransactionSidecar>> for BlobSidecars {
    fn from(value: Vec<BlobTransactionSidecar>) -> Self {
        Self::eip4844(value)
    }
}

impl From<Vec<BlobTransactionSidecarEip7594>> for BlobSidecars {
    fn from(value: Vec<BlobTransactionSidecarEip7594>) -> Self {
        Self::eip7594(value)
    }
}

impl From<alloc::vec::IntoIter<BlobTransactionSidecar>> for BlobSidecars {
    fn from(value: alloc::vec::IntoIter<BlobTransactionSidecar>) -> Self {
        value.collect::<Vec<_>>().into()
    }
}

impl From<alloc::vec::IntoIter<BlobTransactionSidecarEip7594>> for BlobSidecars {
    fn from(value: alloc::vec::IntoIter<BlobTransactionSidecarEip7594>) -> Self {
        value.collect::<Vec<_>>().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use reth_primitives_traits::{Block as _, RecoveredBlock};

    #[test]
    fn into_execution_data_preserves_requests() {
        let requests = Requests::from_requests([Bytes::from_static(&[1, 2])]);
        let parent_beacon_block_root = B256::with_last_byte(1);

        let mut block = reth_ethereum_primitives::Block::default();
        block.header.parent_beacon_block_root = Some(parent_beacon_block_root);
        block.header.requests_hash = Some(requests.requests_hash());

        let payload = EthBuiltPayload::new(
            Arc::new(RecoveredBlock::new_sealed(block.seal_slow(), vec![])),
            U256::ZERO,
            Some(requests.clone()),
            None,
        );

        let execution_data: ExecutionData = payload.into();

        assert_eq!(
            execution_data.sidecar.parent_beacon_block_root(),
            Some(parent_beacon_block_root)
        );
        assert_eq!(execution_data.sidecar.requests(), Some(&requests));
    }

    #[test]
    fn into_execution_data_preserves_block_access_list() {
        let block_access_list = Bytes::from_static(&[0xc0]);

        let mut block = reth_ethereum_primitives::Block::default();
        block.header.parent_beacon_block_root = Some(B256::ZERO);
        block.header.block_access_list_hash = Some(B256::ZERO);

        let payload = EthBuiltPayload::new(
            Arc::new(RecoveredBlock::new_sealed(block.seal_slow(), vec![])),
            U256::ZERO,
            None,
            Some(block_access_list.clone()),
        );

        let execution_data: ExecutionData = payload.into();

        assert_eq!(execution_data.payload.block_access_list(), Some(&block_access_list));
    }

    #[test]
    fn execution_data_has_infallible_try_from_impl() {
        fn assert_try_from<T: TryFrom<EthBuiltPayload, Error = core::convert::Infallible>>() {}

        assert_try_from::<ExecutionData>();
    }

    // reth-v2.8.1 migration: the tests below are 880ce24ad's. It rewrote this file's
    // `attributes_serde` / `test_payload_id_*` tests for the wrapper; upstream moved its own
    // versions of those to `reth_payload_primitives`, so 0G's are appended here. alloy's
    // `PayloadAttributes` gained `slot_number` and `target_gas_limit`, so the literals end with
    // `..Default::default()` (both `None`, which the expected ids below assume).
    use alloy_primitives::{Address, B64};
    use core::str::FromStr;

    fn attrs(inner: InnerPayloadAttributes) -> EthPayloadAttributes {
        EthPayloadAttributes::new(inner, None)
    }

    #[test]
    fn attributes_serde_v3_shape_unchanged() {
        // Pre-Bridge V3 JSON shape: no `bridgeRequests` field. The wrapper must round-trip
        // identically (default `None`) so V3-only CLs talk to a V4-capable EL on the same
        // wire format.
        let json = r#"{"timestamp":"0x1235","prevRandao":"0xf343b00e02dc34ec0124241f74f32191be28fb370bb48060f5fa4df99bda774c","suggestedFeeRecipient":"0x0000000000000000000000000000000000000000","withdrawals":null,"parentBeaconBlockRoot":null}"#;
        let attributes: EthPayloadAttributes = serde_json::from_str(json).unwrap();
        assert!(attributes.bridge_requests.is_none());
        // Re-serializing must drop the `bridge_requests` key when it's `None`.
        let reser = serde_json::to_string(&attributes).unwrap();
        assert!(!reser.contains("bridgeRequests"));
    }

    #[test]
    fn attributes_serde_v4_carries_bridge_requests() {
        let json = r#"{"timestamp":"0x1235","prevRandao":"0xf343b00e02dc34ec0124241f74f32191be28fb370bb48060f5fa4df99bda774c","suggestedFeeRecipient":"0x0000000000000000000000000000000000000000","withdrawals":[],"parentBeaconBlockRoot":"0x2222222222222222222222222222222222222222222222222222222222222222","bridgeRequests":"0x04000000"}"#;
        let attributes: EthPayloadAttributes = serde_json::from_str(json).unwrap();
        assert_eq!(
            attributes.bridge_requests,
            Some(Bytes::from_static(&[0x04, 0x00, 0x00, 0x00]))
        );
    }

    #[test]
    fn test_payload_id_basic() {
        // Create a parent block and payload attributes
        let parent =
            B256::from_str("0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a")
                .unwrap();
        let attributes = attrs(InnerPayloadAttributes {
            timestamp: 0x5,
            prev_randao: B256::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            suggested_fee_recipient: Address::from_str(
                "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
            )
            .unwrap(),
            withdrawals: None,
            parent_beacon_block_root: None,
            ..Default::default()
        });

        // Verify that the generated payload ID matches the expected value (unchanged from
        // pre-Bridge: `bridge_requests = None` is folded into the hash as a no-op).
        assert_eq!(
            payload_id(&parent, &attributes),
            PayloadId(B64::from_str("0xa247243752eb10b4").unwrap())
        );
    }

    #[test]
    fn test_payload_id_with_withdrawals() {
        // Set up the parent and attributes with withdrawals
        let parent =
            B256::from_str("0x9876543210abcdef9876543210abcdef9876543210abcdef9876543210abcdef")
                .unwrap();
        let attributes = attrs(InnerPayloadAttributes {
            timestamp: 1622553200,
            prev_randao: B256::from_slice(&[1; 32]),
            suggested_fee_recipient: Address::from_str(
                "0xb94f5374fce5edbc8e2a8697c15331677e6ebf0b",
            )
            .unwrap(),
            withdrawals: Some(vec![
                Withdrawal {
                    index: 1,
                    validator_index: 123,
                    address: Address::from([0xAA; 20]),
                    amount: 10,
                },
                Withdrawal {
                    index: 2,
                    validator_index: 456,
                    address: Address::from([0xBB; 20]),
                    amount: 20,
                },
            ]),
            parent_beacon_block_root: None,
            ..Default::default()
        });

        // Verify that the generated payload ID matches the expected value
        assert_eq!(
            payload_id(&parent, &attributes),
            PayloadId(B64::from_str("0xedddc2f84ba59865").unwrap())
        );
    }

    #[test]
    fn test_payload_id_with_parent_beacon_block_root() {
        // Set up the parent and attributes with a parent beacon block root
        let parent =
            B256::from_str("0x9876543210abcdef9876543210abcdef9876543210abcdef9876543210abcdef")
                .unwrap();
        let attributes = attrs(InnerPayloadAttributes {
            timestamp: 1622553200,
            prev_randao: B256::from_str(
                "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234",
            )
            .unwrap(),
            suggested_fee_recipient: Address::from_str(
                "0xc94f5374fce5edbc8e2a8697c15331677e6ebf0b",
            )
            .unwrap(),
            withdrawals: None,
            parent_beacon_block_root: Some(
                B256::from_str(
                    "0x2222222222222222222222222222222222222222222222222222222222222222",
                )
                .unwrap(),
            ),
            ..Default::default()
        });

        // Verify that the generated payload ID matches the expected value
        assert_eq!(
            payload_id(&parent, &attributes),
            PayloadId(B64::from_str("0x0fc49cd532094cce").unwrap())
        );
    }

    #[test]
    fn test_payload_id_diverges_on_bridge_requests() {
        // Two attributes that differ only in `bridge_requests` MUST produce different
        // payload ids — otherwise the EL would conflate two distinct CL builds (e.g. round 0
        // empty vs. round 1 with messages) under one cached payload.
        let parent =
            B256::from_str("0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a")
                .unwrap();
        let inner = InnerPayloadAttributes {
            timestamp: 0x5,
            prev_randao: B256::ZERO,
            suggested_fee_recipient: Address::from_str(
                "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
            )
            .unwrap(),
            withdrawals: None,
            parent_beacon_block_root: None,
            ..Default::default()
        };
        let id_no_bridge = payload_id(&parent, &EthPayloadAttributes::new(inner.clone(), None));
        let id_empty_bridge = payload_id(
            &parent,
            &EthPayloadAttributes::new(inner.clone(), Some(Bytes::from_static(&[0, 0, 0, 0]))),
        );
        let id_with_bridge = payload_id(
            &parent,
            &EthPayloadAttributes::new(inner, Some(Bytes::from_static(&[1, 2, 3, 4]))),
        );
        assert_ne!(id_no_bridge, id_empty_bridge);
        assert_ne!(id_empty_bridge, id_with_bridge);
        assert_ne!(id_no_bridge, id_with_bridge);
    }
}
