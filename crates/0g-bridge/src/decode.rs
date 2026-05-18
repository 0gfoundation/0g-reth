//! SSZ decoding of EIP-7685 type-`0xf0` bridge request payload.

use crate::{BRIDGE_REQUEST_TYPE, MAX_BRIDGE_MESSAGES_PER_BLOCK};
use alloc::vec::Vec;
use alloy_primitives::{Address, FixedBytes, U256};
use ssz::{Decode, DecodeError};
use ssz_derive::{Decode as SszDecode, Encode as SszEncode};

/// SSZ container matching the CL Go struct field-for-field.
///
/// Layout (canonical, frozen across CL/EL/contracts):
///
/// | Field        | Type     | Bytes | Endianness |
/// |--------------|----------|-------|------------|
/// | SrcChainID   | U64      | 8     | LE         |
/// | DstChainID   | U64      | 8     | LE         |
/// | Nonce        | U64      | 8     | LE         |
/// | LocalToken   | Bytes20  | 20    | raw        |
/// | Recipient    | Bytes20  | 20    | raw        |
/// | Amount       | Bytes32  | 32    | BE         |
/// | Mode         | U8       | 1     | -          |
/// | SrcBlock     | U64      | 8     | LE         |
/// | **Total**    |          | 105   |            |
///
/// `Amount` is stored big-endian on the wire so that it round-trips into a `uint256` ABI
/// argument without re-shuffling bytes.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct BridgeMessage {
    /// Source chain EL chainId.
    pub src_chain_id: u64,
    /// Destination chain EL chainId. EL drops this field before ABI-encoding (the destination
    /// is implicit — it's the chain executing the system call).
    pub dst_chain_id: u64,
    /// Per-`(srcCID, dstCID)` strictly monotonic nonce assigned by the source-chain Bridge.
    pub nonce: u64,
    /// Address of the token on the **destination** chain (CL poller already resolved the
    /// remote-token mapping from the source chain's `BridgeOut.remoteToken`).
    pub local_token: FixedBytes<20>,
    /// Recipient address on the destination chain.
    pub recipient: FixedBytes<20>,
    /// Big-endian uint256 amount.
    pub amount: FixedBytes<32>,
    /// Source-chain bridge mode (`0 = LockRelease`, `1 = MintBurn`). Audit-only — the
    /// destination contract decides execution mode from its own `tokens[localToken].mode`.
    pub mode: u8,
    /// Source-chain block height where the originating `BridgeOut` event was emitted.
    /// Audit-only.
    pub src_block: u64,
}

impl BridgeMessage {
    /// Convenience accessor: amount as `U256` (big-endian decoded).
    pub fn amount_u256(&self) -> U256 {
        U256::from_be_bytes::<32>(self.amount.0)
    }

    /// Convenience accessor: local token as `Address`.
    pub fn local_token_address(&self) -> Address {
        Address::from(self.local_token.0)
    }

    /// Convenience accessor: recipient as `Address`.
    pub fn recipient_address(&self) -> Address {
        Address::from(self.recipient.0)
    }
}

/// SSZ Container holding a variable-length `List[BridgeMessage, MaxBridgeMessagesPerBlock]`.
///
/// **Wire format must match the matching SSZ container on the CL side**: the field is
/// variable-length, so SSZ requires a 4-byte offset prefix even for an empty list (empty
/// list = 4 bytes, one message = 4 + 105 = 109 bytes). The derive must produce Container
/// layout — do NOT add `#[ssz(struct_behaviour = "transparent")]`, which would flatten to a
/// bare `Vec` and drop the 4-byte offset, breaking byte-equality with CL. The per-block cap
/// is enforced post-decode by [`decode_bridge_messages`] rather than by the SSZ derive
/// (`ethereum_ssz_derive` has no `max_len` attribute).
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct BridgeRequests {
    /// Decoded messages. Length must be `<= MAX_BRIDGE_MESSAGES_PER_BLOCK`; enforced at
    /// decode time. CL builder pre-sorts by `(SrcChainID, DstChainID, Nonce)`; EL preserves
    /// input order.
    pub messages: Vec<BridgeMessage>,
}

/// Errors that can occur when decoding a type-`0xf0` request payload.
#[derive(Debug, thiserror::Error)]
pub enum BridgeDecodeError {
    /// Type byte was missing or did not match [`BRIDGE_REQUEST_TYPE`] (`0xf0`).
    #[error("expected EIP-7685 request type byte 0xf0, got 0x{0:02x}")]
    WrongTypeByte(u8),

    /// Empty payload (no type byte).
    #[error("empty bridge request payload")]
    Empty,

    /// SSZ decoder rejected the bytes.
    #[error("ssz decode failed: {0:?}")]
    Ssz(DecodeError),

    /// Decoded list exceeds [`MAX_BRIDGE_MESSAGES_PER_BLOCK`].
    #[error("bridge request contains {got} messages, exceeds cap of {MAX_BRIDGE_MESSAGES_PER_BLOCK}")]
    TooManyMessages {
        /// Actual decoded length.
        got: usize,
    },

    /// `mode` byte is neither `0` (LockRelease) nor `1` (MintBurn).
    #[error("invalid bridge mode byte: 0x{0:02x}")]
    InvalidMode(u8),
}

impl From<DecodeError> for BridgeDecodeError {
    fn from(value: DecodeError) -> Self {
        Self::Ssz(value)
    }
}

/// Decodes a full EIP-7685 type-`0xf0` request entry: leading type byte stripped, then SSZ
/// container body, then length cap and mode-byte sanity checks.
///
/// The expected wire format is:
///
/// ```text
/// request_bytes = 0xf0 || ssz_bytes(BridgeRequests)
/// ```
///
/// Note: this function expects the **entire** entry including the leading type byte. Callers
/// that have already stripped the type byte should call [`decode_bridge_messages`] instead.
pub fn decode_bridge_request(bytes: &[u8]) -> Result<Vec<BridgeMessage>, BridgeDecodeError> {
    let first = bytes.first().ok_or(BridgeDecodeError::Empty)?;
    if *first != BRIDGE_REQUEST_TYPE {
        return Err(BridgeDecodeError::WrongTypeByte(*first));
    }
    decode_bridge_messages(&bytes[1..])
}

/// Decodes the SSZ body (`BridgeRequests`) without the EIP-7685 type byte.
pub fn decode_bridge_messages(body: &[u8]) -> Result<Vec<BridgeMessage>, BridgeDecodeError> {
    let requests = BridgeRequests::from_ssz_bytes(body)?;

    if requests.messages.len() > MAX_BRIDGE_MESSAGES_PER_BLOCK {
        return Err(BridgeDecodeError::TooManyMessages { got: requests.messages.len() });
    }
    // Validate mode bytes early so callers don't have to.
    for msg in &requests.messages {
        let _ = crate::BridgeMode::try_from(msg.mode)?;
    }
    Ok(requests.messages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::Encode;

    fn sample_msg(nonce: u64) -> BridgeMessage {
        BridgeMessage {
            src_chain_id: 16700,
            dst_chain_id: 16702,
            nonce,
            local_token: FixedBytes([1; 20]),
            recipient: FixedBytes([2; 20]),
            amount: FixedBytes(U256::from(1_000_000_000_000_000_000u128).to_be_bytes::<32>()),
            mode: 1,
            src_block: 42,
        }
    }

    #[test]
    fn roundtrip_single_message() {
        let m = sample_msg(7);
        let body = BridgeRequests { messages: vec![m.clone()] }.as_ssz_bytes();
        let mut wire = Vec::with_capacity(body.len() + 1);
        wire.push(BRIDGE_REQUEST_TYPE);
        wire.extend_from_slice(&body);
        let decoded = decode_bridge_request(&wire).expect("decode happy path");
        assert_eq!(decoded, vec![m]);
    }

    #[test]
    fn empty_message_list_roundtrips() {
        let body = BridgeRequests { messages: vec![] }.as_ssz_bytes();
        let mut wire = vec![BRIDGE_REQUEST_TYPE];
        wire.extend_from_slice(&body);
        let decoded = decode_bridge_request(&wire).unwrap();
        assert!(decoded.is_empty());
    }

    /// Wire compatibility with CL's `karalabe/ssz`-encoded `BridgeRequests` container.
    /// Empty messages must encode to **exactly 4 bytes** — the SSZ container offset prefix
    /// (`u32 LE = 4`, pointing past the offset itself to where the empty list content starts).
    #[test]
    fn empty_list_wire_format_matches_cl_container() {
        let body = BridgeRequests { messages: vec![] }.as_ssz_bytes();
        assert_eq!(
            body.len(),
            4,
            "empty BridgeRequests must serialize to 4 bytes (the variable-list offset); got \
             {} bytes — wire format must match CL Container layout.",
            body.len()
        );
        // Offset value = 4 (points just past the offset itself, since the list is empty).
        assert_eq!(body, [0x04, 0x00, 0x00, 0x00], "offset must be `4` u32 LE");
    }

    /// Single-message wire compatibility: 4-byte offset + 105 bytes of `BridgeMessage` content.
    #[test]
    fn single_message_wire_format_is_offset_plus_105() {
        let body =
            BridgeRequests { messages: vec![sample_msg(7)] }.as_ssz_bytes();
        assert_eq!(
            body.len(),
            4 + 105,
            "one-message BridgeRequests must be 4-byte offset + 105 bytes; got {} bytes",
            body.len()
        );
    }

    #[test]
    fn rejects_wrong_type_byte() {
        let body = BridgeRequests { messages: vec![sample_msg(1)] }.as_ssz_bytes();
        // Bridge uses request type byte `0xf0` (private 0G namespace `0xf0..=0xfe`) rather
        // than `0x05` because Ethereum upstream may claim low type bytes like `0x03..=0x05`
        // for new EIP-7685 standard request types in a future fork — squatting on `0x05`
        // would risk a future collision. Assert the new decoder rejects `0x05` cleanly so a
        // stale CL (or a crafted payload using the old byte) wouldn't be silently accepted.
        let mut wire = vec![0x05];
        wire.extend_from_slice(&body);
        let err = decode_bridge_request(&wire).unwrap_err();
        assert!(matches!(err, BridgeDecodeError::WrongTypeByte(0x05)), "got {err:?}");
    }

    #[test]
    fn rejects_empty_payload() {
        let err = decode_bridge_request(&[]).unwrap_err();
        assert!(matches!(err, BridgeDecodeError::Empty));
    }

    #[test]
    fn rejects_malformed_ssz() {
        // Type byte present but truncated / garbage SSZ body.
        let wire = vec![BRIDGE_REQUEST_TYPE, 0xff, 0xff];
        let err = decode_bridge_request(&wire).unwrap_err();
        assert!(matches!(err, BridgeDecodeError::Ssz(_)), "got {err:?}");
    }

    #[test]
    fn enforces_message_cap() {
        // Build a list with cap+1 messages.
        let many: Vec<BridgeMessage> =
            (0..(MAX_BRIDGE_MESSAGES_PER_BLOCK + 1) as u64).map(sample_msg).collect();
        let body = BridgeRequests { messages: many }.as_ssz_bytes();
        let mut wire = vec![BRIDGE_REQUEST_TYPE];
        wire.extend_from_slice(&body);
        let err = decode_bridge_request(&wire).unwrap_err();
        match err {
            BridgeDecodeError::Ssz(_) | BridgeDecodeError::TooManyMessages { .. } => {}
            other => panic!("expected ssz/cap rejection, got {other:?}"),
        }
    }

    #[test]
    fn at_cap_is_accepted() {
        let exactly_cap: Vec<BridgeMessage> =
            (0..MAX_BRIDGE_MESSAGES_PER_BLOCK as u64).map(sample_msg).collect();
        let body = BridgeRequests { messages: exactly_cap.clone() }.as_ssz_bytes();
        let mut wire = vec![BRIDGE_REQUEST_TYPE];
        wire.extend_from_slice(&body);
        let decoded = decode_bridge_request(&wire).expect("at cap should succeed");
        assert_eq!(decoded.len(), MAX_BRIDGE_MESSAGES_PER_BLOCK);
        assert_eq!(decoded, exactly_cap);
    }

    #[test]
    fn rejects_invalid_mode_byte() {
        let mut bad = sample_msg(1);
        bad.mode = 0xFF;
        let body = BridgeRequests { messages: vec![bad] }.as_ssz_bytes();
        let mut wire = vec![BRIDGE_REQUEST_TYPE];
        wire.extend_from_slice(&body);
        let err = decode_bridge_request(&wire).unwrap_err();
        assert!(matches!(err, BridgeDecodeError::InvalidMode(0xFF)), "got {err:?}");
    }

    #[test]
    fn amount_be_decode_matches_u256() {
        let m = sample_msg(1);
        assert_eq!(m.amount_u256(), U256::from(1_000_000_000_000_000_000u128));
    }
}
