//! 0G cross-chain bridge primitives for the EL.
//!
//! Implements the on-wire types and conversions for EIP-7685 request type byte `0xf0`
//! (private 0G namespace, allocated to avoid colliding with future Ethereum upstream request
//! types). The CL emits a list of [`BridgeMessage`] items as SSZ bytes; this crate decodes
//! them and re-encodes the subset that the destination-chain Bridge contract consumes as ABI
//! calldata for `Bridge.parkRemoteMessages(InboundMessage[])`.
//!
//! Field definitions, byte order, and length caps are pinned across the CL/EL/contract
//! stack; see [`BridgeMessage`] and [`MAX_BRIDGE_MESSAGES_PER_BLOCK`].

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

// Bridge messages live in std-only land: SSZ-derive macros generate code that
// pulls in `std::vec::Vec` etc., and the EL host that consumes this crate is
// always built with std. We deliberately do NOT support no_std here.
extern crate alloc;

mod decode;
pub mod encode;

pub use decode::{
    decode_bridge_messages, decode_bridge_request, BridgeDecodeError, BridgeMessage, BridgeRequests,
};
pub use encode::{encode_park_remote_messages_calldata, InboundMessage};

/// EIP-7685 request type byte for 0G bridge inbound messages.
///
/// Lives in the private 0G namespace `0xf0..=0xfe` to avoid colliding with future Ethereum
/// upstream request types (`0x03+` are reserved for new EIP standards). The same constant is
/// pinned across the CL Go and Solidity contract sides. CL emits with this byte prepended;
/// EL strips it before SSZ-decoding the body.
pub const BRIDGE_REQUEST_TYPE: u8 = 0xf0;

/// Hard cap on the number of [`BridgeMessage`] items the EL will accept per block.
///
/// Pinned in the cross-stream schema; matches the CL builder budget. Decoders enforce this
/// at the byte level — a longer list aborts payload validation rather than silently
/// truncating, see [`BridgeDecodeError::TooManyMessages`].
///
/// Consensus parameter: MUST equal the CL `constants.MaxBridgeMessagesPerBlock` and the value
/// exercised by the Bridge contract's all-park gas test. Sized for the park-only system call:
/// `parkRemoteMessages` does no token delivery — it only writes each message into contract
/// storage for later permissionless delivery — costing ~144k gas per message in the worst
/// (all-park) case. 128 × ~144k ≈ 18.4M, which fits the sizing rule of ≤ 65% of the 30M
/// system-call gas limit, leaving headroom for ABI decoding and dispatch overhead.
pub const MAX_BRIDGE_MESSAGES_PER_BLOCK: usize = 128;

/// Bridge transfer modes mirrored from the Solidity enum. Values must stay byte-identical
/// across CL Go, EL Rust, and Solidity — `LockRelease = 0`, `MintBurn = 1`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeMode {
    /// Source chain locks tokens; destination chain releases them from a pool.
    LockRelease = 0,
    /// Source chain burns tokens; destination chain mints fresh supply.
    MintBurn = 1,
}

impl TryFrom<u8> for BridgeMode {
    type Error = BridgeDecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::LockRelease),
            1 => Ok(Self::MintBurn),
            other => Err(BridgeDecodeError::InvalidMode(other)),
        }
    }
}
