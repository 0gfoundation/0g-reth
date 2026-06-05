//! Off-trie PerpState 读句柄，供共识 EVM 与 RPC 冷读路径共用。

use alloc::{sync::Arc, vec::Vec};
use alloy_primitives::B256;

/// 对 off-trie PerpDEX 存储(`canonical_perp`)的只读句柄。
///
/// 返回空 `Vec` 表示该 key 不存在。object-safe，可作 `dyn` 使用。
pub trait PerpStateHandle: Send + Sync {
    /// 返回 `key` 对应的已提交字节；不存在则返回空 `Vec`。
    fn perp_get(&self, key: B256) -> Vec<u8>;
}

/// 可共享、类型擦除的 [`PerpStateHandle`]。
pub type PerpHandle = Arc<dyn PerpStateHandle>;
