//! Off-trie PerpState 读句柄，供共识 EVM 与 RPC 冷读路径共用。

use alloc::{sync::Arc, vec::Vec};
use alloy_primitives::B256;
use revm_context_interface::journaled_state::PerpBlob;

/// 对 off-trie PerpDEX 存储(`canonical_perp`)的只读句柄。
///
/// 返回空 `Vec` 表示该 key 不存在。object-safe，可作 `dyn` 使用。
pub trait PerpStateHandle: Send + Sync {
    /// 返回 `key` 对应的已提交字节；不存在则返回空 `Vec`。
    fn perp_get(&self, key: B256) -> Vec<u8>;

    /// 返回 `key` 已提交、跨块常驻的**解码后**结构（选项A）：命中则冷读跳过反序列化。
    /// 无解码态（仅以裸字节提交的键，或 startup seed 后尚未重写的键）返回 `None`，
    /// 调用方回退到 [`Self::perp_get`] 字节 + decode。默认无解码态。
    fn perp_get_arc(&self, _key: B256) -> Option<Arc<PerpBlob>> {
        None
    }
}

/// 可共享、类型擦除的 [`PerpStateHandle`]。
pub type PerpHandle = Arc<dyn PerpStateHandle>;
