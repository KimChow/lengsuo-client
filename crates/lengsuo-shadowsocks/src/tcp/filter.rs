//! TCP 读端的**重放判定句柄**分派（唯一可变引用 / 跨连接共享 / 持久化持有者）。
//!
//! 用枚举而非 trait object，避免在热路径上引入动态分发；三种形态都只是借用，
//! 不改变 `Reader` 各 future 的 `Send`/`Sync` 性质（`&Arc<Mutex<..>>` 是 `Send`）。

use crate::replay::{ReplayFilter, ReplayFilterShared};
use crate::salt_store::{SaltStore, SaltStoreError};

use super::Error;

/// 重放判定句柄：一次性可变借用、跨连接共享句柄或持久化持有者三选一。
pub enum FilterRef<'a> {
    /// 调用方持有唯一可变引用（单连接测试路径）。
    Unique(&'a mut ReplayFilter),
    /// 跨连接共享句柄（中继服务路径，纯内存）。
    Shared(&'a ReplayFilterShared),
    /// 持久化持有者（中继服务路径，记录后按策略回写状态文件）。
    Store(&'a SaltStore),
}

impl FilterRef<'_> {
    /// 记录 salt 并做重放判定。**只在 AEAD 认证通过后调用**。
    pub(crate) fn record(
        &mut self,
        salt: &[u8],
        now_millis: u64,
    ) -> std::result::Result<(), Error> {
        match self {
            Self::Unique(filter) => filter.record(salt, now_millis).map_err(Error::Replay),
            Self::Shared(shared) => shared
                .lock()
                .expect("重放窗口锁中毒")
                .record(salt, now_millis)
                .map_err(Error::Replay),
            // 持久化持有者：重放判定与另两条分支同语义（`Error::Replay`），
            // 回写失败另报 `Error::SaltStore`（状态文件写盘失败，fail-closed）。
            Self::Store(store) => store.record(salt, now_millis).map_err(|err| match err {
                SaltStoreError::Replay(replay) => Error::Replay(replay),
                other => Error::SaltStore(other),
            }),
        }
    }
}
