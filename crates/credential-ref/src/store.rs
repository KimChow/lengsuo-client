//! 凭据存储抽象与时钟注入（过期判定可确定性测试）。

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::StoreError;
use crate::plaintext::Plaintext;
use crate::reference::{CredentialRef, Scope};

/// 毫秒时钟：返回当前 unix 毫秒；存储实现用它判定引用是否过期。
pub type StoreClock = Arc<dyn Fn() -> u64 + Send + Sync + 'static>;

/// 系统时钟。
pub fn system_clock() -> StoreClock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as u64)
            .unwrap_or_default()
    })
}

/// 固定毫秒时钟：确定性测试用。
pub fn fixed_clock(now_ms: u64) -> StoreClock {
    Arc::new(move || now_ms)
}

/// 凭据存储：`put/get/delete/list`，明文只在返回值里短暂存在。
///
/// 实现必须满足的语义：
/// - `put`：引用必须 `is_valid()`，否则 [`StoreError::InvalidReference`]；同 id 再次写入
///   视为覆盖（upsert），不新增第二条记录。
/// - `get`：按 id 定位记录，判定顺序为
///   找不到 → [`StoreError::NotFound`]；作用域不符 → [`StoreError::ScopeMismatch`]（跨作用域
///   不可见，不返回明文）；已过期 → [`StoreError::Expired`]。
/// - `delete`：幂等，不存在返回 `Ok(false)`。
/// - `list`：只返回该作用域内、未过期的引用元数据（不含明文）。
/// - 错误值与 `Debug` 输出不得包含明文、口令、派生密钥、salt 或密文字节。
pub trait SecretStore: Send + Sync {
    /// 写入明文凭据，与引用元数据一起加密存储。
    fn put(&self, reference: &CredentialRef, plaintext: &Plaintext) -> Result<(), StoreError>;

    /// 按引用取回明文。
    fn get(&self, reference: &CredentialRef) -> Result<Plaintext, StoreError>;

    /// 删除引用对应的记录；返回是否确实删除了一条记录。
    fn delete(&self, reference: &CredentialRef) -> Result<bool, StoreError>;

    /// 列出作用域内可见（未过期）的引用元数据。
    fn list(&self, scope: &Scope) -> Result<Vec<CredentialRef>, StoreError>;
}

impl<T: SecretStore + ?Sized> SecretStore for Arc<T> {
    fn put(&self, reference: &CredentialRef, plaintext: &Plaintext) -> Result<(), StoreError> {
        (**self).put(reference, plaintext)
    }

    fn get(&self, reference: &CredentialRef) -> Result<Plaintext, StoreError> {
        (**self).get(reference)
    }

    fn delete(&self, reference: &CredentialRef) -> Result<bool, StoreError> {
        (**self).delete(reference)
    }

    fn list(&self, scope: &Scope) -> Result<Vec<CredentialRef>, StoreError> {
        (**self).list(scope)
    }
}
