//! 内存实现（测试与单进程开发用）：只存明文副本于互斥表内，`Debug` 恒为掩码。

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::error::StoreError;
use crate::plaintext::Plaintext;
use crate::reference::{CredentialRef, RefId, Scope};
use crate::store::{fixed_clock, SecretStore};
use crate::store::{system_clock, StoreClock};

/// 单条内存记录。
struct Entry {
    reference: CredentialRef,
    plaintext: Plaintext,
}

/// 内存凭据存储。
///
/// 注意：本实现**不落盘**，明文常驻进程内存，仅供测试与开发路径；
/// 生产落盘请使用 [`crate::FileStore`]。
#[derive(Clone)]
pub struct MemoryStore {
    inner: Arc<Mutex<HashMap<RefId, Entry>>>,
    clock: StoreClock,
}

impl fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 掩码：条数属统计信息，不含任何引用值或明文。
        let count = self.lock().len();
        f.debug_struct("MemoryStore")
            .field("entries", &count)
            .field("redacted", &true)
            .finish()
    }
}

impl MemoryStore {
    /// 新建（使用固定 0 时钟，便于确定性过期测试）。
    pub fn new() -> Self {
        Self::with_clock(fixed_clock(0))
    }

    /// 新建并指定时钟。
    pub fn with_clock(clock: StoreClock) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            clock,
        }
    }

    /// 使用系统真实时钟。
    pub fn with_system_clock() -> Self {
        Self::with_clock(system_clock())
    }

    /// 当前记录条数（含已过期但未清理的记录）。
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// 是否没有任何记录。
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// 删除已过期记录，返回删除条数（过期记录默认只在读取时拒绝，不清理）。
    pub fn retain_unexpired(&self) -> usize {
        let now = (self.clock)();
        let mut table = self.lock();
        let before = table.len();
        table.retain(|_, entry| !entry.reference.is_expired_at(now));
        before - table.len()
    }

    /// 把已过期引用暴露给测试：按 id 取回存储的引用元数据。
    pub fn stored_reference(&self, id: &RefId) -> Option<CredentialRef> {
        self.lock().get(id).map(|entry| entry.reference.clone())
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<RefId, Entry>> {
        // 中毒只由外部 panic 造成：恢复守卫，避免把 panic 传染成存储不可用。
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStore for MemoryStore {
    fn put(&self, reference: &CredentialRef, plaintext: &Plaintext) -> Result<(), StoreError> {
        if !reference.is_valid() {
            return Err(StoreError::InvalidReference);
        }
        let mut table = self.lock();
        table.insert(
            reference.id(),
            Entry {
                reference: reference.clone(),
                plaintext: Plaintext::new(plaintext.as_bytes().to_vec()),
            },
        );
        Ok(())
    }

    fn get(&self, reference: &CredentialRef) -> Result<Plaintext, StoreError> {
        let table = self.lock();
        let entry = table.get(&reference.id()).ok_or(StoreError::NotFound)?;
        if !entry.reference.scope().same_scope(reference.scope()) {
            return Err(StoreError::ScopeMismatch);
        }
        if entry.reference.is_expired_at((self.clock)()) {
            return Err(StoreError::Expired);
        }
        Ok(Plaintext::new(entry.plaintext.as_bytes().to_vec()))
    }

    fn delete(&self, reference: &CredentialRef) -> Result<bool, StoreError> {
        let mut table = self.lock();
        // 作用域不符时不得删除他人记录。
        match table.get(&reference.id()) {
            Some(entry) if entry.reference.scope().same_scope(reference.scope()) => {
                table.remove(&reference.id());
                Ok(true)
            }
            Some(_) => Err(StoreError::ScopeMismatch),
            None => Ok(false),
        }
    }

    fn list(&self, scope: &Scope) -> Result<Vec<CredentialRef>, StoreError> {
        let now = (self.clock)();
        let table = self.lock();
        let mut out: Vec<CredentialRef> = table
            .values()
            .filter(|entry| entry.reference.scope().same_scope(scope))
            .filter(|entry| !entry.reference.is_expired_at(now))
            .map(|entry| entry.reference.clone())
            .collect();
        out.sort_by_key(|reference| reference.id().as_uuid().as_u128());
        Ok(out)
    }
}
