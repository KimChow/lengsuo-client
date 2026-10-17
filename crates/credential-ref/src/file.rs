//! 加密落盘实现：口令派生密钥，AES-256-GCM 逐条随机 nonce 密封，原子重写文件。
//!
//! 并发规则：任何会改变落盘内容的操作（`put`/`delete`/`create`）都在**持有状态守卫的
//! 整个期间**完成「改视图 → 快照 → 编码 → 临时文件 → rename」，因此文件内容永远等于
//! 某一次完整视图，不会发生基于过期快照的覆盖写（丢失更新）。

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use uuid::Uuid;

use crate::container::{self, Record};
use crate::crypto::{self, KdfParams};
use crate::error::StoreError;
use crate::plaintext::Plaintext;
use crate::reference::{CredentialRef, RefId, Scope};
use crate::store::{fixed_clock, system_clock, SecretStore, StoreClock};

/// 句柄内状态：文件路径 + 口令 + 已解密记录表。
struct State {
    records: HashMap<RefId, (CredentialRef, Plaintext)>,
}

/// 文件凭据存储（schema v0）。
///
/// 行为：
/// - 构造即读取并解密文件（不存在则视为空库，首次写入时创建）；
///   版本不识别、结构损坏、口令错误一律 fail-closed 返回错误。
/// - 每次 `put`/`delete` 生成新 salt 与逐条新 nonce，整库原子重写（临时文件 + rename）。
/// - 单文件内不落明文；错误信息与 `Debug` 不含明文、口令、salt 或密文。
pub struct FileStore {
    path: PathBuf,
    passphrase: ZeroedPassphrase,
    state: Mutex<State>,
    clock: StoreClock,
    rng: Mutex<StdRng>,
}

/// 口令缓冲：受 `Zeroizing` 保护，drop 清零。
struct ZeroedPassphrase(zeroize::Zeroizing<Vec<u8>>);

impl ZeroedPassphrase {
    fn new(passphrase: &str) -> Self {
        Self(zeroize::Zeroizing::new(passphrase.as_bytes().to_vec()))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for ZeroedPassphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase(<redacted>)")
    }
}

impl fmt::Debug for FileStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 掩码：只暴露条数与是否落盘路径，不暴露 id、作用域、口令或明文。
        let count = self.lock().records.len();
        f.debug_struct("FileStore")
            .field("entries", &count)
            .field("passphrase", &self.passphrase)
            .field("redacted", &true)
            .finish()
    }
}

impl FileStore {
    /// 打开（或创建）存储文件；`passphrase` 为口令。
    pub fn open(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, StoreError> {
        Self::with_clock(path, passphrase, system_clock())
    }

    /// 打开并指定时钟（确定性过期测试用）。
    pub fn with_clock(
        path: impl AsRef<Path>,
        passphrase: &str,
        clock: StoreClock,
    ) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let passphrase = ZeroedPassphrase::new(passphrase);
        let records = match read_records(&path, passphrase.as_bytes()) {
            Ok(records) => records,
            // 文件不存在 → 空库；其余错误必须上抛（fail-closed，不静默当作空库）。
            Err(StoreError::Io(io_err)) if io_err.kind() == std::io::ErrorKind::NotFound => {
                Vec::new()
            }
            Err(err) => return Err(err),
        };
        let store = Self {
            path,
            passphrase,
            state: Mutex::new(State {
                records: records
                    .into_iter()
                    .map(|(reference, plaintext)| (reference.id(), (reference, plaintext)))
                    .collect(),
            }),
            clock,
            rng: Mutex::new(StdRng::from_entropy()),
        };
        // 已存在的文件也要收紧权限。
        store.tighten_permissions_best_effort();
        Ok(store)
    }

    /// 新建空库（覆盖已有文件）。
    pub fn create(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, StoreError> {
        let store = Self::open(path, passphrase)?;
        {
            let mut state = store.lock();
            state.records.clear();
            store.flush_locked(&state)?;
        }
        Ok(store)
    }

    /// 固定时钟的新建（测试常用）。
    pub fn with_fixed_clock(
        path: impl AsRef<Path>,
        passphrase: &str,
        now_ms: u64,
    ) -> Result<Self, StoreError> {
        Self::with_clock(path, passphrase, fixed_clock(now_ms))
    }

    /// 存储路径。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 当前库使用的 KDF 参数（新写入一律用 [`KdfParams::V0`]）。
    pub fn kdf_params(&self) -> KdfParams {
        KdfParams::V0
    }

    /// 重新从磁盘读取并替换内存视图；文件损坏或口令错误 fail-closed。
    pub fn reload(&self) -> Result<(), StoreError> {
        let records = read_records(&self.path, self.passphrase.as_bytes())?;
        let mut state = self.lock();
        state.records = records
            .into_iter()
            .map(|(reference, plaintext)| (reference.id(), (reference, plaintext)))
            .collect();
        Ok(())
    }

    /// 把 `state` 视图写盘（原子重写）：新 salt、逐条新 nonce，过期记录不写回。
    ///
    /// **并发前提：调用方必须全程持有 `state` 守卫**。快照与 rename 处在同一个临界区内，
    /// 否则线程 A 可以先快照、线程 B 完成写入并重命名，A 再把旧快照盖在 B 的更新之上
    /// （经典丢失更新：内存视图正确，文件却少记录）。
    /// 编码与写盘期间持锁会让 `get`/`list` 短暂等待，换取「文件 == 最后一次写入的视图」。
    fn flush_locked(&self, state: &State) -> Result<(), StoreError> {
        let now = (self.clock)();
        let mut snapshot: Vec<&(CredentialRef, Plaintext)> = state
            .records
            .values()
            .filter(|(reference, _)| !reference.is_expired_at(now))
            .collect();
        // 记录顺序必须稳定：按 id 排序，保证同一库内容写盘结果与插入顺序无关。
        snapshot.sort_by_key(|(reference, _)| reference.id().as_uuid().as_u128());
        let records: Vec<Record<'_>> = snapshot
            .iter()
            .map(|entry| Record {
                reference: &entry.0,
                plaintext: entry.1.as_bytes(),
            })
            .collect();
        // 锁序固定为 state → rng，反向路径不存在，不会自锁。
        let bytes = {
            let mut guard = self
                .rng
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let salt = random_salt(&mut *guard);
            let key = self.derived_key(&salt)?;
            container::encode_container(KdfParams::V0, &salt, &key, &records, &mut *guard)?
        };
        write_atomic(&self.path, &bytes)?;
        self.tighten_permissions_best_effort();
        Ok(())
    }

    fn derived_key(&self, salt: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, StoreError> {
        crypto::derive_key(self.passphrase.as_bytes(), salt, KdfParams::V0)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// unix 上把文件权限收紧到 0600；失败仅影响 best-effort，不改变数据语义。
    fn tighten_permissions_best_effort(&self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600));
        }
    }
}

fn random_salt(rng: &mut impl RngCore) -> Vec<u8> {
    crypto::random_bytes::<{ crypto::SALT_LEN }>(rng).to_vec()
}

/// 从磁盘读取并解密全部引用对应的明文，返回引用列表。
fn read_records(
    path: &Path,
    passphrase: &[u8],
) -> Result<Vec<(CredentialRef, Plaintext)>, StoreError> {
    let bytes = fs::read(path)?;
    let r = container::decode_container(&bytes, passphrase);
    match &r {
        Ok((_p, recs)) => eprintln!(
            "[probe] decode ok bytes={} records={}",
            bytes.len(),
            recs.len()
        ),
        Err(e) => eprintln!(
            "[probe] decode err bytes={} err={:?} file={}",
            bytes.len(),
            e,
            path.display()
        ),
    }
    let (_params, records) = r?;
    Ok(records
        .into_iter()
        .map(|record| (record.reference, record.plaintext))
        .collect())
}

/// 原子写：同目录临时文件 + rename；临时文件立即 0600。
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".{}.tmp-{}", crypt_name(path), Uuid::new_v4()));
    {
        let mut file: File = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
        }
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
    }
    match fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = fs::remove_file(&tmp);
            Err(StoreError::Io(err))
        }
    }
}

fn crypt_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "credentials".to_owned())
}

impl SecretStore for FileStore {
    fn put(&self, reference: &CredentialRef, plaintext: &Plaintext) -> Result<(), StoreError> {
        if !reference.is_valid() {
            return Err(StoreError::InvalidReference);
        }
        // 守卫横跨「改视图 → 快照 → 编码 → rename」，写盘失败也不放锁再回滚，
        // 保证任何时刻文件都是某一次完整视图，不会落下中间态。
        let mut state = self.lock();
        let previous = state.records.insert(
            reference.id(),
            (
                reference.clone(),
                Plaintext::new(plaintext.as_bytes().to_vec()),
            ),
        );
        if let Err(err) = self.flush_locked(&state) {
            // 写盘失败：恢复原值（而非直接删除），避免覆盖写失败时丢掉旧记录。
            match previous {
                Some(entry) => state.records.insert(reference.id(), entry),
                None => state.records.remove(&reference.id()),
            };
            return Err(err);
        }
        Ok(())
    }

    fn get(&self, reference: &CredentialRef) -> Result<Plaintext, StoreError> {
        let state = self.lock();
        let (stored, plaintext) = state
            .records
            .get(&reference.id())
            .ok_or(StoreError::NotFound)?;
        if !stored.scope().same_scope(reference.scope()) {
            return Err(StoreError::ScopeMismatch);
        }
        if stored.is_expired_at((self.clock)()) {
            return Err(StoreError::Expired);
        }
        Ok(Plaintext::new(plaintext.as_bytes().to_vec()))
    }

    fn delete(&self, reference: &CredentialRef) -> Result<bool, StoreError> {
        let mut state = self.lock();
        let removed = match state.records.get(&reference.id()) {
            Some((stored, _)) if stored.scope().same_scope(reference.scope()) => {
                state.records.remove(&reference.id())
            }
            Some(_) => return Err(StoreError::ScopeMismatch),
            None => None,
        };
        let Some(entry) = removed else {
            return Ok(false);
        };
        // 删除同样必须在持有守卫时落盘，否则并发写会基于旧视图重写，把已删记录带回文件。
        if let Err(err) = self.flush_locked(&state) {
            // 写盘失败：把刚摘下的记录原样放回，内存视图与文件保持一致。
            state.records.insert(reference.id(), entry);
            return Err(err);
        }
        Ok(true)
    }

    fn list(&self, scope: &Scope) -> Result<Vec<CredentialRef>, StoreError> {
        let now = (self.clock)();
        let state = self.lock();
        let mut out: Vec<CredentialRef> = state
            .records
            .values()
            .filter(|(reference, _)| reference.scope().same_scope(scope))
            .filter(|(reference, _)| !reference.is_expired_at(now))
            .map(|(reference, _)| reference.clone())
            .collect();
        out.sort_by_key(|reference| reference.id().as_uuid().as_u128());
        Ok(out)
    }
}
