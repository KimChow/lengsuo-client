//! 入站 salt 记忆池的**持久化运行时持有者**：启动加载 → 运行时记录 → 定期/收尾回写。
//!
//! 与固定参考（Xray v26.3.27 / `d2758a02`）的关系：**参考没有任何重放过滤，也没有
//! 任何重放状态持久化**（`proxy/shadowsocks/config.go` 只定义 `ErrIVNotUnique`，
//! `protocol.go` 的两个错误分支是死代码）。本模块因此是**在参考之上新增**的入站
//! 防护。对齐的只是**形态**：参考把「持久化文件路径 + 窗口」放在**入站配置**里，
//! 本模块同样把路径与时间窗放在入站配置（[`SaltStoreConfig`]）里，而不是运行期
//! 临时状态。
//!
//! 密钥来源：状态文件的 MAC 密钥**从口令派生**（与 `crate::key` 的主密钥绑定）：
//!
//! ```text
//! master_key = evp_bytes_to_key(password, KeyBytes)          // crate::key
//! mac_key    = HMAC-SHA256(key = "LSS-SALT-MAC", msg = master_key)
//! ```
//!
//! 派生形态对齐参考 `proxy/shadowsocks/validator.go` 的
//! `HMAC-SHA256("SSBSKDF", account.Key)`（固定标签 + 账号密钥）。**MAC 密钥不落盘**，
//! 状态文件里只有 HMAC 标签：口令、主密钥、MAC 密钥都不进文件。
//!
//! 生命周期：
//!
//! - **启动**（[`SaltStore::open`]）：用 `ReplayFilter::load_with_keys` 加载（当前
//!   MAC 密钥 + 上一代 MAC 密钥两个候选）。**文件不存在 ⇒ 空窗口（不是错误）**；
//!   文件损坏 / MAC 不符 / 版本不符 ⇒ **fail-closed 报错**，绝不静默当空窗口
//!   （否则等于把重放保护关掉）。命中上一代密钥 ⇒ 立即用当前密钥**升级重写**。
//! - **运行时**（[`SaltStore::record`]）：只在 AEAD 认证通过后调用；跨连接共享
//!   **同一个**记忆池（不每连接新建过滤器）。
//! - **回写**（[`SaltStore::flush`]）：用当前 MAC 密钥重算标签（原子写 + fsync）。
//!   触发时机由 [`FlushPolicy`] 决定：间隔回写（记录路径上）或收尾回写
//!   （连接收尾 / 服务停止）。服务停止时的回写**总是**执行。

mod config;

pub(crate) use config::store_config;
pub use config::{FlushPolicy, SaltStateConfig, SaltStoreConfig};

use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ss_core::crypto::CipherSuite;

use crate::key::{KeyError, MasterKey};
use crate::persist::{self, MacKey};
use crate::replay::{Error as ReplayError, ReplayFilter};
use crate::tcp::ReplayFilterShared;

/// 状态文件 MAC 密钥的派生标签（固定标签 + 账号密钥，形态对齐参考
/// `validator.go` 的 `HMAC-SHA256("SSBSKDF", account.Key)`）。
const MAC_KEY_LABEL: &[u8] = b"LSS-SALT-MAC";

/// 回写节流状态：只记「上次成功回写」的时刻与窗口版本号，不含任何密钥。
#[derive(Debug, Default)]
struct FlushState {
    /// 上次成功回写的时刻（`None` = 从未回写过）。
    last_flush: Option<Instant>,
    /// 窗口版本号：每**真正新增**一条记录就 +1（重放拒绝不改窗口 ⇒ 不递增）。
    version: u64,
    /// 已经落盘的窗口版本号。`version != flushed_version` ⇒ 窗口变脏。
    ///
    /// 只有真正新增了记录才需要回写：**被判定为重放的连接不改变窗口**，
    /// 不应触发写盘（否则每次重放尝试都会引发一次 fsync ⇒ 放大型 DoS 面）。
    flushed_version: u64,
}

/// salt 记忆池的失败原因。所有变体都不含口令、主密钥或 MAC 密钥。
#[derive(Debug, thiserror::Error)]
pub enum SaltStoreError {
    /// 配置非法（容量为零、时间窗为零等）。
    #[error("salt 记忆池配置非法：{0}")]
    Config(String),

    /// 口令派生失败（空口令、套件参数不符）。
    #[error("口令派生失败：{0}")]
    Key(#[from] KeyError),

    /// 记忆池状态失败：`Duplicate`（重放）、`Corrupt` / `MacMismatch`（状态文件
    /// 损坏或密钥不匹配 ⇒ fail-closed）、`Io`（读写失败）等。
    #[error("salt 记忆池状态失败：{0}")]
    Replay(#[from] ReplayError),
}

/// salt 记忆池的运行时持有者：**跨连接共享**一个重放窗口，负责加载、记录与回写。
///
/// 内部用 `Arc<Mutex<ReplayFilter>>`（与 [`ReplayFilterShared`] 同一范式）：
/// `record` 是同步方法，锁只在这一次调用内持有，**不跨 await**。
pub struct SaltStore {
    /// 跨连接共享的记忆池本体。
    filter: ReplayFilterShared,
    /// 回写节流状态（短临界区：只读版本号与时刻）。
    state: Mutex<FlushState>,
    /// 回写互斥锁：同一时刻只允许一个回写（防并发 rename 互相覆盖）。
    flush_lock: Mutex<()>,
    /// 状态文件路径。
    path: PathBuf,
    /// 当前 MAC 密钥（**不落盘**）。
    key: MacKey,
    /// 回写策略。
    flush_policy: FlushPolicy,
}

impl SaltStore {
    /// 打开（或新建）salt 记忆池：**加载 → 必要时升级重写**。
    ///
    /// - 文件不存在 ⇒ 空窗口启动（**不是错误**，首次启动的正常情形）；
    /// - 文件损坏 / MAC 不符 / 版本不符 ⇒ **fail-closed 报错**，调用方必须拒绝启动；
    /// - 命中上一代密钥 ⇒ 立即用当前密钥升级重写（轮换完成）。
    pub fn open(
        config: &SaltStoreConfig,
        suite: CipherSuite,
        password: &[u8],
    ) -> Result<Self, SaltStoreError> {
        if config.capacity == 0 {
            return Err(SaltStoreError::Config("记忆池容量必须大于零".into()));
        }
        if config.window.is_zero() {
            return Err(SaltStoreError::Config("记忆池时间窗必须大于零".into()));
        }
        let key = derive_mac_key(suite, password)?;
        let previous_key = match &config.previous_password {
            Some(previous) => Some(derive_mac_key(suite, previous)?),
            None => None,
        };
        let now = ReplayFilter::system_now_millis();
        // 加载：文件不存在 ⇒ `None`；损坏 / MAC 不符 ⇒ `Err`（fail-closed，不静默清空）。
        let loaded = ReplayFilter::load_with_keys(&config.path, now, &key, previous_key.as_ref())?;
        let (filter, rotated) = match loaded {
            Some(state) => (state.filter, state.key_rotated),
            None => (ReplayFilter::new(config.capacity, config.window)?, false),
        };
        // 配置权威：容量与时间窗以配置为准（文件里记的是上一份配置的取值）。
        let filter = filter.retarget(config.capacity, config.window, now)?;
        let store = Self {
            filter: Arc::new(Mutex::new(filter)),
            state: Mutex::new(FlushState::default()),
            flush_lock: Mutex::new(()),
            path: config.path.clone(),
            key,
            flush_policy: config.flush_policy,
        };
        // 命中上一代密钥 ⇒ 立刻用当前密钥升级重写（轮换完成）。
        if rotated {
            store.flush_at(now)?;
        }
        Ok(store)
    }

    /// **只在 AEAD 认证通过后调用**：判定 salt 是否为窗口内的首次出现并记录。
    ///
    /// 同一个 salt 在窗口内第二次出现返回 [`SaltStoreError::Replay`]（内含
    /// `ReplayError::Duplicate`）——此时**窗口未变**，不触发任何写盘。
    /// 记录成功后按 [`FlushPolicy`] 决定是否立刻回写。
    pub fn record(&self, salt: &[u8], now_millis: u64) -> Result<(), SaltStoreError> {
        {
            let mut filter = self.filter.lock().expect("salt 记忆池锁中毒");
            filter.record(salt, now_millis)?;
            // 只在**真正新增**了记录时递增版本号（重放拒绝不改窗口 ⇒ 不递增）。
            self.state.lock().expect("回写状态锁中毒").version += 1;
        }
        self.maybe_flush(now_millis)
    }

    /// 强制回写状态文件（服务停止时用；不受回写策略节流）。
    pub fn flush(&self) -> Result<(), SaltStoreError> {
        self.flush_at(ReplayFilter::system_now_millis())
    }

    /// 连接收尾时的回写：按 [`FlushPolicy`] 决定是否落盘
    /// （`OnClose` 只在窗口变脏时写；`Interval` 只在间隔已到时写）。
    pub fn flush_on_close(&self) -> Result<(), SaltStoreError> {
        let now = ReplayFilter::system_now_millis();
        match self.flush_policy {
            FlushPolicy::OnClose => {
                if self.is_dirty() {
                    self.flush_at(now)
                } else {
                    Ok(())
                }
            }
            FlushPolicy::Interval(_) => self.maybe_flush(now),
        }
    }

    /// 当前仍记在窗口内的 salt 数（诊断用）。
    #[must_use]
    pub fn len(&self) -> usize {
        self.filter.lock().expect("salt 记忆池锁中毒").len()
    }

    /// 窗口是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 跨连接共享的记忆池句柄（只做重放判定，不参与回写节流；需要回写语义
    /// 请走 [`SaltStore::record`]）。
    #[must_use]
    pub fn shared(&self) -> ReplayFilterShared {
        Arc::clone(&self.filter)
    }

    /// 距上次回写是否已到间隔。`None` 表示从未回写过。
    fn due(&self) -> bool {
        let elapsed = {
            let state = self.state.lock().expect("回写状态锁中毒");
            state.last_flush.map(|last| last.elapsed())
        };
        self.flush_policy.due(elapsed)
    }

    /// 窗口在上次回写之后是否新增过记录（版本号比对，避免竞态）。
    fn is_dirty(&self) -> bool {
        let state = self.state.lock().expect("回写状态锁中毒");
        state.version != state.flushed_version
    }

    /// 记录之后按策略决定是否立刻回写。
    fn maybe_flush(&self, now_millis: u64) -> Result<(), SaltStoreError> {
        if !self.due() {
            return Ok(());
        }
        self.flush_at(now_millis)
    }

    /// 把当前窗口序列化并原子写盘（用当前 MAC 密钥重算标签）。
    ///
    /// 序列化在记忆池锁内完成（拿到一致快照），**写盘在锁外**执行，避免 fsync
    /// 阻塞其它连接的记录路径。回写期间到达的新记录由版本号兜住：写完只把
    /// 「已落盘的版本号」推进到快照时的版本，**不会把期间新增的记录标成已落盘**
    /// （否则崩溃时会静默丢记录）。
    ///
    /// 锁序固定为 `flush_lock → filter → state`；`record` 走的是
    /// `filter → state`（不碰 `flush_lock`），因此不存在 ABBA 反转。
    fn flush_at(&self, now_millis: u64) -> Result<(), SaltStoreError> {
        // 回写互斥：同一时刻只允许一个回写在进行（防并发 rename 互相覆盖）。
        let _flush_guard = self.flush_lock.lock().expect("回写锁中毒");
        let snapshot_version = {
            let state = self.state.lock().expect("回写状态锁中毒");
            state.version
        };
        let body = {
            let filter = self.filter.lock().expect("salt 记忆池锁中毒");
            filter.encode_body(now_millis)?
        };
        persist::save_with_key(&self.path, &body, &self.key)?;
        let mut state = self.state.lock().expect("回写状态锁中毒");
        state.last_flush = Some(Instant::now());
        state.flushed_version = snapshot_version;
        Ok(())
    }
}

impl fmt::Debug for SaltStore {
    /// 只输出路径、窗口与条目数；**不输出** MAC 密钥与任何 salt 字节。
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SaltStore")
            .field("path", &self.path)
            .field("flush_policy", &self.flush_policy)
            .field("active", &self.len())
            .finish_non_exhaustive()
    }
}

/// 从口令派生状态文件的 MAC 密钥：主密钥 → `HMAC-SHA256("LSS-SALT-MAC", 主密钥)`。
///
/// MAC 密钥**只在本进程内存里存在**，既不落盘也不进日志。
fn derive_mac_key(suite: CipherSuite, password: &[u8]) -> Result<MacKey, KeyError> {
    let master = MasterKey::new(suite, password)?;
    let mac = persist::hmac_sha256(MAC_KEY_LABEL, master.master_bytes());
    Ok(MacKey::new(mac.to_vec()))
}

#[cfg(test)]
mod tests;
