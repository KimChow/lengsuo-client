//! 接收侧 salt 重放窗口（有界容量 + 时间窗）。
//!
//! Shadowsocks AEAD 的 `salt`（= IV，AES-128-GCM 16 字节，其余三类 32 字节）由发送
//! 方每次新建会话时随机生成，线上明文可见。参考基线（Xray v26.3.27 /
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）只在 `proxy/shadowsocks/config.go`
//! 定义了 `ErrIVNotUnique`，并在 `protocol.go` 的 `ReadTCPSession` / `DecodeUDPPacket`
//! 里为其留了错误分支，但**没有任何代码路径真正产生该错误**（`validator.go` 里的
//! `CheckIV` 调用被整行注释掉、且被 `if matchErr == nil` 短路绕过），固定参考实际
//! 既不过滤重放 salt，也不持久化任何重放状态。本模块把「salt 唯一性」做成可验证
//! 机制时，因此是**在参考之上新增**的入站防护，不是对参考行为的转写；这一差异记录
//! 在 `docs/shadowsocks-status.md` 的偏离清单里。
//!
//! 语义（与 ss-core 的计数器窗口 [[ss-core replay]] 保持一致的原则：先认证后判定）：
//!
//! - 只应由调用方在 **AEAD 认证通过之后** 调用 [`ReplayFilter::record`]，避免攻击者
//!   用无法通过认证的随机 salt 灌满窗口；
//! - salt 逐字节比较；同一 salt 在时间窗内第二次出现即拒绝（`Error::Duplicate`）；
//! - 窗口有界：条目数不超过 `capacity`（FIFO 逐出最旧一条），且超过 `window` 的条目
//!   在下次 `record`/`save`/`load` 时清除，**不会无界增长**；
//! - 时间窗判定假设系统时钟单调；时钟回拨最多使旧条目延迟逐出（fail-closed 地多保留），
//!   不会放行任何重放。
//!
//! 持久化与完整性校验拆到 `crate::persist`（HMAC-SHA256 密钥化 MAC、版本字节、
//! 密钥轮换、原子写），本模块只负责组装/解析状态体。重放判定的窗口大小、驱逐顺序、
//! 时间口径均**未改动**，本卡只替换了文件完整性校验。

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::persist::{self, MacKey};

/// 跨连接共享的重放过滤器句柄。用 `Arc<Mutex<..>>`（**Send + Sync**）：`record`
/// 是同步方法，锁只在这一次调用内持有，不跨 await。
pub type ReplayFilterShared = Arc<Mutex<ReplayFilter>>;

/// 构造一个共享句柄。
#[must_use]
pub fn shared_replay(filter: ReplayFilter) -> ReplayFilterShared {
    Arc::new(Mutex::new(filter))
}

/// 持久化格式把 salt 长度限制在单个字节（≤255，协议套件只用到 16/32）。
const MAX_SALT_LEN: usize = u8::MAX as usize;

/// 重放窗口与持久化状态的失败原因。所有变体都不携带 salt 字节。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// 构造参数：容量必须大于零。
    #[error("重放窗口容量必须大于零（实际 {capacity}）")]
    InvalidCapacity { capacity: usize },
    /// 构造参数：时间窗必须大于零。
    #[error("重放窗口时间窗必须大于零")]
    InvalidWindow,
    /// 同一 salt 在时间窗内第二次出现。
    #[error("salt 重放：窗口内已收到相同 salt")]
    Duplicate,
    /// salt 长度超过持久化格式上限（255 字节）。
    #[error("salt 长度 {len} 超过持久化上限 255 字节")]
    SaltTooLong { len: usize },
    /// 状态文件损坏 / 截断 / 结构不一致。
    #[error("重放状态文件损坏：{0}")]
    Corrupt(String),
    /// 状态文件版本与本实现不符（fail-closed，拒绝启动）。
    #[error("重放状态文件版本不符：文件 {file}，期望 {expected}")]
    VersionMismatch { file: u32, expected: u32 },
    /// 状态文件 HMAC-SHA256 标签校验失败（篡改，或密钥不匹配）。
    #[error("重放状态文件 HMAC-SHA256 标签校验失败（篡改或密钥不匹配）")]
    MacMismatch,
    /// 读写状态文件时的底层 I/O 失败。
    #[error("重放状态文件 I/O 失败：{0}")]
    Io(#[from] std::io::Error),
}

/// 一条记录：salt 与之首次收下时的毫秒时间戳。
struct Entry {
    salt: Vec<u8>,
    seen: u64,
}

/// 接收侧 salt 重放窗口。`Debug` 只输出容量、时间窗与活跃条目数，不输出 salt。
pub struct ReplayFilter {
    capacity: usize,
    window: Duration,
    /// 插入序（= 时间序，见模块头关于单调时钟的说明），用于 FIFO 容量逐出。
    order: VecDeque<Entry>,
    /// salt 字节 → 首次收下的毫秒时间戳，O(1) 判定是否已见。
    index: HashMap<Vec<u8>, u64>,
}

impl fmt::Debug for ReplayFilter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayFilter")
            .field("capacity", &self.capacity)
            .field("window", &self.window)
            .field("active", &self.order.len())
            .finish_non_exhaustive()
    }
}

impl ReplayFilter {
    /// 新建空窗口。`capacity` 是内存中最多保留的 salt 数；`window` 是每条记录的有效期。
    /// 两者都必须大于零。
    pub fn new(capacity: usize, window: Duration) -> Result<Self, Error> {
        if capacity == 0 {
            return Err(Error::InvalidCapacity { capacity });
        }
        if window.is_zero() {
            return Err(Error::InvalidWindow);
        }
        Ok(Self {
            capacity,
            window,
            order: VecDeque::new(),
            index: HashMap::new(),
        })
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    #[must_use]
    pub fn window(&self) -> Duration {
        self.window
    }

    /// 当前仍记录在窗口内的 salt 数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// 该 salt 是否仍记录在窗口内（仅供测试与诊断，不改变状态）。
    #[must_use]
    pub fn contains(&self, salt: &[u8]) -> bool {
        self.index.contains_key(salt)
    }

    /// 系统当前 UNIX 毫秒时间戳。系统时钟早于 UNIX 纪元的极端情况下返回 0
    /// （此时新条目会多保留、不消失，fail-closed，不放行重放）。
    #[must_use]
    pub fn system_now_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as u64)
            .unwrap_or(0)
    }

    /// **仅在 AEAD 认证通过后调用**：判定 salt 是否为时间窗内的首次出现并记录。
    ///
    /// `Ok(())` 表示该 salt 此前未见过（或在窗口外已过期），已记录；返回
    /// `Error::Duplicate` 表示重放，且窗口状态保持不变。记录前先逐出过期条目，
    /// 容量到顶时逐出最旧一条，保证内存有界。
    pub fn record(&mut self, salt: &[u8], now_millis: u64) -> Result<(), Error> {
        if salt.len() > MAX_SALT_LEN {
            return Err(Error::SaltTooLong { len: salt.len() });
        }
        self.prune_expired(now_millis);
        if self.index.contains_key(salt) {
            return Err(Error::Duplicate);
        }
        while self.order.len() >= self.capacity {
            // capacity > 0 由构造保证，因此这里必然能弹出最旧一条。
            let oldest = self.order.pop_front().expect("容量大于零时队列非空");
            self.index.remove(&oldest.salt);
        }
        self.index.insert(salt.to_vec(), now_millis);
        self.order.push_back(Entry {
            salt: salt.to_vec(),
            seen: now_millis,
        });
        Ok(())
    }

    /// 状态体（`capacity | window_ms | body`，见 [`Self::parse_body`]）：把当前窗口内
    /// 尚未过期的条目序列化到字节串，不改变内存状态。`now_millis` 决定哪些条目已过期。
    pub(crate) fn encode_body(&self, now_millis: u64) -> Result<Vec<u8>, Error> {
        let window_millis = self.window_millis();
        let mut body = Vec::new();
        for entry in &self.order {
            if expired(entry.seen, now_millis, window_millis) {
                continue;
            }
            if entry.salt.len() > MAX_SALT_LEN {
                return Err(Error::SaltTooLong {
                    len: entry.salt.len(),
                });
            }
            body.push(entry.salt.len() as u8);
            body.extend_from_slice(&entry.salt);
            body.extend_from_slice(&entry.seen.to_le_bytes());
        }
        let mut out = Vec::with_capacity(16 + body.len());
        out.extend_from_slice(&(self.capacity as u64).to_le_bytes());
        out.extend_from_slice(&window_millis.to_le_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// 解析状态体（`capacity | window_ms | body`），逐条做边界校验，过期条目丢弃。
    /// 任何结构不一致都返回 `Error::Corrupt`（fail-closed）。
    fn parse_body(body: &[u8], now_millis: u64) -> Result<Self, Error> {
        if body.len() < 16 {
            return Err(Error::Corrupt(format!(
                "状态体仅 {} 字节，小于最小长度 16",
                body.len()
            )));
        }
        let capacity = usize::try_from(read_u64(body, 0))
            .map_err(|_| Error::Corrupt("容量字段超出本平台范围".to_string()))?;
        let window_millis = read_u64(body, 8);
        if capacity == 0 {
            return Err(Error::Corrupt("容量为 0".to_string()));
        }
        if window_millis == 0 {
            return Err(Error::Corrupt("时间窗为 0".to_string()));
        }
        let records = &body[16..];
        let mut order = VecDeque::new();
        let mut index = HashMap::new();
        let mut cursor = 0usize;
        while cursor < records.len() {
            let salt_len = records[cursor] as usize;
            cursor += 1;
            if cursor + salt_len + 8 > records.len() {
                return Err(Error::Corrupt(format!("记录在偏移 {cursor} 处截断")));
            }
            let salt = records[cursor..cursor + salt_len].to_vec();
            cursor += salt_len;
            let seen = read_u64(records, cursor);
            cursor += 8;
            if expired(seen, now_millis, window_millis) {
                continue;
            }
            if index.contains_key(&salt) {
                return Err(Error::Corrupt("文件内出现重复 salt".to_string()));
            }
            index.insert(salt.clone(), seen);
            order.push_back(Entry { salt, seen });
        }
        if order.len() > capacity {
            return Err(Error::Corrupt(format!(
                "文件条目数 {} 超过声明容量 {}",
                order.len(),
                capacity
            )));
        }
        Ok(Self {
            capacity,
            window: Duration::from_millis(window_millis),
            order,
            index,
        })
    }

    /// 用当前密钥把窗口内未过期条目原子写盘（HMAC-SHA256 标签 + 临时文件 + rename）。
    /// 只读不改变内存状态；`now_millis` 决定哪些条目已过期、不必写出。写失败返回错误。
    pub fn save_with_key(&self, path: &Path, now_millis: u64, key: &MacKey) -> Result<(), Error> {
        let body = self.encode_body(now_millis)?;
        persist::save_with_key(path, &body, key)
    }

    /// 用当前密钥与可选上一代密钥加载窗口。
    ///
    /// 三分支：文件不存在 → 全新空窗口（`Ok(None)`）；MAC 正确（当前或上一代密钥）→
    /// `Ok(Some)`；**MAC 错误 / 截断 / 格式非法 / 版本不符 → `Err`（fail-closed），
    /// 绝不静默清空状态继续跑**。命中上一代密钥时，返回的 `bool` 为真（需升级），且
    /// 调用方应随即调用 [`ReplayFilter::save_with_key`] 用当前密钥重写文件完成轮换。
    ///
    /// 第二、三个返回值是「是否需要升级重写」与「命中密钥」，供调用方决定落盘。
    pub fn load_with_keys(
        path: &Path,
        now_millis: u64,
        current: &MacKey,
        previous: Option<&MacKey>,
    ) -> Result<Option<LoadedState>, Error> {
        let Some(loaded) = persist::load_with_keys(path, current, previous)? else {
            return Ok(None);
        };
        let filter = Self::parse_body(&loaded.body, now_millis)?;
        Ok(Some(LoadedState {
            filter,
            key_rotated: loaded.key_rotated,
        }))
    }

    fn window_millis(&self) -> u64 {
        self.window.as_millis() as u64
    }

    /// 把容量与时间窗改为配置取值（配置权威：文件里记的是上一份配置的取值）。
    /// 过期条目按新时间窗清除；容量收缩时 FIFO 逐出最旧；参数非法即 `Err`。
    pub(crate) fn retarget(
        mut self,
        capacity: usize,
        window: Duration,
        now_millis: u64,
    ) -> Result<Self, Error> {
        if capacity == 0 {
            return Err(Error::InvalidCapacity { capacity });
        }
        if window.is_zero() {
            return Err(Error::InvalidWindow);
        }
        self.capacity = capacity;
        self.window = window;
        self.prune_expired(now_millis);
        while self.order.len() > self.capacity {
            let oldest = self.order.pop_front().expect("队列必然非空");
            self.index.remove(&oldest.salt);
        }
        Ok(self)
    }

    /// 从队首逐出已过期条目。队列按插入序（时间序）排列；单调时钟下队首即最旧。
    fn prune_expired(&mut self, now_millis: u64) {
        let window_millis = self.window_millis();
        while let Some(front) = self.order.front() {
            if !expired(front.seen, now_millis, window_millis) {
                break;
            }
            let entry = self.order.pop_front().expect("front 必然存在");
            self.index.remove(&entry.salt);
        }
    }
}

/// [`ReplayFilter::load_with_keys`] 的结果：窗口状态 + 是否需要密钥升级重写。
pub struct LoadedState {
    /// 加载出的重放窗口。
    pub filter: ReplayFilter,
    /// 为真表示本次以「上一代密钥」命中，调用方应用当前密钥重写状态文件。
    pub key_rotated: bool,
}

impl fmt::Debug for LoadedState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedState")
            .field("filter", &self.filter)
            .field("key_rotated", &self.key_rotated)
            .finish()
    }
}

/// `seen + window <= now` 即视为已过期；`saturating_add` 保证 `seen` 近满时也不回绕。
fn expired(seen: u64, now_millis: u64, window_millis: u64) -> bool {
    seen.saturating_add(window_millis) <= now_millis
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("偏移由调用方保证在界内"),
    )
}

#[cfg(test)]
mod tests;
