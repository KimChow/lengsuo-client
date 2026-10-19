//! 接收侧 salt 重放窗口（有界容量 + 时间窗）与跨重启持久化状态。
//!
//! Shadowsocks AEAD 的 `salt`（= IV，AES-128-GCM 16 字节，其余三类 32 字节）由发送
//! 方每次新建会话时随机生成，线上明文可见。参考基线（Xray v26.3.27 /
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）只在 `proxy/shadowsocks/config.go`
//! 定义了 `ErrIVNotUnique`，并在 `protocol.go` 的 `ReadTCPSession` / `DecodeUDPPacket`
//! 里为其留了错误分支，但**没有任何代码路径真正产生该错误**——固定参考实际并不
//! 过滤重放 salt，也不持久化任何重放状态。本模块把「salt 唯一性」做成可验证机制时，
//! 因此是**在参考之上新增**的入站防护，不是对参考行为的转写；这一差异记录在
//! `docs/shadowsocks-status.md` 的偏离清单里。
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
//! 持久化格式（小端）：`magic(8) | version(u32) | capacity(u64) | window_millis(u64)
//! | body_len(u64) | body | crc32(u32)`。body 为若干 `salt_len(u8) | salt | seen(u64)`
//! 记录。写盘走「临时文件 + fsync + rename」的原子替换；损坏 / 截断 / 校验失败 /
//! 版本不符一律返回 `Err`（fail-closed），调用方必须拒绝启动，**不得静默清空**。
//! 校验为 CRC-32/IEEE，用于检测意外损坏与截断，不是密钥化 MAC：能改文件的攻击者
//! 本就可重算校验值，重放状态文件不是针对本地文件写入者的安全边界。

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 文件魔数（8 字节）。
const MAGIC: &[u8; 8] = b"LSS-REP1";
/// 持久化格式版本。
const VERSION: u32 = 1;
/// 头部长度：magic(8) + version(4) + capacity(8) + window(8) + body_len(8)。
const HEADER_LEN: usize = 8 + 4 + 8 + 8 + 8;
/// 尾部 CRC-32 长度。
const CHECKSUM_LEN: usize = 4;
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
    /// 状态文件校验失败（篡改或非原子写入留下的不一致）。
    #[error("重放状态文件校验失败")]
    ChecksumMismatch,
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

    /// 把当前窗口内尚未过期的条目原子写盘（临时文件 + fsync + rename）。
    /// 只读不改变内存状态；`now_millis` 用于决定哪些条目已过期、不必写出。
    pub fn save(&self, path: &Path, now_millis: u64) -> Result<(), Error> {
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
        let mut bytes = Vec::with_capacity(HEADER_LEN + body.len() + CHECKSUM_LEN);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&(self.capacity as u64).to_le_bytes());
        bytes.extend_from_slice(&window_millis.to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&body);
        let checksum = crc32(&bytes);
        bytes.extend_from_slice(&checksum.to_le_bytes());
        atomic_write(path, &bytes).map_err(Error::Io)
    }

    /// 从状态文件加载窗口。损坏 / 截断 / 校验失败 / 版本不符一律返回 `Err`
    /// （fail-closed）；调用方必须据此拒绝启动，不得静默清空。`now_millis` 只用于
    /// 逐出已过期条目，过期本身不是错误。
    pub fn load(path: &Path, now_millis: u64) -> Result<Self, Error> {
        let bytes = std::fs::read(path).map_err(Error::Io)?;
        if bytes.len() < HEADER_LEN + CHECKSUM_LEN {
            return Err(Error::Corrupt(format!(
                "文件仅 {} 字节，小于最小长度 {}",
                bytes.len(),
                HEADER_LEN + CHECKSUM_LEN
            )));
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(Error::Corrupt("魔数不符".to_string()));
        }
        let version = read_u32(&bytes, 8);
        if version != VERSION {
            return Err(Error::VersionMismatch {
                file: version,
                expected: VERSION,
            });
        }
        let capacity = usize::try_from(read_u64(&bytes, 12))
            .map_err(|_| Error::Corrupt("容量字段超出本平台范围".to_string()))?;
        let window_millis = read_u64(&bytes, 20);
        let body_len = usize::try_from(read_u64(&bytes, 28))
            .map_err(|_| Error::Corrupt("正文长度字段超出本平台范围".to_string()))?;
        if bytes.len() != HEADER_LEN + body_len + CHECKSUM_LEN {
            return Err(Error::Corrupt(format!(
                "长度不符：文件 {} 字节，头部声明正文 {} 字节",
                bytes.len(),
                body_len
            )));
        }
        let body_end = HEADER_LEN + body_len;
        let stored = read_u32(&bytes, body_end);
        if stored != crc32(&bytes[..body_end]) {
            return Err(Error::ChecksumMismatch);
        }
        if capacity == 0 {
            return Err(Error::Corrupt("容量为 0".to_string()));
        }
        if window_millis == 0 {
            return Err(Error::Corrupt("时间窗为 0".to_string()));
        }

        let body = &bytes[HEADER_LEN..body_end];
        let mut order = VecDeque::new();
        let mut index = HashMap::new();
        let mut cursor = 0usize;
        while cursor < body.len() {
            let salt_len = body[cursor] as usize;
            cursor += 1;
            if cursor + salt_len + 8 > body.len() {
                return Err(Error::Corrupt(format!("记录在偏移 {cursor} 处截断")));
            }
            let salt = body[cursor..cursor + salt_len].to_vec();
            cursor += salt_len;
            let seen = read_u64(body, cursor);
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

    fn window_millis(&self) -> u64 {
        self.window.as_millis() as u64
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

/// `seen + window <= now` 即视为已过期；`saturating_add` 保证 `seen` 近满时也不回绕。
fn expired(seen: u64, now_millis: u64, window_millis: u64) -> bool {
    seen.saturating_add(window_millis) <= now_millis
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("偏移由调用方保证在界内"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("偏移由调用方保证在界内"),
    )
}

/// 目标路径同目录下的临时文件路径，供原子替换使用。
fn temp_path(path: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(path.as_os_str());
    name.push(".tmp");
    PathBuf::from(name)
}

/// 原子写：先写同目录临时文件并 fsync，再 rename 覆盖目标；失败时尽量清理临时文件。
fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = temp_path(path);
    let result = (|| {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// CRC-32（IEEE 802.3，多项式 0xEDB88320 反射形式），用于持久化文件的损坏检测。
fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (index, entry) in table.iter_mut().enumerate() {
        let mut value = index as u32;
        for _ in 0..8 {
            value = if value & 1 != 0 {
                0xEDB8_8320 ^ (value >> 1)
            } else {
                value >> 1
            };
        }
        *entry = value;
    }
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc = table[((crc ^ u32::from(byte)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_standard_check_value() {
        // CRC-32/IEEE 的标准校验值（"123456789" → 0xCBF43926）。
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn construction_rejects_zero_capacity_or_window() {
        assert!(matches!(
            ReplayFilter::new(0, Duration::from_secs(1)),
            Err(Error::InvalidCapacity { capacity: 0 })
        ));
        assert!(matches!(
            ReplayFilter::new(1, Duration::ZERO),
            Err(Error::InvalidWindow)
        ));
    }

    #[test]
    fn duplicate_rejected_and_fresh_salt_accepted() {
        let mut filter = ReplayFilter::new(8, Duration::from_secs(10)).unwrap();
        filter.record(b"same", 0).unwrap();
        assert!(matches!(filter.record(b"same", 5), Err(Error::Duplicate)));
        // 拒绝不改变窗口大小。
        assert_eq!(filter.len(), 1);
        filter.record(b"other", 5).unwrap();
        assert_eq!(filter.len(), 2);
    }

    #[test]
    fn capacity_evicts_oldest_and_time_window_expires() {
        let mut filter = ReplayFilter::new(2, Duration::from_millis(100)).unwrap();
        filter.record(b"s1", 0).unwrap();
        filter.record(b"s2", 50).unwrap();
        filter.record(b"s3", 60).unwrap();
        // 容量 2：s1 被最旧逐出，可再次作为新 salt 记录；s2/s3 仍在窗内。
        assert!(!filter.contains(b"s1"));
        assert!(filter.contains(b"s2") && filter.contains(b"s3"));
        filter.record(b"s1", 80).unwrap();
        assert_eq!(filter.len(), 2);

        let mut windowed = ReplayFilter::new(4, Duration::from_millis(100)).unwrap();
        windowed.record(b"a", 0).unwrap();
        windowed.record(b"b", 1000).unwrap();
        // a 的窗口在 100 处到期，b 在 1000 处新记录 ⇒ a 被逐出。
        assert!(!windowed.contains(b"a"));
        assert!(windowed.contains(b"b"));
    }

    #[test]
    fn save_and_load_roundtrip_preserves_window_and_rejects_replay() {
        let dir =
            std::env::temp_dir().join(format!("lengsuo-ss-replay-self-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("replay.bin");
        let now = 1_000_000u64;
        let mut filter = ReplayFilter::new(16, Duration::from_secs(60)).unwrap();
        filter.record(&[0x5Au8; 32], now).unwrap();
        filter.record(&[0x6Bu8; 16], now + 1).unwrap();
        filter.save(&path, now).unwrap();

        let mut loaded = ReplayFilter::load(&path, now).unwrap();
        assert_eq!(loaded.capacity(), 16);
        assert_eq!(loaded.window(), Duration::from_secs(60));
        assert!(loaded.contains(&[0x5Au8; 32]));
        assert!(loaded.contains(&[0x6Bu8; 16]));
        assert!(matches!(
            loaded.record(&[0x5Au8; 32], now + 2),
            Err(Error::Duplicate)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
