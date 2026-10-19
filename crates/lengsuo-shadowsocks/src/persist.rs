//! 重放状态文件的**密钥化完整性**持久化（HMAC-SHA256 + 原子写 + 版本 + 密钥轮换）。
//!
//! 取代旧的 CRC-32 校验：CRC 只能检测意外损坏，**敌手可以改文件让已用过的 salt
//! 重新被接受**（重放窗口重新打开）。本模块改为用调用方注入的密钥计算
//! HMAC-SHA256 标签，密钥**不落盘**；任何篡改（状态体、版本字节、标签本身）都会
//! 使标签验证失败，加载路径一律 **fail-closed** 返回 `Error::MacMismatch`，绝不
//! 静默清空重放状态继续跑。
//!
//! 文件布局（小端）：`[magic(8)="LSS-REP2"][version(u32)][body_len(u64)][body]
//! [hmac_sha256(32)]`。MAC 覆盖标签之前的全部字节（含版本与长度字段），因此它们
//! 也受保护。密钥由调用方通过 [`MacKey`] 注入，**本模块不提供默认密钥**。
//!
//! 密钥轮换：加载时同时接受「当前密钥」与「上一代密钥」两个候选（各算一次标签）；
//! 命中上一代时 [`Loaded::key_rotated`] 为真，调用方随即用当前密钥重写文件（升级），
//! 两个候选都不中即 fail-closed。
//!
//! 本模块自实现 SHA-256（FIPS 180-4）与 HMAC（RFC 2104）：内部 `ss-core` 虽已编译
//! `sha2`/`hmac` 但**未重新导出**，而本卡不得改任何 `Cargo.toml`。实现以 FIPS/RFC
//! 公开测试向量自检（见 `tests`）。

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::replay::Error;

pub(crate) mod sha256;
pub(crate) use sha256::hmac_sha256;
/// 供测试与外部调用复用的 SHA-256 摘要（一次更新全部数据）。
#[cfg(test)]
use sha256::{sha256, Sha256};

/// 文件魔数（8 字节）。较 CRC 时代的 `LSS-REP1` 换代，旧文件天然不被识别。
const MAGIC: &[u8; 8] = b"LSS-REP2";
/// 持久化格式版本（u32 小端）。
const VERSION: u32 = 1;
/// 版本/长度头（magic 之后）的字节数：version(4) + body_len(8)。
const LEN_FIELD_LEN: usize = 4 + 8;
/// HMAC-SHA256 标签长度。
const MAC_LEN: usize = 32;
/// 标签之前被 MAC 覆盖的固定前缀长度：magic(8) + version(4) + body_len(8)。
const MAC_PREFIX_LEN: usize = MAGIC.len() + LEN_FIELD_LEN;
/// 文件最小长度：前缀 + 标签（body 可为空）。
const MIN_LEN: usize = MAC_PREFIX_LEN + MAC_LEN;

/// 完整性密钥（HMAC-SHA256 密钥）。**故意不实现 `Debug`**：密钥不得进入日志。
#[derive(Clone)]
pub struct MacKey(Vec<u8>);

impl MacKey {
    /// 由任意长度密钥字节构造（HMAC 对短于/长于块长的密钥都有定义）。
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
}

/// 加载成功的结果：状态体已通过 MAC 校验，并标记命中的密钥代数。
pub struct Loaded {
    /// 状态体：`version | body_len | body` 的原始字节（供 `replay` 模块解析）。
    pub body: Vec<u8>,
    /// 命中「上一代密钥」而为真：调用方应据当前密钥重写文件完成升级。
    pub key_rotated: bool,
}

impl std::fmt::Debug for Loaded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Loaded")
            .field("body_len", &self.body.len())
            .field("key_rotated", &self.key_rotated)
            .finish_non_exhaustive()
    }
}
/// 版本号在文件中的偏移（magic 之后）。
const VERSION_OFFSET: usize = MAGIC.len();

/// 用当前密钥原子地把状态体写入 `path`。
///
/// 写盘走「同目录临时文件 + fsync + rename」；任何 I/O 失败都返回 `Err`（不吞）。
pub fn save_with_key(path: &Path, body: &[u8], key: &MacKey) -> Result<(), Error> {
    let mut bytes = Vec::with_capacity(MAC_PREFIX_LEN + body.len() + MAC_LEN);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
    bytes.extend_from_slice(body);
    let tag = hmac_sha256(&key.0, &bytes);
    bytes.extend_from_slice(&tag);
    atomic_write(path, &bytes).map_err(Error::Io)
}

/// 用 `current` 与可选的 `previous` 两个候选密钥加载并校验状态文件。
///
/// 三分支：
/// - 文件不存在 → `Ok(None)`（全新状态，正常）；
/// - 文件存在且任一候选密钥 MAC 正确 → `Ok(Some(Loaded))`；
/// - 文件存在但 **MAC 错误 / 截断 / 格式非法 / 未知版本** → `Err`（fail-closed）。
///
/// 命中 `previous` 时 `Loaded::key_rotated` 为真，调用方据此用 `current` 覆盖重写；
/// 两个候选都不中返回 [`Error::MacMismatch`]。
pub fn load_with_keys(
    path: &Path,
    current: &MacKey,
    previous: Option<&MacKey>,
) -> Result<Option<Loaded>, Error> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(Error::Io(err)),
    };
    if bytes.len() < MIN_LEN {
        return Err(Error::Corrupt(format!(
            "文件仅 {} 字节，小于最小长度 {MIN_LEN}",
            bytes.len()
        )));
    }
    if &bytes[..MAGIC.len()] != MAGIC {
        return Err(Error::Corrupt("魔数不符".to_string()));
    }
    let version = read_u32(&bytes, VERSION_OFFSET);
    if version != VERSION {
        return Err(Error::VersionMismatch {
            file: version,
            expected: VERSION,
        });
    }
    let body_len = usize::try_from(read_u64(&bytes, MAGIC.len() + 4))
        .map_err(|_| Error::Corrupt("正文长度字段超出本平台范围".to_string()))?;
    if bytes.len() != MAC_PREFIX_LEN + body_len + MAC_LEN {
        return Err(Error::Corrupt(format!(
            "长度不符：文件 {} 字节，头部声明正文 {} 字节",
            bytes.len(),
            body_len
        )));
    }
    let mac_end = MAC_PREFIX_LEN + body_len;
    let stored = &bytes[mac_end..];
    // 常量时间比较：两个候选各算一次标签，任一命中即接受。
    let mac_input = &bytes[..mac_end];
    let current_tag = hmac_sha256(&current.0, mac_input);
    if constant_time_eq(stored, &current_tag) {
        return Ok(Some(Loaded {
            body: bytes[MAC_PREFIX_LEN..mac_end].to_vec(),
            key_rotated: false,
        }));
    }
    if let Some(previous) = previous {
        let previous_tag = hmac_sha256(&previous.0, mac_input);
        if constant_time_eq(stored, &previous_tag) {
            return Ok(Some(Loaded {
                body: bytes[MAC_PREFIX_LEN..mac_end].to_vec(),
                key_rotated: true,
            }));
        }
    }
    Err(Error::MacMismatch)
}

/// 目标路径同目录下的临时文件路径，供原子替换使用。
fn temp_path(path: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(path.as_os_str());
    name.push(".tmp");
    PathBuf::from(name)
}

/// 原子写：先写同目录临时文件并 fsync，再 rename 覆盖目标；失败时清理临时文件。
///
/// rename 前先 fsync 文件内容，保证 rename 落地后目标文件内容完整（不出现半写文件，
/// 也不会破坏 rename 前的原文件）。
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

/// 常量时间比较：长度不等直接返回 false（长度本身不是秘密），长度相等则逐字节累积
/// 异或差，最后判零。不使用 `==` 短路比较。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests;
