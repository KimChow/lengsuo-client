//! `Bandwidth` 解析与校验（对齐 Xray `infra/conf/transport_internet.go`
//! 的 `type Bandwidth string` 及其 `Bps()` 方法，行 460-511）。
//!
//! 参考语义（逐条对应，不作「等价」改写）：
//! - 先 `TrimSpace` + `ToLower`，空串返回 `0`（缺省 = 未指定，非错误）；
//! - 数字部分 = 从左到右第一个既非数字又非 `.` 的字符之前的全部字符；
//!   其后为「单位」，单位再做一次 `TrimSpace`；
//! - 数字部分用 `ParseFloat`（允许小数、允许 `1.` / `.5` 形态，
//!   不允许空串、不允许科学计数法在数字段之外出现）；
//! - 单位表：`""|"b"|"bps"`=1、`k|kb|kbps`=1024、`m|mb|mbps`=1024²、
//!   `g|gb|gbps`=1024³、`t|tb|tbps`=1024⁴；其它单位一律拒绝；
//! - 结果 = `uint64(val * mul) / 8`（**先乘后除**，且是浮点乘后截断为
//!   `uint64`，再整除 8）。
//!
//! 越界与非法值一律 fail-closed：返回 `Err`，绝不截断、绝不回退到默认值。

use std::fmt;

/// 千字节倍数，与参考 `Kilobyte` 同值（1024，非 1000）。
pub const KILOBYTE: u64 = 1024;
pub const MEGABYTE: u64 = 1024 * KILOBYTE;
pub const GIGABYTE: u64 = 1024 * MEGABYTE;
pub const TERABYTE: u64 = 1024 * GIGABYTE;

/// 单位后缀字节乘数。对齐参考 `Bps()` 的 `switch unit` 分支。
///
/// 返回 `None` 表示单位不被支持 —— 调用方必须 fail-closed。
fn unit_multiplier(unit: &str) -> Option<u64> {
    match unit {
        "" | "b" | "bps" => Some(1),
        "k" | "kb" | "kbps" => Some(KILOBYTE),
        "m" | "mb" | "mbps" => Some(MEGABYTE),
        "g" | "gb" | "gbps" => Some(GIGABYTE),
        "t" | "tb" | "tbps" => Some(TERABYTE),
        _ => None,
    }
}

/// `Bandwidth` 解析失败的原因。
///
/// 每个变体对应参考的一个显式失败分支；错误文本不回显原始凭据/地址，
/// 只携带必要的取值与单位。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BandwidthError {
    /// 数字部分不是合法浮点（对齐参考 `strconv.ParseFloat` 失败）。
    #[error("带宽数字部分不是合法浮点数：{num:?}")]
    InvalidNumber { num: String },

    /// 单位不在参考支持表内（对齐参考 `unsupported unit:` 分支）。
    #[error(
        "不支持的带宽单位：{unit:?}（合法：b/bps、k/kb/kbps、m/mb/mbps、g/gb/gbps、t/tb/tbps）"
    )]
    UnsupportedUnit { unit: String },

    /// 浮点乘积溢出 `u64`（Go 的 `uint64(float64)` 在越界时为未定义取值，
    /// 这里 fail-closed 拒绝而非取一个任意值）。
    #[error("带宽数值溢出 u64：数字 {num:?} × 单位乘数 {mul}")]
    Overflow { num: String, mul: u64 },

    /// 低于参考下限 65536 B/s（对齐 `BrutalUp/BrutalDown must be at least
    /// 65536 bytes per second`）。
    #[error("{which} 必须至少 {min} 字节/秒，实际 {got}")]
    BelowMinimum {
        which: &'static str,
        got: u64,
        min: u64,
    },
}

/// 已解析的带宽值，单位字节每秒（参考 `Bps()` 的返回语义）。
///
/// `0` 是**合法且有意义**的取值：表示「未配置/自动」，与解析失败严格区分。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Bandwidth(pub u64);

impl Bandwidth {
    /// 字节每秒取值。
    pub const fn bps(self) -> u64 {
        self.0
    }

    /// 是否为「未指定」（参考中 `BrutalUp == 0` 即走 BBR 分支）。
    pub const fn is_unset(self) -> bool {
        self.0 == 0
    }

    /// 解析参考 `Bandwidth.Bps()` 的字符串形式。
    ///
    /// 空串（或纯空白）返回 `Ok(Bandwidth(0))`，与参考
    /// `if s == "" { return 0, nil }` 一致。
    pub fn parse(s: &str) -> Result<Bandwidth, BandwidthError> {
        let s = s.trim().to_lowercase();
        if s.is_empty() {
            return Ok(Bandwidth(0));
        }

        // 数字段 = 第一个非 [0-9.] 字符之前的部分；单位 = 其后部分并再 trim。
        let idx = s
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(s.len());
        let num_str = &s[..idx];
        let unit = s[idx..].trim();

        let val: f64 = num_str.parse().map_err(|_| BandwidthError::InvalidNumber {
            num: num_str.to_string(),
        })?;

        let mul = unit_multiplier(unit).ok_or_else(|| BandwidthError::UnsupportedUnit {
            unit: unit.to_string(),
        })?;

        // 参考 `uint64(val*float64(mul)) / 8`：先浮点乘、再截断，最后整除 8。
        // 浮点乘可能越界，先做有限性与范围检查，避免未定义取值。
        let scaled = val * mul as f64;
        if !scaled.is_finite() || scaled < 0.0 || scaled > u64::MAX as f64 {
            return Err(BandwidthError::Overflow {
                num: num_str.to_string(),
                mul,
            });
        }
        Ok(Bandwidth(scaled as u64 / 8))
    }
}

impl fmt::Display for Bandwidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bps", self.0)
    }
}

/// Brutal 带宽下限（字节/秒），对齐 Xray `infra/conf/transport_internet.go`
/// 行 1906-1911：`up > 0 && up < 65536` 与 `down > 0 && down < 65536` 均报错。
///
/// 注意判据是**严格大于 0 才检查下限**：`0` 表示未配置，不触发下限拒绝。
pub const BRUTAL_MIN_BPS: u64 = 65536;

/// 校验参考在 `QuicParams` 构建期对单侧带宽做的下限检查。
///
/// 返回 `Ok(())` 当且仅当 `bw == 0`（未配置）或 `bw >= 65536`。
pub fn check_brutal_min(bw: Bandwidth, which: &'static str) -> Result<(), BandwidthError> {
    if !bw.is_unset() && bw.bps() < BRUTAL_MIN_BPS {
        return Err(BandwidthError::BelowMinimum {
            which,
            got: bw.bps(),
            min: BRUTAL_MIN_BPS,
        });
    }
    Ok(())
}
