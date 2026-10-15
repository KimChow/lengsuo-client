//! Hysteria2 padding 长度策略（纯函数，不含随机源）。
//!
//! 参考实现 `core/internal/protocol/padding.go`（完整 commit
//! `ca8fbd874fd6ca82413948de6dc5924405e103e1`）把每个用途的填充长度定义成
//! 半开区间 `[Min, Max)`，长度与字符都用 `math/rand` 取：
//!
//! ```text
//! authRequestPadding  = [256, 2048)
//! authResponsePadding = [256, 2048)
//! tcpRequestPadding   = [64, 512)
//! tcpResponsePadding  = [128, 1024)
//! ```
//!
//! 本模块只复刻**长度策略**这一半：纯函数、无 IO、无随机 —— 随机取值由调用方
//! 注入（[`Range::sample`] 把 `[0, span)` 的抽样结果映射为区间内长度），填充字节
//! 内容也归调用方（参考实现用 `[a-zA-Z0-9]` 字符表；HTTP 头 `Hysteria-Padding`
//! 与帧内 padding 只作长度混淆，两侧都忽略内容）。因此不依赖随机数库，
//! 也不产生不可复现的输出。
//!
//! 两条边界语义与参考实现相同：
//! - 半开区间：`Min` 可取到、`Max` 取不到，所以可用长度个数是 `Max - Min`；
//! - `Min >= Max` 是配置错误（`span() == 0`），任何抽样请求都 fail-closed 报错，
//!   绝不静默退化成固定长度填充（取模会让退化区间恒定产出 `Min`，长度指纹
//!   直接暴露）。
//!
//! 另提供 `SegmentSize` 式的尺寸上下取整：把载荷长度对齐到固定段长的整数倍
//! （向上补齐 / 向下截断到段边界），用于把帧长离散化以抵抗包长指纹。
//! 这些都只是长度计算，不触碰字节内容，也不代替调用方做随机决策。
//!
//! CONNECT-UDP 消息层（`connect_udp.rs`）用本模块得到的长度填充自己的 padding；
//! 参考 commit 未定义 UDP 专用区间，所以 CONNECT-UDP 用哪个区间由调用方显式
//! 选择（未与原生实现对齐，见 `docs/hysteria-status.md`）。认证 token 与
//! QUIC TLS transcript 派生不属于本模块。

use crate::Error;

/// padding 长度的半开区间 `[min, max)`，与参考实现 `padding{Min, Max}` 对应。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    /// 最小长度（可取到）。
    pub min: usize,
    /// 最大长度（取不到）。
    pub max: usize,
}

impl Range {
    /// `authRequestPadding`：`[256, 2048)`。
    pub const AUTH_REQUEST: Range = Range {
        min: 256,
        max: 2048,
    };
    /// `authResponsePadding`：`[256, 2048)`。
    pub const AUTH_RESPONSE: Range = Range {
        min: 256,
        max: 2048,
    };
    /// `tcpRequestPadding`：`[64, 512)`。
    pub const TCP_REQUEST: Range = Range { min: 64, max: 512 };
    /// `tcpResponsePadding`：`[128, 1024)`。
    pub const TCP_RESPONSE: Range = Range {
        min: 128,
        max: 1024,
    };

    /// 构造任意区间；`min > max` 返回 `None`（负宽度没有意义）。
    /// `min == max` 是空区间：可以构造，但 [`Range::sample`] 会拒绝。
    #[must_use]
    pub const fn new(min: usize, max: usize) -> Option<Range> {
        if min > max {
            None
        } else {
            Some(Range { min, max })
        }
    }

    /// 区间内可用长度个数（半开区间）；`min == max` 时为 0，即没有合法长度。
    #[must_use]
    pub const fn span(self) -> usize {
        self.max.saturating_sub(self.min)
    }

    /// 长度是否落在 `[min, max)`。
    #[must_use]
    pub const fn contains(self, len: usize) -> bool {
        len >= self.min && len < self.max
    }

    /// 把调用方抽样值 `sample`（应来自 `[0, span)`）映射为区间内长度。
    ///
    /// `sample` 越界，或区间退化到 `span == 0`，都 fail-closed 报错：宁可拒绝
    /// 构造帧，也不能靠取模把越界值伪装成随机分布。
    pub fn sample(self, sample: usize) -> Result<usize, Error> {
        let span = self.span();
        if span == 0 || sample >= span {
            return Err(Error::PaddingRangeInvalid {
                min: self.min as u64,
                max: self.max as u64,
                sample: sample as u64,
                span: span as u64,
            });
        }
        Ok(self.min + sample)
    }

    /// 把任意长度夹紧进区间：低于 `min` 取 `min`，高于等于 `max` 取 `max - 1`。
    ///
    /// 用于"长度已定、只能补到区间允许范围"的场合。`span == 0` 的空区间没有
    /// 任何可返回值，仍按配置错误报错。
    pub fn clamp(self, len: usize) -> Result<usize, Error> {
        let span = self.span();
        if span == 0 {
            return Err(Error::PaddingRangeInvalid {
                min: self.min as u64,
                max: self.max as u64,
                sample: len as u64,
                span: 0,
            });
        }
        if len <= self.min {
            return Ok(self.min);
        }
        Ok(self.min + (len - self.min).min(span - 1))
    }
}

/// `SegmentSize` 语义：把 `len` 向上取整到 `segment` 的整数倍所需的 padding
/// 字节数（补齐到下一段边界；`len` 已对齐时为 0）。
///
/// `segment == 0` 无法定义取整，fail-closed 报错。
pub fn padding_to_next_segment(len: usize, segment: usize) -> Result<usize, Error> {
    if segment == 0 {
        return Err(Error::SegmentSizeInvalid { segment: 0 });
    }
    let remainder = len % segment;
    Ok(if remainder == 0 {
        0
    } else {
        segment - remainder
    })
}

/// `SegmentSize` 语义：把 `len` 向下取整到 `segment` 的整数倍，返回取整后的长度。
///
/// `segment == 0` 同样报错。
pub fn floor_to_segment(len: usize, segment: usize) -> Result<usize, Error> {
    if segment == 0 {
        return Err(Error::SegmentSizeInvalid { segment: 0 });
    }
    Ok(len - (len % segment))
}

/// 按区间与抽样值得到 padding 后，检查 `header_len + padding` 是否不超过
/// `max_total`（QUIC datagram / 帧长上限），返回 padding 长度或报错。
///
/// 把"长度策略"与"总长上限"的交叉检查留在一个函数里，调用方不会因为补齐
/// padding 而静默越过大小说明。相加溢出归一为 `usize::MAX`，仍按超限失败。
pub fn sampled_within_total(
    range: Range,
    sample: usize,
    header_len: usize,
    max_total: usize,
) -> Result<usize, Error> {
    let padding = range.sample(sample)?;
    let total = header_len.saturating_add(padding);
    if total > max_total {
        return Err(Error::TooLong {
            field: "padded frame",
            len: total as u64,
            max: max_total as u64,
        });
    }
    Ok(padding)
}
