//! Padding 方案：对齐 anytls-go fd6167a `proxy/padding/padding.go`。
//!
//! 方案是 UTF-8 文本，每行 `key=value`：`stop=N` 指定第 N 个写包起停止填充；
//! 其余键是十进制包序号，值是逗号分隔的条目，条目为 `min-max`（闭区间随机，
//! `GenerateRecordPayloadSizes` 用 `rand.Int(max-min)+min`，即上界不含——
//! 此处按参考原样保留该开区间语义）或检查符 `c`。`c` 表示“载荷尚未写完就不要
//! 填充”，写出侧遇到剩余载荷为 0 时直接停止处理本包。
//!
//! 默认方案来自参考 `defaultPaddingScheme`，逐字节转录。
use crate::Error;

/// 检查符 `c` 在大小表中的哨兵值（参考 `padding.CheckMark = -1`）。
pub const CHECK_MARK: i32 = -1;

/// 参考默认方案（anytls-go `padding.go` 逐字转录）。
pub const DEFAULT_SCHEME: &[u8] = b"stop=8\n\
0=30-30\n\
1=100-400\n\
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n\
3=9-9,500-1000\n\
4=500-1000\n\
5=500-1000\n\
6=500-1000\n\
7=500-1000";

/// 默认方案的 md5（小写十六进制），即 Settings `padding-md5` 字段的取值。
/// 常量形式避免每次写出 Settings 时重算，且可供 `tunnel` 无分配地取用。
pub const DEFAULT_PADDING_MD5: &str = "75cff2ad89aadf5e257059ee571ebe11";

/// 已解析的方案：`stop` 阈值 + 每个写包的大小表。
/// 每个写包的一次性随机取值在写出侧现算（见 `server/padding`）。
#[derive(Clone)]
pub struct PaddingScheme {
    raw: Vec<u8>,
    md5: String,
    stop: u32,
    packets: Vec<(u32, Vec<Spec>)>,
}

/// 大小表条目：闭区间 `[min, max]`（参考生成时用 `max-min` 作上界）或检查符。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spec {
    Range { min: i64, max: i64 },
    Check,
}

impl PaddingScheme {
    /// 解析方案；非法（无 `stop`、`stop` 非十进制、无任何有效条目）时返回 `None`，
    /// 与参考 `NewPaddingFactory` 一致：解析失败不更新工厂。
    pub fn new(raw: Vec<u8>) -> Option<Self> {
        let text = std::str::from_utf8(&raw).ok()?;
        let mut stop = None;
        let mut packets: Vec<(u32, Vec<Spec>)> = Vec::new();
        for line in text.split('\n') {
            let (key, value) = match line.split_once('=') {
                Some(pair) => pair,
                None => continue,
            };
            if key == "stop" {
                stop = value.parse::<u32>().ok();
                continue;
            }
            let Ok(index) = key.parse::<u32>() else {
                continue;
            };
            let specs = parse_specs(value);
            if !specs.is_empty() {
                packets.push((index, specs));
            }
        }
        let stop = stop?;
        if packets.is_empty() {
            return None;
        }
        Some(Self {
            md5: md5_hex(&raw),
            raw,
            stop,
            packets,
        })
    }

    /// 默认方案（参考 `init()` 里的 `UpdatePaddingScheme(defaultPaddingScheme)`）。
    pub fn default_scheme() -> Self {
        Self::new(DEFAULT_SCHEME.to_vec()).expect("默认 padding 方案必须可解析")
    }

    /// 原始方案字节：`UpdatePaddingScheme` 帧的载荷，也是 md5 的输入。
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// 方案 md5 的小写十六进制：Settings 的 `padding-md5` 字段。
    pub fn md5(&self) -> &str {
        &self.md5
    }

    /// `stop`：写包计数达到该值后停止填充（参考比较是 `pkt < stop`）。
    pub fn stop(&self) -> u32 {
        self.stop
    }

    /// 第 `pkt` 个写包对应的条目表；参考用 `strconv.Itoa(int(pkt))` 查表，
    /// 因此这里也按“无该键则空表”处理。
    pub fn specs(&self, pkt: u32) -> &[Spec] {
        self.packets
            .iter()
            .find(|(index, _)| *index == pkt)
            .map(|(_, specs)| specs.as_slice())
            .unwrap_or(&[])
    }
}

/// 解析一个大小表条目值；非法区间（非数值、任一端非正）与参考一样跳过。
fn parse_specs(value: &str) -> Vec<Spec> {
    let mut specs = Vec::new();
    for item in value.split(',') {
        if item == "c" {
            specs.push(Spec::Check);
            continue;
        }
        let Some((low, high)) = item.split_once('-') else {
            continue;
        };
        let (Ok(low), Ok(high)) = (low.parse::<i64>(), high.parse::<i64>()) else {
            continue;
        };
        let (min, max) = (low.min(high), low.max(high));
        if min <= 0 || max <= 0 {
            continue;
        }
        specs.push(Spec::Range { min, max });
    }
    specs
}

/// 方案 md5（小写十六进制），与参考 `fmt.Sprintf("%x", md5.Sum(rawScheme))` 一致。
pub fn md5_hex(raw: &[u8]) -> String {
    let digest = <md5::Md5 as md5::Digest>::digest(raw);
    let mut text = String::with_capacity(32);
    for byte in digest {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// 会话层「UpdatePaddingScheme」帧载荷必须能解析，否则按参考处理为不更新。
pub fn parse_update(raw: &[u8]) -> Result<PaddingScheme, Error> {
    PaddingScheme::new(raw.to_vec()).ok_or(Error::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scheme_matches_reference_bytes_and_md5() {
        let scheme = PaddingScheme::default_scheme();
        assert_eq!(scheme.raw(), DEFAULT_SCHEME);
        assert_eq!(scheme.stop(), 8);
        assert_eq!(scheme.md5().len(), 32);
        assert_eq!(scheme.md5(), md5_hex(DEFAULT_SCHEME));
        // 参考默认方案：包 0 固定 30；包 1 是 100-400；包 2 含 4 个 c。
        assert_eq!(scheme.specs(0), [Spec::Range { min: 30, max: 30 }]);
        assert_eq!(scheme.specs(1), [Spec::Range { min: 100, max: 400 }]);
        assert_eq!(
            scheme.specs(2),
            [
                Spec::Range { min: 400, max: 500 },
                Spec::Check,
                Spec::Range {
                    min: 500,
                    max: 1000
                },
                Spec::Check,
                Spec::Range {
                    min: 500,
                    max: 1000
                },
                Spec::Check,
                Spec::Range {
                    min: 500,
                    max: 1000
                },
                Spec::Check,
                Spec::Range {
                    min: 500,
                    max: 1000
                },
            ]
        );
        assert!(scheme.specs(8).is_empty(), "stop 之后无大小表");
    }

    #[test]
    fn md5_matches_known_digest() {
        // 参考用 crypto/md5；空输入是标准向量。
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn invalid_schemes_are_rejected() {
        assert!(PaddingScheme::new(b"".to_vec()).is_none(), "空方案");
        assert!(
            PaddingScheme::new(b"0=30-30".to_vec()).is_none(),
            "无 stop 应拒绝"
        );
        assert!(
            PaddingScheme::new(b"stop=x\n0=30-30".to_vec()).is_none(),
            "stop 非十进制应拒绝"
        );
        assert!(
            PaddingScheme::new(b"stop=8\nnot-a-key=1".to_vec()).is_none(),
            "无任何数值键应拒绝"
        );
    }

    #[test]
    fn invalid_ranges_are_skipped_like_reference() {
        let scheme =
            PaddingScheme::new(b"stop=2\n1=0-30,30-0,5-6,abc,9".to_vec()).expect("仍然有合法条目");
        // 0-30 与 30-0 因有非正端点被跳过；abc、9 非法；仅 5-6 留下。
        assert_eq!(scheme.specs(1), [Spec::Range { min: 5, max: 6 }]);
    }

    #[test]
    fn reversed_range_is_normalised() {
        let scheme = PaddingScheme::new(b"stop=2\n1=400-100".to_vec()).expect("可解析");
        assert_eq!(scheme.specs(1), [Spec::Range { min: 100, max: 400 }]);
    }

    #[test]
    fn check_marker_parses_between_ranges() {
        let scheme = PaddingScheme::new(b"stop=3\n2=9-9,c,9-9".to_vec()).expect("可解析");
        assert_eq!(
            scheme.specs(2),
            [
                Spec::Range { min: 9, max: 9 },
                Spec::Check,
                Spec::Range { min: 9, max: 9 }
            ]
        );
    }
}
