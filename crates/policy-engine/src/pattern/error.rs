//! 模式编译与 URL 归一化的失败原因（全部 fail-closed：调用方不得回退到任何默认模式）。
//!
//! `Display` 文案即审计展示面——它会直接进 `Decision::reasons`，所以每条都带上下文
//! （原文片段或数值），且不得为空。

/// 模式编译或 URL 归一化的失败原因。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompileError {
    /// 模式文本为空或只有空白字符。规则必须有可比较的锚点。
    #[error("模式为空或只有空白字符")]
    EmptyPattern,
    /// URL 文本为空或只有空白字符。
    #[error("URL 为空或只有空白字符")]
    EmptyUrl,
    /// 模式文本超过 [`MAX_PATTERN_LEN`][crate::pattern::MAX_PATTERN_LEN]。
    /// 有人把整段正则或数据 dump 塞进 `url_pattern` 时，这条会挡住。
    #[error("模式长度 {length} 超过上限 {max}")]
    PatternTooLong {
        /// 模式实际长度（字节）。
        length: usize,
        /// 允许的上限（字节）。
        max: usize,
    },
    /// URL 文本超过 [`MAX_URL_LEN`][crate::pattern::MAX_URL_LEN]。
    #[error("URL 长度 {length} 超过上限 {max}")]
    UrlTooLong {
        /// URL 实际长度（字节）。
        length: usize,
        /// 允许的上限（字节）。
        max: usize,
    },
    /// 段数超过 [`MAX_SEGMENTS`][crate::pattern::MAX_SEGMENTS]。
    #[error("段数 {count} 超过上限 {max}")]
    TooManySegments {
        /// 实际段数。
        count: usize,
        /// 允许的上限。
        max: usize,
    },
    /// 跨段通配（`**`）数量超过
    /// [`MAX_CROSS_WILDCARDS`][crate::pattern::MAX_CROSS_WILDCARDS]。
    #[error("跨段通配数量 {count} 超过上限 {max}")]
    TooManyCrossWildcards {
        /// 实际跨段通配数量。
        count: usize,
        /// 允许的上限。
        max: usize,
    },
    /// 单段超过 [`MAX_SEGMENT_LEN`][crate::pattern::MAX_SEGMENT_LEN]。
    #[error("段 {0:?} 长度超过上限")]
    SegmentTooLong(String),
    /// 模式含空白字符（规则文本不该有隐形字符，也不做「去掉空白继续跑」的修复）。
    #[error("模式含空白字符")]
    PatternHasWhitespace,
    /// URL 含空白字符。
    #[error("URL 含空白字符")]
    UrlHasWhitespace,
    /// 控制字符或 DEL 出现在模式/URL 文本中。
    #[error("文本含控制字符 U+{0:04X}")]
    ControlChar(u32),
    /// 模式含查询串写法（`=`）：查询串在比较面上会被剥离，这种模式永不命中。
    #[error("模式不应包含查询串（比较面会剥离 query，这类规则会静默失效）")]
    QueryInPattern,
    /// 模式含片段写法（`#`）：同上，片段不参与比较。
    #[error("模式不应包含片段（比较面会剥离 fragment，这类规则会静默失效）")]
    FragmentInPattern,
    /// 模式写了 scheme：比较面不含 scheme，带 scheme 的模式永远不可能命中。
    #[error("模式不应包含 scheme（比较面只有 host + path，带 scheme 的规则会静默失效）")]
    SchemeInPattern,
    /// 只有 `*` / `**` / `?` 能独占一段；其余写法必须含字面量。
    #[error("段 {0:?} 只有通配符，缺少字面量")]
    EmptySegment(String),
    /// `?` 与 `*` 之后必须紧跟字面量（段内不允许悬空通配）。
    #[error("通配符后面缺少字面量")]
    TrailingWildcard,
    /// `**` 必须独占一段。
    #[error("`**` 必须独占一段，不接受 {0:?} 这类混合写法")]
    MixedDoubleStar(String),
    /// `{..}` 只能出现在模式最末尾。
    #[error("段数限定 `{0}` 只能出现在模式尾部")]
    CountNotAtEnd(String),
    /// `{..}` 写法非法（未闭合、非数字、负数）。
    #[error("段数限定 `{0}` 写法非法")]
    BadCount(String),
    /// `{n..m}` 中 m 小于 n：区间反向等价于永不命中，属于配置缺陷。
    #[error("段数限定区间反向：{min}..{max} 下界大于上界")]
    InvertedSegmentRange {
        /// 区间下界。
        min: usize,
        /// 区间上界。
        max: usize,
    },
    /// `{0..0}` 只接受空路径，而分隔符 `/` 在模式里只是分段符，因此该模式无法命中任何 URL。
    #[error("段数限定区间 {min}..{max} 为空：该模式无法命中任何 URL")]
    EmptySegmentRange {
        /// 区间下界。
        min: usize,
        /// 区间上界。
        max: usize,
    },
    /// `{0..}` 的上界缺省即隐式全通配，会绕过精度排序，必须显式写出有界上界。
    #[error("段数限定开区间 {min}.. 的上界缺省即隐式全通配，必须写出有界上界")]
    UnboundedAllWildcard {
        /// 区间下界。
        min: usize,
    },
    /// 段数限定超过上限。
    #[error("段数限定 {count} 超过上界 {max}")]
    CountTooLarge {
        /// 实际请求的上界。
        count: usize,
        /// 允许的上界（[`MAX_SEGMENT_COUNT`][crate::pattern::MAX_SEGMENT_COUNT]）。
        max: usize,
    },
    /// 段数限定不能跨 host（写在 host 段或 host/path 的分界上）。
    #[error("段数限定只能作用于路径")]
    CountOnHost,
    /// scheme 不是 http/https，或写法残缺。
    #[error("URL 的 scheme {0:?} 不是 http/https")]
    BadScheme(String),
    /// host 为空。
    #[error("URL 或模式缺少主机名")]
    EmptyHost,
    /// host 含空白字符。
    #[error("主机名含空白字符")]
    HostHasWhitespace,
    /// host 含非法字符。
    #[error("主机名含非法字符：{0:?}")]
    BadHostChar(char),
    /// host 出现空标签（`a..b`、`.a`、`a.`）。
    #[error("主机名标签为空")]
    EmptyLabel,
    /// 百分号转义不合法（只校验，不解码）。
    #[error("百分号转义不合法：{0:?}")]
    BadPercentEscape(String),
    /// userinfo（`user@host`）在比较面上没有落点，出现即拒绝。
    #[error("URL 不允许包含 userinfo")]
    UserInfo,
    /// IPv6 字面量写法非法。
    #[error("IPv6 字面量写法非法：{0:?}")]
    BadIpv6Literal(String),
}
