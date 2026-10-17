//! URL 归一化与通配符模式编译（规格 §2.5「URL 匹配」）。
//!
//! 本 crate 冻结的匹配语言（刻意不引入正则依赖：**编译一次，匹配期只借用输入**）：
//!
//! - 比较面只有 **host + path**：`scheme` 归一化后丢弃（缺省 `https`），
//!   `query`/`fragment` 剥离，userinfo 直接拒绝——追加 `?x=` 无法逃逸黑名单。
//! - 按分隔符切段后逐段匹配：host 以 `.` 切分，path 以 `/` 切分。
//! - `*` 段内通配：不跨分隔符、至少吃掉一个字符。例外：整个 host 部分只写 `*`
//!   时按「任意主机」处理（可跨标签），这是「所有网页」通配的写法。
//! - `**` 跨段通配：必须独占一段，禁止 `a**b` 混合写法；host 上至少一个标签，
//!   path 上允许零段。
//! - `?` 段内单字符；`{n}` / `{n..m}` / `{n..}` 只允许出现在模式尾部，限定剩余段数。
//!   非数字写法（`{a}`）按字面量处理，不做展开解释。
//! - 其余字符一律字面量（没有转义语言）；大小写敏感。
//! - 百分号转义只校验合法性，不解码（`%2F` 永远不等于 `/`）。
//!
//! 模式侧的 query/fragment 防护（fail-closed）：`#` 在模式里没有匹配落点，出现即拒绝；
//! `?` 本身是通配符，只有当它后面跟着 `=`/`&` 这类键值写法（即真正的查询串）时才拒绝——
//! `example.com/a?c` 是通配，`example.com/a?q=1` 是查询串写法错误。
//!
//! 「所有网页」判定（规格 §2.4「白名单/黑名单各自覆盖"所有网页"通配」的识别面）：
//! host 部分是裸 `*`/`**`，且路径部分要么整体缺省、要么只写一个 `**`，且不含任何字面量。
//! 只有这种模式参与「通配兜底 vs 精确规则」的精度分级（见 [`Specificity`]）。
//!
//! 资源上限（全部显式、可预期，失败即拒绝，不做静默宽松解析）：
//! 模式长度 ≤ [`MAX_PATTERN_LEN`]，段数 ≤ [`MAX_SEGMENTS`]，跨段通配 ≤
//! [`MAX_CROSS_WILDCARDS`]，URL 长度 ≤ [`MAX_URL_LEN`]，单段长度 ≤ [`MAX_SEGMENT_LEN`]。

mod compiled;
mod engine;
mod error;
mod lex;
mod normalize;
mod specificity;

pub use compiled::Pattern;
pub use error::CompileError;
pub use normalize::NormalizedUrl;
pub use specificity::{more_specific, Specificity};

/// 模式文本长度上限（字节）。策略作者应写短锚点；超此长度即拒绝，
/// 避免有人把整段正则或数据 dump 塞进 `url_pattern`。
pub const MAX_PATTERN_LEN: usize = 512;
/// 单条模式的最大段数（host + path 各自计）。
pub const MAX_SEGMENTS: usize = 64;
/// 单条模式的最大跨段通配（`**`）数量：越多组合越爆炸，应拆成多条规则。
pub const MAX_CROSS_WILDCARDS: usize = 8;
/// 待匹配 URL 文本长度上限（字节）。
pub const MAX_URL_LEN: usize = 4096;
/// 单段（标签或路径段）最大字节数。
pub const MAX_SEGMENT_LEN: usize = 255;
/// 尾部段数限定的最大上界；`{n..}` 的上界取此值（`{0..}` 直接拒绝）。
pub const MAX_SEGMENT_COUNT: usize = 64;
