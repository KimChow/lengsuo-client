//! 凭据灌注编排（凭据线 W8 · 环境侧）：把环境启动所需的 `cred_refs` 逐条解成明文，
//! 立刻移交 sink，用完即弃。
//!
//! # 只做编排，不做传输
//!
//! 契约 04 §4 规定明文唯一出口是 `POST /client/secrets/unlock`（登录态 + 设备绑定 +
//! 环境授权 + 审计），且**没有**批量/列表/导出明文类接口 ⇒「批量解锁」在本模块只是
//! **对每个引用逐条串行调用一次**，**不是一个批量接口**。
//!
//! 解锁的**传输**由调用方以 [`SecretUnlock`] 实现注入：本仓目前没有任何服务端 HTTP
//! 客户端（`reqwest` 只在根 `Cargo.toml` 的 `[workspace.dependencies]`、不在锁文件里，
//! 引入即新增依赖树）⇒ 本模块**不发起任何 IO**，不碰网络、文件与系统调用，与 crate
//! 顶部「纯内存」的边界一致。
//!
//! # 硬语义（由契约 04 §4 直接推出）
//!
//! 1. **即用即弃**：明文只存在于 [`Plaintext`]（Drop 时零化）；不缓存、不落盘、
//!    不进日志/错误/任何序列化输出。
//! 2. **逐条串行**：第 i 条的 `unlock` 与 `accept` 都完成后才发起第 i+1 条。
//! 3. **fail-closed**：任何一条失败**不得**静默降级、填空串或跳过。
//! 4. **无状态**：本模块没有任何可变状态、没有持有已解明文或已解记录的结构体
//!    ⇒ 这是「重启后重灌（同环境重放 ≠ 跨环境迁移）」与「不跨环境复用」的
//!    **结构性**保证。
//!
//! # 未冻结项（G1–G4，原样上报待裁定）
//!
//! - **G1**：`cred_refs` 的字段面 / JSON 键名 / 字节格式在契约里**没有定义**
//!   ⇒ 这里只定义**进程内**类型 [`CredRefId`]，**不做任何反序列化**。
//! - **G2**：环境启动的引用列表从哪来（`POST /client/fingerprint/lease` 未实现）
//!   ⇒ 入参由调用方给出，本模块不实现、不假设 lease。
//! - **G3**：解锁传输由调用方注入（泛型参数，不做 trait object）。
//! - **G4**：某一条失败时是「拒绝启动」还是「部分注入」契约未定 ⇒ 本模块**不内置
//!   策略**，只产出结构化结果（第几条 / 哪一类原因 / 失败前已注入几条）。

use std::{collections::BTreeMap, fmt, ops::Deref};
use zeroize::Zeroizing;

/// 引用 id 的长度上限（UTF-8 字节）。
///
/// **自设工程决定，非契约规定**：契约只写「引用 id + 过期 + 作用域」，未给长度约束。
/// 取 256 的依据：覆盖 UUIDv4（36 字符）与 base64url(16/32 字节随机数 → 22/43 字符)
/// 并留一倍以上余量，同时给单条引用一个硬内存上界，使超长/垃圾输入无法撑爆启动。
pub const MAX_REF_ID_LEN: usize = 256;

/// 单次环境启动允许灌注的凭据条数上限。
///
/// **自设工程决定，非契约规定**：契约列出的明文类别（密码 / Cookie / token /
/// 代理口令 / Passkey 私钥）是常数级，条数由「每环境几个站点 × 每站点几个类别」
/// 决定 ⇒ 取 64 留足余量，同时给审计条数与内存占用一个硬上界。
pub const MAX_REFS: usize = 64;

/// 引用 id 形态不合法的原因（⛔ 不含被拒内容，更没有明文）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidRefReason {
    /// 空串。
    Empty,
    /// 超过 [`MAX_REF_ID_LEN`] 字节。
    TooLong { len: usize },
    /// 含 ASCII 控制字符（含 `\0`）。
    ControlByte,
    /// 含空白（含 Unicode 空白）。
    Whitespace,
}

impl fmt::Display for InvalidRefReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidRefReason::Empty => write!(f, "引用 id 不得为空"),
            InvalidRefReason::TooLong { len } => {
                write!(f, "引用 id 长度 {len} 字节，超过上限 {MAX_REF_ID_LEN}")
            }
            InvalidRefReason::ControlByte => write!(f, "引用 id 含 ASCII 控制字符"),
            InvalidRefReason::Whitespace => write!(f, "引用 id 含空白"),
        }
    }
}

impl std::error::Error for InvalidRefReason {}

/// 凭据引用 id 的**进程内**形态：就是服务端给出的那个 id 本身。
///
/// ⛔ 不假设任何前缀/URL 形态，不 trim、不截断、不做编码归一化——形态校验只管
/// 「能不能安全地当作一个不透明标识串来持有与比较」。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredRefId(String);

impl CredRefId {
    /// 外部到达的引用 id 原样封装：**不做校验**，形态判定留给 [`Self::validate`]
    /// 与 [`inject_credentials`] 的预检（在任何 unlock 之前全量校验）。
    ///
    /// 存在的理由：`cred_refs` 的跨仓字段面尚未冻结（G1），引用 id 只能以「外部
    /// 来的字节」的身份进入进程 ⇒ 需要一个不做校验的载体。
    pub fn from_external(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// fail-closed 构造：形态不合法即拒绝（空 / 超长 / 控制字符 / 空白）。
    pub fn parse(raw: impl Into<String>) -> Result<Self, InvalidRefReason> {
        let id = Self::from_external(raw);
        id.validate()?;
        Ok(id)
    }

    /// 形态判定：与 [`Self::parse`]、[`inject_credentials`] 预检共用同一实现。
    ///
    /// 判定次序固定为「空 → 超长 → 逐字符（控制字符优先于空白）」：`\t`/`\n`/`\r`
    /// 既属 ASCII 控制字符又属空白，按**控制字符**归类（更早拒绝）。
    pub fn validate(&self) -> Result<(), InvalidRefReason> {
        if self.0.is_empty() {
            return Err(InvalidRefReason::Empty);
        }
        if self.0.len() > MAX_REF_ID_LEN {
            return Err(InvalidRefReason::TooLong { len: self.0.len() });
        }
        for c in self.0.chars() {
            if c.is_ascii_control() {
                return Err(InvalidRefReason::ControlByte);
            }
            if c.is_whitespace() {
                return Err(InvalidRefReason::Whitespace);
            }
        }
        Ok(())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 一条凭据的明文：**即用即弃**，Drop 时零化。
///
/// 刻意**不实现** `Clone`（编译期就不允许复制明文）、**不实现**
/// `Serialize`/`Deserialize`（防明文被误序列化进 JSON / 事件流）；
/// `Debug`/`Display` 只输出长度。加了 `Clone` 会让下面的文档测试**编译通过**，
/// 于是 `cargo test` 直接变红——那是刻意留的编译期闸门。
///
/// ```compile_fail
/// use lengsuo_environment::credential::Plaintext;
/// let p = Plaintext::new("x".to_string());
/// let _q = p.clone(); // Plaintext 不实现 Clone
/// ```
pub struct Plaintext(Zeroizing<String>);

impl Plaintext {
    pub fn new(raw: impl Into<String>) -> Self {
        Self(Zeroizing::new(raw.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Deref for Plaintext {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Plaintext(<{} 字节，内容不显示>)", self.0.len())
    }
}

impl fmt::Display for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} 字节明文，内容不显示>", self.0.len())
    }
}

/// 解锁失败原因：可区分「引用失效」（≈ 服务端 60006）与「被审计拦截」（≈ 60007）
/// 与「传输或其它故障」；⛔ 不携带明文、口令或密文字节，也不硬编码 HTTP 状态码。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockError {
    /// 引用本身无效（≈ 60006）。
    RefInvalid,
    /// 解锁被审计拦截（≈ 60007）。
    AuditDenied,
    /// 传输或其它故障（含登录态/设备绑定未就绪）。
    Transport,
}

impl UnlockError {
    /// 稳定短码，供上层映射到自己的错误面（⛔ 与明文无关）。
    pub fn code(&self) -> &'static str {
        match self {
            UnlockError::RefInvalid => "unlock.ref_invalid",
            UnlockError::AuditDenied => "unlock.audit_denied",
            UnlockError::Transport => "unlock.transport",
        }
    }
}

impl fmt::Display for UnlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnlockError::RefInvalid => write!(f, "凭据引用失效"),
            UnlockError::AuditDenied => write!(f, "解锁被审计拦截"),
            UnlockError::Transport => write!(f, "解锁传输故障"),
        }
    }
}

impl std::error::Error for UnlockError {}

/// 接收方拒绝明文的原因。
///
/// **自设工程决定，非契约规定**：契约未定义 sink 失败分类，这里只给最小可分辨的
/// 两档（策略拒绝 / 自身故障）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkError {
    /// 接收方按策略拒绝（例如目标已占用、形态不被接受）。
    Rejected,
    /// 接收方自身故障（本地存储或接口不可用）。
    Failed,
}

impl SinkError {
    /// 稳定短码，供上层映射（⛔ 与明文无关）。
    pub fn code(&self) -> &'static str {
        match self {
            SinkError::Rejected => "sink.rejected",
            SinkError::Failed => "sink.failed",
        }
    }
}

impl fmt::Display for SinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SinkError::Rejected => write!(f, "接收方按策略拒绝明文"),
            SinkError::Failed => write!(f, "接收方自身故障"),
        }
    }
}

impl std::error::Error for SinkError {}

/// 解**一条**引用 → 明文。由后续接线卡注入实现（传输不在本卡）。
///
/// ⛔ 不用 `dyn SecretUnlock`：本仓锁文件没有 `async-trait`，而 async fn in trait
/// 不做 dyn 兼容 ⇒ 一律泛型参数（照 `runtime.rs` 的泛型写法）。
/// ⛔ 本卡不内置超时与重试：那是解锁实现与上层的事。
// 该 lint 针对「公开 trait 里的 async fn 无法声明 auto trait 边界」；本 trait 只做
// 泛型分发、永不 dyn，`Send` 边界留待接线卡按具体实现裁定 ⇒ 在此局部豁免。
#[allow(async_fn_in_trait)]
pub trait SecretUnlock {
    /// 解一条：入参只含引用 id；返回明文（即用即弃）。
    async fn unlock(&self, r: &CredRefId) -> Result<Plaintext, UnlockError>;

    /// 自查连接可用性（可选）：上层据此判断登录态/设备绑定是否就绪。
    async fn probe(&self) -> Result<(), UnlockError>;
}

/// 接收明文并**接管所有权**（用完即 Drop ⇒ 零化）。
pub trait CredentialSink {
    /// 接受一条明文；返回 [`SinkError`] 表示拒绝/故障（明文随参数一起被丢弃）。
    fn accept(&mut self, r: &CredRefId, plaintext: Plaintext) -> Result<(), SinkError>;
}

/// 灌注结果：已注入条数 + 顺序（= 入参顺序）。⛔ 不含明文。
#[derive(Debug, Default, PartialEq, Eq)]
pub struct InjectReport {
    refs: Vec<CredRefId>,
}

impl InjectReport {
    pub fn len(&self) -> usize {
        self.refs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.refs.is_empty()
    }

    /// 已注入的引用 id，按注入顺序。
    pub fn refs(&self) -> &[CredRefId] {
        &self.refs
    }
}

/// 注入失败：回答「第几条 / 哪一类原因 / 失败前已注入几条」。
#[derive(Debug, PartialEq, Eq)]
pub enum InjectError {
    /// 引用条数超过 [`MAX_REFS`]。
    TooManyRefs { count: usize, max: usize },
    /// 第 `index` 条形不合法（预检，未发起任何 unlock）。
    InvalidRef {
        index: usize,
        reason: InvalidRefReason,
    },
    /// 第 `index` 条与第 `first` 条重复（预检，未发起任何 unlock）。
    DuplicateRef { index: usize, first: usize },
    /// 第 `index` 条解锁失败。
    Unlock {
        index: usize,
        reason: UnlockError,
        injected: usize,
    },
    /// 第 `index` 条移交失败。
    Sink {
        index: usize,
        reason: SinkError,
        injected: usize,
    },
}

impl InjectError {
    /// 失败前已注入条数（预检类失败恒为 0：预检不通过时一条都不发起）。
    pub fn injected(&self) -> usize {
        match self {
            InjectError::Unlock { injected, .. } | InjectError::Sink { injected, .. } => *injected,
            _ => 0,
        }
    }

    /// 出错条目的下标（0 起计）；[`InjectError::TooManyRefs`] 无对应条目 ⇒ `None`。
    pub fn index(&self) -> Option<usize> {
        match self {
            InjectError::TooManyRefs { .. } => None,
            InjectError::InvalidRef { index, .. }
            | InjectError::DuplicateRef { index, .. }
            | InjectError::Unlock { index, .. }
            | InjectError::Sink { index, .. } => Some(*index),
        }
    }

    /// 稳定短码，供上层映射（⛔ 与明文无关）。
    pub fn code(&self) -> &'static str {
        match self {
            InjectError::TooManyRefs { .. } => "inject.too_many_refs",
            InjectError::InvalidRef { .. } => "inject.invalid_ref",
            InjectError::DuplicateRef { .. } => "inject.duplicate_ref",
            InjectError::Unlock { reason, .. } => reason.code(),
            InjectError::Sink { reason, .. } => reason.code(),
        }
    }
}

impl fmt::Display for InjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InjectError::TooManyRefs { count, max } => {
                write!(f, "引用条数 {count} 超过上限 {max}（一条都未解锁）")
            }
            InjectError::InvalidRef { index, reason } => {
                write!(
                    f,
                    "第 {index} 条引用 id 形态不合法：{reason}（一条都未解锁）"
                )
            }
            InjectError::DuplicateRef { index, first } => {
                write!(f, "第 {index} 条引用与第 {first} 条重复（一条都未解锁）")
            }
            InjectError::Unlock {
                index,
                reason,
                injected,
            } => write!(f, "第 {index} 条解锁失败（已注入 {injected} 条）：{reason}"),
            InjectError::Sink {
                index,
                reason,
                injected,
            } => write!(f, "第 {index} 条移交失败（已注入 {injected} 条）：{reason}"),
        }
    }
}

impl std::error::Error for InjectError {}

/// 环境启动时把 `refs` 逐条解成明文并移交给 `sink`。
///
/// 1. **先全量预检**：条数 ≤ [`MAX_REFS`]、每条形合法、无重复；任一项不满足 ⇒
///    直接返回错误且**一条 unlock 都不发起**（不部分开工）。
/// 2. **逐条串行**：`unlock` 完成后立刻 `accept`（明文移交），才进入下一条。
/// 3. **失败即中止**：任一条失败 ⇒ 立即返回，不吞错、不重试、不跳过；失败条
///    不计入报告。
/// 4. **即用即弃**：明文不进 [`InjectReport`] 也不进 [`InjectError`]，不跨调用保留。
/// 5. **重复引用显式拒绝**（`DuplicateRef`）：同一环境启动对同一引用解两次明文 =
///    多一条审计 + 多一份明文在内存里。
pub async fn inject_credentials<U, S>(
    unlock: &U,
    refs: &[CredRefId],
    sink: &mut S,
) -> Result<InjectReport, InjectError>
where
    U: SecretUnlock,
    S: CredentialSink,
{
    validate_all(refs)?;
    let mut report = InjectReport::default();
    for (index, r) in refs.iter().enumerate() {
        let plaintext = unlock
            .unlock(r)
            .await
            .map_err(|reason| InjectError::Unlock {
                index,
                reason,
                injected: report.len(),
            })?;
        sink.accept(r, plaintext)
            .map_err(|reason| InjectError::Sink {
                index,
                reason,
                injected: report.len(),
            })?;
        report.refs.push(r.clone());
    }
    Ok(report)
}

/// 全量预检：**不发起任何 unlock**。顺序：条数 → 逐条形 → 逐条查重。
fn validate_all(refs: &[CredRefId]) -> Result<(), InjectError> {
    if refs.len() > MAX_REFS {
        return Err(InjectError::TooManyRefs {
            count: refs.len(),
            max: MAX_REFS,
        });
    }
    let mut first_seen: BTreeMap<&str, usize> = BTreeMap::new();
    for (index, r) in refs.iter().enumerate() {
        r.validate()
            .map_err(|reason| InjectError::InvalidRef { index, reason })?;
        if let Some(&first) = first_seen.get(r.as_str()) {
            return Err(InjectError::DuplicateRef { index, first });
        }
        first_seen.insert(r.as_str(), index);
    }
    Ok(())
}
