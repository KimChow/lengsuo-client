//! 契约 §5.3.1 的**载荷层**：请求 / 响应字段表 + `clientDataJSON` 模板。
//!
//! 字节定义的唯一真相是契约 §5.3.1 的字段表 ⇒ 本模块把那张表**逐字**落成
//! Rust 结构（字段名 / 类型 / 必填性 / base64url 口径一致）。
//!
//! # 只做宿主方向：收请求、发响应
//!
//! [`decode_request`]（`type` 0–10 请求字节 ⇒ [`Request`]）+ [`encode_response`]
//! （[`Response`] ⇒ `type` 0–9 响应字节）+ [`client_data_json`] + [`verify_nonce_echo`]。
//! 反方向的 `encode_request` / `decode_response`（扩展侧那半）本卡不做 ——
//! 单文件 700 行硬上限下的取舍，见仓外报告的「越界与取舍」。
//!
//! # 规则（契约 §5.3.1）
//!
//! - 每条请求必带 `nonce`；响应必**回显**同一条 `nonce`（[`verify_nonce_echo`]）。
//! - **未知字段一律忽略**（前向兼容）：多给字段**不**算错。
//! - 缺必填 / 类型不符 / 取值非法 ⇒ **具名错误**，⛔ 不给默认值、⛔ 不 panic。
//! - 载荷内二进制字段一律 **base64url（无 padding）**，解码时逐字段校验。
//! - 自设：`nonce` 收 `u64`（扩展侧 `newNonce()` 实际只出 u32，
//!   `fido2_page_script.js:81-83`）；`expires_in` 按契约收 `u32`；`origin` 加
//!   fail-closed 形状校验（只收 `http(s)://` + 授权段）；`null` 视为字段缺席；
//!   夹具一律合成值。逐条依据见仓外报告。
//!
//! # type 10 的方向张力（本卡不裁定）
//!
//! 契约 §5.3 把 11 种类型**全部**标成「扩展 → host」；§5.3.1 的表却在 type 10
//! 的**响应**列写「**仅宿主 → 扩展**，无载荷」；[`crate::message`] 又写「契约
//! 没有定义 host → 扩展 的方向」。三处表述互不一致 ⇒ 本模块**只**把 type 10 的
//! **载荷**定义成空（`{}`，即 [`Request::UseNativeResponse`]），**不裁定方向**；
//! [`Response`] 没有 type 10 变体 ⇒ 构造上不可能编出 type 10 的响应载荷。

use crate::base64url::{self, Base64UrlError};
use crate::json::{self, Fields, JsonError, ObjectBuilder, Value};
use crate::message::MessageType;

/// 载荷解码 / 编码失败（全部 fail-closed：不给部分结果、不给默认值、不 panic）。
///
/// 变体只带**字段级**定位信息 —— 「是哪个 type 的载荷」由调用方知道
/// （它手里就有 [`MessageType`]）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    /// 载荷不是合法 JSON，或结构 / 类型不符（含缺必填、字段类型不符）。
    #[error("载荷 JSON 非法：{0}")]
    Json(JsonError),
    /// 二进制字段不是合法 base64url（无 padding）。
    #[error("载荷字段 {field:?} 不是合法 base64url：{source}")]
    InvalidBinary {
        /// 出问题的字段名。
        field: &'static str,
        /// base64url 的具体失败。
        source: Base64UrlError,
    },
    /// 字段取值非法（如 `origin` 不是合法的 `http(s)://` 授权段）。
    #[error("载荷字段 {field:?} 取值非法：{reason}")]
    InvalidValue {
        /// 出问题的字段名。
        field: &'static str,
        /// 人读的原因。
        reason: &'static str,
    },
    /// 响应回显的 `nonce` 与请求的不一致。
    #[error("响应 nonce {response} 与请求 nonce {request} 不一致")]
    NonceMismatch {
        /// 请求里的 `nonce`。
        request: u64,
        /// 响应回显的 `nonce`。
        response: u64,
    },
}
impl From<JsonError> for PayloadError {
    fn from(error: JsonError) -> Self {
        Self::Json(error)
    }
}

/// `clientDataJSON` 的 `type` 字段取值（契约 §5.3.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientDataKind {
    /// `webauthn.create`（passkey 创建）。
    Create,
    /// `webauthn.get`（passkey 取断言）。
    Get,
}
impl ClientDataKind {
    /// 线上字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "webauthn.create",
            Self::Get => "webauthn.get",
        }
    }
}

/// 凭据条目种类（契约 §5.3.1 的 `kind`，只允许这三值）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    /// 密码条目。
    Password,
    /// TOTP 条目。
    Totp,
    /// passkey 条目。
    Passkey,
}
impl CredentialKind {
    /// 线上字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Totp => "totp",
            Self::Passkey => "passkey",
        }
    }
}

/// 风控预检结论（契约 §5.3.1 的 `decision`；缺省由调用方定为 deny）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// 允许。
    Allow,
    /// 拒绝。
    Deny,
}
impl Decision {
    /// 线上字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}
/// 列举凭据返回的一条（响应 `items[]` 元素）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialItem {
    /// 凭据内部句柄（列举返回的 `id`，也是后续 `ref` 的来源）。
    pub id: String,
    /// 信赖方标识。
    pub rp_id: String,
    /// 条目种类。
    pub kind: CredentialKind,
    /// 用户名（可选）。
    pub username: Option<String>,
}
/// passkey 的用户信息（请求 `user{}`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfo {
    /// `user.id`：原始字节的 **base64url**（无 padding）。
    pub id: String,
    /// `user.name`。
    pub name: String,
    /// `user.display_name`。
    pub display_name: String,
}

// ---------------------------------------------------------------- 请求载荷
/// type 0 请求：`{nonce, store_id?}`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListCredentialsRequest {
    /// 一次性随机数，防重放（§5.1）。
    pub nonce: u64,
    /// 环境 / 店铺标识；省略时用连接上下文默认店铺。
    pub store_id: Option<String>,
}

/// type 1 请求：`{nonce, origin, username?}`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetPasswordRequest {
    /// 一次性随机数。
    pub nonce: u64,
    /// 页面 origin（= `location.origin`）。
    pub origin: String,
    /// 用户名（可选）。
    pub username: Option<String>,
}

/// type 2 请求：`{nonce, ref}`。
///
/// ⚠️ `ref` 是 Rust 关键字 ⇒ 字段写 `r#ref`，**线上键名仍是 `ref`**。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetTotpRequest {
    /// 一次性随机数。
    pub nonce: u64,
    /// 凭据引用（列举返回的 `id`）。
    pub r#ref: String,
}

/// type 3 请求：`{nonce, origin, rp_id, challenge, user:{id,name,display_name}}`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyCreateRequest {
    /// 一次性随机数。
    pub nonce: u64,
    /// 页面 origin。
    pub origin: String,
    /// 信赖方标识。
    pub rp_id: String,
    /// 挑战原始字节的 **base64url**（无 padding）。
    pub challenge: String,
    /// 用户信息。
    pub user: UserInfo,
}

/// type 4 请求：`{nonce, origin, rp_id, challenge, allow_ids:[...]}`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyGetRequest {
    /// 一次性随机数。
    pub nonce: u64,
    /// 页面 origin。
    pub origin: String,
    /// 信赖方标识。
    pub rp_id: String,
    /// 挑战原始字节的 **base64url**（无 padding）。
    pub challenge: String,
    /// 允许的凭据 id（原始字节的 **base64url** 列表）。
    pub allow_ids: Vec<String>,
}

/// type 5 请求：`{nonce, origin, username, password}`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavePasswordRequest {
    /// 一次性随机数。
    pub nonce: u64,
    /// 页面 origin。
    pub origin: String,
    /// 用户名。
    pub username: String,
    /// 密码。
    pub password: String,
}

/// type 6 请求：`{nonce, origin}`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskCheckRequest {
    /// 一次性随机数。
    pub nonce: u64,
    /// 页面 origin。
    pub origin: String,
}

/// type 7 请求：`{nonce, ref}`。⚠️ 字段写 `r#ref`，线上键名仍是 `ref`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokePasskeyRefRequest {
    /// 一次性随机数。
    pub nonce: u64,
    /// 凭据引用。
    pub r#ref: String,
}

/// type 8 请求：`{nonce, recovery_code}`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverRequest {
    /// 一次性随机数。
    pub nonce: u64,
    /// 恢复码。
    pub recovery_code: String,
}

/// type 9 请求：`{nonce, store_id}`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthQueryRequest {
    /// 一次性随机数。
    pub nonce: u64,
    /// 环境 / 店铺标识（必填，无默认）。
    pub store_id: String,
}

// ---------------------------------------------------------------- 响应载荷
/// type 0 响应：`{nonce, items:[{id, rp_id, kind, username?}]}`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListCredentialsResponse {
    /// 回显请求的 `nonce`。
    pub nonce: u64,
    /// 条目列表（可为空数组）。
    pub items: Vec<CredentialItem>,
}

/// type 1 响应：`{nonce, password}`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetPasswordResponse {
    /// 回显请求的 `nonce`。
    pub nonce: u64,
    /// 密码。
    pub password: String,
}

/// type 2 响应：`{nonce, code, expires_in}`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetTotpResponse {
    /// 回显请求的 `nonce`。
    pub nonce: u64,
    /// 6 位验证码。
    pub code: String,
    /// 剩余有效秒数（u32）。
    pub expires_in: u32,
}

/// type 3 响应：`{nonce, credential_id, cose_key_b64, auth_data_b64,
/// client_data_json_b64, signature_b64}`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyCreateResponse {
    /// 回显请求的 `nonce`。
    pub nonce: u64,
    /// 凭据 id：16 字节 raw bytes 的 base64url（§1.3）。
    pub credential_id: String,
    /// COSE_Key（§2.2，77 字节）的 base64url。
    pub cose_key_b64: String,
    /// authData（§2）的 base64url。
    pub auth_data_b64: String,
    /// 宿主签名时覆盖的 clientDataJSON 的 base64url（与签名输入**字节相等**）。
    pub client_data_json_b64: String,
    /// `authData || SHA-256(clientDataJSON)` 的 ES256 签名（base64url）。
    pub signature_b64: String,
}

/// type 4 响应：`{nonce, credential_id, auth_data_b64, client_data_json_b64,
/// signature_b64, user_handle?}`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyGetResponse {
    /// 回显请求的 `nonce`。
    pub nonce: u64,
    /// 凭据 id（base64url）。
    pub credential_id: String,
    /// authData 的 base64url。
    pub auth_data_b64: String,
    /// clientDataJSON 的 base64url。
    pub client_data_json_b64: String,
    /// ES256 签名（base64url）。
    pub signature_b64: String,
    /// user handle（base64url，可选）。
    pub user_handle: Option<String>,
}

/// type 5 响应：`{nonce, ok}`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavePasswordResponse {
    /// 回显请求的 `nonce`。
    pub nonce: u64,
    /// 是否成功。
    pub ok: bool,
}

/// type 6 响应：`{nonce, decision}`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskCheckResponse {
    /// 回显请求的 `nonce`。
    pub nonce: u64,
    /// 预检结论。
    pub decision: Decision,
}

/// type 7 响应：`{nonce, ok}`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokePasskeyRefResponse {
    /// 回显请求的 `nonce`。
    pub nonce: u64,
    /// 是否成功。
    pub ok: bool,
}

/// type 8 响应：`{nonce, ok}`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverResponse {
    /// 回显请求的 `nonce`。
    pub nonce: u64,
    /// 是否成功。
    pub ok: bool,
}

/// type 9 响应：`{nonce, granted}`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthQueryResponse {
    /// 回显请求的 `nonce`。
    pub nonce: u64,
    /// 是否已授权。
    pub granted: bool,
}

// ---------------------------------------------------------------- 载荷枚举

/// 扩展 → host 的请求载荷（type 0–10）。
///
/// `type = 10`（[`Self::UseNativeResponse`]）的载荷是**空对象** `{}`：契约
/// §5.3.1 的表把它列成 `{}`（无载荷）⇒ 本模块只把载荷定义成空，
/// ⛔ 不裁定方向（见模块文档的「方向张力」）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// type 0。
    ListCredentials(ListCredentialsRequest),
    /// type 1。
    GetPassword(GetPasswordRequest),
    /// type 2。
    GetTotp(GetTotpRequest),
    /// type 3。
    PasskeyCreate(PasskeyCreateRequest),
    /// type 4。
    PasskeyGet(PasskeyGetRequest),
    /// type 5。
    SavePassword(SavePasswordRequest),
    /// type 6。
    RiskCheck(RiskCheckRequest),
    /// type 7。
    RevokePasskeyRef(RevokePasskeyRefRequest),
    /// type 8。
    Recover(RecoverRequest),
    /// type 9。
    AuthQuery(AuthQueryRequest),
    /// type 10：无载荷（`{}`）。
    UseNativeResponse,
}

/// host → 扩展 的响应载荷（type 0–9）。
///
/// ⛔ 没有 type 10 变体：契约 §5.3.1 里 type 10 的响应无载荷（且它写的是
/// 「仅宿主 → 扩展」）⇒ 方向张力原样保留（见模块文档）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// type 0。
    ListCredentials(ListCredentialsResponse),
    /// type 1。
    GetPassword(GetPasswordResponse),
    /// type 2。
    GetTotp(GetTotpResponse),
    /// type 3。
    PasskeyCreate(PasskeyCreateResponse),
    /// type 4。
    PasskeyGet(PasskeyGetResponse),
    /// type 5。
    SavePassword(SavePasswordResponse),
    /// type 6。
    RiskCheck(RiskCheckResponse),
    /// type 7。
    RevokePasskeyRef(RevokePasskeyRefResponse),
    /// type 8。
    Recover(RecoverResponse),
    /// type 9。
    AuthQuery(AuthQueryResponse),
}

impl Request {
    /// 请求里的 `nonce`；`type = 10` 无载荷 ⇒ `None`。
    #[must_use]
    pub fn nonce(&self) -> Option<u64> {
        match self {
            Self::ListCredentials(request) => Some(request.nonce),
            Self::GetPassword(request) => Some(request.nonce),
            Self::GetTotp(request) => Some(request.nonce),
            Self::PasskeyCreate(request) => Some(request.nonce),
            Self::PasskeyGet(request) => Some(request.nonce),
            Self::SavePassword(request) => Some(request.nonce),
            Self::RiskCheck(request) => Some(request.nonce),
            Self::RevokePasskeyRef(request) => Some(request.nonce),
            Self::Recover(request) => Some(request.nonce),
            Self::AuthQuery(request) => Some(request.nonce),
            Self::UseNativeResponse => None,
        }
    }
}

impl Response {
    /// 响应回显的 `nonce`。
    #[must_use]
    pub fn nonce(&self) -> u64 {
        match self {
            Self::ListCredentials(response) => response.nonce,
            Self::GetPassword(response) => response.nonce,
            Self::GetTotp(response) => response.nonce,
            Self::PasskeyCreate(response) => response.nonce,
            Self::PasskeyGet(response) => response.nonce,
            Self::SavePassword(response) => response.nonce,
            Self::RiskCheck(response) => response.nonce,
            Self::RevokePasskeyRef(response) => response.nonce,
            Self::Recover(response) => response.nonce,
            Self::AuthQuery(response) => response.nonce,
        }
    }
}

/// 校验响应回显的 `nonce` 与请求的**逐字节相同**（契约 §5.3.1：响应必回显
/// 同一条 `nonce`，供扩展匹配请求与响应）。
///
/// # Errors
/// - 请求是 `type = 10`（无 `nonce`）⇒ [`JsonError::MissingField`]。
/// - 二者 `nonce` 不同 ⇒ [`PayloadError::NonceMismatch`]。
pub fn verify_nonce_echo(request: &Request, response: &Response) -> Result<(), PayloadError> {
    match request.nonce() {
        Some(nonce) if nonce == response.nonce() => Ok(()),
        Some(nonce) => Err(PayloadError::NonceMismatch {
            request: nonce,
            response: response.nonce(),
        }),
        None => Err(PayloadError::Json(JsonError::MissingField {
            field: "nonce",
        })),
    }
}

/// 生成 `clientDataJSON`（宿主生成，**单一可信来源**；页面不得重新编码）。
///
/// 逐字节等于契约 §5.3.1 的固定模板：无空格、键顺序固定
/// （`type` → `challenge` → `origin` → `crossOrigin`）、`crossOrigin` 为 `false`。
#[must_use]
pub fn client_data_json(kind: ClientDataKind, challenge_b64url: &str, origin: &str) -> String {
    json::encode(
        &ObjectBuilder::new()
            .push("type", kind.as_str())
            .push("challenge", challenge_b64url)
            .push("origin", origin)
            .push("crossOrigin", false)
            .build(),
    )
}

/// 把响应编成契约 §5.3.1 的载荷字节（UTF-8 JSON）。
#[must_use]
pub fn encode_response(response: &Response) -> Vec<u8> {
    json::encode(&response_value(response)).into_bytes()
}

fn response_value(response: &Response) -> Value {
    match response {
        Response::ListCredentials(r) => ObjectBuilder::new()
            .push("nonce", r.nonce)
            .push(
                "items",
                Value::Array(r.items.iter().map(credential_item_value).collect()),
            )
            .build(),
        Response::GetPassword(r) => ObjectBuilder::new()
            .push("nonce", r.nonce)
            .push("password", r.password.as_str())
            .build(),
        Response::GetTotp(r) => ObjectBuilder::new()
            .push("nonce", r.nonce)
            .push("code", r.code.as_str())
            .push("expires_in", u64::from(r.expires_in))
            .build(),
        Response::PasskeyCreate(r) => ObjectBuilder::new()
            .push("nonce", r.nonce)
            .push("credential_id", r.credential_id.as_str())
            .push("cose_key_b64", r.cose_key_b64.as_str())
            .push("auth_data_b64", r.auth_data_b64.as_str())
            .push("client_data_json_b64", r.client_data_json_b64.as_str())
            .push("signature_b64", r.signature_b64.as_str())
            .build(),
        Response::PasskeyGet(r) => ObjectBuilder::new()
            .push("nonce", r.nonce)
            .push("credential_id", r.credential_id.as_str())
            .push("auth_data_b64", r.auth_data_b64.as_str())
            .push("client_data_json_b64", r.client_data_json_b64.as_str())
            .push("signature_b64", r.signature_b64.as_str())
            .opt("user_handle", &r.user_handle)
            .build(),
        Response::SavePassword(r) => ObjectBuilder::new()
            .push("nonce", r.nonce)
            .push("ok", r.ok)
            .build(),
        Response::RiskCheck(r) => ObjectBuilder::new()
            .push("nonce", r.nonce)
            .push("decision", r.decision.as_str())
            .build(),
        Response::RevokePasskeyRef(r) => ObjectBuilder::new()
            .push("nonce", r.nonce)
            .push("ok", r.ok)
            .build(),
        Response::Recover(r) => ObjectBuilder::new()
            .push("nonce", r.nonce)
            .push("ok", r.ok)
            .build(),
        Response::AuthQuery(r) => ObjectBuilder::new()
            .push("nonce", r.nonce)
            .push("granted", r.granted)
            .build(),
    }
}

fn credential_item_value(item: &CredentialItem) -> Value {
    ObjectBuilder::new()
        .push("id", item.id.as_str())
        .push("rp_id", item.rp_id.as_str())
        .push("kind", item.kind.as_str())
        .opt("username", &item.username)
        .build()
}

/// 解出请求载荷；`message_type` 来自帧头（契约 §5.3），决定载荷形状。
///
/// # Errors
/// - 载荷不是合法 JSON / 不是对象 ⇒ [`PayloadError::Json`]。
/// - 缺必填字段 ⇒ [`JsonError::MissingField`]；类型不符 ⇒
///   [`JsonError::FieldTypeMismatch`]。
/// - 二进制字段不是合法 base64url ⇒ [`PayloadError::InvalidBinary`]。
/// - `origin` 形状非法 ⇒ [`PayloadError::InvalidValue`]。
/// - `type = 10` 的载荷必须是 `{}`（空对象或只含未知字段）。
pub fn decode_request(message_type: MessageType, bytes: &[u8]) -> Result<Request, PayloadError> {
    let value = json::parse(bytes)?;
    let fields = Fields::new(&value, "请求载荷")?;
    let request = match message_type {
        MessageType::ListCredentials => Request::ListCredentials(ListCredentialsRequest {
            nonce: fields.uint("nonce")?,
            store_id: fields.opt_string("store_id")?,
        }),
        MessageType::GetPassword => Request::GetPassword(GetPasswordRequest {
            nonce: fields.uint("nonce")?,
            origin: origin_field(&fields)?,
            username: fields.opt_string("username")?,
        }),
        MessageType::GetTotp => Request::GetTotp(GetTotpRequest {
            nonce: fields.uint("nonce")?,
            r#ref: fields.string("ref")?,
        }),
        MessageType::PasskeyCreate => {
            let user = fields.object("user")?;
            Request::PasskeyCreate(PasskeyCreateRequest {
                nonce: fields.uint("nonce")?,
                origin: origin_field(&fields)?,
                rp_id: fields.string("rp_id")?,
                challenge: binary_field(&fields, "challenge")?,
                user: UserInfo {
                    id: binary_field(&user, "id")?,
                    name: user.string("name")?,
                    display_name: user.string("display_name")?,
                },
            })
        }
        MessageType::PasskeyGet => Request::PasskeyGet(PasskeyGetRequest {
            nonce: fields.uint("nonce")?,
            origin: origin_field(&fields)?,
            rp_id: fields.string("rp_id")?,
            challenge: binary_field(&fields, "challenge")?,
            allow_ids: binary_strings(&fields, "allow_ids")?,
        }),
        MessageType::SavePassword => Request::SavePassword(SavePasswordRequest {
            nonce: fields.uint("nonce")?,
            origin: origin_field(&fields)?,
            username: fields.string("username")?,
            password: fields.string("password")?,
        }),
        MessageType::RiskCheck => Request::RiskCheck(RiskCheckRequest {
            nonce: fields.uint("nonce")?,
            origin: origin_field(&fields)?,
        }),
        MessageType::RevokePasskeyRef => Request::RevokePasskeyRef(RevokePasskeyRefRequest {
            nonce: fields.uint("nonce")?,
            r#ref: fields.string("ref")?,
        }),
        MessageType::Recover => Request::Recover(RecoverRequest {
            nonce: fields.uint("nonce")?,
            recovery_code: fields.string("recovery_code")?,
        }),
        MessageType::AuthQuery => Request::AuthQuery(AuthQueryRequest {
            nonce: fields.uint("nonce")?,
            store_id: fields.string("store_id")?,
        }),
        MessageType::UseNativeResponse => Request::UseNativeResponse,
    };
    Ok(request)
}

// ------------------------------------------------------------ 字段层自设校验

/// `origin` 形状校验（自设 fail-closed 规则，见模块文档）。
fn origin_field(fields: &Fields<'_>) -> Result<String, PayloadError> {
    let field = "origin";
    let origin = fields.string(field)?;
    let invalid = |reason: &'static str| PayloadError::InvalidValue { field, reason };
    let Some(authority) = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
    else {
        return Err(invalid("必须以 http:// 或 https:// 开头"));
    };
    if authority.is_empty() {
        return Err(invalid("缺少主机"));
    }
    for character in authority.chars() {
        let forbidden = matches!(character, '"' | '\\' | '@' | '/' | '?' | '#');
        if forbidden || character.is_whitespace() || (character as u32) < 0x20 {
            return Err(invalid("授权段含非法字符"));
        }
    }
    Ok(origin)
}

/// 必填的 base64url 字段：先取字符串，再逐字节校验编码。
fn binary_field(fields: &Fields<'_>, field: &'static str) -> Result<String, PayloadError> {
    let text = fields.string(field)?;
    base64url::decode(&text).map_err(|source| PayloadError::InvalidBinary { field, source })?;
    Ok(text)
}

/// 必填的 base64url **字符串数组**字段，逐元素校验。
fn binary_strings(fields: &Fields<'_>, field: &'static str) -> Result<Vec<String>, PayloadError> {
    let items = fields.strings(field)?;
    for text in &items {
        base64url::decode(text).map_err(|source| PayloadError::InvalidBinary { field, source })?;
    }
    Ok(items)
}
