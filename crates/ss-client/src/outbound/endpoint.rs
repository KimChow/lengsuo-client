//! 其余七协议的出口端点形状：URL → `lengsuo-egress` 协议判别。
//!
//! `ss://` **不在这里**：它的实现是本仓既有的 AEAD 隧道（见 [`super::dialer`]），
//! 不走 `lengsuo-egress`，故 [`super::Dialer::new`] 里先按 `ss://` 前缀分流。
//! 本模块只负责**其余七协议**（vless / vmess / trojan / hysteria2 / anytls /
//! wireguard / ss2022）的端点形状解析。
//!
//! # 形状
//!
//! ```text
//! <scheme>://<userinfo>@<host>:<port>[#<remark>]
//! ```
//!
//! | scheme | userinfo | 说明 |
//! |---|---|---|
//! | `ss2022://` | `<method>:<psk>` | 与 `ss://` 同形；psk 落 `auth.secret_key` |
//! | `vless://` / `vmess://` | `<uuid>` | 16 字节 UUID 文本 |
//! | `trojan://` / `anytls://` / `hysteria2://` | `<password>` | 口令 / auth 串 |
//! | `wireguard://` | `<private_key>:<public_key>` | base64 静态密钥对（各 32 字节） |
//!
//! **本仓没有这些 scheme 的既有 URL 约定**（`lengsuo-node` 用 JSON 配置），故
//! 这里定义的是一套**本客户端自己的、最小且统一**的形状；它**不与**第三方分享
//! 链接格式（vless 分享链接的 `?security=…` 段、vmess 的 base64 JSON）兼容 ——
//! 那属于协议级互通矩阵，不在本卡。
//!
//! # fail-closed
//!
//! - 形状非法、scheme 未知、**带查询参数**（`?`）一律报错；
//! - 错误消息**只说形状**，**不回显任何取值**（取值可能是口令、PSK 或私钥）；
//! - 查询参数选择**显式拒绝**而不是静默忽略：静默丢弃 `?security=none` 这类
//!   约定等于悄悄改变安全语义，正是 fail-closed 要禁止的。
//!
//! # 为什么形状要按 `lengsuo_egress::config::NodeConfig` 校验
//!
//! 客户端不复制一份协议配置模型：形状解析直接构造共享出口层的 [`NodeConfig`]，
//! 并调用其 `validate()`（UUID / 静态密钥 / method 的形态校验都在那里）。这样
//! 「客户端认得的形状」与「出口层能拨的形状」永远是同一个。
//!
//! 校验通过后配置即释放：本卡客户端数据面**尚未**接线（见 [`super::Dialer`] 的
//! `NotWiredYet`），留着一份不能拨的配置只会是死代码。

use lengsuo_egress::config::{AuthConfig, Endpoint as NodeEndpoint, NodeConfig, Protocol};
use lengsuo_egress::outbound_ss2022::{base64_decode_public, method_from_name};

use super::DialError;

/// 解析其余七协议的端点形状，返回共享出口层的协议判别。
///
/// 形状非法 ⇒ [`DialError::InvalidUrl`]（消息只说形状，不回显取值）；
/// 未知 scheme ⇒ 同样是 `InvalidUrl`（不猜、不回落）。
pub(crate) fn classify(raw: &str) -> Result<Protocol, DialError> {
    let trimmed = raw.trim();
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        return Err(DialError::InvalidUrl("missing `scheme://`"));
    };
    let protocol = protocol_of(scheme)?;
    // 备注（`#` 之后）不参与解析。
    let rest = rest.split('#').next().unwrap_or("");
    if rest.contains('?') {
        return Err(DialError::InvalidUrl(
            "query parameters are not supported (unknown parameters are never silently dropped)",
        ));
    }
    // 口令里可能有裸 `@`：用**最后一个** `@` 切分（与 `ss://` 同规则）。
    let Some((userinfo, host_part)) = rest.rsplit_once('@') else {
        return Err(DialError::InvalidUrl("missing credentials"));
    };
    let Some((host, port_text)) = host_part.rsplit_once(':') else {
        return Err(DialError::InvalidUrl("missing port"));
    };
    if host.is_empty() {
        return Err(DialError::InvalidUrl("host must not be empty"));
    }
    let port: u16 =
        port_text
            .parse()
            .ok()
            .filter(|port| *port != 0)
            .ok_or(DialError::InvalidUrl(
                "port must be an integer in 1..=65535",
            ))?;

    let (auth, method) = credentials(protocol, userinfo)?;
    let node = NodeConfig {
        // 名字只进出口层校验的错误文本；用常量，不带端点或凭据。
        name: "ss-client-outbound".to_owned(),
        protocol,
        endpoint: NodeEndpoint {
            host: host.to_owned(),
            port,
        },
        probe_target: None,
        // URL 形状不承载 TLS 段（信任锚 / SNI / REALITY 参数）——见模块文档。
        tls: None,
        auth,
        method,
        reality: None,
        vision: None,
        encryption: None,
        xel: None,
        mux: None,
        forward: None,
    };
    // 形态校验交给共享出口层（UUID / 静态密钥 / method），不在这里复制一份。
    // 失败只报形状：`ConfigError` 的 reason 不含凭据取值。
    node.validate()
        .map_err(|_| DialError::InvalidUrl("endpoint shape rejected by the egress validator"))?;
    Ok(protocol)
}

/// **唯一一处**「scheme → 协议」映射（`ss://` 由 [`super::Dialer::new`] 先行分流，
/// 故 `ss` 不在表内：本表与那张分流表合起来覆盖八项）。
fn protocol_of(scheme: &str) -> Result<Protocol, DialError> {
    match scheme {
        "ss2022" => Ok(Protocol::Ss2022),
        "vless" => Ok(Protocol::Vless),
        "vmess" => Ok(Protocol::Vmess),
        "trojan" => Ok(Protocol::Trojan),
        "hysteria2" => Ok(Protocol::Hysteria),
        "anytls" => Ok(Protocol::AnyTls),
        "wireguard" => Ok(Protocol::Wireguard),
        _ => Err(DialError::InvalidUrl("unknown outbound scheme")),
    }
}

/// 按协议切分 `userinfo` 并落到共享出口层的凭据结构上。
///
/// 返回 `(凭据, method)`；`method` 只有 ss2022 需要（其余协议为 `None`）。
fn credentials(
    protocol: Protocol,
    userinfo: &str,
) -> Result<(AuthConfig, Option<String>), DialError> {
    let mut auth = AuthConfig {
        password: String::new(),
        secret_key: None,
        private_key: None,
        public_key: None,
    };
    match protocol {
        Protocol::Ss2022 => {
            let Some((method, psk)) = userinfo.split_once(':') else {
                return Err(DialError::InvalidUrl("must be `ss2022://<method>:<psk>@…`"));
            };
            if method.is_empty() {
                return Err(DialError::InvalidUrl("encryption method must not be empty"));
            }
            // 与 `ss://` 一样在**加载期**就拒绝不支持的加密名，免得连不上才发现。
            if method_from_name(Some(method)).is_err() {
                return Err(DialError::InvalidUrl(
                    "unsupported encryption method for this client",
                ));
            }
            if psk.is_empty() {
                return Err(DialError::InvalidUrl("psk must not be empty"));
            }
            auth.secret_key = Some(psk.to_owned());
            Ok((auth, Some(method.to_owned())))
        }
        Protocol::Wireguard => {
            let Some((private, public)) = userinfo.split_once(':') else {
                return Err(DialError::InvalidUrl(
                    "must be `wireguard://<private_key>:<public_key>@…`",
                ));
            };
            if !is_static_key(private) || !is_static_key(public) {
                return Err(DialError::InvalidUrl(
                    "static keys must be 32-byte standard base64",
                ));
            }
            auth.private_key = Some(private.to_owned());
            auth.public_key = Some(public.to_owned());
            Ok((auth, None))
        }
        Protocol::Vless
        | Protocol::Vmess
        | Protocol::Trojan
        | Protocol::Hysteria
        | Protocol::AnyTls => {
            if userinfo.is_empty() {
                return Err(DialError::InvalidUrl("credential must not be empty"));
            }
            auth.password = userinfo.to_owned();
            Ok((auth, None))
        }
        // `ss://` 在 `Dialer::new` 里已按前缀分流到既有实现，不会走到这里。
        Protocol::Shadowsocks => Err(DialError::InvalidUrl(
            "`ss://` must be routed through the existing Shadowsocks path",
        )),
    }
}

/// WireGuard 静态密钥形状：标准 base64 解码后必须是 32 字节。
///
/// 复用出口层的解码器（`lengsuo_egress::outbound_ss2022::base64_decode_public`），
/// 不新增依赖、不复制第二套 base64。
fn is_static_key(text: &str) -> bool {
    base64_decode_public(text).is_some_and(|key| key.len() == 32)
}
