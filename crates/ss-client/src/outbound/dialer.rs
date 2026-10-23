//! 出口拨号：八协议**一处分发** —— `ss://` 走本仓既有的 AEAD 隧道，
//! 其余七协议如实报「未接线」。
//!
//! `ss://` 仍沿用 `crates/ss-client/src/config/ss_url.rs` 的 URL 形状（该模块是
//! 私有 `mod`，无法从 `outbound` 复用，故此处只镜像同一套切分规则）：
//! `ss://<method>:<password>@<host>:<port>[#<remark>]`，口令与 `@` 之间用
//! **最后一个** `@` 切分，`#` 之后忽略。其余七协议的形状解析见
//! [`super::endpoint`]。
//!
//! 认证判据与 `crates/lengsuo-node/src/outbound_ss.rs` 一致：SS-AEAD 没有
//! 成功响应帧，**回程解出一个通过 AEAD 认证的 chunk** 才算建连成功；
//! 解不出即 `AuthFailed`，绝不回退明文或直连。
//!
//! # 未接线的七个协议（[`DialError::NotWiredYet`]）
//!
//! `Dialer::new` 会**构造并通过 `lengsuo-egress` 的 `NodeConfig::validate()`**
//! 校验这些协议的端点形状（形状非法 ⇒ `InvalidUrl`），但 `connect` 一律返回
//! `NotWiredYet`：`lengsuo-egress` 目前给它们提供的拨号入口是 **dry-run /
//! probe** 语义（见各自分支的文案），真正可转发的会话适配层仍在
//! `crates/lengsuo-node/src/forward/session/`，而 `ss-client` 依赖不到它。
//!
//! ⛔ 不静默回退 Shadowsocks、不静默直连、不假装成功 —— 如实报未接线。

use std::io;
use std::time::Duration;

use lengsuo_egress::config::Protocol;
use lengsuo_shadowsocks::{CipherSuite, TcpError, TcpReader, TcpWriter};
use ss_core::target::TargetAddr;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::config::OutboundConfig;

use super::endpoint;
use super::Tunnel;

/// 拨号失败原因。错误消息不含口令、salt 或主密钥。
#[derive(Debug, thiserror::Error)]
pub enum DialError {
    #[error("unsupported encryption method")]
    UnsupportedMethod,

    /// 出口 URL 形状不合法（消息只说形状，不回显取值）。
    #[error("invalid outbound url: {0}")]
    InvalidUrl(&'static str),

    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("connect or handshake timed out")]
    Timeout,

    #[error("server response failed AEAD authentication (wrong password or tampering)")]
    AuthFailed,

    #[error("target address cannot be encoded: {0}")]
    TargetEncode(&'static str),

    #[error("server closed without an authenticated response")]
    NoResponse,

    /// 形状已解析并校验，但本客户端的数据面**尚未**把该协议的出口实现接线。
    ///
    /// 携带 `"<协议名>: <原因>"`；原因见 [`Dialer::connect`] 各分支的文档。
    #[error("outbound not wired for this client yet: {0}")]
    NotWiredYet(&'static str),
}

/// 拨号器：持有出口协议判别与 `ss://` 参数，可重复建连。
///
/// 故意不实现 `Debug`：`Shadowsocks` 分支内部持有口令。
pub struct Dialer {
    kind: Kind,
    wait: Duration,
}

/// 「协议 → 出口实现」的判别：`Shadowsocks` 有参数，其余七个只报未接线。
enum Kind {
    /// `ss://`：既有 AEAD 隧道参数（行为逐字不变）。
    Shadowsocks {
        /// `host:port`（IPv6 带方括号，直接交给 `TcpStream::connect` 解析）。
        server: String,
        suite: CipherSuite,
        password: Vec<u8>,
    },
    /// 其余七协议：形状已过共享出口层校验，但数据面尚未接线。
    ///
    /// 变体名即协议名，`connect` 逐协议分支（见其实现）。
    Ss2022,
    Vless,
    Vmess,
    Trojan,
    Hysteria,
    AnyTls,
    Wireguard,
}

/// `ss://` 的最小结构（只读借用，不复制口令）。
struct Endpoint<'a> {
    method: &'a str,
    password: &'a str,
    host: &'a str,
    port: u16,
}

impl Dialer {
    /// 解析配置并选择套件。未知 method ⇒ [`DialError::UnsupportedMethod`]；
    /// 形状错误 ⇒ [`DialError::InvalidUrl`]。
    ///
    /// `ss://` 走既有解析与实现（行为逐字不变）；其余七协议交给
    /// [`endpoint::classify`] 做 fail-closed 形状解析。
    ///
    /// `connect_timeout_ms` 为 0 时按文档缺省 5000ms 处理（零时长会让
    /// `TcpReader` / `TcpWriter` 的截止时间立即过期）。
    pub fn new(cfg: OutboundConfig) -> Result<Self, DialError> {
        let timeout_ms = if cfg.connect_timeout_ms == 0 {
            5_000
        } else {
            cfg.connect_timeout_ms
        };
        let raw = cfg.ss_url.trim();
        let kind = if raw.starts_with("ss://") {
            let ep = parse_ss_url(raw)?;
            let suite = CipherSuite::from_name(ep.method).ok_or(DialError::UnsupportedMethod)?;
            Kind::Shadowsocks {
                server: format!("{}:{}", ep.host, ep.port),
                suite,
                password: ep.password.as_bytes().to_vec(),
            }
        } else {
            // 其余七协议：形状解析 + 共享出口层校验，再按协议选分支。
            match endpoint::classify(raw)? {
                Protocol::Ss2022 => Kind::Ss2022,
                Protocol::Vless => Kind::Vless,
                Protocol::Vmess => Kind::Vmess,
                Protocol::Trojan => Kind::Trojan,
                Protocol::Hysteria => Kind::Hysteria,
                Protocol::AnyTls => Kind::AnyTls,
                Protocol::Wireguard => Kind::Wireguard,
                // `classify` 不接受 `ss`，上面的前缀分流已处理。
                Protocol::Shadowsocks => {
                    return Err(DialError::InvalidUrl(
                        "`ss://` must be routed through the Shadowsocks path",
                    ));
                }
            }
        };
        Ok(Self {
            kind,
            wait: Duration::from_millis(timeout_ms),
        })
    }

    /// 建连并写请求（地址 + 首批载荷），然后**必须**读出一个通过 AEAD 认证的
    /// 回程 chunk。成功时该 chunk 同时作为 [`Tunnel::first_response`] 与隧道
    /// 读方向的首批字节。
    ///
    /// `first_payload` 与目标地址写在**同一次** `send` 中：先地址、后载荷，
    /// salt 由 `TcpWriter` 在首次 `send` 时生成并上线。
    pub async fn connect(
        &self,
        target: &TargetAddr,
        first_payload: &[u8],
    ) -> Result<Tunnel, DialError> {
        // 八协议**一处**分发：SS 走本仓既有实现，其余七协议如实报未接线。
        match &self.kind {
            Kind::Shadowsocks {
                server,
                suite,
                password,
            } => {
                self.connect_shadowsocks(server, *suite, password, target, first_payload)
                    .await
            }

            // 以下七个分支的**共同原因**：`lengsuo-egress` 目前只为它们提供
            // dry-run / probe 拨号入口，真正可转发的会话适配层仍在
            // `lengsuo-node/src/forward/session/`（`ss-client` 依赖不到）。
            // ⛔ 不静默回退 Shadowsocks、不静默直连、不假装成功。
            Kind::Ss2022 => Err(DialError::NotWiredYet(
                "ss2022: 客户端未接线（egress 的 ss2022 拨号是 dry-run：探测载荷写进请求变长头）",
            )),
            Kind::Vless => Err(DialError::NotWiredYet(
                "vless: 客户端未接线（URL 形状不承载 TLS 信任锚 / REALITY 参数）",
            )),
            Kind::Vmess => Err(DialError::NotWiredYet(
                "vmess: 客户端未接线（egress 的 vmess 拨号是 dry-run：写完探测载荷即发 EOF 帧）",
            )),
            Kind::Trojan => Err(DialError::NotWiredYet(
                "trojan: 客户端未接线（egress 的 trojan 拨号会在观察窗里读掉 1 字节回程数据）",
            )),
            Kind::Hysteria => Err(DialError::NotWiredYet(
                "hysteria: 客户端未接线（egress 出口是 probe 语义，且 TcpProxyStream 不能拆成读写两半）",
            )),
            Kind::AnyTls => Err(DialError::NotWiredYet(
                "anytls: 客户端未接线（egress 只做到认证 + ServerSettings，未开流）",
            )),
            Kind::Wireguard => Err(DialError::NotWiredYet(
                "wireguard: 客户端未接线（L3 隧道，转发层没有可转发的字节流，与 node 同判定）",
            )),
        }
    }

    /// `ss://` 的既有实现（逐字搬入方法，行为不变）。
    async fn connect_shadowsocks(
        &self,
        server: &str,
        suite: CipherSuite,
        password: &[u8],
        target: &TargetAddr,
        first_payload: &[u8],
    ) -> Result<Tunnel, DialError> {
        let stream = timeout(self.wait, TcpStream::connect(server))
            .await
            .map_err(|_| DialError::Timeout)?
            .map_err(DialError::Io)?;
        let (read_half, write_half) = stream.into_split();

        let mut writer = TcpWriter::new(write_half, suite, password, self.wait).map_err(map_tcp)?;
        let mut request = Vec::with_capacity(target.encoded_len() + first_payload.len());
        target
            .encode_checked(&mut request)
            .map_err(|_| DialError::TargetEncode("目标地址长度非法"))?;
        request.extend_from_slice(first_payload);
        writer.send(&request).await.map_err(map_tcp)?;

        let mut reader = TcpReader::new(read_half, suite, password, self.wait).map_err(map_tcp)?;
        let first_response = match reader.recv().await {
            Ok(Some(chunk)) => chunk,
            // 没有认证 chunk 就收尾：不能证明对端持有同一口令，fail-closed。
            Ok(None) => return Err(DialError::NoResponse),
            Err(err) => return Err(map_tcp(err)),
        };

        Ok(Tunnel::new(reader, writer, first_response))
    }
}

/// 把 TCP chunk 层的错误映射到拨号语义：认证失败与超时单独报告。
fn map_tcp(err: TcpError) -> DialError {
    match err {
        TcpError::Timeout => DialError::Timeout,
        TcpError::Authentication => DialError::AuthFailed,
        TcpError::Io(io) => DialError::Io(io),
        other => DialError::Io(io::Error::other(other.to_string())),
    }
}

/// 解析 `ss://<method>:<password>@<host>:<port>[#<remark>]`。
///
/// 只校验形状；method 是否受支持由 [`Dialer::new`] 通过 `CipherSuite` 判定。
/// 错误消息只说形状，不回显口令。
fn parse_ss_url(raw: &str) -> Result<Endpoint<'_>, DialError> {
    let trimmed = raw.trim();
    let Some(rest) = trimmed.strip_prefix("ss://") else {
        return Err(DialError::InvalidUrl("must start with `ss://`"));
    };
    // 备注（`#` 之后）不参与解析。
    let rest = rest.split('#').next().unwrap_or("");
    let Some((method, tail)) = rest.split_once(':') else {
        return Err(DialError::InvalidUrl(
            "must be `ss://<method>:<password>@<host>:<port>`",
        ));
    };
    if method.is_empty() {
        return Err(DialError::InvalidUrl("encryption method must not be empty"));
    }
    // 口令里可能有裸 `@`：用**最后一个** `@` 切分。
    let Some((password, host_part)) = tail.rsplit_once('@') else {
        return Err(DialError::InvalidUrl("missing credentials"));
    };
    if password.is_empty() {
        return Err(DialError::InvalidUrl("password must not be empty"));
    }
    let Some((host, port_text)) = host_part.rsplit_once(':') else {
        return Err(DialError::InvalidUrl("missing port"));
    };
    if host.is_empty() {
        return Err(DialError::InvalidUrl("host must not be empty"));
    }
    let port: u16 = port_text
        .parse()
        .map_err(|_| DialError::InvalidUrl("port must be an integer in 1..=65535"))?;
    if port == 0 {
        return Err(DialError::InvalidUrl(
            "port must be an integer in 1..=65535",
        ));
    }
    Ok(Endpoint {
        method,
        password,
        host,
        port,
    })
}
