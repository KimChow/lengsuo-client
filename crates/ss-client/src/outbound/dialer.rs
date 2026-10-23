//! 出口拨号：`ss://` → 套件 + 凭据 + 服务器，建立 AEAD TCP 隧道。
//!
//! 沿用 `crates/ss-client/src/config/ss_url.rs` 的 URL 形状（该模块是私有
//! `mod`，无法从 `outbound` 复用，故此处只镜像同一套切分规则）：
//! `ss://<method>:<password>@<host>:<port>[#<remark>]`，口令与 `@` 之间用
//! **最后一个** `@` 切分，`#` 之后忽略。
//!
//! 认证判据与 `crates/lengsuo-node/src/outbound_ss.rs` 一致：SS-AEAD 没有
//! 成功响应帧，**回程解出一个通过 AEAD 认证的 chunk** 才算建连成功；
//! 解不出即 `AuthFailed`，绝不回退明文或直连。

use std::io;
use std::time::Duration;

use lengsuo_shadowsocks::{CipherSuite, TcpError, TcpReader, TcpWriter};
use ss_core::target::TargetAddr;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::config::OutboundConfig;

use super::Tunnel;

/// 拨号失败原因。错误消息不含口令、salt 或主密钥。
#[derive(Debug, thiserror::Error)]
pub enum DialError {
    #[error("unsupported encryption method")]
    UnsupportedMethod,

    /// `ss://` 形状不合法（消息只说形状，不回显取值）。
    #[error("invalid ss:// url: {0}")]
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
}

/// 拨号器：持有出口服务器地址、套件与口令，可重复建连。
///
/// 故意不实现 `Debug`：内部持有口令。
pub struct Dialer {
    /// `host:port`（IPv6 带方括号，直接交给 `TcpStream::connect` 解析）。
    server: String,
    suite: CipherSuite,
    password: Vec<u8>,
    wait: Duration,
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
    /// `ss://` 形状错误 ⇒ [`DialError::InvalidUrl`]。
    ///
    /// `connect_timeout_ms` 为 0 时按文档缺省 5000ms 处理（零时长会让
    /// `TcpReader` / `TcpWriter` 的截止时间立即过期）。
    pub fn new(cfg: OutboundConfig) -> Result<Self, DialError> {
        let ep = parse_ss_url(&cfg.ss_url)?;
        let suite = CipherSuite::from_name(ep.method).ok_or(DialError::UnsupportedMethod)?;
        let timeout_ms = if cfg.connect_timeout_ms == 0 {
            5_000
        } else {
            cfg.connect_timeout_ms
        };
        Ok(Self {
            server: format!("{}:{}", ep.host, ep.port),
            suite,
            password: ep.password.as_bytes().to_vec(),
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
        let stream = timeout(self.wait, TcpStream::connect(&self.server))
            .await
            .map_err(|_| DialError::Timeout)?
            .map_err(DialError::Io)?;
        let (read_half, write_half) = stream.into_split();

        let mut writer =
            TcpWriter::new(write_half, self.suite, &self.password, self.wait).map_err(map_tcp)?;
        let mut request = Vec::with_capacity(target.encoded_len() + first_payload.len());
        target
            .encode_checked(&mut request)
            .map_err(|_| DialError::TargetEncode("目标地址长度非法"))?;
        request.extend_from_slice(first_payload);
        writer.send(&request).await.map_err(map_tcp)?;

        let mut reader =
            TcpReader::new(read_half, self.suite, &self.password, self.wait).map_err(map_tcp)?;
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
