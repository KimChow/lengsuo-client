//! Hysteria2 出口：QUIC（TLS1.3/ALPN=h3）→ H3 认证 → TCP 承载请求。
//!
//! 语义来源（只读参考，固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）：
//! `transport/internet/hysteria/dialer.go` 的 `init`（`auth` 经 HTTP/3 请求头
//! `Hysteria-Auth` 提交，服务端以 **HTTP 状态码 233** 表示认证通过）+ `conn.go`/
//! `client.go` 的 TCP 承载（一条 QUIC 双向流 = 一个代理连接，首写
//! `varint(0x401) + TCPRequest`，随后读 `TCPResponse`，`status == 0` 才开始转发）。
//!
//! **认证完成的正向证据分两段**（本卡两段都要）：
//! 1. H3 认证：`HysteriaClient::connect` 返回 `Ok` 即 status=233（认证被拒时
//!    参考回 masquerade 404，本仓 `ConnectError::Auth(Rejected { status })`）；
//! 2. TCP 承载：`proxy::tcp_connect` 返回 `Ok` 即 `TCPResponse.status == Ok`，
//!    说明服务端**已为本次请求建立目标连接**（认证与路由都已通过）。
//!
//! 证书校验收口：`ClientConfig.roots_der` 由配置的 `tls.ca_pem` 提供，
//! 始终启用完整校验链。`tls.insecure` 需要协议 crate 暴露「自定义验证器」，
//! 而本仓 `lengsuo-hysteria` 的 `ClientConfig` 当前没有该开关（跨 crate 改动，
//! 见本卡报告）⇒ 此处继续 **fail-closed**，不静默直连、不回落明文。
//!
//! 偏离：拥塞控制用 quinn 默认（不移植 Brutal/BBR），`Hysteria-CC-RX` 仍按
//! 参考发送——与 `lengsuo-hysteria` 的互通结论一致（见其 docs 偏离清单）。

use std::net::SocketAddr;
use std::time::Duration;

use lengsuo_hysteria::proxy::{self, TcpProxyStream};
use lengsuo_hysteria::quic::{ClientConfig, HysteriaClient};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::CertificateDer;

use crate::config::NodeConfig;
use crate::outbound::{resolve_public, DialError};

/// hysteria 出站会话：H3 已认证（status=233）且 TCP 承载请求已被接受。
pub struct HysteriaOutbound {
    /// 已建立的代理流（TCPResponse 之后的 QUIC 双向流）。
    pub stream: TcpProxyStream,
    /// 目标地址文本 `host:port`（TCPRequest 里携带的那个）。
    pub target: String,
}

/// hysteria 出站：QUIC/H3 认证 → TCP 承载请求被接受。
pub async fn dial_hysteria(
    config: &NodeConfig,
    wait: Duration,
) -> Result<HysteriaOutbound, DialError> {
    let Some(tls) = config.tls.as_ref() else {
        return Err(DialError::InvalidTls(
            "hysteria 要求 tls 配置（QUIC 的 TLS1.3 承载）".to_owned(),
        ));
    };
    if tls.insecure {
        return Err(DialError::InvalidTls(
            "tls.insecure 对 hysteria 尚未接通：lengsuo-hysteria 的 ClientConfig 无跳过校验开关（需跨 crate 改动，见本卡报告）；自签场景请用 tls.ca_pem 固定信任锚".to_owned(),
        ));
    }
    let pem = tls.ca_pem.as_deref().unwrap_or_default();
    let roots_der: Vec<Vec<u8>> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| DialError::InvalidTls(format!("ca_pem 解析失败：{err}")))?
        .into_iter()
        .map(|der| der.to_vec())
        .collect();
    if roots_der.is_empty() {
        return Err(DialError::InvalidTls(
            "tls.ca_pem 未包含任何证书（本卡不加载系统根）".to_owned(),
        ));
    }
    let server_name = tls
        .server_name
        .clone()
        .unwrap_or_else(|| config.endpoint.host.clone());
    // hysteria 的 server_addr 必须是 IP:port（参考拒绝域名），因此解析走同一个
    // resolve，只是这里需要 `SocketAddr` 而不是 `TargetAddr`。
    let server_addr = resolve_hysteria_addr(config, wait).await?;

    let client = HysteriaClient::connect(ClientConfig {
        server_addr,
        server_name,
        auth: config.auth.password.clone(),
        roots_der,
        brutal_down: 0,
        // 出口运行时暂不协商 Brutal：保持 quinn 默认 CUBIC（空串 = 不注入），
        // 与本次改动前的行为一致；启用需在节点配置里显式给出带宽。
        brutal_up: 0,
        congestion: String::new(),
        peer_cc_rx: None,
    })
    .await?;

    let target = match &config.probe_target {
        Some(probe) => format!("{}:{}", probe.host, probe.port),
        None => format!("{}:{}", config.endpoint.host, config.endpoint.port),
    };
    let stream = proxy::tcp_connect(&client, &target).await?;
    Ok(HysteriaOutbound { stream, target })
}

/// 解析 hysteria 服务端 UDP 地址。复用 `outbound::resolve_public` 的解析逻辑，
/// 但结果必须能转成 `SocketAddr`（域名解析后取首个地址）。
async fn resolve_hysteria_addr(
    config: &NodeConfig,
    wait: Duration,
) -> Result<SocketAddr, DialError> {
    resolve_public(&config.endpoint.host, config.endpoint.port, wait).await
}
