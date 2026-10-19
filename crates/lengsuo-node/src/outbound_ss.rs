//! 传统 Shadowsocks（AEAD）出口：TCP → salt + 目标地址 + 首批载荷 → 回程认证。
//!
//! 语义来源（只读参考，固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）：
//! `proxy/shadowsocks/protocol.go` 的 `WriteTCPRequest`/`ReadTCPResponse`
//! ——客户端第一段明文就是 SOCKS5 风格的目标地址（本层用
//! `TargetAddr::encode_checked` 写出），随后是业务载荷。
//!
//! **认证完成的正向证据**：SS-AEAD 没有显式的成功响应帧，服务端在目标连接
//! 建立后直接回**已加密的响应帧**。因此判据是「回程方向能解出一个通过 AEAD
//! 认证的 chunk」：能解开说明对端持有同一口令（错误口令下 salt 派生出的
//! subkey 不同，AEAD 认证必然失败）。这与 trojan 的负向排除不同，也与
//! ss2022 的固定头归属校验不同。
//!
//! 本模块只做「配置 → 选套件 → 建连 → 写请求 → 读一个已认证 chunk」，
//! 分帧与 AEAD 全部复用 `lengsuo-shadowsocks::{TcpReader, TcpWriter}`。

use std::time::Duration;

use lengsuo_shadowsocks::{CipherSuite, TcpReader, TcpWriter};
use ss_core::target::TargetAddr;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::config::NodeConfig;
use crate::outbound::{connect_tcp, probe_target, DialError};

/// dry-run 首批载荷：不是业务数据，只让请求方向确实产生至少一个加密 chunk。
const DRY_RUN_PAYLOAD: &[u8] = b"lengsuo-node-dryrun";

/// shadowsocks 出站会话：请求方向已写出且回程方向已解出一个认证 chunk。
pub struct ShadowsocksOutbound {
    /// 已切分的连接两半（写端与读端各自持有独立 salt/nonce 序列）。
    pub read: tokio::io::ReadHalf<TcpStream>,
    pub write: tokio::io::WriteHalf<TcpStream>,
    /// 回程方向解出的首个已认证 chunk。
    pub first_response: Vec<u8>,
    pub target: TargetAddr,
}

/// shadowsocks 出站：选套件 → 建 TCP → 写地址 + 载荷 → 读一个已认证回程 chunk。
pub async fn dial_shadowsocks(
    config: &NodeConfig,
    wait: Duration,
) -> Result<ShadowsocksOutbound, DialError> {
    let suite = suite_from_method(config.method.as_deref())?;
    let password = config
        .auth
        .secret_key
        .as_deref()
        .ok_or_else(|| DialError::Rejected("shadowsocks 缺少 auth.secret_key".to_owned()))?;
    let stream = connect_tcp(config, wait).await?;
    let (mut read_half, mut write_half) = tokio::io::split(stream);
    let target = probe_target(config);

    // 请求方向：salt（首次 send 上线）+ 地址 + 首批载荷 → 写半关闭。
    let mut writer = TcpWriter::new(&mut write_half, suite, password.as_bytes(), wait)?;
    let mut payload = Vec::new();
    target
        .encode_checked(&mut payload)
        .map_err(|err| DialError::Resolve(format!("目标地址编码失败：{err}")))?;
    payload.extend_from_slice(DRY_RUN_PAYLOAD);
    writer.send(&payload).await?;
    writer.shutdown().await?;

    // 回程方向：解出一个已认证 chunk 即认证完成。（服务端认证失败时会关闭
    // 连接；`recv` 会得到 Truncated/Io，或返回 `None` 表示无数据即收尾。）
    let mut reader = TcpReader::new(&mut read_half, suite, password.as_bytes(), wait)?;
    let first_response = match timeout(wait, reader.recv()).await {
        Ok(Ok(Some(chunk))) => chunk,
        Ok(Ok(None)) => Vec::new(),
        Ok(Err(err)) => return Err(DialError::Shadowsocks(err)),
        Err(_) => return Err(DialError::Timeout),
    };
    // dry-run 不转发业务载荷；read_half 归还到 Outbound 供后续复用，
    // 不在本层调用 shutdown（ReadHalf 无该方法）。
    Ok(ShadowsocksOutbound {
        read: read_half,
        write: write_half,
        first_response,
        target,
    })
}

/// 由配置的 `method` 取套件。四类 AEAD 套件由 `ss-core` 决定，未知一律拒绝。
pub(crate) fn suite_from_method(method: Option<&str>) -> Result<CipherSuite, DialError> {
    let Some(name) = method else {
        return Err(DialError::Rejected("shadowsocks 缺少 method".to_owned()));
    };
    CipherSuite::from_name(name)
        .ok_or_else(|| DialError::Rejected(format!("不支持的加密方式：{name}")))
}
