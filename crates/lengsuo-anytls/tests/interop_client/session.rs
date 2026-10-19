//! 本仓 AnyTLS 客户端组装（仅供互通测试使用）：
//! tokio-rustls 客户端流之上的认证 → Settings(v=2) → SYN → PUSH(target+载荷) → 收帧
//! → FIN。帧方向与协商语义由 `client_state::ClientState` 状态机校验，字节由 frame 原语
//! 编解码；认证 padding 与参考一致（默认方案 "0=30-30" → 0 号记录 30 字节），但按记录的
//! padding 引擎（UpdatePadding 生成/应用）仍属未实现清单。
//! 语义基线 anytls-go fd6167a：客户端 Settings 含 v=2 / client / padding-md5 三键，
//! padding-md5 取默认方案摘要，使 server 不必下发 UpdatePadding 即完成 v=2 协商。
use lengsuo_anytls::auth::Credential;
use lengsuo_anytls::client_state::ClientState;
use lengsuo_anytls::frame::{Command, Frame};
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};

/// 单会话活跃流上限（本端自设，与参考默认值等量）。
const MAX_STREAMS: usize = 16;
/// 客户端标识：参考用 `anytls/0.0.13`，本实现如实用自身标识（server 不校验该键）。
const CLIENT_IDENT: &str = "lengsuo-anytls";
/// 默认 padding 方案的 md5（由 v0.0.13 pad/padding.go 逐字节算出，与参考一致）。
/// 客户端上报它作为 Settings.padding-md5，使 server 免于下发 UpdatePadding。
const DEFAULT_SCHEME_MD5: &str = "75cff2ad89aadf5e257059ee571ebe11";
/// 认证块 padding：参考客户端以默认方案 `0=30-30` 生成，0 号记录恒为 30 字节零值。
const AUTH_PADDING: [u8; 30] = [0; 30];

/// 客户端单流 echo 往返的统计；不含载荷之外的任何凭据或敏感文本。
#[derive(Debug, Default)]
pub struct ClientReport {
    /// 收到的成功（无载荷）SYNACK 帧数。
    pub syn_acks: usize,
    /// 出现过 PUSH/SYNACK 的流编号集合（应为且仅为 1）。
    pub data_streams: BTreeSet<u32>,
    /// 回程 PUSH 载荷按序拼接。
    pub echo: Vec<u8>,
    /// AnyTLS Alert 帧数（健康会话应为 0）。
    pub alerts: usize,
    /// server 下发的 UpdatePadding 帧数（md5 对齐时应为 0）。
    pub update_padding: usize,
    /// ServerSettings 原文（应含 v=2）。
    pub server_settings: Option<String>,
    /// 协商出的对端版本。
    pub peer_version: u8,
    /// 本端能否完成 TLS close_notify 干净关闭。
    pub tls_shutdown_ok: bool,
}

/// 在已完成 TLS 握手的流上跑完一次认证 + 单流 echo；`target` 为回环 echo 目标地址。
/// 成功后发 FIN 并 close_notify；任何协议违规都以 `Err` 结束（fail-closed）。
pub async fn echo_once<S>(
    stream: &mut S,
    password: &[u8],
    target: SocketAddr,
    payload: &[u8],
    wait: Duration,
    total: Duration,
) -> Result<ClientReport, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 认证：SHA256(password) + BE16 padding 长度 + padding；成功无回包。
    // 与参考 createOutboundConnection 一致：认证块整体一次写入，padding 用默认方案的 30 字节。
    Credential::new(password)
        .send(stream, &AUTH_PADDING, wait)
        .await
        .map_err(|err| format!("认证发送失败：{err}"))?;

    let mut state =
        ClientState::new(MAX_STREAMS).map_err(|err| format!("客户端状态机配置失败：{err}"))?;
    state
        .mark_settings_sent()
        .map_err(|err| format!("标记 Settings 失败：{err}"))?;

    // Settings 先行：与参考客户端一致的三键（key=value 换行分隔，顺序无语义）。
    let settings_data = format!("v=2\nclient={CLIENT_IDENT}\npadding-md5={DEFAULT_SCHEME_MD5}");
    Frame {
        command: Command::Settings,
        stream_id: 0,
        data: settings_data.into_bytes(),
    }
    .write(stream, wait)
    .await
    .map_err(|err| format!("写 Settings 失败：{err}"))?;

    // 参考客户端在 Settings 之后立即开流；stream id 由本端从 1 开始连续分配。
    let sid = state
        .open_stream()
        .map_err(|err| format!("取流 ID 失败：{err}"))?;
    assert_eq!(sid, 1, "首条流 ID 应为 1");
    Frame {
        command: Command::Syn,
        stream_id: sid,
        data: Vec::new(),
    }
    .write(stream, wait)
    .await
    .map_err(|err| format!("写 SYN 失败：{err}"))?;

    // PUSH 首段为 SOCKS 地址（ATYP=1 IPv4 + 端口），其后为应用载荷。
    let mut push_data = Vec::with_capacity(7 + payload.len());
    push_data.push(1u8);
    let IpAddr::V4(v4) = target.ip() else {
        return Err("echo 目标不是 IPv4 回环".to_owned());
    };
    push_data.extend_from_slice(&v4.octets());
    push_data.extend_from_slice(&target.port().to_be_bytes());
    push_data.extend_from_slice(payload);
    Frame {
        command: Command::Push,
        stream_id: sid,
        data: push_data,
    }
    .write(stream, wait)
    .await
    .map_err(|err| format!("写 PUSH 失败：{err}"))?;

    // 收 server 方向帧直到回程收齐：ServerSettings/SYNACK/PUSH；UpdatePadding/心跳忽略。
    let mut report = ClientReport {
        peer_version: state.peer_version(),
        ..ClientReport::default()
    };
    let deadline = Instant::now() + total;
    while report.echo.len() < payload.len() {
        if Instant::now() >= deadline {
            return Err(format!(
                "期限内未收齐回程（缺口 {} B）",
                payload.len() - report.echo.len()
            ));
        }
        let frame = Frame::read(stream, u16::MAX, wait)
            .await
            .map_err(|err| format!("读服务端帧失败：{err}"))?;
        state
            .accept(&frame)
            .map_err(|err| format!("客户端状态机拒绝帧 cmd={}: {err}", frame.command as u8))?;
        match frame.command {
            Command::ServerSettings => {
                report.server_settings = Some(String::from_utf8_lossy(&frame.data).into_owned());
            }
            Command::SynAck => {
                assert_eq!(frame.stream_id, sid, "SYNACK 必须绑在本端流上");
                if frame.data.is_empty() {
                    report.syn_acks += 1;
                    report.data_streams.insert(frame.stream_id);
                } else {
                    return Err(format!(
                        "server 以错误 SYNACK 拒绝本端流：{}",
                        String::from_utf8_lossy(&frame.data)
                    ));
                }
            }
            Command::Push => {
                assert_eq!(frame.stream_id, sid, "PUSH 必须绑在本端流上");
                report.data_streams.insert(frame.stream_id);
                report.echo.extend_from_slice(&frame.data);
            }
            Command::UpdatePadding => report.update_padding += 1,
            Command::Alert => {
                report.alerts += 1;
                return Err("server 发送 Alert，会话被拒".to_owned());
            }
            // Waste / 心跳等：不影响单流 echo，静默记入状态机即可。
            _ => {}
        }
        report.peer_version = state.peer_version();
    }

    // 收齐后本地关流并 FIN，再 TLS close_notify 收尾。
    state
        .close_stream(sid)
        .map_err(|err| format!("本地关流失败：{err}"))?;
    Frame {
        command: Command::Fin,
        stream_id: sid,
        data: Vec::new(),
    }
    .write(stream, wait)
    .await
    .map_err(|err| format!("写 FIN 失败：{err}"))?;
    report.tls_shutdown_ok = tokio::io::AsyncWriteExt::shutdown(stream).await.is_ok();
    report.peer_version = state.peer_version();
    Ok(report)
}
