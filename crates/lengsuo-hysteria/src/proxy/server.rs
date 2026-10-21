//! 服务端侧承载（对齐 `proxy/hysteria/server.go` 的 `Process` 与
//! `hub.go` 的 `StreamDispatcher` / `udpSessionManagerServer`）。

use crate::h3_auth;
use crate::padding::Range;
use crate::tcp::{Status, TcpResponse};
use crate::udp::UdpMessage;

use super::error::ProxyError;
use super::udp::{udp_out_datagrams, OwnedDefragger};

/// 服务端 TCPRequest 增量读取的缓冲上限：9 + 2048 + 9 + 4096 的上界。
const MAX_REQUEST_BUFFER: usize = 8192;

/// 出站 UDP 单次读取的最大载荷（对齐 `MaxUDPSize` = 4096）。
const MAX_UDP_PAYLOAD: usize = 4096;

/// 服务端处理一条已认证的 TCP 双向流（对齐 server.go `Process` 的 TCP 分支）。
///
/// 调用方（`h3_auth::serve_connection`）已读走帧类型 `0x401`；这里继续读
/// `TCPRequest`（地址 + padding）→ `net.ParseDestination("tcp:"+addr)` 的
/// 等价解析 → 建立出站 → 写 `TCPResponse(ok=true)` → 双向中继。
///
/// 失败语义与参考一致：请求解析失败即回 status=1 的响应并结束该流；
/// 出站失败同样回 status=1（消息为空，对齐参考只回 `WriteTCPResponse`）。
pub async fn serve_tcp_stream(
    conn: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
) -> Result<(), ProxyError> {
    serve_tcp_stream_paced(conn, send, recv, 0, Vec::new()).await
}

/// 同 [`serve_tcp_stream`]，但下行按 `rate`（字节/秒，`0` = 不限速）节流，
/// 且 `prefix` 是调用方已从流上预读、原样应交还的字节（TCPRequest 解析输入）。
///
/// `rate` 来自服务端拥塞协商 `min(BrutalUp, clientDown)`（hub.go 194-200）：
/// quinn 服务端的 `TransportConfig` 是端点级、握手前固定，无法为单条连接换
/// 拥塞器，故服务端发送方向在承载层执行同一速率（见 `congestion::wire`）。
pub async fn serve_tcp_stream_paced(
    _conn: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    rate: u64,
    prefix: Vec<u8>,
) -> Result<(), ProxyError> {
    // 增量读 TCPRequest（帧类型已被调用方读走，这里从地址长度开始）。
    let mut buf: Vec<u8> = prefix;
    buf.reserve(1024);
    let mut chunk = [0u8; 2048];
    let request = loop {
        match server_read_tcp_request(&buf) {
            Ok((req, consumed)) => {
                buf.drain(..consumed);
                break req;
            }
            Err(crate::Error::Truncated { .. }) => {
                if buf.len() >= MAX_REQUEST_BUFFER {
                    let _ = write_server_response(&mut send, false, "").await;
                    return Err(ProxyError::ResponseTooLarge);
                }
                match recv.read(&mut chunk).await? {
                    Some(n) => buf.extend_from_slice(&chunk[..n]),
                    None => return Err(ProxyError::PrematureEof),
                }
            }
            Err(e) => {
                let _ = write_server_response(&mut send, false, "").await;
                return Err(ProxyError::Frame(e));
            }
        }
    };

    // 建立出站（freedom 等价物：直连 `host:port`）。
    let outbound = match tokio::net::TcpStream::connect(&request.address).await {
        Ok(s) => s,
        Err(_) => {
            let _ = write_server_response(&mut send, false, "").await;
            return Err(ProxyError::Rejected("出站连接失败".into()));
        }
    };
    let _ = outbound.set_nodelay(true);

    // 回 TCPResponse(ok=true) 后开始中继；请求帧后的残余字节属于目标数据。
    write_server_response(&mut send, true, "").await?;
    let (orx, otx) = outbound.into_split();
    let leftover = buf; // 请求帧之后同包到达的目标数据
    relay(send, recv, orx, otx, leftover, rate).await
}

/// 服务端双向中继：QUIC 流 ↔ 出站 TCP。
async fn relay(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    orx: tokio::net::tcp::OwnedReadHalf,
    mut otx: tokio::net::tcp::OwnedWriteHalf,
    mut leftover: Vec<u8>,
    rate: u64,
) -> Result<(), ProxyError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // 上行：QUIC 流 → 出站 TCP
    let up = async {
        if !leftover.is_empty() {
            otx.write_all(&leftover).await?;
            leftover.clear();
        }
        let mut chunk = [0u8; 16 * 1024];
        loop {
            match recv.read(&mut chunk).await? {
                Some(0) | None => break,
                Some(n) => otx.write_all(&chunk[..n]).await?,
            }
        }
        let _ = otx.shutdown().await;
        Ok::<(), ProxyError>(())
    };
    // 下行：出站 TCP → QUIC 流（`rate != 0` 时经节拍器）。
    let down = async {
        let mut paced = crate::congestion::PacedReader::new(orx, rate);
        let mut chunk = [0u8; 16 * 1024];
        loop {
            match paced.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if send.write_all(&chunk[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = send.finish();
        Ok::<(), ProxyError>(())
    };
    let (up, down) = tokio::join!(up, down);
    up?;
    down?;
    Ok(())
}

/// 服务端增量读 TCPRequest：调用方已读走 0x401，这里从地址长度起解析。
/// 返回（地址，padding 长度消耗）与消耗字节数；帧后字节留给应用。
fn server_read_tcp_request(input: &[u8]) -> Result<(ServerRequest, usize), crate::Error> {
    use crate::frame::{check_len, read_varint, take_bytes, text};
    let (addr_len, offset) = read_varint(input, 0)?;
    check_len("address", addr_len, 1, crate::tcp::MAX_ADDRESS_LENGTH)?;
    let (address, offset) = take_bytes(input, offset, addr_len)?;
    let address = text("address", address)?;
    let (padding_len, offset) = read_varint(input, offset)?;
    check_len("padding", padding_len, 0, crate::tcp::MAX_PADDING_LENGTH)?;
    let (_padding, offset) = take_bytes(input, offset, padding_len)?;
    Ok((ServerRequest { address }, offset))
}

/// 服务端解析出的请求（只保留承载层需要的地址）。
struct ServerRequest {
    address: String,
}

/// 写服务端 TCPResponse（对齐 `WriteTCPResponse`）：status + 消息 +
/// padding（`tcpResponsePadding` [128,1024)）。
async fn write_server_response(
    send: &mut quinn::SendStream,
    ok: bool,
    message: &str,
) -> Result<(), ProxyError> {
    let padding = h3_auth::random_padding(Range::TCP_RESPONSE).into_bytes();
    let response = TcpResponse {
        status: if ok { Status::Ok } else { Status::Error },
        message: message.to_string(),
        padding,
    }
    .encode()?;
    send.write_all(&response).await?;
    Ok(())
}

/// 服务端一条 UDP 会话的中继循环（对齐 server.go `Process` 的 UDP 分支：
/// `UDPReader`/`UDPWriter` + `DispatchLink`）。
///
/// 每个会话绑定一条出站 UDP socket，连到首个报文的目标地址（对齐参考用
/// `firstMsg.Addr` 作 `firstDest`：会话内目标由首个报文决定，后续报文地址
/// 被忽略——与 Xray `DispatchLink` 的单目的语义一致）。
/// 接收侧按 `frag.go` 重组（`OwnedDefragger`），发送侧超限分片
/// （`udp_out_datagrams`）。
pub async fn serve_udp_session(
    session: crate::quic::server::UdpInboundSession,
    max_datagram_size: usize,
) -> Result<(), ProxyError> {
    let mut defrag = OwnedDefragger::default();
    let mut session = session;

    // 先等首个可交付报文，确定出站目标；期间解析失败/未收齐的报文丢弃
    //（对齐 server.go 首个 for 循环的 `continue`）。
    let first = loop {
        let raw = session.recv_raw().await.ok_or(ProxyError::PrematureEof)?;
        let Ok(msg) = UdpMessage::decode(&raw) else {
            continue;
        };
        if let Some(done) = defrag.feed(&msg) {
            break done;
        }
    };
    let target_addr = String::from_utf8_lossy(&first.address).into_owned();
    let outbound = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    outbound.connect(&target_addr).await?;
    let outbound = std::sync::Arc::new(outbound);

    // 去程：QUIC datagram → 出站目标 UDP。
    // 会话 ID 与发送句柄在会话被 `up` 移动前取出。
    let session_id = session.id;
    let send_handle = session.sender();
    let up_out = std::sync::Arc::clone(&outbound);
    let up = async move {
        // 首个报文已收齐，先发它。
        up_out.send(&first.data).await?;
        loop {
            let Some(raw) = session.recv_raw().await else {
                break;
            };
            let Ok(msg) = UdpMessage::decode(&raw) else {
                continue;
            };
            if let Some(done) = defrag.feed(&msg) {
                // 与参考一致：会话内目标固定为首个报文地址，忽略后续地址。
                let _ = up_out.send(&done.data).await?;
            }
        }
        Ok::<(), ProxyError>(())
    };

    // 回程：出站 UDP → QUIC datagram（写入真实会话 ID 前缀；超限分片）。
    let down_out = std::sync::Arc::clone(&outbound);
    let addr_prefix = first.address.clone();
    let down = async move {
        let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
        loop {
            match down_out.recv(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let dgrams =
                        udp_out_datagrams(session_id, &addr_prefix, &buf[..n], max_datagram_size)?;
                    for d in dgrams {
                        send_handle.send_raw(&d)?;
                    }
                }
            }
        }
        Ok::<(), ProxyError>(())
    };

    let (up, down) = tokio::join!(up, down);
    up?;
    down?;
    Ok(())
}
