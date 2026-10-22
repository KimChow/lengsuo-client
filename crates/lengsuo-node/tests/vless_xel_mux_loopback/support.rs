//! VLESS XEL / Mux 回环夹具：本仓服务端 ↔ node 出站。
//!
//! ⛔ **本文件只覆盖 Rust↔Rust 回环**：对端是**本仓**协议 crate 的服务端原语，
//! **不**声称与参考实现（Xray `d2758a023cd7…`）互通。参考侧（固定版本 Xray）在
//! **库层**已有真实对端证据（`crates/lengsuo-vless/tests/xray_vision.rs` 等）；
//! **node 侧**与参考对端的互通**尚未验证**（见本卡报告偏离清单）。
//!
//! 全部只绑回环、只用临时端口（`127.0.0.1:0` 交给内核分配）、只用假凭据。
//! 每个网络操作都有截止时间；日志不输出任何密钥材料。

#![allow(dead_code)]

use std::collections::HashMap;
use std::time::Duration;

use lengsuo_node::config::NodeConfig;
use lengsuo_tls::{PrivatePkcs8KeyDer, TlsServer};
use lengsuo_vless::header::Command;
use lengsuo_vless::mux::frame::{decode_from_async, read_data_async, SessionStatus, TargetNetwork};
use lengsuo_vless::mux::worker::{Action, MuxServer, SessionWriter};
use lengsuo_vless::stream::{receive_request, send_response};
use lengsuo_vless::xel::aead::XelCipher;
use lengsuo_vless::xel::XelKey;
use lengsuo_vless::xel_wire::{XelStream, XelWireConfig};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// 单步截止时间（建流 / 帧读写）。
pub const WAIT: Duration = Duration::from_secs(8);
/// 用例总截止时间。
pub const DEADLINE: Duration = Duration::from_secs(30);
/// 测试用 UUID（假凭据；服务端与 node 侧共用同一份）。
pub const UUID: &str = "11111111-1111-1111-1111-111111111111";
/// 服务端读 VLESS 头时用的凭据（与 UUID 文本的 16 字节一致）。
pub const KEY: [u8; 16] = [0x11; 16];
/// 回环载荷（含二进制字节）。
pub const PAYLOAD: &[u8] = b"node vless xel payload\0\xff\xfe binary";
/// 篡改用例的载荷长度（远大于一条 VLESS 头记录 ⇒ 偏移可安全落在载荷密文里）。
pub const BIG_PAYLOAD_LEN: usize = 4096;
/// 篡改用例的翻转偏移（**记录层**下行方向的第 N 个字节）。
///
/// 记录层下行字节流 = 响应头记录（`5` 字节记录头 + `2` 字节明文 + `16` 字节 tag =
/// `23` 字节）‖ 载荷记录（`5` 字节记录头 + 密文 + `16` 字节 tag）⇒ 载荷密文从
/// 第 `28` 字节开始。取 `128` ⇒ 稳稳落在载荷密文里，既不碰响应头记录，也不碰
/// 记录头（AAD）与末尾 tag。
pub const TAMPER_OFFSET: usize = 128;
/// 记录层与传输层之间的桥接管道容量（篡改用例用）。
const BRIDGE_CAPACITY: usize = 64 * 1024;

/// 客户端 XEL 上行密钥（假材料，运行时常量 ⇒ 不是真凭据）。
pub const XEL_UPLINK_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
/// 客户端 XEL 下行密钥（假材料）。
pub const XEL_DOWNLINK_HEX: &str =
    "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
/// 服务端故意用错的密钥（⇒ 客户端的 AEAD 认证必然失败）。
pub const XEL_WRONG_HEX: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
/// 服务端的上行密钥（= 客户端的**下行**密钥；方向相对客户端对调）。
pub const XEL_SERVER_UPLINK_HEX: &str = XEL_DOWNLINK_HEX;
/// 服务端的下行密钥（= 客户端的**上行**密钥）。
pub const XEL_SERVER_DOWNLINK_HEX: &str = XEL_UPLINK_HEX;

/// 双向流抽象（读 + 写）。
pub trait Duplex: AsyncRead + AsyncWrite + Unpin {}
impl<T> Duplex for T where T: AsyncRead + AsyncWrite + Unpin {}

/// 装箱后的双向流。
pub type BoxedDuplex = Box<dyn Duplex>;

/// 十六进制文本 → 字节（测试夹具内部用；失败即 panic）。
fn hex_bytes(text: &str) -> Vec<u8> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    (0..compact.len() / 2)
        .map(|index| u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16).expect("十六进制"))
        .collect()
}

/// 回环服务端的三件套：端口、信任锚 PEM、监听器 + TLS 服务端。
pub struct ServerFixture {
    /// 监听端口（node 侧连它）。
    pub port: u16,
    /// 自签证书的 PEM（node 侧的信任锚）。
    pub ca_pem: String,
    listener: TcpListener,
    tls: TlsServer,
}

/// 备好一个只服务一次连接的 TLS 服务端（尚未 accept）。
pub async fn server_fixture() -> ServerFixture {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let ca_pem = cert.cert.pem().to_owned();
    let tls = TlsServer::new(
        vec![cert.cert.der().clone()],
        PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        WAIT,
    )
    .expect("TLS 服务端");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("回环监听");
    let port = listener.local_addr().unwrap().port();
    ServerFixture {
        port,
        ca_pem,
        listener,
        tls,
    }
}

/// 起一个**只 accept** 的监听器：用于「坏配置下没有建立连接」的判定。
///
/// 返回（端口，accept 计数句柄，观察任务）。观察任务在**没有连接**时一直挂着
/// （直到调用方的截止时间到），有连接则记一次数并立刻返回。
pub async fn accept_only_watcher() -> (
    u16,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = std::sync::Arc::clone(&accepted);
    let watcher = tokio::spawn(async move {
        if let Ok((socket, _)) = listener.accept().await {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            drop(socket);
        }
    });
    (port, accepted, watcher)
}

/// node 配置：vless + TLS（可选 `xel` 段 / `mux` 段）。
#[must_use]
pub fn vless_node(
    port: u16,
    ca_pem: &str,
    xel: Option<serde_json::Value>,
    mux: bool,
) -> NodeConfig {
    let mut value = json!([{
        "name": "vless-xel-mux-loopback",
        "protocol": "vless",
        "endpoint": { "host": "127.0.0.1", "port": port },
        "tls": {
            "server_name": "localhost",
            "ca_pem": ca_pem
        },
        "auth": { "password": UUID }
    }]);
    if let Some(xel) = xel {
        value[0]["xel"] = xel;
    }
    if mux {
        value[0]["mux"] = json!({ "concurrency": 8, "max_connections": 128 });
    }
    let nodes: Vec<NodeConfig> = serde_json::from_value(value).expect("节点配置");
    nodes.into_iter().next().expect("恰好一个节点")
}

/// `xel` 配置段（客户端视角：上行 = 本端发出）。
#[must_use]
pub fn xel_section(uplink_hex: &str, downlink_hex: &str) -> serde_json::Value {
    json!({
        "cipher": "aes-256-gcm",
        "uplink_key": uplink_hex,
        "downlink_key": downlink_hex
    })
}

// --------------------------------------------------------------------------------------
// XEL 服务端
// --------------------------------------------------------------------------------------

/// 服务端侧的 XEL 记录层配置（密钥方向以**服务端**为基准）。
fn xel_server_config(uplink_hex: &str, downlink_hex: &str) -> XelWireConfig {
    XelWireConfig {
        cipher: XelCipher::Aes256Gcm,
        uplink_key: XelKey::new(&hex_bytes(uplink_hex)).expect("服务端上行密钥"),
        downlink_key: XelKey::new(&hex_bytes(downlink_hex)).expect("服务端下行密钥"),
        xor: None,
    }
}

/// XEL 服务端：TLS → XEL 记录层 → 读 VLESS 请求头 → 写成功响应头 → 回环。
///
/// 判据与 node 侧**一致**：只有拿到成功响应头（`[0, 0]`）才算认证通过
/// （参考 `proxy/vless/inbound/inbound.go:619`）。
///
/// 密钥以**服务端视角**给出（`uplink` = 服务端发出）；与客户端的方向必须对调，
/// 否则 AEAD 必然认证失败（负例正是靠这个不匹配）。
///
/// `expect` = 期望读到的上行载荷长度；读完即原样回送（下行方向也逐字节比对）。
///
/// `tamper_offset` = `Some(n)` ⇒ 在**记录层与传输层之间**插入篡改：记录层输出
/// 的第 `n` 个字节被翻一个比特 ⇒ 对端的 **AEAD 认证必然失败**（而不是被 TLS
/// 层的 MAC 先抓出来）。
pub async fn serve_xel(
    fixture: ServerFixture,
    uuid: [u8; 16],
    server_uplink_hex: &str,
    server_downlink_hex: &str,
    expect: usize,
    tamper_offset: Option<usize>,
) -> Result<Vec<u8>, String> {
    let ServerFixture { listener, tls, .. } = fixture;
    let (socket, _) = listener.accept().await.map_err(|e| e.to_string())?;
    let tls_stream = tls.accept(socket).await.map_err(|e| e.to_string())?;
    let config = xel_server_config(server_uplink_hex, server_downlink_hex);
    let mut stream = match tamper_offset {
        None => XelStream::new(tls_stream, config).map_err(|e| e.to_string())?,
        Some(offset) => {
            // 在**记录层**与传输层之间架一段桥：记录层写出的字节先过桥（在这里
            // 翻一个比特）再进 TLS ⇒ 线上被改的是**记录层的密文** ⇒ 对端的
            // 记录层 AEAD 认证失败（而不是 TLS 的 MAC 失败）。
            let (xel_side, bridge_side) = tokio::io::duplex(BRIDGE_CAPACITY);
            let (mut bridge_read, mut bridge_write) = tokio::io::split(bridge_side);
            let (mut tls_read, mut tls_write) = tokio::io::split(tls_stream);
            // 记录层 → TLS（下行方向，篡改点）。
            tokio::spawn(async move {
                let _ = copy_flipping(&mut bridge_read, &mut tls_write, offset).await;
            });
            // TLS → 记录层（上行方向，原样）。
            tokio::spawn(async move {
                let _ = copy_plain(&mut tls_read, &mut bridge_write).await;
            });
            XelStream::new(xel_side, config).map_err(|e| e.to_string())?
        }
    };
    // 请求头走记录层：AEAD 认证不过 ⇒ 这里直接失败（fail-closed）。
    receive_request(&mut stream, &uuid, WAIT)
        .await
        .map_err(|e| format!("读请求头失败：{e}"))?;
    send_response(&mut stream, WAIT)
        .await
        .map_err(|e| format!("写响应头失败：{e}"))?;
    let mut uplink = vec![0u8; expect];
    tokio::time::timeout(WAIT, stream.read_exact(&mut uplink))
        .await
        .map_err(|_| "读上行超时".to_owned())?
        .map_err(|e| format!("读上行失败：{e}"))?;
    stream
        .write_all(&uplink)
        .await
        .map_err(|e| format!("写下行失败：{e}"))?;
    stream
        .flush()
        .await
        .map_err(|e| format!("刷下行失败：{e}"))?;
    // 记录层的写是**后台任务**（`pump_writes`：`pipe → seal → transport.write_all`），
    // `flush()` 只刷应用侧管道、不等传输层 ⇒ 直接 drop 会 `abort` 写任务，回显记录
    // 可能永远没上线。`shutdown()` 等写任务收尾（EOF 时它会 `transport.shutdown()`
    // ⇒ TLS close_notify 顺带把待发记录刷上 socket）。
    stream
        .shutdown()
        .await
        .map_err(|e| format!("下行收尾失败：{e}"))?;
    Ok(uplink)
}

// --------------------------------------------------------------------------------------
// Mux 承载服务端
// --------------------------------------------------------------------------------------

/// mux 承载服务端的运行结果。
pub struct MuxOutcome {
    /// VLESS 响应头 flush 之前收到的客户端 mux 帧数。
    ///
    /// ≥1 ⇒ 客户端**先发了 mux 帧**、再拿到响应头（参考的顺序要求）。
    pub frames_before_header: usize,
    /// 各会话收到的上行载荷（会话 ID → 载荷）。
    pub received: Vec<(u16, Vec<u8>)>,
}

/// mux 承载服务端的运行句柄。
pub struct MuxPeer {
    /// 触发承载断开（参考：承载连接被关闭 ⇒ 所有逻辑会话必须失败）。
    pub close: Option<oneshot::Sender<()>>,
    /// 服务端任务：返回承载上的观测结果。
    pub task: tokio::task::JoinHandle<Result<MuxOutcome, String>>,
}

/// 起一个 mux 承载服务端（TLS + VLESS `command=Mux` + mux 帧回显）。
pub fn spawn_mux_peer(fixture: ServerFixture, uuid: [u8; 16]) -> MuxPeer {
    let (close_tx, close_rx) = oneshot::channel();
    let task = tokio::spawn(async move { serve_mux(fixture, uuid, close_rx).await });
    MuxPeer {
        close: Some(close_tx),
        task,
    }
}

/// 会话回显时加的会话标签（`会话 ID ‖ 载荷`）：路由串扰会立刻暴露。
fn tag(id: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 2);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// 滞留的 VLESS 响应头（参考 `common/buf/writer.go` 的 `BufferedWriter` +
/// `SetFlushNext()`）。
///
/// 参考入站把响应头写进 `buf.BufferedWriter`，**之后**才 `SetFlushNext()`；而
/// `SetFlushNext()` 只让**下一次 Write** 触发 flush ⇒ **响应头滞留缓冲区**，
/// 要等**第一个 mux 帧写出**才一起 flush。
///
/// ⇒ 本夹具**照抄**这个时序：响应头先攒着，首个 mux 帧写出时才与它一起写出。
/// ⇒ 若 node 侧「先阻塞等响应头、再发 mux 帧」，本夹具就永远不会写出首个帧
/// （它在等帧）⇒ 互锁成死锁 ⇒ 用例超时失败。**这正是本卡要覆盖的那条语义。**
struct PendingHeader {
    /// 滞留的响应头字节（VLESS 成功响应头恒为 `00 00`）。
    bytes: Vec<u8>,
    /// 是否已经随某一帧 flush 过。
    flushed: bool,
    /// flush 之前收到的客户端 mux 帧数。
    frames_before_flush: Option<usize>,
}

impl PendingHeader {
    fn new() -> Self {
        Self {
            bytes: vec![0u8, 0u8],
            flushed: false,
            frames_before_flush: None,
        }
    }

    /// 把滞留的响应头拼到即将写出的帧前面（只在第一次生效）。
    fn prepend(&mut self, frame: &mut Vec<u8>, frames_seen: usize) {
        if !self.flushed {
            frame.splice(0..0, self.bytes.drain(..));
            self.flushed = true;
            self.frames_before_flush = Some(frames_seen);
        }
    }
}

/// mux 承载服务端。
///
/// ## ⛔ 响应头的 flush 时序（参考 `common/buf/writer.go`）
///
/// 见 [`PendingHeader`]：响应头滞留到**第一个 mux 帧写出**才一起 flush。
///
/// 参考的 mux 服务端（`common/mux/server.go` 的 `handleStatusNew`）在 `New` 帧上
/// **不写首帧**（目标产生产生数据时才写）⇒ 本夹具在 `New` 帧上**只登记会话、
/// 不写任何字节**，与参考一致。
async fn serve_mux(
    fixture: ServerFixture,
    uuid: [u8; 16],
    mut close_rx: oneshot::Receiver<()>,
) -> Result<MuxOutcome, String> {
    let ServerFixture { listener, tls, .. } = fixture;
    let (socket, _) = listener.accept().await.map_err(|e| e.to_string())?;
    let mut tls_stream = tls.accept(socket).await.map_err(|e| e.to_string())?;
    // 承载请求头：参考 `proxy/vless/outbound/outbound.go:218-232` 写 `command=Mux`。
    let request = receive_request(&mut tls_stream, &uuid, WAIT)
        .await
        .map_err(|e| format!("读承载请求头失败：{e}"))?;
    if request.command != Command::Mux {
        return Err(format!(
            "承载请求头 command 不是 Mux：{:?}",
            request.command
        ));
    }
    let (mut reader, mut writer) = tokio::io::split(tls_stream);
    // 响应头**滞留缓冲区**（参考 `buf.BufferedWriter` + `SetFlushNext()`）。
    let mut pending = PendingHeader::new();
    let mut server = MuxServer::new();
    let mut writers: HashMap<u16, SessionWriter> = HashMap::new();
    let mut received: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut frames_seen = 0usize;
    loop {
        let meta = tokio::select! {
            biased;
            // 承载断开（测试触发）：退出循环 ⇒ TLS 流析构 ⇒ TCP 关闭。
            _ = &mut close_rx => break,
            result = decode_from_async(&mut reader, false) => match result {
                Ok(meta) => meta,
                Err(error) => return Err(format!("解帧失败：{error:?}")),
            },
        };
        frames_seen += 1;
        // 参考的四个 handle* 分支在有 OptionData 时都会消费数据段 ⇒ 必须先读再派发。
        let data = if meta.has_data() {
            match read_data_async(&mut reader, true).await {
                Ok(data) => Some(data),
                Err(error) => return Err(format!("读数据段失败：{error:?}")),
            }
        } else {
            None
        };
        match meta.status {
            SessionStatus::New => {
                server
                    .handle_new(&meta)
                    .map_err(|error| format!("登记会话失败：{error:?}"))?;
                // 参考的 `handleStatusNew`（TCP 分支）**不写首帧**：目标产生产生
                // 数据时才写 ⇒ 这里只登记会话与响应侧 writer。
                writers.insert(
                    meta.session_id,
                    SessionWriter::response(meta.session_id, TargetNetwork::Tcp),
                );
            }
            SessionStatus::Keep => {
                match server
                    .handle(&meta, data)
                    .map_err(|error| format!("派发失败：{error:?}"))?
                {
                    Action::Deliver { id, payload, .. } => {
                        // 参考把数据写给该会话的下游；本夹具回环（并加会话标签）。
                        let session_writer = writers
                            .get_mut(&id)
                            .ok_or_else(|| format!("会话 {id} 不存在"))?;
                        // 先发一个**零长数据帧**（`OptionData` 置位 + BE16 长度 0）：
                        // 线格式合法，参考读取侧会把它当成「空写」交给下游
                        // （`common/mux/writer.go:100` 的 `writeMetaOnly`；空写 = no-op）。
                        // ⇒ 会话读⛔不得把它当成 EOF。若被当成 EOF，下面的回显就永远
                        // 读不到，本夹具的每条 mux 用例都会失败（这就是那条可跑的自检）。
                        let mut empty = Vec::new();
                        session_writer
                            .write_data(&mut empty, &[])
                            .map_err(|error| format!("写空帧失败：{error:?}"))?;
                        pending.prepend(&mut empty, frames_seen);
                        writer.write_all(&empty).await.map_err(|e| e.to_string())?;
                        writer.flush().await.map_err(|e| e.to_string())?;
                        let mut frame = Vec::new();
                        session_writer
                            .write_multi(&mut frame, &tag(id, &payload))
                            .map_err(|error| format!("写回失败：{error:?}"))?;
                        // 首个 mux 帧 ⇒ 把滞留的响应头与它一起写出（参考的 flush 时序）。
                        pending.prepend(&mut frame, frames_seen);
                        writer.write_all(&frame).await.map_err(|e| e.to_string())?;
                        writer.flush().await.map_err(|e| e.to_string())?;
                        received.push((id, payload));
                    }
                    Action::SendEnd { id } => {
                        let mut frame = Vec::new();
                        write_end(&mut frame, id)
                            .map_err(|error| format!("写 End 失败：{error:?}"))?;
                        pending.prepend(&mut frame, frames_seen);
                        writer.write_all(&frame).await.map_err(|e| e.to_string())?;
                        writer.flush().await.map_err(|e| e.to_string())?;
                    }
                    Action::CloseSession { id } => {
                        writers.remove(&id);
                    }
                    Action::None => {}
                }
            }
            SessionStatus::End => {
                if let Ok(Action::CloseSession { id }) = server.handle(&meta, None) {
                    writers.remove(&id);
                }
            }
            SessionStatus::KeepAlive => {}
        }
    }
    Ok(MuxOutcome {
        frames_before_header: pending.frames_before_flush.unwrap_or(frames_seen),
        received,
    })
}

/// 写一个 `End` 帧（会话不存在时通知对端关闭）。
fn write_end(out: &mut Vec<u8>, id: u16) -> Result<(), lengsuo_vless::mux::frame::FrameError> {
    let mut session_writer = SessionWriter::response(id, TargetNetwork::Tcp);
    session_writer.close(out)
}

// --------------------------------------------------------------------------------------
// 篡改搬运（记录层 ↔ 传输层之间）
// --------------------------------------------------------------------------------------

/// 原样转发。
async fn copy_plain(
    src: &mut (impl AsyncRead + Unpin),
    dst: &mut (impl AsyncWrite + Unpin),
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 4096];
    loop {
        let read = src.read(&mut buf).await?;
        if read == 0 {
            return Ok(());
        }
        dst.write_all(&buf[..read]).await?;
        dst.flush().await?;
    }
}

/// 转发并在第 `flip_offset` 个字节上翻一个比特。
async fn copy_flipping(
    src: &mut (impl AsyncRead + Unpin),
    dst: &mut (impl AsyncWrite + Unpin),
    flip_offset: usize,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 4096];
    let mut seen = 0usize;
    loop {
        let read = src.read(&mut buf).await?;
        if read == 0 {
            return Ok(());
        }
        let mut chunk = buf[..read].to_vec();
        if seen <= flip_offset && flip_offset < seen + read {
            chunk[flip_offset - seen] ^= 0xff;
        }
        seen += read;
        dst.write_all(&chunk).await?;
        dst.flush().await?;
    }
}
