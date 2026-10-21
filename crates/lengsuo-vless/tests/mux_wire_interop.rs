//! 参考互通：`MuxWire` 出站原语与固定版本参考端的真实互跑。
//!
//! 显式执行：
//! `LENGSUO_XRAY=/绝对路径/xray cargo test -p lengsuo-vless --test mux_wire_interop -- --ignored --nocapture`
//!
//! 与 `mux_wire.rs` 分文件：前者是**参考互通**（需外部二进制、默认跳过），
//! 后者是**本仓自洽**（往返 / 拒绝路径，默认跑）。职责不同，分文件避免单文件超行数上限。
//!
//! 全部用例只用回环地址、临时端口、假凭据；不打印任何密钥/明文。
//!
//! ## 握手顺序：为什么**不能**先读 VLESS 响应头
//!
//! 参考 VLESS 入站（`proxy/vless/inbound/inbound.go:618-634`）把响应头写进
//! `buf.BufferedWriter` **之后**才 `SetFlushNext()`；而 `common/buf/writer.go` 的
//! `SetFlushNext()` 只让**下一次** `WriteMultiBuffer` 触发 flush
//! （`if w.flushNext { w.buffered = false; w.flushNext = false; return w.flushInternal() }`）
//! ⇒ **响应头滞留缓冲区**，要等第一个 mux 下行帧才一起发出。
//!
//! ⇒ 客户端**不能先阻塞等响应头**：那会与「对端等第一个帧才 flush 响应头」互锁
//! 成死锁（上一张卡 `w4-vless-mux-wire` 的 `new_after_prefix` 就是这个方向，
//! 依然死锁）。参考自己的客户端不死锁，是因为
//! `proxy/vless/outbound/outbound.go:321/420` 的 `postRequest` 里
//! `buf.Copy(clientReader, serverWriter, ...)` **持续**转发 mux 帧流。
//!
//! 本用例的正确顺序：**先发 mux 帧**（`MuxWire::open`/`write` 不等响应头），
//! 再在**读帧循环**里消费开头的响应头（`MuxWire::new_over_vless` 登记，
//! `MuxWire::next_inbound` 在解第一帧之前消费掉）。
//!
//! ## 为什么用 TCP 中继
//!
//! 中继把客户端与参考端之间的**双向原始字节**逐字节记录下来，供本用例做
//! **字节级断言**：我方发出的 `New`/`Keep`/`End` 帧与参考回程的 `Keep` 帧，
//! 逐字段与参考 `common/mux/frame.go` 的帧布局对照。

mod support;

use std::sync::Arc;
use std::time::Duration;

use lengsuo_vless::mux::frame::TargetNetwork;
use lengsuo_vless::mux::worker::{Action, Strategy};
use lengsuo_vless::mux_wire::MuxWire;
use ss_core::target::TargetAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const TCP: TargetNetwork = TargetNetwork::Tcp;
const PAYLOAD: &[u8] = b"lengsuo-mux-interop-payload";
/// 单次 I/O 的等待上限。
const WAIT: Duration = Duration::from_secs(5);
/// 整个用例（含拉起参考端）的上限。
const TOTAL: Duration = Duration::from_secs(30);

/// 目标地址（回环 + 端口）。
fn target(port: u16) -> (TargetAddr, TargetNetwork) {
    (TargetAddr::V4([127, 0, 0, 1], port), TCP)
}

// ============================================================================
// TCP 中继：记录双向原始字节
// ============================================================================

/// 客户端 ⇄ 中继 ⇄ 参考端；双向原始字节逐字节记录。
struct Relay {
    /// 中继对客户端的监听端口。
    port: u16,
    /// 客户端 → 参考端 的原始字节。
    c2s: Arc<Mutex<Vec<u8>>>,
    /// 参考端 → 客户端 的原始字节。
    s2c: Arc<Mutex<Vec<u8>>>,
}

/// 单向泵：读一段 → 记录 → 转发。
async fn pump<R, W>(mut reader: R, mut writer: W, record: Arc<Mutex<Vec<u8>>>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 4096];
    loop {
        let read = match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        record.lock().await.extend_from_slice(&buffer[..read]);
        if writer.write_all(&buffer[..read]).await.is_err() {
            break;
        }
        let _ = writer.flush().await;
    }
    let _ = writer.shutdown().await;
}

/// 拉起中继，转发到参考端的 `upstream_port`。
async fn start_relay(upstream_port: u16) -> Relay {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let c2s = Arc::new(Mutex::new(Vec::new()));
    let s2c = Arc::new(Mutex::new(Vec::new()));
    let (c2s_record, s2c_record) = (Arc::clone(&c2s), Arc::clone(&s2c));
    tokio::spawn(async move {
        let (client, _) = listener.accept().await.unwrap();
        let server = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, upstream_port))
            .await
            .unwrap();
        let (mut client_read, mut client_write) = client.into_split();
        let (mut server_read, mut server_write) = server.into_split();
        let _ = tokio::join!(
            pump(&mut client_read, &mut server_write, c2s_record),
            pump(&mut server_read, &mut client_write, s2c_record),
        );
    });
    Relay { port, c2s, s2c }
}

/// 等中继记录到至少 `len` 字节（转发是异步的）。
async fn wait_record(record: &Mutex<Vec<u8>>, len: usize) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let current = record.lock().await.len();
        if current >= len {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "中继记录未在时限内达到 {len} 字节（当前 {current}）"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    record.lock().await.clone()
}

// ============================================================================
// 期望字节：按参考 `common/mux/frame.go` 的帧布局逐字段拼出
// ============================================================================

/// 参考 `FrameMetadata.WriteTo` 的帧布局：
/// `BE16 metaLen | meta | [BE16 数据长度 | 数据]`。
///
/// `metaLen` 只算 meta 段（参考的 `len1-len0`），**不含**数据段长度字节。
fn expected_frame(
    session_id: u16,
    status: u8,
    option: u8,
    address: Option<(u16, [u8; 4])>,
    payload: Option<&[u8]>,
) -> Vec<u8> {
    let mut meta = Vec::new();
    meta.extend_from_slice(&session_id.to_be_bytes());
    meta.push(status);
    meta.push(option);
    if let Some((port, ip)) = address {
        meta.push(0x01); // network = TCP
        meta.extend_from_slice(&port.to_be_bytes()); // PortThenAddress：端口在前
        meta.push(0x01); // 地址类型 = IPv4
        meta.extend_from_slice(&ip);
    }
    let mut frame = Vec::new();
    frame.extend_from_slice(&(meta.len() as u16).to_be_bytes());
    frame.extend_from_slice(&meta);
    if let Some(payload) = payload {
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
    }
    frame
}

/// 参考 `EncodeRequestHeader`（`command=Mux` 不写地址段）：
/// `00 | 16 字节 UUID | 00 (addons 长度) | 03 (command=Mux)`。
fn expected_request_header() -> Vec<u8> {
    let mut header = Vec::new();
    header.push(0x00); // version
    header.extend_from_slice(&support::KEY); // UUID 字节
    header.push(0x00); // addons 长度（参考 `EncodeHeaderAddons` 的 default 分支）
    header.push(0x03); // command = Mux
    header
}

// ============================================================================
// 参考互通：本仓 `mux_wire` 出站原语 ⇄ 固定版本 Xray mux 服务端
// ============================================================================

/// 参考互通：参考端 mux 服务端 ⇄ 本仓 `mux_wire` 出站原语。
///
/// 显式执行：
/// `LENGSUO_XRAY=/绝对路径/xray cargo test -p lengsuo-vless --test mux_wire_interop -- --ignored --nocapture`
///
/// 覆盖：
/// - 本仓 `MuxWire` 发出的 `New` 帧（承载 VLESS `command=Mux` 头）被参考端识别为
///   mux 会话并转发到真实回环 echo 目标；
/// - 参考端的下行 `Keep` 帧被本仓 `MuxWire::next_inbound` 正确解出，载荷逐字节一致；
/// - 参考端对本仓 `MuxSession::close` 发出的 `End` 帧不报错（对齐参考
///   `handleStatusEnd`：只关会话，不回 `End`）；
/// - **字节级断言**：我方 C2S 的 `New`/`Keep`/`End` 帧与参考 S2C 的 `Keep` 帧，
///   逐字段与参考 `common/mux/frame.go` 的帧布局一致。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_mux_server_accepts_mux_wire_outbound() {
    use lengsuo_vless::header::{Command, Request};
    use lengsuo_vless::mux::MUX_COOL_ADDRESS;
    use lengsuo_vless::stream::send_request;
    use serde_json::json;
    use support::{free_port, launch, ID, KEY};
    use tokio::time::timeout;

    timeout(TOTAL, async {
        // 参考端的回环 echo 目标：每条会话用不同载荷，串包会被立刻发现。
        // echo 在写回载荷后**保持连接打开**（等 `close` 信号），否则参考端
        // `handle` 的 `writer.Close()` 会在断言前就多发一个 `End` 帧。
        let mut echo_ports = Vec::new();
        let mut echo_tasks = Vec::new();
        let mut close_senders = Vec::new();
        for index in 0..2u8 {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            echo_ports.push(listener.local_addr().unwrap().port());
            let payload = [PAYLOAD, &[index]].concat();
            let (close_tx, close_rx) = tokio::sync::oneshot::channel::<()>();
            close_senders.push(close_tx);
            echo_tasks.push(tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut received = vec![0; payload.len()];
                stream.read_exact(&mut received).await.unwrap();
                assert_eq!(received, payload, "参考端转发的载荷必须与请求一致");
                stream.write_all(&received).await.unwrap();
                stream.flush().await.unwrap();
                let _ = close_rx.await;
            }));
        }

        let port = free_port();
        let reference = launch(
            json!({
                "log":{"loglevel":"info"},
                "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"vless",
                    "settings":{"clients":[{"id":ID}],"decryption":"none"}}],
                "outbounds":[{"protocol":"freedom"}]
            }),
            port,
        )
        .await;

        // 中继：取双向原始字节（见模块头「为什么用 TCP 中继」）。
        let relay = start_relay(port).await;

        // 承载连接：先发 VLESS `command=Mux` 头（参考 `EncodeRequestHeader` 对
        // `RequestCommandMux` 不写地址），再由 `MuxWire` 接管同一条字节流。
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, relay.port))
            .await
            .unwrap();
        let request = Request {
            command: Command::Mux,
            target: TargetAddr::Domain(MUX_COOL_ADDRESS.to_string(), 0),
        };
        send_request(&mut stream, &request, &KEY, WAIT)
            .await
            .unwrap();

        // ⚠️ 此处**不能**读响应头：参考把它滞留到第一个 mux 下行帧才 flush ⇒
        // 先读会与对端互锁成死锁。`new_over_vless` 登记待消费的响应头，由读侧
        // （`next_inbound`）在解第一帧之前消费掉。
        let mut wire = MuxWire::new_over_vless(stream, Strategy::default());
        let mut sessions = Vec::new();
        let mut payloads = Vec::new();
        for (index, echo_port) in echo_ports.iter().enumerate() {
            let mut session = wire
                .open(target(*echo_port), None, WAIT)
                .await
                .expect("可开会话");
            // 首包走 `Keep` 帧的数据段（参考 `writeFirstPayload` 的等价路径）。
            let payload = [PAYLOAD, &[index as u8]].concat();
            session.write(&payload, WAIT).await.expect("可写");
            sessions.push(session);
            payloads.push(payload);
        }

        // 收齐两条会话的回程：每条响应首帧为 `Keep`，载荷必须与本会话一致。
        let mut received: std::collections::HashMap<u16, Vec<u8>> =
            std::collections::HashMap::new();
        let deadline = tokio::time::Instant::now() + WAIT;
        while received.len() < 2 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "等待两条会话回程超时，已收到 {:?}",
                received.keys().collect::<Vec<_>>()
            );
            let inbound = wire.next_inbound(WAIT).await.expect("可读下行帧");
            if let Action::Deliver { id, payload, .. } = inbound.action {
                received.insert(id, payload);
            }
        }
        for (index, session) in sessions.iter().enumerate() {
            assert_eq!(
                received.get(&session.id()).map(Vec::as_slice),
                Some(payloads[index].as_slice()),
                "会话 {} 的回程必须与自己的载荷一致（不串包）",
                session.id()
            );
        }

        // ---- 字节级断言（1）：我方 C2S 帧 ----
        // 期望：VLESS 请求头 ‖ New#1 ‖ Keep#1 ‖ New#2 ‖ Keep#2
        let mut expected_c2s = expected_request_header();
        for (index, session) in sessions.iter().enumerate() {
            expected_c2s.extend_from_slice(&expected_frame(
                session.id(),
                0x01, // status = New
                0x00, // option：无数据段
                Some((echo_ports[index], [127, 0, 0, 1])),
                None,
            ));
            expected_c2s.extend_from_slice(&expected_frame(
                session.id(),
                0x02, // status = Keep
                0x01, // option = OptionData
                None,
                Some(&payloads[index]),
            ));
        }
        let c2s = wait_record(&relay.c2s, expected_c2s.len()).await;
        assert_eq!(
            &c2s[..expected_c2s.len()],
            expected_c2s.as_slice(),
            "我方 C2S 字节必须与参考帧布局逐字段一致（C2S={:02x?} 期望={:02x?}）",
            &c2s[..expected_c2s.len()],
            expected_c2s
        );

        // ---- 字节级断言（2）：参考 S2C 帧 ----
        // 期望：VLESS 响应头 `00 00` ‖ Keep#1 ‖ Keep#2（会话间顺序不定）。
        let mut expected_down = Vec::new();
        expected_down.extend_from_slice(&[0x00, 0x00]);
        for (index, session) in sessions.iter().enumerate() {
            expected_down.extend_from_slice(&expected_frame(
                session.id(),
                0x02, // status = Keep（参考 `NewResponseWriter` 的 followup=true）
                0x01, // option = OptionData
                None,
                Some(&payloads[index]),
            ));
        }
        let s2c = wait_record(&relay.s2c, expected_down.len()).await;
        assert_eq!(
            &s2c[..2],
            &[0x00, 0x00],
            "参考的 VLESS 响应头必须是 `00 00`（version 0 + addons 长度 0）"
        );
        let down = &s2c[2..];
        let mut swapped = Vec::new();
        for index in (0..sessions.len()).rev() {
            swapped.extend_from_slice(&expected_frame(
                sessions[index].id(),
                0x02,
                0x01,
                None,
                Some(&payloads[index]),
            ));
        }
        assert!(
            down == &expected_down[2..] || down == swapped.as_slice(),
            "参考回程字节必须逐字段等于两条会话的 Keep 帧（实际={:02x?}）",
            down
        );

        // 收尾：`End` 帧（参考 `handleStatusEnd` 只关会话，不回 `End`）。
        let mut expected_tail = Vec::new();
        for session in sessions {
            expected_tail.extend_from_slice(&expected_frame(session.id(), 0x03, 0x00, None, None));
            session.close(WAIT).await.expect("可收尾");
        }
        let c2s = wait_record(&relay.c2s, expected_c2s.len() + expected_tail.len()).await;
        assert_eq!(
            &c2s[expected_c2s.len()..expected_c2s.len() + expected_tail.len()],
            expected_tail.as_slice(),
            "我方 `End` 帧必须与参考 `Writer.Close` 的帧布局逐字段一致"
        );

        // 放行 echo 收尾，等回环任务完成。
        for sender in close_senders {
            let _ = sender.send(());
        }
        for task in echo_tasks {
            task.await.expect("回环 echo 完成");
        }
        drop(reference);
    })
    .await
    .expect("与参考端的互通未在时限内完成");
}
