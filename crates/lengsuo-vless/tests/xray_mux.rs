//! 通用多会话 Mux 的参考端到端互通（明文协议层，仅回环）。
//!
//! 显式执行：
//! `LENGSUO_XRAY=/绝对路径/xray cargo test -p lengsuo-vless --test xray_mux -- --ignored --nocapture`
//!
//! 两个方向：
//! - [`rust_mux_client_to_xray_server`]：本仓 mux 客户端在一条 VLESS 连接上并发三条
//!   逻辑流，参考端 Xray 以 `v1.mux.cool` 服务端身份接收并转发；
//! - [`xray_mux_client_to_rust_mux_server`]：参考端 Xray 开启 `mux` 后以 mux 客户端
//!   身份连本仓 mux 服务端（承载连接同为 `command=Mux` + `v1.mux.cool`）。
mod support;
use lengsuo_vless::{
    header::{self, Command, Request},
    mux::{
        frame::{
            decode_from_async, read_data_async, write_frame_async, FrameMetadata, SessionStatus,
            TargetNetwork,
        },
        worker::{MuxServer, SessionWriter},
    },
    stream::*,
};
use serde_json::json;
use ss_core::target::TargetAddr;
use std::collections::HashMap;
use support::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const PAYLOAD: &[u8] = b"VLESS mux logical stream payload\0\xfe";
/// 分组/流式统一按 TCP 语义（本用例全部是 TCP 逻辑流）。
const TCP: TargetNetwork = TargetNetwork::Tcp;

fn target(port: u16) -> (TargetAddr, TargetNetwork) {
    (TargetAddr::V4([127, 0, 0, 1], port), TCP)
}

/// 承载连接的请求头。
///
/// 注意端口：参考的 `EncodeRequestHeader` 对 `RequestCommandMux` **不写地址**，
/// 解码侧（`encoding.go`）硬编码 `v1.mux.cool` 且端口为 0；`muxCoolPort = 9527`
/// 只用于 Xray 客户端内部构造出站目标，不在线上出现。本仓 `header.rs` 的
/// Mux 分支同样返回端口 0，二者一致。
fn mux_request() -> Request {
    Request {
        command: Command::Mux,
        target: TargetAddr::Domain(lengsuo_vless::mux::MUX_COOL_ADDRESS.to_string(), 0),
    }
}

async fn echo_once(listener: TcpListener, expected: Vec<u8>) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut received = vec![0; expected.len()];
    stream.read_exact(&mut received).await.unwrap();
    assert_eq!(received, expected);
    stream.write_all(&received).await.unwrap();
    stream.shutdown().await.unwrap();
}

/// 本仓 mux 客户端 → Xray 服务端：三条并发会话，任一条 End 不影响其余。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn rust_mux_client_to_xray_server() {
    timeout(WAIT, async {
        let mut ports = Vec::new();
        let mut echo_tasks = Vec::new();
        for index in 0..3u8 {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            ports.push(listener.local_addr().unwrap().port());
            // 每条会话用不同载荷，串包会被立刻发现。
            let payload = [PAYLOAD, &[index]].concat();
            echo_tasks.push(tokio::spawn(echo_once(listener, payload)));
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

        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        // 承载请求头与首帧 mux 帧**同一次写出**：参考客户端就是这样发的
        // （实测 `firstLen = 48`，即头 + 首帧在同一读中到达），参考服务端的
        // `isMuxAndNotXUDP` 会直接检查 `first` 里的帧字节。
        let mut wire = header::encode(&mux_request(), &KEY).unwrap();
        for (index, target_port) in ports.iter().enumerate() {
            let id = (index + 1) as u16;
            let payload = [PAYLOAD, &[index as u8]].concat();
            SessionWriter::request(id, target(*target_port), TCP)
                .write_data(&mut wire, &payload)
                .expect("可编码");
        }
        stream.write_all(&wire).await.unwrap();
        stream.flush().await.unwrap();
        // 参考端先回 VLESS 响应头，之后才是 mux 帧（`inbound.go`：
        // `EncodeResponseHeader` 在 `DispatchLink` 之前）。
        receive_response(&mut stream, WAIT).await.unwrap();

        // 收齐三条会话的回程：每条响应首帧为 Keep，携带自己的载荷。
        let mut received = HashMap::new();
        let deadline = tokio::time::Instant::now() + WAIT;
        while received.len() < 3 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "等待三条会话回程超时，已收到 {received:?}"
            );
            let meta = decode_from_async(&mut stream, false).await.expect("帧头");
            if meta.has_data() {
                let payload = read_data_async(&mut stream, true).await.expect("数据");
                received.insert(meta.session_id, payload);
            }
        }
        for index in 0..3usize {
            let id = (index + 1) as u16;
            assert_eq!(
                received.get(&id).map(Vec::as_slice),
                Some(&[PAYLOAD, &[index as u8]].concat()[..]),
                "会话 {id} 的回程必须与自己的载荷一致（不串包）"
            );
        }

        // 结束会话 2：其余两条会话不受影响。
        //
        // 语义对齐参考 `handleStatusEnd`：它只 `s.Close(false)`，**不回** End 帧。
        // 因此这里不断言「收到 End 回执」，而是断言：发送 End 之后承载连接仍然
        // 可用（后续 KeepAlive 帧可正常写出），且参考端为会话 1/3 自行下发的 End
        // 帧会陆续到达（它们各自 echo 完成后收尾）。
        let mut end = Vec::new();
        FrameMetadata {
            session_id: 2,
            status: SessionStatus::End,
            option: 0,
            target: None,
            source: None,
            local: None,
            udp_continuation: false,
        }
        .encode_into(&mut end)
        .unwrap();
        stream.write_all(&end).await.unwrap();
        stream.flush().await.unwrap();

        // keep-alive：参考端对 KeepAlive 不回应，但连接保持可用（继续发一条
        // KeepAlive 后仍能正常关闭，不报错即为通过）。
        let mut keep_alive = Vec::new();
        FrameMetadata {
            session_id: 0,
            status: SessionStatus::KeepAlive,
            option: 0,
            target: None,
            source: None,
            local: None,
            udp_continuation: false,
        }
        .encode_into(&mut keep_alive)
        .unwrap();
        stream.write_all(&keep_alive).await.unwrap();
        stream.flush().await.unwrap();

        // 关闭承载连接：参考端随之为所有会话收尾并断开上游，echo 任务才可能结束。
        drop(stream);
        let mut joined = 0usize;
        for task in echo_tasks {
            // 会话 2 的上游在参考端整体断开后才收尾，故给每个 echo 一个独立时限，
            // 超时不算通过、但也不会把「协议正确」误判成失败。
            if tokio::time::timeout(WAIT, task).await.is_ok() {
                joined += 1;
            }
        }
        assert!(
            joined >= 3,
            "三条上游 echo 都应完成一次完整往返，实际 {joined}"
        );
        drop(reference);
    })
    .await
    .unwrap();
}

/// Xray mux 客户端 → 本仓 mux 服务端：参考端开启 `mux` 后在一条连接上发两条会话。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_mux_client_to_rust_mux_server() {
    timeout(WAIT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rust_port = listener.local_addr().unwrap().port();
        // 参考端两个入站端口必须**互不相同**且都可用：用 free_ports 一次预留，
        // 不再用 free_port() + 1（相邻口可能被占用导致入站绑定失败、用例偶发失败）。
        let inbound_ports = free_ports(2);
        let port = inbound_ports[0];
        let port_next = inbound_ports[1];

        // 两个回环 echo 目标，载荷不同以便检出串包。
        let payload_a = b"first-logical-stream".to_vec();
        let payload_b = b"second-logical-stream".to_vec();
        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port_a = listener_a.local_addr().unwrap().port();
        let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port_b = listener_b.local_addr().unwrap().port();
        let echo_a = tokio::spawn(echo_once(listener_a, payload_a.clone()));
        let echo_b = tokio::spawn(echo_once(listener_b, payload_b.clone()));

        let reference = launch(
            json!({
                "log":{"loglevel":"info"},
                "inbounds":[
                    {"listen":"127.0.0.1","port":port,"protocol":"dokodemo-door",
                     "settings":{"address":"127.0.0.1","port":port_a,"network":"tcp"}},
                    {"listen":"127.0.0.1","port":port_next,"protocol":"dokodemo-door",
                     "settings":{"address":"127.0.0.1","port":port_b,"network":"tcp"}}
                ],
                "outbounds":[{"protocol":"vless",
                    "settings":{"vnext":[{
                        "address":"127.0.0.1","port":rust_port,
                        "users":[{"id":ID,"encryption":"none"}]}]},
                    "mux":{"enabled":true,"concurrency":8}}]
            }),
            port,
        )
        .await;

        // 本仓 mux 服务端：按 New 帧目标建回环连接，桥接数据。
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = receive_request(&mut stream, &KEY, WAIT).await.unwrap();
            // 线上 Mux 请求不带地址/端口：参考 `encoding.go` 解码时把
            // `RequestCommandMux` 直接映射成 `v1.mux.cool`（端口 0），
            // 与 `mux_request()` 的构造一致。
            assert_eq!(request, mux_request());
            send_response(&mut stream, WAIT).await.unwrap();
            let mut server = MuxServer::new();
            let mut upstreams: HashMap<u16, TcpStream> = HashMap::new();
            // 记录服务端实际看到的会话目标，用于断言两条会话各自命中**不同**目标
            // （同目标会掩盖串包问题）。
            let mut seen_targets: Vec<(u16, u16)> = Vec::new();
            let mut ended = 0usize;
            loop {
                // 两个会话都已 End 才退出。**不能**在「已见到两条 New」时就 break：
                // 参考端的首包（`writeFirstPayload`）可能晚于第二个 New 帧到达，
                // 提前丢承载连接会让参考侧报 `failed to write first payload > EOF`，
                // 表现为用例偶发失败。
                if ended >= 2 {
                    break;
                }
                let meta = match decode_from_async(&mut stream, false).await {
                    Ok(meta) => meta,
                    Err(_) => break,
                };
                match meta.status {
                    SessionStatus::New => {
                        let (addr, _) = meta.target.clone().expect("New 必带目标");
                        let TargetAddr::V4(ip, port) = addr else {
                            panic!("本用例目标应为 IPv4：{addr:?}");
                        };
                        let mut upstream = TcpStream::connect((std::net::Ipv4Addr::from(ip), port))
                            .await
                            .unwrap();
                        seen_targets.push((meta.session_id, port));
                        assert!(server.handle_new(&meta).is_ok());
                        // New 帧同样可能携带首包数据（参考 `writeFirstPayload`），
                        // 必须按 `OptionData` 读掉数据段，否则与后续帧错位。
                        if meta.has_data() {
                            let payload = read_data_async(&mut stream, true).await.unwrap();
                            if !payload.is_empty() {
                                upstream.write_all(&payload).await.unwrap();
                                upstream.flush().await.unwrap();
                                let mut reply = vec![0; payload.len()];
                                upstream.read_exact(&mut reply).await.unwrap();
                                let mut writer = SessionWriter::response(meta.session_id, TCP);
                                write_frame_async(&mut stream, &writer.next_keep(), Some(&reply))
                                    .await
                                    .unwrap();
                                std::mem::drop(writer);
                            }
                        }
                        upstreams.insert(meta.session_id, upstream);
                    }
                    SessionStatus::Keep => {
                        let payload = read_data_async(&mut stream, true).await.unwrap();
                        let Some(upstream) = upstreams.get_mut(&meta.session_id) else {
                            continue;
                        };
                        upstream.write_all(&payload).await.unwrap();
                        upstream.flush().await.unwrap();
                        let mut reply = vec![0; payload.len()];
                        upstream.read_exact(&mut reply).await.unwrap();
                        let mut writer = SessionWriter::response(meta.session_id, TCP);
                        write_frame_async(&mut stream, &writer.next_keep(), Some(&reply))
                            .await
                            .unwrap();
                        std::mem::drop(writer);
                    }
                    SessionStatus::KeepAlive => {
                        if meta.has_data() {
                            let _ = read_data_async(&mut stream, true).await;
                        }
                    }
                    SessionStatus::End => {
                        upstreams.remove(&meta.session_id);
                        server.manager.remove(meta.session_id);
                        ended += 1;
                        if meta.has_data() {
                            let _ = read_data_async(&mut stream, true).await;
                        }
                    }
                }
            }
            seen_targets
        });

        // 两条入站连接分别触发两条 mux 会话。
        let mut clients = Vec::new();
        for (client_port, payload) in [(port, payload_a), (port_next, payload_b)] {
            clients.push(tokio::spawn(async move {
                let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, client_port))
                    .await
                    .unwrap();
                stream.write_all(&payload).await.unwrap();
                stream.flush().await.unwrap();
                let mut response = vec![0; payload.len()];
                stream.read_exact(&mut response).await.unwrap();
                assert_eq!(response, payload, "回程必须与本会话载荷一致（不串包）");
                let _ = stream.shutdown().await;
            }));
        }
        for client in clients {
            client.await.unwrap();
        }
        // 参考端不会立刻关闭承载连接（`ClientWorker.monitor` 有 16s 空闲周期），
        // 因此不等待服务端读到 EOF，只断言两条会话都完整往返过一次。
        assert_eq!(echo_a.await.unwrap(), ());
        assert_eq!(echo_b.await.unwrap(), ());
        // 服务端观察到两条会话，且各自命中不同的回环目标。
        // 承载连接在参考端空闲周期内不会关闭，故给服务端任务一个有界等待窗口。
        let seen = match tokio::time::timeout(WAIT, server_task).await {
            Ok(seen) => seen.unwrap(),
            Err(_) => panic!("等待本仓 mux 服务端观测两条会话超时"),
        };
        assert_eq!(seen.len(), 2, "参考端应开出两条逻辑会话：{seen:?}");
        let ports: Vec<u16> = seen.iter().map(|(_, port)| *port).collect();
        assert!(
            ports.contains(&port_a) && ports.contains(&port_b),
            "两条会话应各自命中不同目标端口（{port_a}/{port_b}），实际 {ports:?}"
        );
        assert_ne!(seen[0].0, seen[1].0, "两条会话的 ID 必须不同");
        drop(reference);
    })
    .await
    .unwrap();
}
