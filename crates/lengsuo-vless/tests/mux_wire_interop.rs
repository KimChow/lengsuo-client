//! 参考互通：`MuxWire` 出站原语与固定版本参考端的真实互跑。
//!
//! 显式执行：
//! `LENGSUO_XRAY=/绝对路径/xray cargo test -p lengsuo-vless --test mux_wire_interop -- --ignored --nocapture`
//!
//! 本文件与 `mux_wire.rs` 分开：前者是**参考互通**（需外部二进制、默认跳过），
//! 后者是**本仓自洽**（往返 / 拒绝路径，默认跑）。两者职责不同，分文件避免
//! 单文件超行数上限。

mod support;

use lengsuo_vless::mux::frame::{SessionStatus, TargetNetwork};
use lengsuo_vless::mux::worker::Strategy;
use lengsuo_vless::mux_wire::{MuxWire, DEFAULT_DEADLINE};
use ss_core::target::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PAYLOAD: &[u8] = b"lengsuo-mux-interop-payload";

/// 目标网络常量（TCP=1）。
const TCP: TargetNetwork = TargetNetwork::Tcp;

fn target(port: u16) -> (TargetAddr, TargetNetwork) {
    (
        TargetAddr::Ip("127.0.0.1".parse().expect("合法 IP")),
        TargetNetwork::Tcp,
    )
}

// ============================================================================
// 参考互通：新 API 与固定版本 Xray 真实互跑（`#[ignore]`，显式实跑）
// ============================================================================

/// 参考互通：Xray mux 服务端 ⇄ 本仓 `mux_wire` 出站原语。
///
/// 显式执行：
/// `LENGSUO_XRAY=/绝对路径/xray cargo test -p lengsuo-vless --test mux_wire -- --ignored --nocapture`
///
/// 覆盖：
/// - 本仓 `MuxWire` 发出的 `New` 帧（承载 VLESS `command=Mux` 头）被参考端识别为
///   mux 会话并转发到真实回环 echo 目标；
/// - 参考端的下行 `Keep` 帧被本仓 `MuxWire::next_inbound` 正确解出，载荷逐字节一致；
/// - 参考端对本仓 `MuxSession::close` 发出的 `End` 帧不报错（对齐参考
///   `handleStatusEnd`：只关会话，不回 `End`）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_mux_server_accepts_mux_wire_outbound() {
    use lengsuo_vless::header::{Command, Request};
    use lengsuo_vless::stream::{receive_response, send_request};
    use serde_json::json;
    use support::{free_port, launch, ID, KEY};
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    timeout(support::WAIT, async {
        // 参考端的回环 echo 目标：每条会话用不同载荷，串包会被立刻发现。
        let mut echo_ports = Vec::new();
        let mut echo_tasks = Vec::new();
        for index in 0..2u8 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            echo_ports.push(listener.local_addr().unwrap().port());
            let payload = [PAYLOAD, &[index]].concat();
            echo_tasks.push(tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut received = vec![0; payload.len()];
                stream.read_exact(&mut received).await.unwrap();
                assert_eq!(received, payload, "参考端转发的载荷必须与请求一致");
                stream.write_all(&received).await.unwrap();
                stream.flush().await.unwrap();
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

        // 承载连接：先发 VLESS `command=Mux` 头（参考 `EncodeRequestHeader` 对
        // `RequestCommandMux` 不写地址），再由 `MuxWire` 接管同一条字节流。
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let request = Request {
            command: Command::Mux,
            target: TargetAddr::Domain(lengsuo_vless::mux::MUX_COOL_ADDRESS.to_string(), 0),
        };
        send_request(&mut stream, &request, &KEY, support::WAIT)
            .await
            .unwrap();
        // 参考端先回 VLESS 响应头，之后才是 mux 帧。
        receive_response(&mut stream, support::WAIT).await.unwrap();

        let mut wire = MuxWire::new(stream, Strategy::default());
        let mut sessions = Vec::new();
        for (index, echo_port) in echo_ports.iter().enumerate() {
            let target = (TargetAddr::V4([127, 0, 0, 1], *echo_port), TCP);
            let payload = [PAYLOAD, &[index as u8]].concat();
            let mut session = wire
                .open(target, Some(&payload), support::WAIT)
                .await
                .expect("可开会话");
            // 首包已随 `New` 帧发出；再补一包 `Keep` 数据，验证续帧路径。
            session.write(&payload, support::WAIT).await.expect("可写");
            sessions.push(session);
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
            let inbound = wire.next_inbound(support::WAIT).await.expect("可读下行帧");
            if let Action::Deliver { id, payload, .. } = inbound.action {
                received.insert(id, payload);
            }
        }
        for (index, session) in sessions.iter().enumerate() {
            let expected = [PAYLOAD, &[index as u8]].concat();
            assert_eq!(
                received.get(&session.id()).map(Vec::as_slice),
                Some(expected.as_slice()),
                "会话 {} 的回程必须与自己的载荷一致（不串包）",
                session.id()
            );
        }

        // 收尾：`End` 帧（参考 `handleStatusEnd` 只关会话，不回 `End`）。
        for session in sessions {
            session.close(support::WAIT).await.expect("可收尾");
        }
        for task in echo_tasks {
            task.await.expect("回环 echo 完成");
        }
        drop(reference);
    })
    .await
    .expect("与参考端的互通未在时限内完成");
}
