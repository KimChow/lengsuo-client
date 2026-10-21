//! 异常矩阵「**清理**」格的 Mux 部分：Mux **会话表**与**承载连接读任务**
//! 的回收。
//!
//! 与 `cleanup/mod.rs` 同属「清理」格，但单独成文件（按职责拆分，控制在
//! 400 行软目标内）。走 `src/mux/worker.rs` 的**公开 API**
//! （`MuxServer::new` / `handle_new` / `handle` / `manager.remove` /
//! `manager.size()`），不新增任何 API。

use std::time::Duration;

use lengsuo_vless::mux::{
    frame::{FrameMetadata, SessionStatus, TargetNetwork, OPTION_DATA},
    worker::{Action, MuxServer},
};
use ss_core::target::TargetAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use super::super::DEADLINE;

/// 「任务必须结束」的观察上限。
const JOIN_LIMIT: Duration = Duration::from_secs(8);

/// **3. Mux 会话表回收：会话关闭后 `manager.size()` 回到 0。**
///
/// 走 `src/mux/worker.rs` 的**公开 API**（`MuxServer::new` / `handle_new` /
/// `handle` / `manager.remove` / `manager.size()`）。断言点：
/// - 登记 3 条会话后 `size() == 3`；
/// - 逐条 `remove` 后 `size()` 回到 **0**（会话表不残留）；
/// - `manager.close()` 之后 `size()` 仍为 0，且表被标记为已关闭。
#[tokio::test]
async fn mux_session_table_returns_to_zero_after_close() {
    let mut server = MuxServer::new();
    assert_eq!(server.manager.size(), 0, "初始会话表必须为空");
    for id in [1u16, 2, 3] {
        let meta = new_frame(id);
        assert_eq!(server.handle_new(&meta).expect("可登记"), id);
    }
    assert_eq!(server.manager.size(), 3, "三条会话都应登记在表里");
    for id in [1u16, 2, 3] {
        let end = FrameMetadata {
            session_id: id,
            status: SessionStatus::End,
            option: 0,
            target: None,
            source: None,
            local: None,
            udp_continuation: false,
        };
        assert_eq!(
            server.handle(&end, None).expect("可处理"),
            Action::CloseSession { id },
            "End 帧必须要求关闭该会话"
        );
        server.manager.remove(id);
    }
    assert_eq!(
        server.manager.size(),
        0,
        "会话关闭后表必须回到 0（不得残留会话条目）"
    );
    for id in [1u16, 2, 3] {
        assert!(
            server.manager.get(id).is_none(),
            "会话 {id} 必须已从表里移除"
        );
    }
    // 关闭整张表后仍为空。
    server.manager.close();
    assert_eq!(server.manager.size(), 0, "close 之后表必须为空");
    assert!(server.manager.closed(), "close 之后表必须标记为已关闭");
}

/// **4. 重复 `handle_new` 同一 `session_id` 覆盖旧会话，不堆积。**
///
/// 对应 `src/mux/worker.rs:424` 的既有语义（参考 `SessionManager.Add`
/// 直接覆盖）。断言点：
/// - 重复登记同一 ID 后 `size()` 仍是 **1**（不是 2）；
/// - 表里只剩**一条**该 ID 的会话（`get` 命中）；
/// - 目标地址是**后一次**的值（覆盖语义）。
#[tokio::test]
async fn mux_duplicate_session_id_overwrites_instead_of_accumulating() {
    let mut server = MuxServer::new();
    let first = new_frame(7);
    assert_eq!(server.handle_new(&first).expect("可登记"), 7);
    assert_eq!(server.manager.size(), 1);

    let mut second = new_frame(7);
    second.target = Some((TargetAddr::V4([127, 0, 0, 2], 8080), TargetNetwork::Tcp));
    assert_eq!(server.handle_new(&second).expect("可登记"), 7);
    assert_eq!(
        server.manager.size(),
        1,
        "重复 session_id 必须覆盖旧会话，不得堆积"
    );
    let state = server.manager.get(7).expect("会话仍在表里");
    assert_eq!(
        state.target,
        (TargetAddr::V4([127, 0, 0, 2], 8080), TargetNetwork::Tcp),
        "覆盖后应是后一次的目标"
    );
}

/// **5. Mux 承载连接的读任务在对端关闭后结束（无悬挂读任务）。**
///
/// 用真实 TCP：服务端在 Mux 帧上跑 `MuxServer` 状态机；客户端发完一个
/// `New` 帧后关闭连接。断言点：服务端的承载连接读循环必须在有限时间内
/// 结束（读到 EOF），会话表随之清空。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mux_carrier_read_task_ends_after_peer_close() {
    timeout(DEADLINE, async {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("绑定回环端口");
        let port = listener.local_addr().expect("读取端口").port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("接受连接");
            let mut server = MuxServer::new();
            // 读一个 `New` 帧 → 登记会话。
            let meta = read_new_frame(&mut socket).await.expect("读 New 帧");
            server.handle_new(&meta).expect("登记会话");
            assert_eq!(server.manager.size(), 1, "会话已登记");
            // 继续读承载连接，直到对端关闭（EOF）⇒ 读循环结束。
            loop {
                let mut header = [0u8; 2];
                if socket.read_exact(&mut header).await.is_err() {
                    break;
                }
            }
            server.manager.close();
            server.manager.size()
        });

        let mut socket = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("连接回环");
        // 发一个 `New` 帧（带目标地址）。
        let mut wire = Vec::new();
        new_frame(1).encode_into(&mut wire).expect("可编码");
        socket.write_all(&wire).await.expect("写 New 帧");
        socket.flush().await.expect("flush");
        // 关闭整条承载连接。
        socket.shutdown().await.expect("关闭承载连接");

        let size = timeout(JOIN_LIMIT, server)
            .await
            .expect("Mux 承载读任务挂住（存在悬挂读任务）")
            .expect("Mux 承载任务异常");
        assert_eq!(size, 0, "承载连接结束后会话表必须清空");
    })
    .await
    .expect("用例总超时");
}

/// 造一个带目标的 `New` 帧元数据。
fn new_frame(session_id: u16) -> FrameMetadata {
    FrameMetadata {
        session_id,
        status: SessionStatus::New,
        option: OPTION_DATA,
        target: Some((TargetAddr::V4([127, 0, 0, 1], 80), TargetNetwork::Tcp)),
        source: None,
        local: None,
        udp_continuation: false,
    }
}

/// 从承载连接上读一个 `New` 帧（只取元数据，不读数据段）。
async fn read_new_frame(socket: &mut TcpStream) -> Result<FrameMetadata, String> {
    let mut len_wire = [0u8; 2];
    socket
        .read_exact(&mut len_wire)
        .await
        .map_err(|e| format!("读 metaLen 失败: {e}"))?;
    let meta_len = usize::from(u16::from_be_bytes(len_wire));
    let mut body = vec![0u8; meta_len];
    socket
        .read_exact(&mut body)
        .await
        .map_err(|e| format!("读元数据失败: {e}"))?;
    FrameMetadata::decode_meta(&body, false).map_err(|e| format!("解析元数据失败: {e}"))
}
