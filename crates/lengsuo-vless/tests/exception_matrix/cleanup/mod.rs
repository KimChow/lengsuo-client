//! 异常矩阵「**清理**」格：连接结束/异常断开之后，**会话资源被回收**。
//!
//! 覆盖（与 `docs/audit-all1.md` §3 的「清理」格一一对应）：
//! 1. `clean_close_reclaims_the_stream` —— 正常收尾后，服务端侧**读任务
//!    已结束**且读到的是**干净 EOF**（`Ok(0)`，不是 `Err(UnexpectedEof)` /
//!    `ConnectionReset`）；客户端侧 `RealityStream::close` 在有限时间内返回。
//! 2. `abrupt_reset_is_observed_and_no_further_data_is_delivered` —— 对端
//!    直接 RST（不发 FIN）⇒ 本仓侧**有限时间内**感知到断开（错误或 EOF），
//!    且**后续不再有数据被投递**。
//! 3. Mux 部分（见子模块 [`mux`]）：会话表回收、重复 `session_id` 覆盖、
//!    Mux 承载连接读任务结束。
//! 4. REALITY 收尾**幂等**部分（见子模块 [`reality_idempotent`]）：重复
//!    `shutdown()` / 重复 `close()` / `shutdown()` 后 `close()` 都**不 panic**。
//!
//! 每条用例都有**外层 `timeout(...)` 兜底**：本仓若真的挂住，用例是**超时
//! 失败**而不是静默通过。

use std::time::Duration;

use lengsuo_vless::stream;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use super::{reality_fixture, request, DEADLINE, KEY, WAIT};

mod mux;
mod reality_idempotent;

/// 「任务必须结束」的观察上限。
const JOIN_LIMIT: Duration = Duration::from_secs(8);
/// 载荷（往返比对用）。
const PAYLOAD: &[u8] = b"vless cleanup payload\0\xfe\xff binary";

/// **1. 正常收尾后资源回收。**
///
/// 断言点（三条都要满足）：
/// - 服务端侧**读任务已结束**：对端 `shutdown` 后本仓读到**干净 EOF**
///   （`Ok(0)` 字节，**不是** `Err(UnexpectedEof)` / `ConnectionReset`）；
/// - **没有遗留悬挂的读任务**：后台泵任务在有限时间内结束；
/// - 客户端侧 `RealityStream::close()` 在有限时间内返回（写任务与读任务
///   都收尾）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clean_close_reclaims_the_stream() {
    timeout(DEADLINE, async {
        let server = reality_fixture::start_server().await;
        let config = reality_fixture::client_config();
        let mut client = reality_fixture::connect(&format!("127.0.0.1:{}", server.port), &config)
            .await
            .expect("REALITY 建流");

        // —— 主链路往返：请求头 → 响应头 → 载荷 ——
        stream::send_request(&mut client, &request(), &KEY, WAIT)
            .await
            .expect("写请求头");
        client.write_all(PAYLOAD).await.expect("写载荷");

        let mut server_app = server.app;
        let received = stream::receive_request(&mut server_app, &KEY, WAIT)
            .await
            .expect("服务端读请求头");
        assert_eq!(received, request());
        let mut body = vec![0u8; PAYLOAD.len()];
        timeout(WAIT, server_app.read_exact(&mut body))
            .await
            .expect("服务端读载荷超时")
            .expect("服务端读载荷");
        assert_eq!(&body, PAYLOAD, "载荷必须逐字节一致");
        stream::send_response(&mut server_app, WAIT)
            .await
            .expect("服务端写响应头");
        server_app.write_all(&body).await.expect("服务端回写载荷");
        server_app.flush().await.expect("服务端 flush");

        stream::receive_response(&mut client, WAIT)
            .await
            .expect("客户端读响应头");
        let mut echoed = vec![0u8; PAYLOAD.len()];
        timeout(WAIT, client.read_exact(&mut echoed))
            .await
            .expect("客户端读载荷超时")
            .expect("客户端读载荷");
        assert_eq!(&echoed, PAYLOAD, "回程载荷必须逐字节一致");

        // —— 双方干净关闭 ——
        // 客户端整体收尾：关写方向（FIN）并等写任务与读任务都结束。
        // 观察上限短于传输层内部的 10s 读截止时间，挂住即为失败而不是被
        // 内部超时掩盖。
        timeout(JOIN_LIMIT, client.close())
            .await
            .expect("客户端 close 挂住（存在悬挂任务）");
        // 服务端侧：本仓读到**干净 EOF**（0 字节），不是错误。
        let mut eof_buffer = [0u8; 1];
        let read = timeout(WAIT, server_app.read(&mut eof_buffer))
            .await
            .expect("服务端等 EOF 超时")
            .expect("服务端等 EOF 出错");
        assert_eq!(read, 0, "对端干净关闭必须读到 EOF（0 字节），不是错误");
        // 服务端侧：客户端关掉整条连接后，泵任务必须在有限时间内结束。
        drop(server_app);
        reality_fixture::join_pumps(server.pumps, JOIN_LIMIT)
            .await
            .expect("服务端泵任务挂住（存在悬挂读任务）");
    })
    .await
    .expect("用例总超时");
}

/// **1a. 干净关闭 ⇒ 读侧看到的是「干净 EOF」而不是错误。**
///
/// 这是卡片「清理」格最直接的判据：对端 `shutdown`（FIN）后，本仓读侧
/// 必须读到 `Ok(0)` 字节，**不是** `Err(UnexpectedEof)` / `ConnectionReset`。
/// 用真实 TCP 复现，服务端把请求头与载荷读完后**继续读到 EOF**，并记录
/// 读到的字节数与错误类型。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clean_close_yields_clean_eof_on_the_read_side() {
    timeout(DEADLINE, async {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("绑定回环端口");
        let port = listener.local_addr().expect("读取端口").port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("接受连接");
            let received = stream::receive_request(&mut socket, &KEY, WAIT)
                .await
                .expect("读请求头");
            assert_eq!(received, request());
            let mut body = vec![0u8; PAYLOAD.len()];
            socket.read_exact(&mut body).await.expect("读载荷");
            assert_eq!(&body, PAYLOAD, "载荷必须逐字节一致");
            // 继续读，直到对端关闭：**必须**是干净 EOF。
            let mut extra = [0u8; 8];
            let outcome = socket.read(&mut extra).await;
            match outcome {
                Ok(0) => (0usize, "clean-eof".to_owned()),
                Ok(n) => (n, "unexpected-data".to_owned()),
                Err(error) => (usize::MAX, format!("{:?}", error.kind())),
            }
        });

        let mut socket = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("连接回环");
        stream::send_request(&mut socket, &request(), &KEY, WAIT)
            .await
            .expect("写请求头");
        socket.write_all(PAYLOAD).await.expect("写载荷");
        socket.flush().await.expect("flush");
        // 干净关闭（只发 FIN，不发 RST）。
        socket.shutdown().await.expect("关闭写端");

        let (read, kind) = timeout(WAIT, server)
            .await
            .expect("服务端读侧挂住（本仓没有感知到关闭）")
            .expect("服务端任务异常");
        assert_eq!(read, 0, "对端干净关闭必须读到 0 字节（干净 EOF）");
        assert_eq!(kind, "clean-eof", "读侧必须拿到干净 EOF，而不是错误");
        println!("干净关闭取证：读侧拿到 clean EOF（0 字节）");
    })
    .await
    .expect("用例总超时");
}

/// **2. 对端异常断开（RST）后回收。**
///
/// 对端 `set_zero_linger` 后直接关连接 ⇒ 本仓侧收到 RST。断言点：
/// - 读方向**有限时间内**返回（错误或 EOF），不得挂住；
/// - 断开后**后续不再有数据被投递**：再读一次必须是 `Ok(0)` 或错误，
///   绝不会读到新载荷。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abrupt_reset_is_observed_and_no_further_data_is_delivered() {
    timeout(DEADLINE, async {
        let (port, trigger) = resetting_peer().await;

        let mut socket = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("连接回环");
        // 先写一点数据，确认连接已建立。
        socket.write_all(b"ping").await.expect("写探测字节");
        socket.flush().await.expect("flush");
        // 通知对端：现在可以 RST 了（避免 RST 早于连接的竞态）。
        trigger.send(()).expect("通知对端");
        // 对端此刻关闭连接（发 RST）。

        // 第一次读：有限时间内必须感知到断开（错误或 EOF）。
        let mut buffer = [0u8; 16];
        let first = timeout(WAIT, socket.read(&mut buffer))
            .await
            .expect("感知断开超时（本仓挂住了）");
        match first {
            Ok(0) => { /* 干净 EOF 也算感知到断开 */ }
            Ok(_) => panic!("RST 之后不应读到数据"),
            Err(error) => {
                // RST 的典型表现：`ConnectionReset` / `ConnectionAborted`。
                let kind = error.kind();
                assert!(
                    matches!(
                        kind,
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ),
                    "RST 必须是连接类错误，实际：{kind:?}"
                );
            }
        }
        // 断开后**不再有数据被投递**：再读一次只能是 EOF 或同样的错误。
        let second = timeout(WAIT, socket.read(&mut buffer))
            .await
            .expect("断开后再次读超时");
        match second {
            Ok(0) | Err(_) => {}
            Ok(read) => panic!("断开后不得再投递数据，实际读到 {read} 字节"),
        }
    })
    .await
    .expect("用例总超时");
}

/// **2b. 对端异常断开后，VLESS 主链路读方向**也必须在有限时间内失败。
///
/// 用真实 socket：客户端发完请求头后，对端 RST；`receive_response` 必须
/// 有限时间内返回错误（**不是**超时、也不是 `Ok`）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abrupt_reset_fails_the_main_link_read_in_bounded_time() {
    timeout(DEADLINE, async {
        let (port, trigger) = resetting_peer().await;
        let mut socket = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("连接回环");
        stream::send_request(&mut socket, &request(), &KEY, WAIT)
            .await
            .expect("写请求头");
        // 通知对端：现在可以 RST 了。
        trigger.send(()).expect("通知对端");

        let result = timeout(WAIT, stream::receive_response(&mut socket, WAIT))
            .await
            .expect("主链路读挂住（本仓没有感知断开）");
        assert!(
            result.is_err(),
            "RST 之后主链路读必须失败，实际：{result:?}"
        );
        assert!(
            !matches!(result, Err(stream::Error::Timeout)),
            "RST 是连接错误，不是超时：{result:?}"
        );
    })
    .await
    .expect("用例总超时");
}

/// 起一个「收到信号就发 RST 断开」的回环对端。
///
/// 返回 `(端口, 触发信号)`：调用方写完数据后 `send` 一下，对端随即
/// `set_zero_linger` + drop（**不发 FIN**，直接 RST）。用信号而不是「立即
/// 断开」是为了消除「RST 早于客户端 connect 完成」的竞态。
async fn resetting_peer() -> (u16, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑定回环端口");
    let port = listener.local_addr().expect("读取端口").port();
    let (trigger, wait) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let Ok((socket, _)) = listener.accept().await else {
            return;
        };
        // 等调用方写完再断开。
        let _ = wait.await;
        // 零 linger 的关闭会发 RST（而不是正常 FIN 握手）。
        socket.set_zero_linger().expect("设置零 linger");
        drop(socket);
    });
    (port, trigger)
}
