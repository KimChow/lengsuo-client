//! 异常矩阵「**超时**」格：握手/读响应在**有限时间**内失败，且失败被明确
//! 判为超时（而不是 `Ok`、也不是无限等待）。
//!
//! 覆盖（与 `docs/audit-all1.md` §3 的「超时」格一一对应）：
//! 1. `silent_peer_makes_client_handshake_time_out` —— 协议层：**对端接受
//!    连接后一个字都不写**（既不回响应头、也不回字节），客户端方向必须在
//!    有限时间内拿到**超时类**错误。
//! 2. `silent_peer_makes_server_handshake_time_out` —— 协议层：服务端方向
//!    （`receive_request`）对端沉默时同样必须超时失败。
//! 3. `reality_transport_silent_peer_times_out` —— 传输层：REALITY 握手
//!    对端沉默时 `RealityStream::connect` 必须在有限时间内返回超时。
//! 4. `mismatched_response_header_is_a_protocol_error` —— 对端回了**完整但
//!    错误**的响应头（`[0, 1]`）⇒ 必须是**协议错误**，既不是成功、也不是超时。
//! 5. `truncated_response_header_is_an_io_error` —— 对端只回 `[0]`（半个
//!    响应头）后关闭 ⇒ 必须是 **I/O 错误**，与第 4 条的协议错误**可区分**。
//! 6. `timeout_does_not_poison_the_next_connection` —— 一次超时**不得**污染
//!    后续连接：新建一条连接走同样流程必须成功。
//!
//! 每条用例都有**外层 `timeout(...)` 兜底**：本仓若真的挂住，用例是**超时
//! 失败**而不是静默通过。

use std::time::Duration;

use lengsuo_vless::{header::Request, stream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use super::{reality_fixture, request, DEADLINE, KEY, WAIT};

/// 「对端沉默」场景的观察窗口：必须**明显短于** `WAIT`，这样「本仓自己
/// 超时」与「用例层兜底超时」能被区分开。
const SILENT_WINDOW: Duration = Duration::from_millis(300);

/// 起一个**只 accept、不写任何字节**的回环服务端；返回端口。
///
/// 对端既不回 VLESS 响应头、也不回任何载荷——这正是「握手过程中对端接受
/// 连接后不回任何字节」的故障注入。
async fn silent_peer() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑定回环端口");
    let port = listener.local_addr().expect("读取端口").port();
    tokio::spawn(async move {
        // 只接受连接并**保持沉默**：不写、不关。
        let Ok((socket, _)) = listener.accept().await else {
            return;
        };
        // 把 socket 留住（不 drop、不写），对端就一直等不到任何字节。
        std::mem::forget(socket);
    });
    port
}

/// **1. 客户端方向：对端沉默 ⇒ 有限时间内判为超时失败。**
///
/// 断言点：返回值是 `Err` 且**错误变体是超时类**（`stream::Error::Timeout`）；
/// 不是 `Ok`，也不是「读到了半个响应头」这种别的错误。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_peer_makes_client_handshake_time_out() {
    timeout(DEADLINE, async {
        let port = silent_peer().await;
        let mut socket = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("连接回环");
        // 先把请求头发出去（写成功不代表对端会回响应头）。
        stream::send_request(&mut socket, &request(), &KEY, WAIT)
            .await
            .expect("写请求头");
        // 对端沉默：读响应头必须**有界**地失败。
        let started = tokio::time::Instant::now();
        let result = stream::receive_response(&mut socket, SILENT_WINDOW).await;
        let elapsed = started.elapsed();
        assert!(
            matches!(result, Err(stream::Error::Timeout)),
            "对端沉默时必须是超时类错误，实际：{result:?}"
        );
        assert!(
            elapsed < WAIT,
            "超时判定必须在观察窗口内生效，实测 {elapsed:?}"
        );
    })
    .await
    .expect("用例总超时");
}

/// **2. 服务端方向：对端沉默 ⇒ `receive_request` 必须超时失败。**
///
/// 断言点：`Err(stream::Error::Timeout)`，且**没有**把沉默误判成认证失败
/// 或「收到空请求」。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_peer_makes_server_handshake_time_out() {
    timeout(DEADLINE, async {
        let port = silent_peer().await;
        let mut socket = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("连接回环");
        let result = stream::receive_request(&mut socket, &KEY, SILENT_WINDOW).await;
        assert!(
            matches!(result, Err(stream::Error::Timeout)),
            "对端沉默时服务端方向也必须超时，实际：{result:?}"
        );
    })
    .await
    .expect("用例总超时");
}

/// **3. 传输层：REALITY 握手对端沉默 ⇒ `connect` 必须超时失败。**
///
/// 断言点：`RealityStream::connect` 返回 `Err` 且错误变体是
/// `reality_link::Error::Timeout`（**不是** `Handshake`，也不是 `Ok`）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reality_transport_silent_peer_times_out() {
    timeout(DEADLINE, async {
        let port = silent_peer().await;
        let config = reality_fixture::client_config();
        let result = reality_fixture::connect_with_deadline(
            &format!("127.0.0.1:{port}"),
            &config,
            SILENT_WINDOW,
        )
        .await;
        assert!(
            matches!(result, Err(lengsuo_vless::reality_link::Error::Timeout)),
            "REALITY 握手对端沉默必须是超时错误，实际：{result:?}"
        );
    })
    .await
    .expect("用例总超时");
}

/// **4. 响应头不匹配 ⇒ 明确的协议错误（不是成功、也不是超时）。**
///
/// 对端回了**完整但错误**的响应头 `[0, 1]`（`receive_response` 只接受
/// `[0, 0]`）。断言点：拿到 `Err(stream::Error::Header(_))`——协议错误
/// 变体，可与第 1 条的超时、第 5 条的 I/O 错误**三向区分**。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mismatched_response_header_is_a_protocol_error() {
    timeout(DEADLINE, async {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(&[0, 1]).await.expect("写错误响应头");
        let result = stream::receive_response(&mut reader, WAIT).await;
        assert!(
            matches!(result, Err(stream::Error::Header(_))),
            "错误响应头必须是协议错误，实际：{result:?}"
        );
        // 明确排除「被当成超时」与「被当成成功」。
        assert!(!matches!(result, Err(stream::Error::Timeout)));
        assert!(!matches!(result, Ok(())));
    })
    .await
    .expect("用例总超时");
}

/// **5. 响应头截断 ⇒ I/O 错误（与第 4 条的协议错误可区分）。**
///
/// 对端只回 `[0]`（半个响应头）后关闭。断言点：`Err(stream::Error::Io(_))`
/// ——与「完整但错误的响应头」（协议错误）**变体不同**，因此两种失败
/// 在调用方侧是可区分的。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn truncated_response_header_is_an_io_error() {
    timeout(DEADLINE, async {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(&[0]).await.expect("写半个响应头");
        writer.shutdown().await.expect("关闭写端");
        let result = stream::receive_response(&mut reader, WAIT).await;
        assert!(
            matches!(result, Err(stream::Error::Io(_))),
            "截断响应头必须是 I/O 错误，实际：{result:?}"
        );
        // 与第 4 条区分：截断**不是**协议错误。
        assert!(!matches!(result, Err(stream::Error::Header(_))));
        assert!(!matches!(result, Ok(())));
    })
    .await
    .expect("用例总超时");
}

/// **5b. 截断响应头在真实 TCP 上同样是 I/O 错误**（不是超时）。
///
/// 用真实 socket 复现「对端回半个响应头后关闭」，断言失败原因与第 5 条
/// 一致，且**不是**超时。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn truncated_response_header_over_tcp_is_an_io_error() {
    timeout(DEADLINE, async {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("绑定回环端口");
        let port = listener.local_addr().expect("读取端口").port();
        tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let _ = socket.write_all(&[0]).await;
            let _ = socket.shutdown().await;
        });
        let mut socket = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("连接回环");
        let result = stream::receive_response(&mut socket, WAIT).await;
        assert!(
            matches!(result, Err(stream::Error::Io(_))),
            "TCP 上截断响应头必须是 I/O 错误，实际：{result:?}"
        );
    })
    .await
    .expect("用例总超时");
}

/// **6. 超时后仍可用：一次超时不得污染后续连接。**
///
/// 断言点：先在一条连接上拿到超时错误；再新建一条连接（对端这次会正常
/// 回应），完整走「请求头 → 响应头 → 载荷」并**逐字节**比对成功。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeout_does_not_poison_the_next_connection() {
    timeout(DEADLINE, async {
        // 第一条：对端沉默 ⇒ 超时。
        let silent_port = silent_peer().await;
        let mut silent = TcpStream::connect(("127.0.0.1", silent_port))
            .await
            .expect("连接回环");
        stream::send_request(&mut silent, &request(), &KEY, WAIT)
            .await
            .expect("写请求头");
        assert!(matches!(
            stream::receive_response(&mut silent, SILENT_WINDOW).await,
            Err(stream::Error::Timeout)
        ));
        drop(silent);

        // 第二条：正常对端 ⇒ 同样流程必须成功。
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("绑定回环端口");
        let port = listener.local_addr().expect("读取端口").port();
        let payload = b"after-timeout payload";
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("接受连接");
            let received = stream::receive_request(&mut socket, &KEY, WAIT)
                .await
                .expect("读请求头");
            assert_eq!(received, request());
            let mut body = vec![0u8; payload.len()];
            socket.read_exact(&mut body).await.expect("读载荷");
            assert_eq!(&body, payload);
            stream::send_response(&mut socket, WAIT)
                .await
                .expect("写响应头");
            socket.write_all(&body).await.expect("回写载荷");
            socket.flush().await.expect("flush");
        });

        let mut socket = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("连接回环");
        stream::send_request(&mut socket, &request(), &KEY, WAIT)
            .await
            .expect("写请求头");
        socket.write_all(payload).await.expect("写载荷");
        stream::receive_response(&mut socket, WAIT)
            .await
            .expect("读响应头");
        let mut echoed = vec![0u8; payload.len()];
        timeout(WAIT, socket.read_exact(&mut echoed))
            .await
            .expect("读载荷超时")
            .expect("读载荷");
        assert_eq!(&echoed, payload, "超时之后的新连接必须逐字节一致");
        server.await.expect("服务端任务");
    })
    .await
    .expect("用例总超时");
}

/// **6b. 协议层超时后，同一监听端点仍能服务新连接**（服务端侧不被污染）。
///
/// 断言点：服务端在一次「读到对端就关闭」的连接后，`receive_request` 拿到
/// I/O 错误（**不是**超时，也**不是**认证失败）；随后同一条监听再服务一条
/// 正常连接并成功完成往返。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_side_failure_does_not_poison_the_next_session() {
    timeout(DEADLINE, async {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("绑定回环端口");
        let port = listener.local_addr().expect("读取端口").port();

        // 第一次：客户端连上就关 ⇒ 服务端读到 I/O 错误。
        let mut abrupt = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("连接回环");
        abrupt.shutdown().await.expect("关闭写端");
        let (mut accepted, _) = listener.accept().await.expect("接受连接");
        let first = stream::receive_request(&mut accepted, &KEY, WAIT).await;
        assert!(
            matches!(first, Err(stream::Error::Io(_))),
            "对端关闭必须是 I/O 错误，实际：{first:?}"
        );
        drop(accepted);

        // 第二次：正常往返必须成功。
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("接受连接");
            let received = stream::receive_request(&mut socket, &KEY, WAIT)
                .await
                .expect("读请求头");
            assert_eq!(received, request());
            stream::send_response(&mut socket, WAIT)
                .await
                .expect("写响应头");
            socket.write_all(b"ok").await.expect("写载荷");
            socket.flush().await.expect("flush");
        });
        let mut socket = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("连接回环");
        stream::send_request(&mut socket, &request(), &KEY, WAIT)
            .await
            .expect("写请求头");
        stream::receive_response(&mut socket, WAIT)
            .await
            .expect("读响应头");
        let mut body = vec![0u8; 2];
        timeout(WAIT, socket.read_exact(&mut body))
            .await
            .expect("读载荷超时")
            .expect("读载荷");
        assert_eq!(&body, b"ok");
        server.await.expect("服务端任务");
    })
    .await
    .expect("用例总超时");
}

/// **辅助**：确认「对端接受连接后一个字都不写」时，本仓的**写**方向不受
/// 影响（请求头确实发出去了），从而上面的超时是「读不到响应」而不是
/// 「写不出去」造成的假象。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_write_succeeds_against_a_silent_peer() {
    timeout(DEADLINE, async {
        let port = silent_peer().await;
        let mut socket = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("连接回环");
        let request: Request = request();
        stream::send_request(&mut socket, &request, &KEY, WAIT)
            .await
            .expect("向沉默对端写请求头必须成功");
    })
    .await
    .expect("用例总超时");
}
