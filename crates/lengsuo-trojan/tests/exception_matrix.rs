//! Trojan 服务端**完整异常矩阵**（非忽略）——每条都有明确判据与超时。
//!
//! 判定纪律：**不把“我方读操作超时”当“被拒绝”**。每条拒绝都要求
//! （a）对端在观察上限内**主动结束连接**（读到 `Ok(0)`/`Err`），且
//! （b）本仓服务端处理任务返回**可判别的错误变体**（不是 panic、不是挂起）。
//!
//! 覆盖面：
//! - 错密码（含“正确密码对照组”证明观测面有效）；
//! - 截断请求头的**每一部分**：哈希 / 哈希后 CRLF / 命令 / 地址（IPv4 各前缀）/
//!   尾 CRLF；
//! - 篡改 SHA224 摘要（首字节、末字节、全零）；
//! - 重放同一请求头（记录参考与实现行为）；
//! - 半关闭：客户端 `shutdown(Write)` 后仍读完响应；服务端关闭后客户端 EOF 不挂死；
//! - 超时与资源清理：连接被拒/超时后**无悬挂任务**（任务计数回到基线）。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use lengsuo_tls::{PrivatePkcs8KeyDer, TlsClient};
use lengsuo_trojan::codec;
use lengsuo_trojan::server::{Error, Inbound, Server, Timeouts, Validator};
use lengsuo_trojan::{Command, Credential, Request, TargetAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

const PASSWORD: &str = "exception-matrix-good-password";
const BAD_PASSWORD: &str = "exception-matrix-wrong-password";
const PAYLOAD: &[u8] = b"exception-matrix-payload";
/// 回显后端按 `PAYLOAD.len()` 读取并原样回写，故回程等于 PAYLOAD。
const REPLY: &[u8] = PAYLOAD;
/// 参考默认握手截止 60s 太长；本文件用 2s 观测“写一半后静默”的有界拒绝，
/// 并确保 `CLOSE_BOUND` 明显大于它且又远小于总预算。
const HANDSHAKE: Duration = Duration::from_secs(2);
/// 单次读/写/任务回收的观察上限。
const WAIT: Duration = Duration::from_secs(8);
const CLOSE_BOUND: Duration = Duration::from_secs(8);
const TOTAL: Duration = Duration::from_secs(45);

struct Identity {
    client: TlsClient,
    cert: rcgen::CertifiedKey,
}

impl Identity {
    fn new() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let client = TlsClient::new("localhost", [cert.cert.der().clone()], WAIT).unwrap();
        Self { client, cert }
    }

    fn inbound(&self) -> Inbound {
        Inbound::new(
            vec![self.cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(self.cert.key_pair.serialize_der()).into(),
            WAIT,
        )
        .unwrap()
    }

    async fn connect(&self, port: u16) -> impl AsyncReadExt + AsyncWriteExt + Unpin {
        self.client
            .connect(([127, 0, 0, 1], port).into())
            .await
            .unwrap()
    }
}

/// 单连接服务端：accept 一条 → `handle_tcp` → 返回其结果。带任务计数观测。
struct Harness {
    port: u16,
    live: Arc<AtomicUsize>,
}

impl Harness {
    async fn start(
        identity: &Identity,
        password: &str,
    ) -> (Harness, tokio::task::JoinHandle<Result<(), Error>>) {
        let mut validator = Validator::new();
        validator.add("matrix@example.com", password).unwrap();
        let server = Server::with_tls(
            validator,
            Timeouts::new(HANDSHAKE, WAIT).unwrap(),
            identity.inbound(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let live = Arc::new(AtomicUsize::new(0));
        let counter = live.clone();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
            let outcome = server.handle_tcp(socket).await;
            counter.fetch_sub(1, Ordering::SeqCst);
            outcome
        });
        (Harness { port, live }, task)
    }
}

/// 回显后端：读满 `len` 字节后原样回写并关写端，accept 计数。
async fn spawn_echo(len: usize) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = vec![0u8; len];
                if socket.read_exact(&mut buf).await.is_err() {
                    return;
                }
                let _ = socket.write_all(&buf).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (port, accepted)
}

/// 断言对端在 `within` 内**主动结束**连接：读到 `Ok(0)` 或 `Err`。
/// 只读到超时即 panic（超时不算拒绝证据）。
async fn assert_peer_closed<S: tokio::io::AsyncRead + Unpin>(stream: &mut S, within: Duration) {
    let mut buf = [0u8; 32];
    let outcome = timeout(within, stream.read(&mut buf))
        .await
        .expect("对端必须在观察上限内主动结束连接（超时不算拒绝证据）");
    assert!(
        matches!(outcome, Ok(0) | Err(_)),
        "不得收到应答：{outcome:?}"
    );
}

/// 完整合法请求头字节（正确密码，TCP → 127.0.0.1:port）。
fn valid_header(port: u16) -> Vec<u8> {
    codec::encode(
        &Request {
            command: Command::Tcp,
            target: TargetAddr::V4([127, 0, 0, 1], port),
        },
        &Credential::new(PASSWORD),
    )
    .unwrap()
}

// ───────────────────────── 错密码 ─────────────────────────

/// 错密码：服务端必须返回 `Authentication` 且主动关闭；业务目标 accept 计数不增长。
/// 先跑正确密码对照组证明观测面有效。
#[tokio::test]
async fn wrong_password_rejected_and_target_untouched() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let (echo_port, accepted) = spawn_echo(REPLY.len()).await;

        // 对照组：正确密码抵达业务目标。
        let (harness, task) = Harness::start(&identity, PASSWORD).await;
        {
            let mut stream = identity.connect(harness.port).await;
            let header = valid_header(echo_port);
            stream.write_all(&header).await.unwrap();
            stream.write_all(PAYLOAD).await.unwrap();
            stream.flush().await.unwrap();
            let mut reply = vec![0u8; REPLY.len()];
            timeout(WAIT, stream.read_exact(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply, REPLY);
            stream.shutdown().await.unwrap();
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "对照组必须抵达业务目标");
        let _ = timeout(WAIT, task).await;

        // 错误密码：拒绝 + 计数不增长。
        let before = accepted.load(Ordering::SeqCst);
        let (harness, task) = Harness::start(&identity, PASSWORD).await;
        {
            let mut stream = identity.connect(harness.port).await;
            let header = codec::encode(
                &Request {
                    command: Command::Tcp,
                    target: TargetAddr::V4([127, 0, 0, 1], echo_port),
                },
                &Credential::new(BAD_PASSWORD),
            )
            .unwrap();
            stream.write_all(&header).await.unwrap();
            stream.write_all(PAYLOAD).await.unwrap();
            stream.flush().await.unwrap();
            assert_peer_closed(&mut stream, CLOSE_BOUND).await;
        }
        match timeout(WAIT, task).await.unwrap().unwrap() {
            Err(Error::Authentication) => {}
            other => panic!("期望 Authentication，得到 {other:?}"),
        }
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            before,
            "错误密码不得抵达业务目标"
        );
    })
    .await
    .unwrap();
}

// ───────────────────── 截断请求头（每一部分） ─────────────────────

/// 截断在**每一个位置**（0..header.len()）：服务端必须在握手截止内有界拒绝，
/// 返回 `Timeout`（读不满）或 `Authentication`（哈希已读完但错），绝不 panic、
/// 绝不挂起、绝不放行。
#[tokio::test]
async fn every_truncation_point_is_rejected_within_deadline() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let (echo_port, accepted) = spawn_echo(REPLY.len()).await;
        let header = valid_header(echo_port);
        assert!(header.len() > 60, "V4 目标头必须多于 60 字节");

        for cut in 0..header.len() {
            let (harness, task) = Harness::start(&identity, PASSWORD).await;
            let mut stream = identity.connect(harness.port).await;
            stream.write_all(&header[..cut]).await.unwrap();
            stream.flush().await.unwrap();
            // 截断点 < 56：哈希未读完 → 握手截止；否则地址/CRLF 未读完 → 同样截止。
            assert_peer_closed(&mut stream, CLOSE_BOUND).await;
            match timeout(WAIT, task).await.unwrap().unwrap() {
                Err(Error::Timeout)
                | Err(Error::Authentication)
                | Err(Error::NotTrojanProtocol) => {}
                other => panic!("截断点 {cut} 期望有界拒绝，得到 {other:?}"),
            }
        }
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "任何截断都不得抵达业务目标"
        );
    })
    .await
    .unwrap();
}

/// 各**结构部分**的精确截断（文档表格用）：哈希 / 哈希后 CRLF / 命令 / 地址 /
/// 尾 CRLF 各截断一字节，断言错误变体。
#[tokio::test]
async fn structural_truncations_have_expected_variants() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let (echo_port, _accepted) = spawn_echo(REPLY.len()).await;
        let header = valid_header(echo_port);
        // 头部结构：56 哈希 + 2 CRLF + 1 命令 + 地址(1+4+2=7) + 2 CRLF = 68。
        assert_eq!(header.len(), 68);
        // 首块守卫：单次首读不足 58 字节即 NotTrojanProtocol（参考
        // `server.go` 的 `first.Byte(56) != '\r'` 判定）；≥58 字节但头部读不满则
        // 走握手截止 Timeout。两者都是“有界拒绝”，此处逐条给出预期变体。
        let cases: &[(&str, usize, Expected)] = &[
            ("哈希（<58，首块守卫）", 30, Expected::Protocol),
            ("哈希后 CRLF（<58，首块守卫）", 57, Expected::Protocol),
            ("命令后（≥58，读地址中）", 59, Expected::Timeout),
            ("地址中间（≥58）", 62, Expected::Timeout),
            ("尾 CRLF 一半（≥58）", 67, Expected::Timeout),
        ];
        for (name, cut, expected) in cases {
            let (harness, task) = Harness::start(&identity, PASSWORD).await;
            let mut stream = identity.connect(harness.port).await;
            stream.write_all(&header[..*cut]).await.unwrap();
            stream.flush().await.unwrap();
            assert_peer_closed(&mut stream, CLOSE_BOUND).await;
            let outcome = timeout(WAIT, task).await.unwrap().unwrap();
            match (expected, &outcome) {
                (Expected::Timeout, Err(Error::Timeout)) => {}
                (Expected::Protocol, Err(Error::NotTrojanProtocol)) => {}
                _ => panic!("{name} 截断期望 {expected:?}，得到 {outcome:?}"),
            }
        }
    })
    .await
    .unwrap();
}

#[derive(Debug, Clone, Copy)]
enum Expected {
    Timeout,
    Protocol,
}

// ───────────────────── 篡改 SHA224 摘要 ─────────────────────

/// 篡改摘要：首字节 / 末字节 / 全零。全部必须在读满 56 字节后判 `Authentication`，
/// 且不抵达业务目标；对照组正确密码仍可用。
#[tokio::test]
async fn tampered_digest_is_rejected() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let (echo_port, accepted) = spawn_echo(REPLY.len()).await;
        let header = valid_header(echo_port);
        let tampered: &[(&str, usize, u8)] = &[("首字节", 0, 0x00), ("末字节", 55, 0x00)];
        for (name, index, value) in tampered {
            let mut bad = header.clone();
            if bad[*index] == *value {
                bad[*index] ^= 0x01;
            } else {
                bad[*index] = *value;
            }
            let (harness, task) = Harness::start(&identity, PASSWORD).await;
            let mut stream = identity.connect(harness.port).await;
            stream.write_all(&bad).await.unwrap();
            stream.write_all(PAYLOAD).await.unwrap();
            stream.flush().await.unwrap();
            assert_peer_closed(&mut stream, CLOSE_BOUND).await;
            match timeout(WAIT, task).await.unwrap().unwrap() {
                Err(Error::Authentication) => {}
                other => panic!("{name} 篡改期望 Authentication，得到 {other:?}"),
            }
        }
        // 全零哈希。
        let mut zero = header.clone();
        zero[..56].fill(0);
        let (harness, task) = Harness::start(&identity, PASSWORD).await;
        let mut stream = identity.connect(harness.port).await;
        stream.write_all(&zero).await.unwrap();
        stream.flush().await.unwrap();
        assert_peer_closed(&mut stream, CLOSE_BOUND).await;
        match timeout(WAIT, task).await.unwrap().unwrap() {
            Err(Error::Authentication) => {}
            other => panic!("全零摘要期望 Authentication，得到 {other:?}"),
        }
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "任何篡改都不得抵达业务目标"
        );
    })
    .await
    .unwrap();
}

// ───────────────────────── 重放 ─────────────────────────

/// 重放同一请求头：在**同一个连接**上把合法头 + 载荷发送两次。
/// Trojan 是无状态协议、无重放防护（参考亦然）：第一次被处理，第二次的字节被当作
/// 第一条连接的应用载荷转发给目标（TCP 流无边界）。本用例**如实记录该行为**：
/// 断言不 panic、服务端不因重放而额外建立第二条到目标的连接（accept 计数 == 1）。
#[tokio::test]
async fn replay_same_header_is_not_specially_guarded() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        // 目标只读一次回复（第一次 CONNECT 的载荷），第二次头字节被并入同一流。
        let (echo_port, accepted) = spawn_echo(REPLY.len()).await;
        let (harness, task) = Harness::start(&identity, PASSWORD).await;
        let mut stream = identity.connect(harness.port).await;
        let header = valid_header(echo_port);
        stream.write_all(&header).await.unwrap();
        stream.write_all(PAYLOAD).await.unwrap();
        // 重放同一请求头（其 68 字节会被当作后续应用载荷）。
        stream.write_all(&header).await.unwrap();
        stream.flush().await.unwrap();
        let mut reply = vec![0u8; REPLY.len()];
        timeout(WAIT, stream.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, REPLY, "第一次请求必须正常完成");
        // 关机并让服务端收尾（会读到重放字节作为载荷，最后我方 EOF 结束）。
        stream.shutdown().await.unwrap();
        let outcome = timeout(WAIT, task).await.unwrap().unwrap();
        // 参考亦无重放防护：允许正常结束（Ok）或中继 IO 结束，但不允许 panic/挂起。
        assert!(
            matches!(
                outcome,
                Ok(()) | Err(Error::Relay(_)) | Err(Error::Io(_)) | Err(Error::Timeout)
            ),
            "重放不得 panic 或挂起：{outcome:?}"
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "重放不得额外建立到目标的连接（无重放防护，如实记录）"
        );
    })
    .await
    .unwrap();
}

// ───────────────────────── 半关闭 ─────────────────────────

/// 客户端 `shutdown(Write)` 后仍能读完响应（我方 FIN 不切断回程）。
#[tokio::test]
async fn client_half_close_still_receives_reply() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let (echo_port, accepted) = spawn_echo(REPLY.len()).await;
        let (harness, task) = Harness::start(&identity, PASSWORD).await;
        let mut stream = identity.connect(harness.port).await;
        stream.write_all(&valid_header(echo_port)).await.unwrap();
        stream.write_all(PAYLOAD).await.unwrap();
        stream.flush().await.unwrap();
        // 写半关闭（WS 下无关；此处为裸 TLS 流上的 SHUT_WR）。
        stream.shutdown().await.unwrap();
        let mut reply = vec![0u8; REPLY.len()];
        timeout(WAIT, stream.read_exact(&mut reply))
            .await
            .expect("半关闭后回程仍须到达")
            .unwrap();
        assert_eq!(reply, REPLY);
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        let _ = timeout(WAIT, task).await;
    })
    .await
    .unwrap();
}

/// 服务端关闭后客户端 EOF 不挂死：目标端拒连（拨号失败）→ 服务端应尽快结束连接。
#[tokio::test]
async fn server_close_after_dial_failure_is_prompt() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        // 一个已释放的端口 → 拨号失败。
        let dead_port = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };
        let (harness, task) = Harness::start(&identity, PASSWORD).await;
        let mut stream = identity.connect(harness.port).await;
        stream.write_all(&valid_header(dead_port)).await.unwrap();
        stream.flush().await.unwrap();
        // 服务端拨号失败 → 主动关闭；客户端读侧必须在观察上限内结束（EOF/Err），
        // 不能挂死到总预算耗尽。
        assert_peer_closed(&mut stream, CLOSE_BOUND).await;
        match timeout(WAIT, task).await.unwrap().unwrap() {
            Err(Error::Dial(_)) => {}
            other => panic!("期望拨号失败，得到 {other:?}"),
        }
    })
    .await
    .unwrap();
}

// ───────────────────── 超时与资源清理 ─────────────────────

/// 拒绝/超时后无悬挂任务：重复“写一半后静默”的连接，每次都在握手截止内结束，
/// 且处理任务全部`await`完成（计数器回到 0），不泄漏。
#[tokio::test]
async fn rejected_connections_leave_no_dangling_tasks() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let (echo_port, accepted) = spawn_echo(REPLY.len()).await;
        let header = valid_header(echo_port);
        for _ in 0..8 {
            let (harness, task) = Harness::start(&identity, PASSWORD).await;
            let mut stream = identity.connect(harness.port).await;
            // 写 58 字节（首块守卫通过：第 57 字节是 CR）后**静默** → 头部读不满，
            // 由握手截止（2s）有界拒绝。这才能真正观测到“超时”路径而非首块短路。
            stream.write_all(&header[..58]).await.unwrap();
            stream.flush().await.unwrap();
            assert_peer_closed(&mut stream, CLOSE_BOUND).await;
            // 任务必须真正结束（await 返回），live 计数回到 0。
            match timeout(WAIT, task).await.unwrap().unwrap() {
                Err(Error::Timeout) => {}
                other => panic!("期望握手超时，得到 {other:?}"),
            }
            assert_eq!(
                harness.live.load(Ordering::SeqCst),
                0,
                "连接处理任务必须已结束"
            );
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 0, "拒绝不得抵达业务目标");
    })
    .await
    .unwrap();
}
