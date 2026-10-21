// 参考端脚手架：服务端配置、客户端建流、拒绝观测与半关闭语义分档。
//
// 本文件由 `tests/transport_matrix/xray_matrix.rs` 以 `include!` 拼入该模块，
// 因此共享的导入都在入口文件里。

/// 参考端配置：trojan 入站 + `network` 外层 + freedom 出站。
///
/// `network` 取参考 `infra/conf/transport_internet.go:1002-1017` 的
/// `TransportProtocol.Build()` 认可的值：`raw`/`tcp`、`ws`/`websocket`、
/// `httpupgrade`。
fn server_config(port: u16, identity: &Identity, outer: Outer) -> Value {
    let mut stream = json!({"security":"tls","tlsSettings":{"certificates":[{
        "certificate":identity.cert_pem().lines().collect::<Vec<_>>(),
        "key":identity.key_pem().lines().collect::<Vec<_>>() }]}});
    match outer {
        Outer::Tcp => {
            // raw：无外层传输层，TLS 之后直接是 trojan 字节流。
            stream["network"] = json!("raw");
        }
        Outer::Ws => {
            stream["network"] = json!("ws");
            stream["wsSettings"] = json!({"path":PATH,"host":"localhost"});
        }
        Outer::HttpUpgrade => {
            stream["network"] = json!("httpupgrade");
            stream["httpupgradeSettings"] = json!({"path":PATH});
        }
    }
    json!({"log":{"loglevel":"warning"},
        // 握手截止压到 2 秒：截断用例必须得到**有界**拒绝。参考默认握手截止是
        // 60 秒（`features/policy/policy.go:120` 的 `Handshake: time.Second * 60`），
        // 不压短的话“观察上限内未结束”与“参考端还没判超时”无法区分。
        "policy":{"levels":{"0":{"handshake":2}}},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"trojan",
            "settings":{"clients":[{"password":PASSWORD}]},
            "streamSettings":stream}],
        "outbounds":[{"protocol":"freedom"}]})
}

/// 客户端在参考服务端上建流（TLS → 外层升级）并跑一次动作。
async fn run_client(
    identity: &Identity,
    port: u16,
    outer: Outer,
    action: Action,
    target_port: u16,
) -> Outcome {
    let endpoint = ([127, 0, 0, 1], port).into();
    match outer {
        Outer::Tcp => {
            let mut stream = identity
                .client()
                .connect(endpoint)
                .await
                .expect("TLS 握手失败");
            client_action(&mut stream, action, target_port).await
        }
        Outer::Ws => {
            let tls = identity
                .client()
                .connect(endpoint)
                .await
                .expect("TLS 握手失败");
            let mut stream = ws::Client::new(PATH, "localhost", "localhost")
                .upgrade(tls, WAIT)
                .await
                .expect("WS 升级失败");
            client_action(&mut stream, action, target_port).await
        }
        Outer::HttpUpgrade => {
            let tls = identity
                .client()
                .connect(endpoint)
                .await
                .expect("TLS 握手失败");
            let mut stream = httpupgrade::Client::new(PATH, "localhost", "localhost")
                .upgrade(tls, WAIT)
                .await
                .expect("HTTPUpgrade 升级失败");
            client_action(&mut stream, action, target_port).await
        }
    }
}

/// 观察参考端是否**主动**结束连接。
///
/// 判据纪律：读到 `Ok(0)` 或 `Err` 都算“主动结束”；只读到数据 = 失败
/// （参考端不应在拒绝路径上回数据）。观察上限内什么都没发生 = **不**算拒绝
/// 证据，调用方据此判定失败。
async fn expect_reference_closed<S: AsyncRead + Unpin>(stream: &mut S) -> bool {
    let mut buf = [0u8; 64];
    match timeout(CLOSE_BOUND, stream.read(&mut buf)).await {
        Ok(Ok(0)) => true,
        Ok(Err(_)) => true,
        Ok(Ok(read)) => panic!("参考端在拒绝路径上回了 {read} 字节"),
        Err(_) => false,
    }
}

/// 参考端在“客户端关写端”之后的**半关闭语义**（按外层分档）。
///
/// 判据来自实测（基线 v26.3.27 / commit `d2758a0`）：
///
/// - `tcp`（raw）与 `httpupgrade`：外层是**裸字节流**，关写端就是 TCP FIN。
///   参考端的请求方向读到 EOF（`buf.Copy` 把 EOF 视为正常结束），会话继续，
///   回程照常送达 ⇒ **保半关闭**。
/// - `ws`：外层是 RFC 6455 帧。本仓客户端关写端时发 `Close` 帧（对齐参考
///   `transport/internet/websocket/connection.go` 的 `Close` 语义），而参考端的
///   gorilla 读侧把 `Close` 帧当作**非 EOF 的读错误**上报；参考的
///   `common/buf/copy.go` 只把 `io.EOF` 当正常结束，于是请求方向被判为
///   “failed to transfer request”，整个会话被拆除 ⇒ **拆会话，不保半关闭**。
///
/// 判据是**可判定的**，不依赖时序：回程由业务目标在**读到对端 EOF 之后**
/// 才回写（`ReplyWhen::AfterEof`）。因此“保半关闭”的档位必然收满整个回程；
/// “拆会话”的档位必然收不到任何回程字节。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HalfClose {
    /// 保半关闭：关写端后回程仍完整送达。
    Preserved,
    /// 拆会话：关写端即终止整个会话，回程被截断（收不到任何字节）。
    SessionTornDown,
}

impl HalfClose {
    /// 按外层取参考端的半关闭语义。
    fn of(outer: Outer) -> Self {
        match outer {
            Outer::Tcp | Outer::HttpUpgrade => HalfClose::Preserved,
            Outer::Ws => HalfClose::SessionTornDown,
        }
    }
}

/// 在参考服务端上跑一个动作，返回（结果、业务目标 accept 计数）。
async fn run_against_reference(outer: Outer, action: Action, reply: Vec<u8>) -> (Outcome, usize) {
    let identity = Identity::new();
    let target = Target::bind(reply).await;
    let port = free_port();
    let reference = launch(server_config(port, &identity, outer), port).await;
    let outcome = run_client(&identity, port, outer, action, target.port()).await;
    // 沉降一点时间再核对观测面，排除迟到的拨号。
    tokio::time::sleep(Duration::from_millis(500)).await;
    let accepted = target.accepted();
    drop(reference);
    target.stop().await;
    (outcome, accepted)
}
