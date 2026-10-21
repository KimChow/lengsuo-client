//! ⑤ 与真实参考（固定 Xray）交叉验证：跨重启**不**防重放。
//!
//! 这是「参考行为」的**一手实跑证据**，不是纯读代码推断：
//! - **同进程内**：同一个 EIH 报文第二次必须被参考丢弃（不转发）；
//! - **跨重启**：参考进程重启后，同一个 EIH 报文**被接受并转发**
//!   ⇒ 证明参考**没有**跨重启的重放保护（窗口纯内存）。
//!
//! 需要显式提供固定版本参考可执行文件：
//! `LENGSUO_XRAY=/path/to/xray cargo test -p lengsuo-ss2022 --test
//! udp_replay_matrix --locked -- --ignored`。
//!
//! 归属：`tests/udp_replay_matrix.rs` 的 ⑤ 组用例。

use super::{key_from, now_secs, support};
use base64::{engine::general_purpose::STANDARD, Engine};
use lengsuo_ss2022::{
    crypto::{Key, Method},
    eih_udp::{EihUdpChain, EihUdpSender},
};
use serde_json::{json, Value};
use ss_core::target::TargetAddr;
use std::{
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use support::{free_port, launch, WAIT};

/// Xray 多用户 SS2022 入站配置：`password` 是服务端身份 PSK，
/// `clients[*].password` 是用户 PSK。
fn multi_user_config(port: u16, method: &str, identity: &[u8], users: &[(&str, &[u8])]) -> Value {
    let clients: Vec<Value> = users
        .iter()
        .map(|(email, psk)| json!({"email": email, "password": STANDARD.encode(psk)}))
        .collect();
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "shadowsocks",
            "settings": {
                "method": method,
                "password": STANDARD.encode(identity),
                "network": "tcp,udp",
                "clients": clients
            }
        }],
        "outbounds": [{"protocol": "freedom"}]
    })
}

/// 真实参考（固定 Xray v26.3.27 = sing-shadowsocks v0.2.7）取证：
/// - **同进程内**：同一个 EIH 报文第二次必须被参考丢弃（不转发）；
/// - **跨重启**：参考进程重启后，同一个 EIH 报文**被接受并转发**
///   ⇒ 证明参考**没有**跨重启的重放保护（窗口纯内存）。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn xray_reference_rejects_replay_in_process_but_accepts_it_after_restart() {
    const OVERALL: Duration = Duration::from_secs(120);
    const NO_REPLY: Duration = Duration::from_secs(3);
    const BIND: &str = "127.0.0.1:0";
    const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

    tokio::time::timeout(OVERALL, async {
        let method = Method::Aes256;
        let identity_psk = vec![0xAA; 32];
        let user_psk = vec![0x11; 32];
        let identity: Key = key_from(method, &identity_psk);
        let user: Key = key_from(method, &user_psk);

        // 回环 echo：统计抵达次数，用于判定「参考是否转发」。
        let echo = tokio::net::UdpSocket::bind(BIND)
            .await
            .expect("echo 应可监听");
        let echo_port = echo.local_addr().expect("echo 有地址").port();
        let delivered = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&delivered);
        let echo_task = tokio::spawn(async move {
            let mut buffer = [0u8; 16384];
            loop {
                let Ok((received, from)) = echo.recv_from(&mut buffer).await else {
                    break;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = echo.send_to(&buffer[..received], from).await;
            }
        });

        let port = free_port();
        let config = multi_user_config(
            port,
            "2022-blake3-aes-256-gcm",
            &identity_psk,
            &[("user1", &user_psk)],
        );
        let reference = launch(config.clone(), port).await;

        let socket = tokio::net::UdpSocket::bind(BIND).await.expect("回环可监听");
        socket
            .connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("应可连接参考");
        let chain = EihUdpChain::new(vec![identity.clone(), user.clone()]).expect("身份链");
        let mut sender = EihUdpSender::new(chain).expect("发送端");
        let payload = b"replay-probe";
        let sealed_at = now_secs();
        let packet = sender
            .seal(&TargetAddr::V4(LOOPBACK, echo_port), payload, sealed_at, 0)
            .expect("封包应成功");

        let mut buffer = [0u8; 16384];
        // ① 首次：参考必须接受并转发。
        socket.send(&packet).await.expect("应可发出");
        let received = tokio::time::timeout(WAIT, socket.recv(&mut buffer))
            .await
            .expect("首次必须收到回包（超时不算通过）")
            .expect("应可收到回包");
        let decoded = user
            .open_server(&buffer[..received], now_secs(), sender.session_id())
            .expect("响应方向应可解密");
        assert_eq!(decoded.payload, payload, "首次回程载荷必须逐字节一致");
        assert_eq!(
            delivered.load(Ordering::SeqCst),
            1,
            "首次必须恰好抵达 echo 一次"
        );

        // ② 同进程重放：参考必须丢弃（窗口 `slidingwindow.go` 拒绝）。
        socket.send(&packet).await.expect("应可发出");
        assert!(
            tokio::time::timeout(NO_REPLY, socket.recv(&mut buffer))
                .await
                .is_err(),
            "参考必须拒绝同进程重放（不应有回包）"
        );
        assert_eq!(delivered.load(Ordering::SeqCst), 1, "重放不得抵达 echo");

        // ③ 重启参考进程：内存态窗口清空 ⇒ 同一报文必须被接受并转发。
        drop(reference);
        let _restarted = launch(config, port).await;
        let elapsed = now_secs().saturating_sub(sealed_at);
        assert!(
            elapsed <= 30,
            "重放必须落在参考的时间戳窗口（±30s）内，实测 {elapsed}s"
        );
        socket.send(&packet).await.expect("应可发出");
        let received = tokio::time::timeout(WAIT, socket.recv(&mut buffer))
            .await
            .expect("重启后参考必须接受重放（内存态窗口已清空）")
            .expect("应可收到回包");
        let decoded = user
            .open_server(&buffer[..received], now_secs(), sender.session_id())
            .expect("响应方向应可解密");
        assert_eq!(decoded.payload, payload, "重启后回程载荷必须逐字节一致");
        assert_eq!(
            delivered.load(Ordering::SeqCst),
            2,
            "重启后重放必须抵达 echo（证明参考不防跨重启重放）"
        );

        echo_task.abort();
    })
    .await
    .expect("参考重放取证总超时");
}
