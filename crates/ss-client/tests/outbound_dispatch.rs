//! 客户端出口**八协议分发**的验收用例。
//!
//! 覆盖三件事：
//! 1. `Protocol::ALL` 逐项遍历 —— 每个协议都能**构造出对应出口**并**真的走到
//!    「尝试拨号」那一步**（八项一个都不能漏）；
//! 2. 未接线的七个协议 **fail-closed**：返回 [`DialError::NotWiredYet`] 且点名
//!    协议，**一个连接都不发起**（不静默回退 Shadowsocks、不静默直连）；
//! 3. 形状非法一律报错，且错误文本**不回显取值**（口令 / PSK / 私钥）。
//!
//! 假值纪律：口令是 `TESTONLY-PASSWORD-DO-NOT-ECHO`，地址是回环 `127.0.0.1`，
//! 无真实出口、无真实口令。既有 Shadowsocks 用例见 `outbound_dial.rs`
//! （本卡不改动那份文件，语义与数量不变）。

use std::net::SocketAddr;
use std::time::Duration;

use lengsuo_egress::Protocol;
use ss_client::config::{load_config_str, OutboundConfig};
use ss_client::outbound::{DialError, Dialer};
use ss_core::target::TargetAddr;
use tokio::net::TcpListener;

const PASSWORD: &str = "TESTONLY-PASSWORD-DO-NOT-ECHO";
const METHOD: &str = "aes-256-gcm";
/// 16 字节 UUID 文本（`8-4-4-4-12` 十六进制），vless / vmess 用。
const UUID: &str = "9c8d0f2e-1a3b-4c5d-8e7f-0123456789ab";
/// 32 字节标准 base64（WireGuard 静态密钥形状）。
const WG_PRIVATE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const WG_PUBLIC: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
/// 32 字节 base64 PSK（ss2022 的形状）。
const PSK: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const SS2022_METHOD: &str = "2022-blake3-aes-256-gcm";

/// 每个协议一份**形状合法**的出口 URL（指向给定的 `host:port`）。
///
/// 这张表就是「八项覆盖」的判据：漏一个协议，`Protocol::ALL` 遍历就会失败。
fn url_for(protocol: Protocol, host_port: &str) -> String {
    match protocol {
        Protocol::Shadowsocks => format!("ss://{METHOD}:{PASSWORD}@{host_port}"),
        Protocol::Ss2022 => format!("ss2022://{SS2022_METHOD}:{PSK}@{host_port}"),
        Protocol::Vless => format!("vless://{UUID}@{host_port}"),
        Protocol::Vmess => format!("vmess://{UUID}@{host_port}"),
        Protocol::Trojan => format!("trojan://{PASSWORD}@{host_port}"),
        Protocol::Hysteria => format!("hysteria2://{PASSWORD}@{host_port}"),
        Protocol::AnyTls => format!("anytls://{PASSWORD}@{host_port}"),
        Protocol::WireGuard => format!("wireguard://{WG_PRIVATE}:{WG_PUBLIC}@{host_port}"),
    }
}

fn config_for(url: &str) -> OutboundConfig {
    OutboundConfig {
        ss_url: url.to_owned(),
        udp: false,
        mux: Default::default(),
        connect_timeout_ms: 500,
    }
}

fn target() -> TargetAddr {
    TargetAddr::Domain("example.com".to_owned(), 8080)
}

/// 必然连不上的回环地址（无监听者）。
fn dead_addr() -> SocketAddr {
    "127.0.0.1:1".parse().unwrap()
}

/// 1. 八协议遍历：每个协议都能构造出对应出口，并真的去尝试拨号。
#[tokio::test]
async fn every_protocol_constructs_and_attempts_a_dial() {
    let mut seen = 0usize;
    for protocol in Protocol::ALL {
        seen += 1;
        let url = url_for(protocol, &dead_addr().to_string());
        let dialer = Dialer::new(config_for(&url))
            .unwrap_or_else(|err| panic!("{} must construct: {err}", protocol.as_str()));

        // 只看错误（`Tunnel` 刻意不实现 `Debug`，不带口令）。
        let err = dialer.connect(&target(), b"ping").await.err();
        match protocol {
            // `ss://` 走本仓既有的 AEAD 隧道：拨不通只能是 IO/超时，
            // 绝不允许落到「未接线」。
            Protocol::Shadowsocks => assert!(
                !matches!(err, Some(DialError::NotWiredYet(_))),
                "ss:// must use the existing tunnel, got {err:?}"
            ),
            // 其余七协议：如实报未接线，且**点名**是哪个协议。
            other => match err {
                Some(DialError::NotWiredYet(msg)) => assert!(
                    msg.starts_with(other.as_str()),
                    "未接线错误必须点名协议 {}：{msg}",
                    other.as_str()
                ),
                other => panic!(
                    "{} must report NotWiredYet, got {other:?}",
                    protocol.as_str()
                ),
            },
        }
    }
    assert_eq!(seen, 8, "八协议一个都不能少");
}

/// 2. 未接线协议 fail-closed：不拨任何连接，也不回退到别的出口。
///
/// 判据与 `tests/e2e_chain.rs::wrong_password_fails_closed` 同风格：**看对端
/// 收到了什么**。这里的「对端」是一个只监听、不服务的回环端口 —— 未接线协议
/// 若真有静默回退（直连 / 回退 Shadowsocks），它必然被连上。
#[tokio::test]
async fn unwired_protocols_never_dial_and_never_fall_back() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    for protocol in Protocol::ALL {
        if protocol == Protocol::Shadowsocks {
            continue;
        }
        let url = url_for(protocol, &addr.to_string());
        let dialer = Dialer::new(config_for(&url))
            .unwrap_or_else(|err| panic!("{} must construct: {err}", protocol.as_str()));

        let err = dialer
            .connect(&target(), b"should-not-leave")
            .await
            .err()
            .expect("unwired protocol must not report success");
        assert!(
            matches!(&err, DialError::NotWiredYet(msg) if msg.starts_with(protocol.as_str())),
            "{} must fail closed with NotWiredYet: {err:?}",
            protocol.as_str()
        );

        // 连一个连接都不该发起：监听端 200ms 内必须什么都 accept 不到。
        assert!(
            tokio::time::timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err(),
            "{} must not dial anything",
            protocol.as_str()
        );
    }
}

/// 3. 形状非法一律报错，且**不回显取值**。
#[test]
fn invalid_shapes_are_rejected_without_echoing_values() {
    let bad: [&str; 6] = [
        // 不是 UUID。
        "vless://not-a-uuid-SECRET@127.0.0.1:8388",
        // 未知 scheme：不猜、不回落。
        "quantum://SECRET@127.0.0.1:8388",
        // 缺端口。
        "trojan://SECRET@127.0.0.1",
        // 带查询参数：静默忽略等于静默丢弃配置，故一律拒绝。
        "vless://9c8d0f2e-1a3b-4c5d-8e7f-0123456789ab@127.0.0.1:8388?security=tls",
        // WireGuard 静态密钥不是 32 字节 base64。
        "wireguard://short:short@127.0.0.1:8388",
        // ss2022 加密名不受支持。
        "ss2022://rc4-md5:SECRET@127.0.0.1:8388",
    ];
    for url in bad {
        let err = Dialer::new(config_for(url))
            .err()
            .unwrap_or_else(|| panic!("{url} must be rejected"));
        assert!(
            matches!(err, DialError::InvalidUrl(_)),
            "{url} must be a shape error, got {err:?}"
        );
        let message = err.to_string();
        assert!(
            !message.contains("SECRET") && !message.contains("not-a-uuid"),
            "错误文本回显了取值：{message}"
        );
    }

    // 形状合法 = 能构造（正例，避免上面全绿只因全都失败）。
    for url in [
        format!("ss2022://{SS2022_METHOD}:{PSK}@127.0.0.1:8388"),
        format!("wireguard://{WG_PRIVATE}:{WG_PUBLIC}@127.0.0.1:8388"),
    ] {
        assert!(
            Dialer::new(config_for(&url)).is_ok(),
            "{url} must construct"
        );
    }
}

/// 4. 加载期就 fail-closed：八协议形状在 `OutboundConfig` 层就要能过/被拒。
///
/// 「加载能过、拨号才报」是坏体验，故 `config::load` 复用同一份解析规则。
#[test]
fn config_load_accepts_eight_shapes_and_rejects_bad_ones() {
    // 八个形状至少都要能加载；`ss://` 走既有校验器。
    for protocol in Protocol::ALL {
        let url = url_for(protocol, "203.0.113.7:8388");
        let text = format!("[outbound]\nss_url = \"{url}\"\n");
        load_config_str(&text)
            .unwrap_or_else(|err| panic!("{} shape must load: {err}", protocol.as_str()));
    }

    // 非法形状在加载期就被拒，且不回显取值。
    let err =
        load_config_str("[outbound]\nss_url = \"vmess://SECRET-not-a-uuid@203.0.113.7:8388\"\n")
            .unwrap_err();
    assert!(
        !err.to_string().contains("SECRET"),
        "加载期错误回显了取值：{err}"
    );
}

/// 5. `ss2022://` 不得被当成 `ss://`（那正是「静默回退 Shadowsocks」）。
#[tokio::test]
async fn ss2022_is_not_silently_treated_as_shadowsocks() {
    let url = format!("ss2022://{SS2022_METHOD}:{PSK}@127.0.0.1:1");
    let dialer = Dialer::new(config_for(&url)).unwrap();
    let err = dialer
        .connect(&target(), b"")
        .await
        .err()
        .expect("ss2022 must not silently use the shadowsocks path");
    assert!(
        matches!(&err, DialError::NotWiredYet(msg) if msg.starts_with("ss2022")),
        "got {err:?}"
    );
}
