//! D-S2：UDP 解密后的 ATYP 高位掩码（对齐 Xray `proxy/shadowsocks/protocol.go:264`）。
//!
//! 参考在解密后立即 `payload[0] &= 0x0F` 再交给地址解析器，因此 ATYP=0x13
//! （0x10 标志位 + 域名 0x03）是合法输入。本文件用固定 salt 手工构造线上字节，
//! 不经过本仓 `seal`（它只会编码 0x01/0x03/0x04），以免把自家编码器当参考。

use lengsuo_shadowsocks::udp::{Error, UdpCodec};
use ss_core::crypto::{CipherSuite, SessionAead};
use ss_core::kdf::{evp_bytes_to_key, hkdf_sha1_subkey};
use ss_core::target::TargetAddr;

#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;

const PASSWORD: &str = "atyp-mask-fixed-vector-password";
const SALT: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

fn codec() -> UdpCodec {
    UdpCodec::new(CipherSuite::Aes128Gcm, PASSWORD.as_bytes()).expect("假口令应能构造编解码器")
}

/// 用固定 salt 按参考线格式封装：salt ‖ AEAD(plaintext)。
fn seal_fixed(plaintext: &[u8]) -> Vec<u8> {
    let suite = CipherSuite::Aes128Gcm;
    let master = evp_bytes_to_key(PASSWORD.as_bytes(), suite.key_len());
    let subkey = hkdf_sha1_subkey(&master, &SALT, suite.key_len());
    let mut aead = SessionAead::new(suite, subkey);
    let mut packet = SALT.to_vec();
    packet.extend_from_slice(&aead.seal(plaintext).expect("固定向量封装不应失败"));
    packet
}

fn domain_plaintext(atyp: u8, host: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![atyp, host.len() as u8];
    buf.extend_from_slice(host.as_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

#[test]
fn atyp_0x13_domain_is_accepted_and_payload_restored() {
    let payload = b"flagged-domain-payload";
    let plaintext = domain_plaintext(0x13, "example.com", 8080, payload);
    let (target, got) = codec()
        .open(&seal_fixed(&plaintext))
        .expect("参考把 0x13 当作域名 0x03 接受");
    assert_eq!(target, TargetAddr::Domain("example.com".into(), 8080));
    assert_eq!(got, payload);
}

#[test]
fn high_nibble_flags_on_v4_and_v6_are_masked() {
    // 0x11 → IPv4，0x14 → IPv6。参考对任意高位同样只保留低 4 位。
    let mut v4 = vec![0x11, 192, 0, 2, 9];
    v4.extend_from_slice(&443u16.to_be_bytes());
    v4.extend_from_slice(b"v4");
    let (target, got) = codec().open(&seal_fixed(&v4)).unwrap();
    assert_eq!(target, TargetAddr::V4([192, 0, 2, 9], 443));
    assert_eq!(got, b"v4");

    let mut v6 = vec![0x14];
    v6.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    v6.extend_from_slice(&53u16.to_be_bytes());
    v6.extend_from_slice(b"v6");
    let (target, got) = codec().open(&seal_fixed(&v6)).unwrap();
    assert_eq!(
        target,
        TargetAddr::V6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            53
        )
    );
    assert_eq!(got, b"v6");
}

#[test]
fn plain_atyp_values_keep_existing_behavior() {
    // 回归：无高位标志的 0x01/0x03/0x04 经掩码后行为不变。
    for target in [
        TargetAddr::V4([198, 51, 100, 7], 80),
        TargetAddr::Domain("plain.example".into(), 53),
        TargetAddr::V6([0x20; 16], 1234),
    ] {
        let packet = codec().seal(&target, b"plain").unwrap();
        let (got_target, got_payload) = codec().open(&packet).unwrap();
        assert_eq!(got_target, target);
        assert_eq!(got_payload, b"plain");
    }
}

#[test]
fn empty_plaintext_still_errors_without_panic() {
    // 掩码不能把空明文变成 panic：沿用既有 TooShort 错误。
    let err = codec().open(&seal_fixed(b"")).unwrap_err();
    assert!(matches!(err, Error::Address(_)));
}

// ---- 参考互通（#[ignore]，需 LENGSUO_XRAY） ----
//
// 参考 Xray 客户端没有设置 ATYP 高位的配置项，无法让它主动发出 0x13；
// 因此这里把**同一条字节级向量**注入参考服务端，验证参考确实接受该包。
// 本仓接收侧对应能力由上面的 `open` 用例覆盖（本 crate 无独立 UDP 服务端）。

use support::{free_port, launch, WAIT};
use tokio::{net::UdpSocket, time::timeout};

const METHOD: &str = "aes-128-gcm";

/// 参考回包 = salt(16) ‖ AEAD(源地址 ‖ payload)；用本仓 `open` 解出载荷。
fn open_response(packet: &[u8]) -> Vec<u8> {
    codec().open(packet).expect("参考回包应能解密").1
}

/// 启动参考 SS UDP 服务端，把 `plaintext`（端口由本函数填入 echo 端口）发给它，
/// 断言 echo 收到 `payload` 且参考把回包加密送回。
async fn xray_accepts(build_plaintext: impl FnOnce(u16) -> Vec<u8>, payload: &'static [u8]) {
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let echo_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let (n, peer) = echo.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], payload);
        echo.send_to(&buf[..n], peer).await.unwrap();
    });

    let ss_port = free_port();
    let _reference = launch(
        serde_json::json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": ss_port, "protocol": "shadowsocks",
                "settings": {"method": METHOD, "password": PASSWORD, "network": "tcp,udp"}}],
            "outbounds": [{"protocol": "freedom"}]
        }),
        ss_port,
    )
    .await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .connect((std::net::Ipv4Addr::LOCALHOST, ss_port))
        .await
        .unwrap();
    client
        .send(&seal_fixed(&build_plaintext(echo_port)))
        .await
        .unwrap();
    let mut buf = [0u8; 4096];
    let n = timeout(WAIT, client.recv(&mut buf)).await.unwrap().unwrap();
    assert_eq!(open_response(&buf[..n]), payload);
    echo_task.await.unwrap();
}

#[tokio::test]
#[ignore = "需要 LENGSUO_XRAY 提供固定版本参考实现"]
async fn xray_server_accepts_atyp_0x13_domain() {
    const PAYLOAD: &[u8] = b"flagged-domain";
    xray_accepts(
        |port| domain_plaintext(0x13, "127.0.0.1", port, PAYLOAD),
        PAYLOAD,
    )
    .await;
}

#[tokio::test]
#[ignore = "需要 LENGSUO_XRAY 提供固定版本参考实现"]
async fn xray_server_accepts_atyp_high_nibble_v4() {
    const PAYLOAD: &[u8] = b"flagged-v4";
    xray_accepts(
        |port| {
            let mut plaintext = vec![0x11, 127, 0, 0, 1];
            plaintext.extend_from_slice(&port.to_be_bytes());
            plaintext.extend_from_slice(PAYLOAD);
            plaintext
        },
        PAYLOAD,
    )
    .await;
}

#[tokio::test]
#[ignore = "需要 LENGSUO_XRAY 提供固定版本参考实现"]
async fn xray_server_accepts_plain_atyp_baseline() {
    const PAYLOAD: &[u8] = b"baseline";
    xray_accepts(
        |port| {
            let mut plaintext = vec![0x01, 127, 0, 0, 1];
            plaintext.extend_from_slice(&port.to_be_bytes());
            plaintext.extend_from_slice(PAYLOAD);
            plaintext
        },
        PAYLOAD,
    )
    .await;
}
