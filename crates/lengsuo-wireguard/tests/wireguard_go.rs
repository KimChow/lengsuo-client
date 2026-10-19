//! Actual loopback UDP exchange with a test adapter around the pinned official
//! wireguard-go Noise/keypair functions; no kernel TUN or browser acceptance.
use lengsuo_wireguard::{
    handshake::{Handshake, Responder},
    transport::{Receiver, Sender, TransportKey},
};
use std::{
    net::UdpSocket,
    process::{Child, Command, Stdio},
    time::Duration,
};
use x25519_dalek::{PublicKey, StaticSecret};

struct Reference(Option<Child>);
impl Drop for Reference {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn exchange(psk: bool) {
    let binary =
        std::env::var_os("LENGSUO_WG_REFERENCE_BIN").expect("reference Go test adapter required");
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(6)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(6)))
        .unwrap();
    let child = Command::new(binary)
        .args([
            "-test.run",
            "^TestLengsuoUDPReference$",
            "-test.timeout",
            "12s",
            "-test.v",
        ])
        .env(
            "LENGSUO_WG_CLIENT",
            socket.local_addr().unwrap().to_string(),
        )
        .env("LENGSUO_WG_PSK", if psk { "1" } else { "0" })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut reference = Reference(Some(child));
    let mut buffer = [0u8; 2048];
    let (n, peer) = socket.recv_from(&mut buffer).unwrap();
    assert!(peer.ip().is_loopback());
    assert_eq!(&buffer[..n], b"wireguard-reference-ready");
    socket.connect(peer).unwrap();
    let server = PublicKey::from(&StaticSecret::from([0x22; 32])).to_bytes();
    let mut handshake =
        Handshake::new(&[0x11; 32], &server, psk.then_some([0x33; 32]), 0x12345678).unwrap();
    socket
        .send(&handshake.create_initiation([0xaa; 32]).unwrap())
        .unwrap();
    let n = socket.recv(&mut buffer).unwrap();
    let keys = handshake.consume_response(&buffer[..n]).unwrap();
    let mut sender = Sender::new(TransportKey::new(&keys.send).unwrap(), keys.remote_index, 0);
    let mut receiver = Receiver::new(
        TransportKey::new(&keys.receive).unwrap(),
        keys.local_index,
        u64::MAX,
    );
    let wire = sender.seal(b"rust-go-payload!").unwrap();
    socket.send(&wire).unwrap();
    let n = socket.recv(&mut buffer).unwrap();
    let packet = receiver.open(&buffer[..n]).unwrap();
    assert_eq!(packet.plaintext.as_slice(), b"go-rust-payload!");
    assert!(
        receiver.open(&buffer[..n]).is_err(),
        "duplicate must be rejected"
    );
    let output = reference.0.take().unwrap().wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "official adapter failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires pinned official wireguard-go test adapter"]
fn rust_initiator_go_responder_zero_psk_udp_both_directions() {
    exchange(false);
}

#[test]
#[ignore = "requires pinned official wireguard-go test adapter"]
fn rust_initiator_go_responder_explicit_psk_udp_both_directions() {
    exchange(true);
}

/// 返回参考 Go 二进制路径；缺 `LENGSUO_WG_REFERENCE_BIN` 时打印原因并跳过。
fn reference_binary() -> Option<std::ffi::OsString> {
    match std::env::var_os("LENGSUO_WG_REFERENCE_BIN") {
        Some(b) => Some(b),
        None => {
            eprintln!(
                "跳过：缺少 LENGSUO_WG_REFERENCE_BIN（先用 \
                 `cp tools/reference/wireguard_go_udp_test.go ~/ref/wireguard-go/device/lengsuo_wg_udp_test.go && \
                 cd ~/ref/wireguard-go && go test -c -o /tmp/wg_ref ./device` 构建参考二进制）"
            );
            None
        }
    }
}

/// Go 官方核心发起 → Rust 响应方。`enforce_mac2` 为真时按“过载/要求 MAC2”路径：
/// 第一条 initiation 的 MAC2（全零）被拒并签发 cookie reply，Go 消费后带有效
/// MAC2 重新发起。双向载荷、重放拒绝在每条路径都断言。
fn exchange_go_initiator(psk: bool, enforce_mac2: bool) {
    let binary = reference_binary().expect("reference Go test adapter required");
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    let child = Command::new(binary)
        .args([
            "-test.run",
            "^TestLengsuoUDPReferenceInitiator$",
            "-test.timeout",
            "15s",
            "-test.v",
            "-role",
            "initiator",
        ])
        .env(
            "LENGSUO_WG_CLIENT",
            socket.local_addr().unwrap().to_string(),
        )
        .env("LENGSUO_WG_PSK", if psk { "1" } else { "0" })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut reference = Reference(Some(child));

    let mut buffer = [0u8; 2048];
    let (n, peer) = socket.recv_from(&mut buffer).unwrap();
    assert!(peer.ip().is_loopback());
    assert_eq!(&buffer[..n], b"wireguard-reference-ready");
    socket.connect(peer).unwrap();

    // Rust 是响应方：本端 0x22 假私钥，对端是 0x11 假私钥生成的客户端公钥。
    let client_pub = PublicKey::from(&StaticSecret::from([0x11; 32])).to_bytes();
    let mut responder =
        Responder::new(&[0x22; 32], &client_pub, psk.then_some([0x33; 32]), 0).unwrap();
    // MAC2 的 `src` 取 Go 对端真实源地址（ip:port），签发与校验必须一致。
    let src = peer.to_string();
    let src = src.as_bytes();

    let n = socket.recv(&mut buffer).unwrap();
    let mut initiation = buffer[..n].to_vec();
    assert!(
        responder.check_mac1(&initiation),
        "Go initiation 的 MAC1 必须校验通过"
    );
    if enforce_mac2 {
        // 尚未签发 cookie：Go 第一次 initiation 的 MAC2 全零，必须被拒。
        assert!(
            !responder.check_mac2(&initiation, src),
            "缺少/错误 MAC2 的 initiation 必须被拒"
        );
        let reply = responder.create_cookie_reply(&initiation, src, [0x44; 32], [0x55; 24]);
        socket.send(&reply).unwrap();
        // Go 消费 cookie reply 后带有效 MAC2 重新发起。
        let n = socket.recv(&mut buffer).unwrap();
        assert!(responder.check_mac1(&buffer[..n]));
        assert!(
            responder.check_mac2(&buffer[..n], src),
            "带有效 MAC2 的重新发起必须通过"
        );
        initiation = buffer[..n].to_vec();
    }
    responder
        .consume_initiation(&initiation)
        .expect("Go initiation 可被响应方剥壳");

    let mut response = responder
        .create_response([0x77; 32], 0x20261234)
        .expect("response 可生成");
    responder.add_macs(&mut response);
    socket.send(&response).unwrap();

    let keys = responder
        .begin_symmetric_session()
        .expect("响应方可派生 transport keys");
    let mut sender = Sender::new(TransportKey::new(&keys.send).unwrap(), keys.remote_index, 0);
    let mut receiver = Receiver::new(
        TransportKey::new(&keys.receive).unwrap(),
        keys.local_index,
        u64::MAX,
    );

    // 双向载荷：先收 Go 的运输载荷，再接受重放包断言拒绝，最后回复。
    let n = socket.recv(&mut buffer).unwrap();
    let first = buffer[..n].to_vec();
    let packet = receiver.open(&first).unwrap();
    assert_eq!(packet.plaintext.as_slice(), b"go-init-payload!");

    let n = socket.recv(&mut buffer).unwrap();
    assert_eq!(&buffer[..n], &first[..], "重放包与原包逐字节相同");
    assert!(
        receiver.open(&buffer[..n]).is_err(),
        "重放 transport 必须被拒"
    );

    let reply = sender.seal(b"rust-resp-payload!").unwrap();
    socket.send(&reply).unwrap();

    let output = reference.0.take().unwrap().wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "official adapter failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires pinned official wireguard-go test adapter"]
fn go_initiator_rust_responder_zero_psk_udp_both_directions() {
    exchange_go_initiator(false, false);
}

#[test]
#[ignore = "requires pinned official wireguard-go test adapter"]
fn go_initiator_rust_responder_explicit_psk_udp_both_directions() {
    exchange_go_initiator(true, false);
}

#[test]
#[ignore = "requires pinned official wireguard-go test adapter"]
fn go_initiator_rust_responder_cookie_mac2_flow() {
    exchange_go_initiator(false, true);
}
