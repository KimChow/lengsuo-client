//! Actual loopback UDP exchange with a test adapter around the pinned official
//! wireguard-go Noise/keypair functions; no kernel TUN or browser acceptance.
use lengsuo_wireguard::{
    handshake::Handshake,
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
