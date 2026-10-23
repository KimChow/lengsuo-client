//! SOCKS5 UDP ASSOCIATE 入站测试（仅回环，不含加密隧道）。

use std::net::SocketAddr;
use std::time::Duration;

use ss_client::inbound::{InboundError, Socks5Config, Socks5Listener, UdpAssociation};
use ss_core::target::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const REPLY_OK: [u8; 3] = [0x05, 0x00, 0x00];
const CMD_REJECT: [u8; 10] = [0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

async fn bind_listener() -> Socks5Listener {
    Socks5Listener::bind(Socks5Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        auth: None,
    })
    .await
    .unwrap()
}

/// 客户端完成 greeting + CMD=3 请求，返回控制连接与 BND 地址。
async fn client_associate(addr: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut c = TcpStream::connect(addr).await.unwrap();
    c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    c.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);

    c.write_all(&[0x05, 0x00, 0x03, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut head = [0u8; 4];
    c.read_exact(&mut head).await.unwrap();
    assert_eq!(&head[..3], &REPLY_OK);
    let bnd = match head[3] {
        0x01 => {
            let mut b = [0u8; 6];
            c.read_exact(&mut b).await.unwrap();
            SocketAddr::from(([b[0], b[1], b[2], b[3]], u16::from_be_bytes([b[4], b[5]])))
        }
        0x04 => {
            let mut b = [0u8; 18];
            c.read_exact(&mut b).await.unwrap();
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&b[..16]);
            SocketAddr::from((ip, u16::from_be_bytes([b[16], b[17]])))
        }
        other => panic!("unexpected BND ATYP {other:#04x}"),
    };
    (c, bnd)
}

/// 驱动监听端与客户端完成一次关联，断言双方看到的 BND 一致。
async fn associate_with(listener: &Socks5Listener) -> (UdpAssociation, TcpStream) {
    let addr = listener.local_addr().unwrap();
    let (res, (ctrl, bnd)) = tokio::join!(listener.accept_udp(), client_associate(addr));
    let assoc = res.unwrap();
    assert_eq!(assoc.relay_addr(), bnd);
    (assoc, ctrl)
}

/// 构造 RFC 1928 §7 数据报。
fn datagram(atyp: u8, addr: &[u8], port: u16, payload: &[u8]) -> Vec<u8> {
    let mut d = vec![0x00, 0x00, 0x00, atyp];
    if atyp == 0x03 {
        d.push(addr.len() as u8);
    }
    d.extend_from_slice(addr);
    d.extend_from_slice(&port.to_be_bytes());
    d.extend_from_slice(payload);
    d
}

async fn client_udp() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

#[tokio::test]
async fn udp_associate_replies_loopback_bnd() {
    let listener = bind_listener().await;
    let (assoc, _ctrl) = associate_with(&listener).await;
    let bnd = assoc.relay_addr();
    assert!(bnd.ip().is_loopback(), "BND must be loopback, got {bnd}");
    assert_ne!(bnd.port(), 0, "BND port must be allocated");
}

#[tokio::test]
async fn ipv4_datagram_roundtrip() {
    let listener = bind_listener().await;
    let (assoc, _ctrl) = associate_with(&listener).await;
    let client = client_udp().await;

    let dg = datagram(0x01, &[1, 2, 3, 4], 53, b"hi");
    client.send_to(&dg, assoc.relay_addr()).await.unwrap();

    let got = assoc.recv_from_client().await.unwrap();
    assert_eq!(
        got,
        Some((TargetAddr::V4([1, 2, 3, 4], 53), b"hi".to_vec()))
    );
}

#[tokio::test]
async fn domain_datagram_with_empty_payload() {
    let listener = bind_listener().await;
    let (assoc, _ctrl) = associate_with(&listener).await;
    let client = client_udp().await;

    let host = b"example.com";
    let dg = datagram(0x03, host, 53, b"");
    client.send_to(&dg, assoc.relay_addr()).await.unwrap();

    let got = assoc.recv_from_client().await.unwrap();
    assert_eq!(
        got,
        Some((TargetAddr::Domain("example.com".into(), 53), Vec::new()))
    );
}

#[tokio::test]
async fn fragmented_datagram_is_dropped_and_association_survives() {
    let listener = bind_listener().await;
    let (assoc, _ctrl) = associate_with(&listener).await;
    let client = client_udp().await;

    let mut dg = datagram(0x01, &[1, 2, 3, 4], 53, b"frag");
    dg[2] = 0x01; // FRAG != 0
    client.send_to(&dg, assoc.relay_addr()).await.unwrap();
    assert_eq!(assoc.recv_from_client().await.unwrap(), None);

    // 关联仍有效：后续合法数据报照常解出。
    let ok = datagram(0x01, &[5, 6, 7, 8], 80, b"ok");
    client.send_to(&ok, assoc.relay_addr()).await.unwrap();
    assert_eq!(
        assoc.recv_from_client().await.unwrap(),
        Some((TargetAddr::V4([5, 6, 7, 8], 80), b"ok".to_vec()))
    );
    assert!(!assoc.is_closed());
}

#[tokio::test]
async fn nonzero_rsv_is_dropped() {
    let listener = bind_listener().await;
    let (assoc, _ctrl) = associate_with(&listener).await;
    let client = client_udp().await;

    let mut dg = datagram(0x01, &[1, 2, 3, 4], 53, b"x");
    dg[1] = 0x01; // RSV != 0
    client.send_to(&dg, assoc.relay_addr()).await.unwrap();
    assert_eq!(assoc.recv_from_client().await.unwrap(), None);
}

#[tokio::test]
async fn send_to_client_encapsulates_exact_bytes() {
    let listener = bind_listener().await;
    let (assoc, _ctrl) = associate_with(&listener).await;
    let client = client_udp().await;

    // 先来一个合法数据报，让关联记住客户端 UDP 源地址。
    let dg = datagram(0x01, &[1, 2, 3, 4], 53, b"probe");
    client.send_to(&dg, assoc.relay_addr()).await.unwrap();
    assert!(assoc.recv_from_client().await.unwrap().is_some());

    let from = TargetAddr::V4([9, 9, 9, 9], 5353);
    assoc.send_to_client(&from, b"pong").await.unwrap();

    let mut buf = [0u8; 64];
    let (n, _src) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let expected = [
        &[0x00, 0x00, 0x00, 0x01, 9, 9, 9, 9][..],
        &5353u16.to_be_bytes(),
        b"pong",
    ]
    .concat();
    assert_eq!(&buf[..n], expected.as_slice());
}

#[tokio::test]
async fn control_close_ends_association() {
    let listener = bind_listener().await;
    let (assoc, ctrl) = associate_with(&listener).await;
    assert!(!assoc.is_closed());

    drop(ctrl);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while !assoc.is_closed() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "control connection close not observed"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn connect_command_rejected_on_udp_endpoint() {
    let listener = bind_listener().await;
    let addr = listener.local_addr().unwrap();

    let client = async {
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0u8; 2];
        c.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);

        c.write_all(&[0x05, 0x00, 0x01, 0x01, 1, 2, 3, 4, 0, 80])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, CMD_REJECT);
        let mut eof = [0u8; 1];
        assert_eq!(c.read(&mut eof).await.unwrap(), 0);
    };

    let (res, ()) = tokio::join!(listener.accept_udp(), client);
    match res {
        Err(InboundError::UnsupportedCommand(1)) => {}
        Err(_) => panic!("unexpected error variant"),
        Ok(_) => panic!("CONNECT must not be accepted by accept_udp"),
    }
}
