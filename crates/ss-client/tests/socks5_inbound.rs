//! SOCKS5 入站协议面测试（仅回环）。

use std::net::SocketAddr;

use ss_client::inbound::{Auth, InboundError, Socks5Config, Socks5Listener};
use ss_core::target::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SUCCESS_REPLY: [u8; 10] = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
const CMD_REJECT: [u8; 10] = [0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
const ATYP_REJECT: [u8; 10] = [0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

async fn bind(auth: Option<Auth>) -> Socks5Listener {
    Socks5Listener::bind(Socks5Config {
        bind: loopback(),
        auth,
    })
    .await
    .unwrap()
}

/// 无认证 greeting：发 `05 01 00`，断言回 `05 00`。
async fn no_auth_greeting(client: &mut TcpStream) {
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x05, 0x00]);
}

/// 断言连接已被对端关闭（读到 EOF）。
async fn expect_eof(client: &mut TcpStream) {
    let mut buf = [0u8; 1];
    assert_eq!(client.read(&mut buf).await.unwrap(), 0);
}

fn expect_auth_failed(result: Result<ss_client::inbound::Accepted, InboundError>) {
    match result {
        Err(InboundError::AuthFailed) => {}
        Err(_) => panic!("unexpected error variant"),
        Ok(_) => panic!("handshake should have failed"),
    }
}

#[tokio::test]
async fn connect_ipv4_without_auth() {
    let listener = bind(None).await;
    let addr = listener.local_addr().unwrap();

    let client = async {
        let mut c = TcpStream::connect(addr).await.unwrap();
        no_auth_greeting(&mut c).await;
        c.write_all(&[0x05, 0x00, 0x01, 0x01, 8, 8, 8, 8, 0x01, 0xBB])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, SUCCESS_REPLY);
    };

    let (accepted, ()) = tokio::join!(listener.accept(), client);
    let accepted = accepted.unwrap();
    assert_eq!(accepted.target, TargetAddr::V4([8, 8, 8, 8], 443));
    assert!(accepted.residual.is_empty());
}

#[tokio::test]
async fn connect_domain_preserves_case_and_length() {
    let listener = bind(None).await;
    let addr = listener.local_addr().unwrap();
    let host = "ExAmPlE.CoM";

    let client = async {
        let mut c = TcpStream::connect(addr).await.unwrap();
        no_auth_greeting(&mut c).await;
        let mut req = vec![0x05, 0x00, 0x01, 0x03, host.len() as u8];
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(&8080u16.to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, SUCCESS_REPLY);
    };

    let (accepted, ()) = tokio::join!(listener.accept(), client);
    let accepted = accepted.unwrap();
    assert_eq!(accepted.target, TargetAddr::Domain(host.to_string(), 8080));
}

#[tokio::test]
async fn connect_ipv6() {
    let listener = bind(None).await;
    let addr = listener.local_addr().unwrap();

    let client = async {
        let mut c = TcpStream::connect(addr).await.unwrap();
        no_auth_greeting(&mut c).await;
        let mut req = vec![0x05, 0x00, 0x01, 0x04];
        req.extend_from_slice(&[0x20; 16]);
        req.extend_from_slice(&80u16.to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, SUCCESS_REPLY);
    };

    let (accepted, ()) = tokio::join!(listener.accept(), client);
    let accepted = accepted.unwrap();
    assert_eq!(accepted.target, TargetAddr::V6([0x20; 16], 80));
}

#[tokio::test]
async fn auth_success_then_connect() {
    let listener = bind(Some(Auth {
        username: "alice".into(),
        password: "s3cret".into(),
    }))
    .await;
    let addr = listener.local_addr().unwrap();

    let client = async {
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut method = [0u8; 2];
        c.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x02]);

        let mut auth = vec![0x01, 5];
        auth.extend_from_slice(b"alice");
        auth.push(6);
        auth.extend_from_slice(b"s3cret");
        c.write_all(&auth).await.unwrap();
        let mut status = [0u8; 2];
        c.read_exact(&mut status).await.unwrap();
        assert_eq!(status, [0x01, 0x00]);

        c.write_all(&[0x05, 0x00, 0x01, 0x01, 1, 2, 3, 4, 0, 53])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, SUCCESS_REPLY);
    };

    let (accepted, ()) = tokio::join!(listener.accept(), client);
    assert_eq!(accepted.unwrap().target, TargetAddr::V4([1, 2, 3, 4], 53));
}

#[tokio::test]
async fn auth_failure_replies_and_closes() {
    let listener = bind(Some(Auth {
        username: "alice".into(),
        password: "s3cret".into(),
    }))
    .await;
    let addr = listener.local_addr().unwrap();

    let client = async {
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut method = [0u8; 2];
        c.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x02]);

        let mut auth = vec![0x01, 5];
        auth.extend_from_slice(b"alice");
        auth.push(5);
        auth.extend_from_slice(b"wrong");
        c.write_all(&auth).await.unwrap();
        let mut status = [0u8; 2];
        c.read_exact(&mut status).await.unwrap();
        assert_eq!(status, [0x01, 0x01]);
        expect_eof(&mut c).await;
    };

    let (result, ()) = tokio::join!(listener.accept(), client);
    expect_auth_failed(result);
}

#[tokio::test]
async fn bind_command_rejected() {
    let listener = bind(None).await;
    let addr = listener.local_addr().unwrap();

    let client = async {
        let mut c = TcpStream::connect(addr).await.unwrap();
        no_auth_greeting(&mut c).await;
        c.write_all(&[0x05, 0x00, 0x02, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, CMD_REJECT);
        expect_eof(&mut c).await;
    };

    let (result, ()) = tokio::join!(listener.accept(), client);
    match result {
        Err(InboundError::UnsupportedCommand(2)) => {}
        other => panic!("expected UnsupportedCommand(2), got {:?}", other.err()),
    }
}

#[tokio::test]
async fn udp_associate_rejected() {
    let listener = bind(None).await;
    let addr = listener.local_addr().unwrap();

    let client = async {
        let mut c = TcpStream::connect(addr).await.unwrap();
        no_auth_greeting(&mut c).await;
        c.write_all(&[0x05, 0x00, 0x03, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, CMD_REJECT);
        expect_eof(&mut c).await;
    };

    let (result, ()) = tokio::join!(listener.accept(), client);
    match result {
        Err(InboundError::UnsupportedCommand(3)) => {}
        Err(_) => panic!("unexpected error variant"),
        Ok(_) => panic!("UDP ASSOCIATE must not be accepted"),
    }
}

#[tokio::test]
async fn bad_version_sends_nothing_and_closes() {
    let listener = bind(None).await;
    let addr = listener.local_addr().unwrap();

    let client = async {
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(&[0x04, 0x01, 0x00]).await.unwrap();
        expect_eof(&mut c).await;
    };

    let (result, ()) = tokio::join!(listener.accept(), client);
    match result {
        Err(InboundError::Protocol("bad greeting version")) => {}
        Err(_) => panic!("unexpected error variant"),
        Ok(_) => panic!("SOCKS4 greeting must be rejected"),
    }
}

#[tokio::test]
async fn zero_methods_replies_ff_and_closes() {
    let listener = bind(None).await;
    let addr = listener.local_addr().unwrap();

    let client = async {
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(&[0x05, 0x00]).await.unwrap();
        let mut reply = [0u8; 2];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0xFF]);
        expect_eof(&mut c).await;
    };

    let (result, ()) = tokio::join!(listener.accept(), client);
    match result {
        Err(InboundError::Protocol(_)) => {}
        Err(_) => panic!("unexpected error variant"),
        Ok(_) => panic!("zero methods must be rejected"),
    }
}

#[tokio::test]
async fn unsupported_atyp_rejected() {
    let listener = bind(None).await;
    let addr = listener.local_addr().unwrap();

    let client = async {
        let mut c = TcpStream::connect(addr).await.unwrap();
        no_auth_greeting(&mut c).await;
        c.write_all(&[0x05, 0x00, 0x01, 0x99, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, ATYP_REJECT);
        expect_eof(&mut c).await;
    };

    let (result, ()) = tokio::join!(listener.accept(), client);
    match result {
        Err(InboundError::UnsupportedAddressType(0x99)) => {}
        Err(_) => panic!("unexpected error variant"),
        Ok(_) => panic!("unknown ATYP must be rejected"),
    }
}

#[tokio::test]
async fn non_loopback_bind_is_rejected() {
    let result = Socks5Listener::bind(Socks5Config {
        bind: "0.0.0.0:0".parse().unwrap(),
        auth: None,
    })
    .await;
    match result {
        Err(InboundError::NotLoopback) => {}
        Err(_) => panic!("unexpected error variant"),
        Ok(_) => panic!("non-loopback bind must fail closed"),
    }
}

#[tokio::test]
async fn residual_payload_is_preserved() {
    let listener = bind(None).await;
    let addr = listener.local_addr().unwrap();
    let payload = b"hello".to_vec();

    let client = async {
        let mut c = TcpStream::connect(addr).await.unwrap();
        no_auth_greeting(&mut c).await;
        let mut req = vec![0x05, 0x00, 0x01, 0x01, 9, 9, 9, 9, 0, 80];
        req.extend_from_slice(&payload);
        c.write_all(&req).await.unwrap();
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, SUCCESS_REPLY);
    };

    let (accepted, ()) = tokio::join!(listener.accept(), client);
    let accepted = accepted.unwrap();
    assert_eq!(accepted.target, TargetAddr::V4([9, 9, 9, 9], 80));
    assert_eq!(accepted.residual, payload);
}
