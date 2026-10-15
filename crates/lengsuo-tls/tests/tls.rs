use lengsuo_tls::{CertificateDer, Error, PrivatePkcs8KeyDer, TlsClient, TlsServer};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};
const LIMIT: Duration = Duration::from_secs(3);

fn identity() -> (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>) {
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    (
        identity.cert.der().clone(),
        identity.key_pair.serialize_der().into(),
    )
}

#[tokio::test]
async fn authenticated_tls_roundtrip() {
    let (cert, key) = identity();
    let server = TlsServer::new(vec![cert.clone()], key.into(), LIMIT).unwrap();
    let client = TlsClient::new("localhost", [cert], LIMIT).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let worker = tokio::spawn(async move {
        timeout(LIMIT, async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut stream = server.accept(socket).await.unwrap();
            let mut bytes = [0u8; 5];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"hello");
            stream.write_all(&bytes).await.unwrap();
            stream.flush().await.unwrap();
            stream.shutdown().await.unwrap();
        })
        .await
        .unwrap();
    });
    timeout(LIMIT, async {
        let mut stream = client.connect(addr).await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();
        let mut bytes = [0u8; 5];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"hello");
        stream.shutdown().await.unwrap();
    })
    .await
    .unwrap();
    timeout(LIMIT, worker).await.unwrap().unwrap();
}

async fn rejects_certificate(name: &str, wrong_root: bool) {
    let (cert, key) = identity();
    let root = if wrong_root {
        identity().0
    } else {
        cert.clone()
    };
    let client = TlsClient::new(name, [root], LIMIT).unwrap();
    let server = TlsServer::new(vec![cert], key.into(), LIMIT).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let worker = tokio::spawn(async move {
        let (socket, _) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
        assert!(server.accept(socket).await.is_err());
    });
    assert!(matches!(client.connect(addr).await, Err(Error::Io(_))));
    timeout(LIMIT, worker).await.unwrap().unwrap();
}

#[tokio::test]
async fn wrong_name_fails_closed() {
    rejects_certificate("wrong.example", false).await;
}

#[tokio::test]
async fn untrusted_certificate_fails_closed() {
    rejects_certificate("localhost", true).await;
}

#[tokio::test]
async fn silent_peer_hits_handshake_deadline() {
    let client = TlsClient::new("localhost", [identity().0], Duration::from_millis(250)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (done, closed) = tokio::sync::oneshot::channel::<()>();
    let worker = tokio::spawn(async move {
        let (socket, _) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
        timeout(LIMIT, closed).await.unwrap().unwrap();
        drop(socket);
    });
    assert!(matches!(client.connect(addr).await, Err(Error::Timeout)));
    done.send(()).unwrap();
    timeout(LIMIT, worker).await.unwrap().unwrap();
}

#[test]
fn invalid_configuration_is_rejected_before_connecting() {
    assert!(matches!(
        TlsClient::new("localhost", [], LIMIT),
        Err(Error::EmptyTrustStore)
    ));
    assert!(matches!(
        TlsClient::new("bad name", [identity().0], LIMIT),
        Err(Error::InvalidServerName)
    ));
    assert!(matches!(
        TlsClient::new("localhost", [identity().0], Duration::ZERO),
        Err(Error::InvalidDeadline)
    ));
    let (cert, key) = identity();
    assert!(matches!(
        TlsServer::new(vec![cert], key.into(), Duration::ZERO),
        Err(Error::InvalidDeadline)
    ));
}
