use lengsuo_vless::{
    header::{self, Command, Request},
    stream::Error,
    xudp::Session,
};
use ss_core::target::TargetAddr;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
const WAIT: Duration = Duration::from_secs(2);
fn target() -> TargetAddr {
    TargetAddr::V4([127, 0, 0, 1], 53)
}
fn vector() -> Vec<u8> {
    vec![0, 12, 0, 0, 1, 1, 2, 0, 53, 1, 127, 0, 0, 1, 0, 1, 0xab]
}

#[tokio::test]
async fn fixed_vector_and_reply_state() {
    timeout(WAIT, async {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let mut session = Session::client(target());
        session.send(&mut client, &[0xab], WAIT).await.unwrap();
        let mut bytes = vec![0; 17];
        server.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes, vector());
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        writer.write_all(&bytes).await.unwrap();
        let mut receiver = Session::server();
        assert_eq!(
            receiver.receive(&mut reader, 512, WAIT).await.unwrap(),
            (target(), vec![0xab])
        );
        receiver.send(&mut reader, b"reply", WAIT).await.unwrap();
        assert_eq!(
            session.receive(&mut writer, 512, WAIT).await.unwrap(),
            (target(), b"reply".to_vec())
        );
        session.send(&mut writer, b"next", WAIT).await.unwrap();
        assert_eq!(
            receiver.receive(&mut reader, 512, WAIT).await.unwrap().1,
            b"next"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn every_truncation_fails_without_hanging() {
    timeout(WAIT, async {
        let bytes = vector();
        for end in 0..bytes.len() {
            let (mut writer, mut reader) = tokio::io::duplex(64);
            writer.write_all(&bytes[..end]).await.unwrap();
            writer.shutdown().await.unwrap();
            assert!(
                Session::server()
                    .receive(&mut reader, 512, WAIT)
                    .await
                    .is_err(),
                "截断 {end}"
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn reject_other_sessions_flags_and_networks() {
    for (offset, value) in [(3, 1), (4, 3), (5, 2), (6, 1)] {
        let mut bytes = vector();
        bytes[offset] = value;
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(&bytes).await.unwrap();
        assert!(matches!(
            Session::server().receive(&mut reader, 512, WAIT).await,
            Err(Error::Header(_))
        ));
    }
    let (mut writer, mut reader) = tokio::io::duplex(64);
    writer
        .write_all(&[0, 4, 0, 0, 2, 1, 0, 1, 7])
        .await
        .unwrap();
    assert!(matches!(
        Session::server().receive(&mut reader, 512, WAIT).await,
        Err(Error::Header(_))
    ));
}

#[tokio::test]
async fn reject_excess_lengths_and_silent_peer() {
    let (mut writer, mut reader) = tokio::io::duplex(64);
    writer.write_all(&[1, 45]).await.unwrap();
    assert!(matches!(
        Session::server().receive(&mut reader, 512, WAIT).await,
        Err(Error::Header(_))
    ));
    let (mut writer, mut reader) = tokio::io::duplex(64);
    writer.write_all(&vector()).await.unwrap();
    assert!(matches!(
        Session::server().receive(&mut reader, 0, WAIT).await,
        Err(Error::FrameTooLarge)
    ));
    let (_writer, mut reader) = tokio::io::duplex(64);
    assert!(matches!(
        Session::server()
            .receive(&mut reader, 512, Duration::from_millis(20))
            .await,
        Err(Error::Timeout)
    ));
}

#[test]
fn mux_header_has_no_address_and_preserves_payload() {
    let request = Request {
        command: Command::Mux,
        target: TargetAddr::Domain("v1.mux.cool".into(), 0),
    };
    let mut encoded = header::encode(&request, &[0x11; 16]).unwrap();
    assert_eq!(encoded.len(), 19);
    encoded.extend_from_slice(&vector());
    let (_, decoded, length) = header::decode(&encoded).unwrap();
    assert_eq!(decoded, request);
    assert_eq!(length, 19);
}
