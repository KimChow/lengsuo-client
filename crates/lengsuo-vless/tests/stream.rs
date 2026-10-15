use lengsuo_vless::{
    header::{Command, Request},
    stream::*,
};
use ss_core::target::TargetAddr;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
const WAIT: Duration = Duration::from_secs(2);
fn request() -> Request {
    Request {
        command: Command::Tcp,
        target: TargetAddr::V4([127, 0, 0, 1], 80),
    }
}

#[tokio::test]
async fn request_payload_response_and_half_close() {
    timeout(WAIT, async {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let worker = tokio::spawn(async move {
            assert_eq!(
                receive_request(&mut server, &[5; 16], WAIT).await.unwrap(),
                request()
            );
            let mut payload = Vec::new();
            server.read_to_end(&mut payload).await.unwrap();
            assert_eq!(payload, b"payload");
            send_response(&mut server, WAIT).await.unwrap();
            server.write_all(b"reply after EOF").await.unwrap();
            server.shutdown().await.unwrap();
        });
        send_request(&mut client, &request(), &[5; 16], WAIT)
            .await
            .unwrap();
        client.write_all(b"payload").await.unwrap();
        client.shutdown().await.unwrap();
        receive_response(&mut client, WAIT).await.unwrap();
        let mut result = Vec::new();
        client.read_to_end(&mut result).await.unwrap();
        assert_eq!(result, b"reply after EOF");
        worker.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wrong_credential_fails_before_waiting_for_address() {
    let (mut client, mut server) = tokio::io::duplex(64);
    client.write_all(&[0; 17]).await.unwrap();
    assert!(matches!(
        receive_request(&mut server, &[1; 16], WAIT).await,
        Err(Error::Authentication)
    ));
}

#[tokio::test]
async fn fragmented_header_does_not_consume_payload() {
    timeout(WAIT, async {
        let (mut client, mut server) = tokio::io::duplex(1);
        let writer = tokio::spawn(async move {
            let bytes = lengsuo_vless::header::encode(&request(), &[2; 16]).unwrap();
            for byte in bytes {
                client.write_all(&[byte]).await.unwrap();
            }
            client.write_all(b"x").await.unwrap();
        });
        receive_request(&mut server, &[2; 16], WAIT).await.unwrap();
        assert_eq!(server.read_u8().await.unwrap(), b'x');
        writer.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn silent_and_truncated_peers_fail() {
    let (_client, mut server) = tokio::io::duplex(64);
    assert!(matches!(
        receive_request(&mut server, &[0; 16], Duration::from_millis(20)).await,
        Err(Error::Timeout)
    ));
    let (mut client, mut server) = tokio::io::duplex(64);
    client.write_all(&[0; 17]).await.unwrap();
    client.shutdown().await.unwrap();
    assert!(matches!(
        receive_request(&mut server, &[0; 16], WAIT).await,
        Err(Error::Io(_))
    ));
    assert!(matches!(
        receive_response(&mut server, Duration::ZERO).await,
        Err(Error::InvalidDeadline)
    ));
}

#[tokio::test]
async fn response_rejects_version_and_addons() {
    for bytes in [[1, 0], [0, 1]] {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(&bytes).await.unwrap();
        assert!(matches!(
            receive_response(&mut reader, WAIT).await,
            Err(Error::Header(_))
        ));
    }
}

#[tokio::test]
async fn datagram_boundaries_and_limits() {
    timeout(WAIT, async {
        let (mut writer, mut reader) = tokio::io::duplex(140000);
        for packet in [vec![], vec![42], vec![7; 65535]] {
            send_datagram(&mut writer, &packet, WAIT).await.unwrap();
            assert_eq!(
                receive_datagram(&mut reader, u16::MAX, WAIT).await.unwrap(),
                packet
            );
        }
        assert!(matches!(
            send_datagram(&mut writer, &vec![0; 65536], WAIT).await,
            Err(Error::FrameTooLarge)
        ));
        writer.write_all(&[0, 10]).await.unwrap();
        assert!(matches!(
            receive_datagram(&mut reader, 9, WAIT).await,
            Err(Error::FrameTooLarge)
        ));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn truncated_and_silent_datagram_fail() {
    let (mut writer, mut reader) = tokio::io::duplex(64);
    writer.write_all(&[0, 3, 1]).await.unwrap();
    writer.shutdown().await.unwrap();
    assert!(matches!(
        receive_datagram(&mut reader, 10, WAIT).await,
        Err(Error::Io(_))
    ));
    let (_writer, mut reader) = tokio::io::duplex(64);
    assert!(matches!(
        receive_datagram(&mut reader, 10, Duration::from_millis(20)).await,
        Err(Error::Timeout)
    ));
}
