use lengsuo_anytls::{
    auth::Credential,
    frame::{Command, Frame},
    Error,
};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
const WAIT: Duration = Duration::from_secs(2);

#[test]
fn fixed_frame_and_all_truncations() {
    let frame = Frame {
        command: Command::Push,
        stream_id: 0x01020304,
        data: vec![0xab, 0xcd],
    };
    let bytes = frame.encode().unwrap();
    assert_eq!(bytes, [2, 1, 2, 3, 4, 0, 2, 0xab, 0xcd]);
    for end in 0..bytes.len() {
        assert!(matches!(
            Frame::decode(&bytes[..end]),
            Err(Error::Incomplete)
        ));
    }
    let mut with_payload = bytes.clone();
    with_payload.extend_from_slice(b"next frame");
    let (decoded, length) = Frame::decode(&with_payload).unwrap();
    assert!(decoded == frame);
    assert_eq!(length, 9);
}

#[test]
fn command_constraints_and_lengths() {
    assert!(Frame::decode(&[11, 0, 0, 0, 0, 0, 0]).is_err());
    for command in [
        Command::Syn,
        Command::Fin,
        Command::HeartRequest,
        Command::HeartResponse,
    ] {
        assert!(Frame {
            command,
            stream_id: 1,
            data: vec![0]
        }
        .encode()
        .is_err());
    }
    let mut frame = Frame {
        command: Command::Waste,
        stream_id: 0,
        data: vec![0; 65535],
    };
    assert_eq!(frame.encode().unwrap().len(), 65542);
    frame.data.push(0);
    assert!(matches!(frame.encode(), Err(Error::TooLarge)));
}

#[tokio::test]
async fn auth_fixed_sha256_vector_and_padding_boundary() {
    timeout(WAIT, async {
        let credential = Credential::new(b"abc");
        let (mut writer, mut reader) = tokio::io::duplex(256);
        credential
            .send(&mut writer, &[1, 2, 3], WAIT)
            .await
            .unwrap();
        let mut bytes = [0; 37];
        reader.read_exact(&mut bytes).await.unwrap();
        let digest = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(&bytes[..32], digest);
        assert_eq!(&bytes[32..], &[0, 3, 1, 2, 3]);
        let (mut writer, mut reader) = tokio::io::duplex(256);
        writer.write_all(&bytes).await.unwrap();
        writer.write_all(&[42]).await.unwrap();
        credential.verify(&mut reader, 3, WAIT).await.unwrap();
        assert_eq!(reader.read_u8().await.unwrap(), 42);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn auth_wrong_password_truncation_limit_and_timeout() {
    let correct = Credential::new(b"correct-test-password");
    let (mut writer, mut reader) = tokio::io::duplex(256);
    Credential::new(b"wrong-test-password")
        .send(&mut writer, &[], WAIT)
        .await
        .unwrap();
    assert!(matches!(
        correct.verify(&mut reader, 0, WAIT).await,
        Err(Error::Authentication)
    ));
    let (mut writer, mut reader) = tokio::io::duplex(256);
    correct.send(&mut writer, &[0; 2], WAIT).await.unwrap();
    assert!(matches!(
        correct.verify(&mut reader, 1, WAIT).await,
        Err(Error::TooLarge)
    ));
    let (mut writer, mut reader) = tokio::io::duplex(256);
    writer.write_all(&[0; 32]).await.unwrap();
    writer.shutdown().await.unwrap();
    assert!(matches!(
        correct.verify(&mut reader, 0, WAIT).await,
        Err(Error::Io(_))
    ));
    let (_writer, mut reader) = tokio::io::duplex(256);
    assert!(matches!(
        correct
            .verify(&mut reader, 0, Duration::from_millis(20))
            .await,
        Err(Error::Timeout)
    ));
}

#[tokio::test]
async fn frame_stream_limits_truncation_and_timeout() {
    timeout(WAIT, async {
        let (mut writer, mut reader) = tokio::io::duplex(256);
        let frame = Frame {
            command: Command::Settings,
            stream_id: 0,
            data: b"v=2".to_vec(),
        };
        frame.write(&mut writer, WAIT).await.unwrap();
        assert!(Frame::read(&mut reader, 3, WAIT).await.unwrap() == frame);
        writer.write_all(&[2, 0, 0, 0, 1, 0, 10]).await.unwrap();
        assert!(matches!(
            Frame::read(&mut reader, 9, WAIT).await,
            Err(Error::TooLarge)
        ));
        let (mut writer, mut reader) = tokio::io::duplex(256);
        writer.write_all(&[2, 0, 0, 0, 1, 0, 3, 1]).await.unwrap();
        writer.shutdown().await.unwrap();
        assert!(matches!(
            Frame::read(&mut reader, 3, WAIT).await,
            Err(Error::Io(_))
        ));
        let (_writer, mut reader) = tokio::io::duplex(256);
        assert!(matches!(
            Frame::read(&mut reader, 3, Duration::from_millis(20)).await,
            Err(Error::Timeout)
        ));
    })
    .await
    .unwrap();
}
