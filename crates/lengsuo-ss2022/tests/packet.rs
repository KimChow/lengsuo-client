use lengsuo_ss2022::{
    crypto::{Key, Method},
    packet::Sender,
    Error,
};
use ss_core::target::TargetAddr;

#[test]
fn both_methods_client_server_fields_and_addresses() {
    for method in [Method::Aes128, Method::Aes256] {
        let key = Key::new(method, &vec![0x11; method.key_len()]).unwrap();
        let mut client = Sender::new(key.clone(), None).unwrap();
        let mut server = Sender::new(key.clone(), Some(client.session_id())).unwrap();
        for (index, target) in [
            TargetAddr::V4([127, 0, 0, 1], 53),
            TargetAddr::Domain("test.invalid".into(), 443),
            TargetAddr::V6([0x11; 16], 80),
        ]
        .into_iter()
        .enumerate()
        {
            let packet = client.seal(&target, b"payload", 1000, 7).unwrap();
            let decoded = key.open_client(&packet, 1030).unwrap();
            assert_eq!(decoded.session_id, client.session_id());
            assert_eq!(decoded.packet_id, index as u64);
            assert_eq!(decoded.target, target);
            assert_eq!(decoded.payload, b"payload");
            assert!(matches!(
                key.open_client(&packet, 1031),
                Err(Error::Timestamp)
            ));
            let packet = server.seal(&target, b"reply", 1000, 0).unwrap();
            let decoded = key.open_server(&packet, 1000, client.session_id()).unwrap();
            assert_eq!(decoded.client_session, Some(client.session_id()));
            assert_eq!(decoded.payload, b"reply");
            assert!(matches!(
                key.open_server(&packet, 1000, [0; 8]),
                Err(Error::ClientSession)
            ));
            assert!(matches!(
                key.open_client(&packet, 1000),
                Err(Error::Direction)
            ));
        }
    }
}

#[test]
fn wrong_key_tampering_and_every_truncation_fail() {
    for method in [Method::Aes128, Method::Aes256] {
        let key = Key::new(method, &vec![0x11; method.key_len()]).unwrap();
        let wrong = Key::new(method, &vec![0x22; method.key_len()]).unwrap();
        let mut sender = Sender::new(key.clone(), None).unwrap();
        let packet = sender
            .seal(&TargetAddr::V4([1; 4], 1), b"payload", 1000, 0)
            .unwrap();
        assert!(wrong.open_client(&packet, 1000).is_err());
        for end in 0..packet.len() {
            assert!(key.open_client(&packet[..end], 1000).is_err());
        }
        for offset in 0..packet.len() {
            let mut bad = packet.clone();
            bad[offset] ^= 1;
            assert!(key.open_client(&bad, 1000).is_err());
        }
    }
}

#[test]
fn key_and_packet_limits() {
    assert!(matches!(
        Key::new(Method::Aes128, &[0; 32]),
        Err(Error::KeyLength)
    ));
    let key = Key::new(Method::Aes128, &[0x11; 16]).unwrap();
    let mut sender = Sender::new(key.clone(), None).unwrap();
    let target = TargetAddr::V4([1; 4], 1);
    assert!(matches!(
        sender.seal(&target, &vec![0; 65507], 1, 0),
        Err(Error::Length)
    ));
    assert!(sender
        .seal(&TargetAddr::Domain(String::new(), 1), b"", 1, 0)
        .is_err());
    let limit = 65507 - 32 - 11 - 7;
    let packet = sender.seal(&target, &vec![0; limit], 1, 0).unwrap();
    assert_eq!(packet.len(), 65507);
    assert_eq!(key.open_client(&packet, 1).unwrap().payload.len(), limit);
}
