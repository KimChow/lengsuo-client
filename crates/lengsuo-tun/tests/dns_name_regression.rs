//! 固定RFC1035编码，防止解析器和转发测试共同接受错误名字。
use lengsuo_tun::dns::parse_query;
fn query(name: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    packet.extend_from_slice(name);
    packet.extend_from_slice(&[0, 1, 0, 1]);
    packet
}
#[test]
fn labels_preserve_length_octets_and_question_boundary() {
    let wire = b"\x07example\x03com\0";
    let message = parse_query(&query(wire)).unwrap();
    assert_eq!(message.question.name.as_bytes(), wire);
    assert_eq!(message.question.name.to_text(), "example.com");
    assert_eq!(message.question.qtype, 1);
    assert_eq!(message.question.qclass, 1);
}
#[test]
fn root_octet_is_consumed_before_question_fields() {
    let message = parse_query(&query(&[0])).unwrap();
    assert!(message.question.name.is_root());
    assert_eq!(message.question.qtype, 1);
    assert_eq!(message.question.qclass, 1);
}
