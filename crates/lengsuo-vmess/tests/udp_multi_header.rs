//! D-M1：VMess `src/udp.rs` 的 SOCKS5 UDP 头「一报多封」缺陷修复用例。
//!
//! # 分歧点（定位到行号）
//!
//! 修复前 `crates/lengsuo-vmess/src/udp.rs` 的两处与参考不符：
//!
//! 1. **地址段格式用错**：旧 [`decode_udp_packet`] 复用
//!    `muxframe::decode_address_port`（`PortThenAddress`：端口在前、ATYP 1/2/3），
//!    而参考 SOCKS5 的 `addrParser`（`proxy/socks/protocol.go:36-40`）是
//!    **`ATYP` 在前、端口在后**（`common/protocol/address.go:113-134`
//!    `portLastAddressParser`）、ATYP 1=IPv4 / **3=域名** / **4=IPv6**。
//! 2. **`read_udp_packet` 用 `read_to_end`**：把多份数据报首尾相接成一份「报文」，
//!    后一份的 SOCKS5 头被当成前一封头的**残余载荷** —— 这就是「一报多封头」的
//!    实际来源。
//!
//! # 参考的真实行为（已用参考源码实跑取证）
//!
//! 参考 `proxy/socks/protocol.go:324-347` `DecodeUDPPacket` **只解析一封头**：
//! 解析完第一封的地址后，**剩余字节全部是载荷**（`proxy/socks/server.go:246-271`
//! 把剩余字节原样转发）。本文件的断言即按此行为写。
//!
//! **取证方式**：在参考仓（`/home/ubuntu/ref/xray`，固定 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）内以 Go 测试直接调用参考自己的
//! `socks.DecodeUDPPacket` / `socks.EncodeUDPPacket`，实跑输出（exit 0）：
//!
//! ```text
//! PROBE single-v4      OK   addr=127.0.0.1 port=53 residual=2 bytes=6869
//! PROBE two-headers    OK   addr=127.0.0.1 port=53 residual=13 bytes=68690000000108080808003578
//! PROBE frag-nonzero   ERR  proxy/socks: discarding fragmented payload.
//! PROBE short-3bytes   ERR  proxy/socks: insufficient length of packet.
//! PROBE short-half-header ERR proxy/socks: failed to read UDP header > unexpected EOF
//! PROBE empty-payload  OK   addr=127.0.0.1 port=53 residual=0 bytes=
//! PROBE domain         OK   addr=localhost port=53 residual=1 bytes=70
//! PROBE ipv6           OK   addr=[::] port=1 residual=3 bytes=003571
//!
//! ENC v4       bytes=000000017f00000100356869
//! ENC domain   bytes=00000003096c6f63616c686f7374003570
//! ENC ipv6     bytes=0000000400000000000000000000000000000001003571
//! ENC empty    bytes=000000010a0000010000
//! ```
//!
//! ⛔ 参考的 `two-headers` 一行是本卡的核心依据：**取第一封头，第二封头整体
//! 落在残余载荷里**（`0000 00 01 08080808 0035 78` = 13 字节），**不**被当作
//! 新目标地址，**不**被拒绝。
//!
//! # ⛔ XUDP 路径未动
//!
//! `crates/lengsuo-vmess/src/muxframe.rs` 与 `muxsession.rs`（`v1.mux.cool` /
//! XUDP 路径）本卡**未做任何改动**。

use lengsuo_vmess::udp::{
    decode_udp_packet, encode_udp_packet, read_udp_packet, UdpPacket, MAX_UDP_PAYLOAD,
};
use ss_core::target::TargetAddr;

/// 参考实跑得到的 `EncodeUDPPacket` 黄金字节（ATYP 在前、端口在后）。
const REF_ENC_V4: &[u8] = &[0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x35, b'h', b'i'];
const REF_ENC_DOMAIN: &[u8] = &[
    0x00, 0x00, 0x00, 0x03, 0x09, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 0x00, 0x35,
    b'p',
];
const REF_ENC_IPV6: &[u8] = &[
    0x00, 0x00, 0x00, 0x04, // RSV(2) + FRAG + ATYP=4
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    // ::1 的 15 个 0 字节
    0x01, // ::1 的末字节
    0x00, 0x35, b'q', // 端口 53 + 载荷
];
const REF_ENC_EMPTY: &[u8] = &[0x00, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0x00, 0x00];

/// 用例 1（回归保护）：单封正常头 ⇒ 解析成功，目标地址与载荷正确。
///
/// 判据取参考实跑黄金字节 `PROBE single-v4 OK addr=127.0.0.1 port=53 residual=2`
/// 与 `ENC v4 bytes=000000017f00000100356869`。
#[test]
fn single_header_decodes_to_target_and_payload() {
    let wire = REF_ENC_V4;
    let packet = decode_udp_packet(wire).expect("单封正常头必须解析成功");
    assert_eq!(
        packet.target,
        TargetAddr::V4([127, 0, 0, 1], 53),
        "目标地址必须来自第一封头"
    );
    assert_eq!(packet.payload, b"hi".to_vec(), "剩余字节即载荷");
}

/// 用例 1b（回归保护）：编码字节与参考 `EncodeUDPPacket` 逐字节一致。
#[test]
fn encoded_bytes_match_reference_golden_vectors() {
    let v4 = UdpPacket {
        target: TargetAddr::V4([127, 0, 0, 1], 53),
        payload: b"hi".to_vec(),
    };
    assert_eq!(
        encode_udp_packet(&v4).expect("可编码"),
        REF_ENC_V4.to_vec(),
        "IPv4 编码必须与参考逐字节一致"
    );

    let domain = UdpPacket {
        target: TargetAddr::Domain("localhost".to_string(), 53),
        payload: b"p".to_vec(),
    };
    assert_eq!(
        encode_udp_packet(&domain).expect("可编码"),
        REF_ENC_DOMAIN.to_vec(),
        "域名编码必须与参考逐字节一致（ATYP=3，端口在最后）"
    );

    let ipv6 = UdpPacket {
        target: TargetAddr::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 53),
        payload: b"q".to_vec(),
    };
    assert_eq!(
        encode_udp_packet(&ipv6).expect("可编码"),
        REF_ENC_IPV6.to_vec(),
        "IPv6 编码必须与参考逐字节一致（ATYP=4）"
    );

    let empty = UdpPacket {
        target: TargetAddr::V4([10, 0, 0, 1], 0),
        payload: Vec::new(),
    };
    assert_eq!(
        encode_udp_packet(&empty).expect("可编码"),
        REF_ENC_EMPTY.to_vec(),
        "空载荷编码必须与参考逐字节一致"
    );
}

/// 用例 1c（回归保护）：域名头解析 ⇒ 域名目标 + 载荷。
///
/// 判据取参考实跑 `PROBE domain OK addr=localhost port=53 residual=1 bytes=70`。
#[test]
fn single_domain_header_decodes_to_domain_target() {
    let packet = decode_udp_packet(REF_ENC_DOMAIN).expect("域名头必须解析成功");
    assert_eq!(
        packet.target,
        TargetAddr::Domain("localhost".to_string(), 53)
    );
    assert_eq!(packet.payload, b"p".to_vec());
}

/// 用例 2（**本卡核心**）：两封头连在一起 ⇒ 参考**只取第一封**，
/// 第二封头整体落入**残余载荷**，**不**被当作新目标地址，**不**被拒绝。
///
/// 判据取参考实跑：
/// `PROBE two-headers OK addr=127.0.0.1 port=53 residual=13
///  bytes=68690000000108080808003578`
///
/// 即：残余载荷 = `"hi"` + 第二封头完整字节（`00 00 00 01 08 08 08 08 00 35 78`
/// 共 11 字节）= 13 字节。
#[test]
fn two_headers_take_first_and_keep_second_as_payload() {
    let mut wire = REF_ENC_V4.to_vec();
    // 第二封头：RSV(2)=0, FRAG=0, ATYP=1, 8.8.8.8:53, 载荷 'x'
    wire.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35, b'x']);

    let packet = decode_udp_packet(&wire).expect("参考接受两封头连在一起的数据报");
    assert_eq!(
        packet.target,
        TargetAddr::V4([127, 0, 0, 1], 53),
        "只取第一封头的目标地址"
    );

    // 残余载荷必须与参考实跑逐字节一致：13 字节，含第二封头全部字节。
    let expected_residual: Vec<u8> = [
        b"hi".as_slice(),
        [0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35, b'x'].as_slice(),
    ]
    .concat();
    assert_eq!(
        packet.payload, expected_residual,
        "第二封头必须整体作为残余载荷（与参考实跑 residual=13 逐字节一致）"
    );
    assert_eq!(packet.payload.len(), 13, "参考实跑残余长度");
    assert_eq!(
        &packet.payload[2..],
        &[0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35, b'x'],
        "第二封头原样保留在载荷里"
    );
}

/// 用例 2b（核心回归）：三封头连在一起 ⇒ 仍只取第一封，后两封全在载荷里。
#[test]
fn three_headers_take_first_and_keep_rest_as_payload() {
    let mut wire = REF_ENC_V4.to_vec();
    wire.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35, b'x']);
    wire.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 9, 9, 9, 9, 0x00, 0x35, b'y']);

    let packet = decode_udp_packet(&wire).expect("参考接受多封头连在一起的数据报");
    assert_eq!(packet.target, TargetAddr::V4([127, 0, 0, 1], 53));
    assert_eq!(packet.payload.len(), 13 + 11, "第二、三封头都在残余载荷里");
}

/// 数据报边界保持的 reader：每次 `read` 返回**一个** UDP 数据报。
///
/// 对应参考 `common/buf/reader.go:10-25` `readOneUDP` 与
/// `proxy/socks/protocol.go:369-384` `UDPReader.ReadMultiBuffer` 的
/// 「一次 read = 一个数据报」语义。
struct DatagramReader {
    socket: std::net::UdpSocket,
}

impl std::io::Read for DatagramReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let (n, _from) = self.socket.recv_from(buf)?;
        Ok(n)
    }
}

/// 用例 2c（核心回归）：`read_udp_packet` **不得**把多份数据报拼成一份报文。
///
/// 旧实现用 `read_to_end`，会把两份数据报首尾相接 ⇒ 第二份的头落进第一份的
/// 载荷（这正是「一报多封头」的来源）。参考
/// `common/buf/reader.go:10-25` `readOneUDP` 只读一次。
///
/// ⛔ 判据用**真 UDP socket** + 边界保持的 reader：`std::io::Cursor` 对 `Vec`
/// 一次 `read` 就会把整个缓冲读空（`Cursor` 语义 ≠ 数据报边界），证明不了
/// 边界语义。
#[test]
fn read_udp_packet_does_not_merge_two_datagrams() {
    use std::net::UdpSocket;

    let first = UdpPacket {
        target: TargetAddr::V4([127, 0, 0, 1], 53),
        payload: b"hi".to_vec(),
    };
    let second = UdpPacket {
        target: TargetAddr::V4([8, 8, 8, 8], 5353),
        payload: b"second".to_vec(),
    };

    let sock = UdpSocket::bind(("127.0.0.1", 0)).expect("绑定回环 UDP socket");
    sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("设置读超时");
    let peer = sock.local_addr().expect("本地地址");
    sock.send_to(&encode_udp_packet(&first).expect("可编码"), peer)
        .expect("发第一个数据报");
    sock.send_to(&encode_udp_packet(&second).expect("可编码"), peer)
        .expect("发第二个数据报");

    let mut reader = DatagramReader { socket: sock };

    // 单次读 ⇒ 只得到第一个数据报，第二个数据报的字节**不在**结果里。
    let got = read_udp_packet(&mut reader).expect("可读");
    assert_eq!(got, first, "单次读只解一个数据报，不得把第二个数据报并进来");
    assert_eq!(got.payload, b"hi".to_vec());

    // 再读一次 ⇒ 拿到第二个数据报（证明两个数据报都在流上，未被吞掉）。
    let got2 = read_udp_packet(&mut reader).expect("第二个数据报可读");
    assert_eq!(got2, second);
}

/// 用例 3（fail-closed）：`FRAG != 0` ⇒ 拒绝。
///
/// 判据取参考实跑 `PROBE frag-nonzero ERR proxy/socks: discarding fragmented payload.`
/// （参考 `proxy/socks/protocol.go:334-336`）。
#[test]
fn frag_nonzero_is_rejected() {
    let mut wire = REF_ENC_V4.to_vec();
    wire[2] = 1; // FRAG=1
    let err = decode_udp_packet(&wire).expect_err("FRAG != 0 必须拒绝");
    assert!(
        matches!(err, lengsuo_vmess::FrameError::Address),
        "FRAG != 0 必须 fail-closed 报错，实际: {err:?}"
    );

    // 多封头场景下，第二封头带 FRAG≠0 也**不**影响判定：只看第一封头的 FRAG。
    let mut two = REF_ENC_V4.to_vec();
    two.extend_from_slice(&[0x00, 0x00, 0x01, 0x01, 8, 8, 8, 8, 0x00, 0x35, b'x']);
    let ok = decode_udp_packet(&two).expect("第一封 FRAG=0 即接受，第二封头只是载荷");
    assert_eq!(ok.target, TargetAddr::V4([127, 0, 0, 1], 53));
}

/// 用例 4（fail-closed）：长度不足 ⇒ 拒绝。
///
/// 判据取参考实跑：
/// - `PROBE short-3bytes ERR proxy/socks: insufficient length of packet.`
///   （参考 `proxy/socks/protocol.go:325-327`）
/// - `PROBE short-half-header ERR proxy/socks: failed to read UDP header > unexpected EOF`
///   （参考 `proxy/socks/protocol.go:340-343`）
#[test]
fn insufficient_length_is_rejected() {
    // 不足 5 字节。
    assert!(
        decode_udp_packet(&[0x00, 0x00, 0x00]).is_err(),
        "3 字节必须拒（参考 insufficient length of packet.）"
    );
    assert!(
        decode_udp_packet(&[0x00, 0x00, 0x00, 0x01]).is_err(),
        "4 字节必须拒"
    );
    // 半个头：ATYP=IPv4 但地址/端口不全。
    assert!(
        decode_udp_packet(&[0x00, 0x00, 0x00, 0x01, 127]).is_err(),
        "半个 IPv4 头必须拒（参考 failed to read UDP header > unexpected EOF）"
    );
    assert!(
        decode_udp_packet(&[0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1]).is_err(),
        "缺端口必须拒"
    );
    // 域名头长度不足。
    assert!(
        decode_udp_packet(&[0x00, 0x00, 0x00, 0x03, 0x09, b'a']).is_err(),
        "域名头截断必须拒"
    );
    // IPv6 头截断。
    assert!(
        decode_udp_packet(&[0x00, 0x00, 0x00, 0x04, 0, 0, 0, 0, 0]).is_err(),
        "IPv6 头截断必须拒"
    );
}

/// 用例 4b：域名段里是 IP 字面量 ⇒ 参考转成 IP 地址。
///
/// 判据取参考实跑：
/// `EDGE domain-ip-literal OK addr=127.0.0.1 port=53 residual=1`
/// （参考 `common/protocol/address.go:213-218` `maybeIPPrefix` + `net.ParseAddress`）。
#[test]
fn domain_carrying_ip_literal_becomes_ip_address() {
    // ATYP=3，域名 = "127.0.0.1"（9 字节），端口 53，载荷 'p'。
    let mut wire = vec![0x00, 0x00, 0x00, 0x03, 0x09];
    wire.extend_from_slice(b"127.0.0.1");
    wire.extend_from_slice(&[0x00, 0x35, b'p']);

    let packet = decode_udp_packet(&wire).expect("IP 字面量域名必须解析成功");
    assert_eq!(
        packet.target,
        TargetAddr::V4([127, 0, 0, 1], 53),
        "IP 字面量必须转成 IP 地址（端口保留）"
    );
    assert_eq!(packet.payload, b"p".to_vec());
}

/// 用例 4c（fail-closed）：域名长度 0 ⇒ 拒绝。
///
/// 判据取参考实跑：
/// `EDGE domain-len-0 ERR proxy/socks: failed to read UDP header > common/protocol: invalid domain name: `
/// （参考 `common/protocol/address.go:208-212` + `159-166`）。
#[test]
fn empty_domain_length_is_rejected() {
    let wire = [0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x35, b'p'];
    assert!(
        decode_udp_packet(&wire).is_err(),
        "域名长度 0 必须拒（参考 invalid domain name）"
    );
}

/// 用例 5（fail-closed）：未知 ATYP ⇒ 拒绝。
///
/// 判据取参考 `common/protocol/address.go:184-191`（`unknown address type`）。
#[test]
fn unknown_address_type_is_rejected() {
    for atyp in [0x00u8, 0x02, 0x05, 0x10, 0xFF] {
        let mut wire = vec![0x00, 0x00, 0x00, atyp];
        wire.extend_from_slice(&[0u8; 16]);
        assert!(decode_udp_packet(&wire).is_err(), "ATYP={atyp:#x} 必须拒");
    }
}

/// 用例 6（fail-closed）：载荷超上限 ⇒ 拒绝（参考 `buf.Size` = 8192）。
#[test]
fn oversized_payload_is_rejected() {
    let mut wire = REF_ENC_V4[..10].to_vec(); // 只有头，没有载荷
    wire.extend_from_slice(&vec![0u8; MAX_UDP_PAYLOAD + 1]);
    let err = decode_udp_packet(&wire).expect_err("超限载荷必须拒");
    assert!(
        matches!(err, lengsuo_vmess::FrameError::PacketTooLarge { .. }),
        "必须报 PacketTooLarge，实际: {err:?}"
    );

    let huge = UdpPacket {
        target: TargetAddr::V4([127, 0, 0, 1], 1),
        payload: vec![0u8; MAX_UDP_PAYLOAD + 1],
    };
    assert!(
        encode_udp_packet(&huge).is_err(),
        "编码侧同样必须 fail-closed"
    );
}
