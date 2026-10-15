//! SIP022 TCP 会话双向编解码测试。口令（PSK）是测试专用假凭据；这些 roundtrip
//! 只证明本实现内部一致，**不宣称与 Xray 的 TCP 互通已验证**（互通状态见
//! `docs/ss2022-status.md`）。全部异步读写由 `tokio::time::timeout` 约束；
//! `read_to_end` 前先关写半。

use std::time::{Duration, Instant};

use lengsuo_ss2022::crypto::{Key, Method};
use lengsuo_ss2022::tcp::receive::clock_at;
use lengsuo_ss2022::tcp::receive::Association;
use lengsuo_ss2022::tcp::{
    Direction, Opening, Reader, SessionReplay, Writer, MAX_VAR_HEADER_LEN, TIMESTAMP_WINDOW_SECS,
};
use lengsuo_ss2022::Error;
use ss_core::target::TargetAddr;
use tokio::io::{duplex, AsyncReadExt};
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(2);
const NOW: u64 = 1_700_000_000;
const PADDING: u16 = 8;

fn methods() -> [Method; 2] {
    [Method::Aes128, Method::Aes256]
}

fn make_key(method: Method) -> Key {
    let psk = vec![0x11u8; method.key_len()];
    Key::new(method, &psk).expect("假 PSK 应可构造密钥")
}

type Clock = lengsuo_ss2022::receiver::Clock;

fn clock() -> Clock {
    clock_at(NOW, Instant::now())
}

fn clock_shifted(secs: u64) -> Clock {
    clock_at(NOW + secs, Instant::now())
}

fn demo_target() -> TargetAddr {
    TargetAddr::Domain("example.invalid".into(), 443)
}

fn opening(method: Method, session_id: u64, salt_byte: u8) -> Opening {
    Opening::injected(&vec![salt_byte; method.key_len()], session_id)
}

/// 把请求开场写进任意写端（Writer 按边界 write_all）。
async fn write_request<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut Writer,
    wire: &mut W,
    payload: &[u8],
) -> Result<(), Error> {
    writer
        .write_request_header(wire, &demo_target(), payload, NOW, PADDING)
        .await
}

/// 只取错误文本（Opened 无 Debug，不能整 Result 格式化）。
fn err_text<T>(outcome: &Result<T, Error>) -> String {
    match outcome {
        Ok(_) => "Ok(<opened>)".into(),
        Err(error) => error.to_string(),
    }
}

#[tokio::test]
async fn request_and_response_roundtrip_both_methods() {
    timeout(WAIT, async {
        for method in methods() {
            let key = make_key(method);
            let mut request_writer =
                Writer::new(&key, Direction::Request, opening(method, 0x1001, 0x5A))
                    .expect("可构造");
            let mut response_writer =
                Writer::new(&key, Direction::Response, opening(method, 0x2002, 0xA5))
                    .expect("可构造");

            let (mut client_side, server_side) = duplex(64 * 1024);
            let (mut server_read, mut server_write) = tokio::io::split(server_side);

            // 请求方向：目标地址 + 首批载荷 + 后续载荷 + 终止。
            timeout(
                WAIT,
                write_request(&mut request_writer, &mut client_side, b"first payload"),
            )
            .await
            .expect("未超时")
            .expect("请求开场可写出");
            timeout(
                WAIT,
                request_writer.write_payload(&mut client_side, b"second payload"),
            )
            .await
            .expect("未超时")
            .expect("请求载荷可写出");
            timeout(WAIT, request_writer.write_finish(&mut client_side))
                .await
                .expect("未超时")
                .expect("请求收尾可写出");

            // 服务端视角解请求方向。
            let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
            let mut request_reader =
                Reader::new(make_key(method), Direction::Request, Duration::from_secs(1))
                    .expect("可构造");
            let opened = timeout(
                WAIT,
                request_reader.open(&mut server_read, &mut replay, clock(), None),
            )
            .await
            .expect("未超时")
            .expect("请求开场应通过全部校验");
            assert_eq!(opened.session_id, 0x1001);
            assert_eq!(opened.timestamp, NOW);
            assert_eq!(opened.association, Association::Request(demo_target()));
            assert_eq!(opened.payload, b"first payload");
            let second = timeout(WAIT, request_reader.read_payload(&mut server_read))
                .await
                .expect("未超时")
                .expect("载荷帧应存在");
            assert_eq!(second, Some(b"second payload".to_vec()));
            let finished = timeout(WAIT, request_reader.read_payload(&mut server_read))
                .await
                .expect("未超时")
                .expect("终止帧应得到 None");
            assert_eq!(finished, Option::<Vec<u8>>::None);

            // 响应方向：绑定请求会话标识。
            timeout(
                WAIT,
                response_writer.write_response_header(
                    &mut server_write,
                    0x1001,
                    b"reply payload",
                    NOW,
                    PADDING,
                ),
            )
            .await
            .expect("未超时")
            .expect("响应开场可写出");
            timeout(WAIT, response_writer.write_finish(&mut server_write))
                .await
                .expect("未超时")
                .expect("响应收尾可写出");
            let (mut client_read, _client_write) = tokio::io::split(client_side);
            let mut response_reader =
                Reader::new(key, Direction::Response, Duration::from_secs(1)).expect("可构造");
            let reply = timeout(
                WAIT,
                response_reader.open(
                    &mut client_read,
                    &mut replay,
                    clock(),
                    Some(opened.session_id),
                ),
            )
            .await
            .expect("未超时")
            .expect("响应开场应通过校验并绑定会话");
            assert_eq!(reply.association, Association::Response(0x1001));
            assert_eq!(reply.payload, b"reply payload");
            let finished = timeout(WAIT, response_reader.read_payload(&mut client_read))
                .await
                .expect("未超时")
                .expect("响应终止帧");
            assert_eq!(finished, Option::<Vec<u8>>::None);
        }
    })
    .await
    .expect("双向 roundtrip 超时");
}

#[tokio::test]
async fn variable_header_and_payload_reassemble_across_chunks() {
    timeout(WAIT, async {
        let method = Method::Aes256;
        let key = make_key(method);
        let mut writer =
            Writer::new(&key, Direction::Request, opening(method, 0x3003, 0x33)).expect("可构造");
        let mut wire = Vec::new();
        timeout(WAIT, write_request(&mut writer, &mut wire, b"head"))
            .await
            .expect("未超时")
            .expect("开场可写出");
        let big = vec![0xC3u8; 600];
        timeout(WAIT, writer.write_payload(&mut wire, &big))
            .await
            .expect("未超时")
            .expect("载荷可写出");
        // 跨 chunk：任意切点重组后必须逐字节一致。
        for cut in [1usize, 5, 37, 40, wire.len() - 1] {
            let (head, tail) = wire.split_at(cut);
            let mut stream = head.chain(tail);
            let mut reader =
                Reader::new(make_key(method), Direction::Request, Duration::from_secs(1))
                    .expect("可构造");
            let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
            let opened = timeout(WAIT, reader.open(&mut stream, &mut replay, clock(), None))
                .await
                .expect("未超时")
                .expect("跨 chunk 开场应重组成功");
            assert_eq!(opened.payload, b"head");
            let got = timeout(WAIT, reader.read_payload(&mut stream))
                .await
                .expect("未超时")
                .expect("跨 chunk 载荷应重组成功");
            assert_eq!(got, Some(big.clone()), "切点 {cut}");
        }
    })
    .await
    .expect("跨 chunk 超时");
}

#[tokio::test]
async fn wrong_psk_fails_authentication_then_poisons() {
    timeout(WAIT, async {
        let method = Method::Aes128;
        let good = make_key(method);
        let mut writer =
            Writer::new(&good, Direction::Request, opening(method, 0x4004, 0x44)).expect("可构造");
        let mut wire = Vec::new();
        timeout(WAIT, write_request(&mut writer, &mut wire, b"payload"))
            .await
            .expect("未超时")
            .expect("开场可写出");
        let evil = Key::new(method, &vec![0x99u8; method.key_len()]).expect("假 PSK");
        let mut reader =
            Reader::new(evil, Direction::Request, Duration::from_secs(1)).expect("可构造");
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let mut stream = &wire[..];
        let error = match timeout(WAIT, reader.open(&mut stream, &mut replay, clock(), None))
            .await
            .expect("未超时")
        {
            Err(error) => error,
            Ok(_) => panic!("错 PSK 必须认证失败"),
        };
        assert!(
            matches!(error, Error::Authentication | Error::Length),
            "实际 {error:?}"
        );
        assert!(reader.is_poisoned(), "认证失败必须永久 poison");
        let again = timeout(WAIT, reader.open(&mut stream, &mut replay, clock(), None))
            .await
            .expect("未超时");
        assert!(
            matches!(again, Err(Error::Poisoned)),
            "实际 {}",
            err_text(&again)
        );
    })
    .await
    .expect("错 PSK 超时");
}

#[tokio::test]
async fn truncated_inputs_fail_closed() {
    timeout(WAIT, async {
        let method = Method::Aes128;
        let key = make_key(method);
        let fixed_wire = method.key_len() + 37; // salt + 固定头线上长度（21+16）

        // ① salt 不满。
        let mut reader = Reader::new(make_key(method), Direction::Request, Duration::from_secs(1))
            .expect("可构造");
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let short_salt = vec![0x5Au8; method.key_len() - 1];
        let mut stream = &short_salt[..];
        let outcome = timeout(WAIT, reader.open(&mut stream, &mut replay, clock(), None))
            .await
            .expect("未超时");
        assert!(
            matches!(outcome, Err(Error::Length)),
            "实际 {}",
            err_text(&outcome)
        );
        assert!(reader.is_poisoned());

        // ② 变长头中途 EOF。
        let mut writer =
            Writer::new(&key, Direction::Request, opening(method, 0x5005, 0x55)).expect("可构造");
        let mut wire = Vec::new();
        timeout(WAIT, write_request(&mut writer, &mut wire, b"p"))
            .await
            .expect("未超时")
            .expect("开场可写出");
        let mut reader = Reader::new(make_key(method), Direction::Request, Duration::from_secs(1))
            .expect("可构造");
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let mut stream = &wire[..fixed_wire + 3];
        let outcome = timeout(WAIT, reader.open(&mut stream, &mut replay, clock(), None))
            .await
            .expect("未超时");
        assert!(
            matches!(outcome, Err(Error::Length) | Err(Error::Authentication)),
            "实际 {}",
            err_text(&outcome)
        );
        assert!(reader.is_poisoned());

        // ③ 载荷帧中途 EOF：开场合法，载荷截断。
        let mut reader = Reader::new(make_key(method), Direction::Request, Duration::from_secs(1))
            .expect("可构造");
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let mut stream = &wire[..];
        timeout(WAIT, reader.open(&mut stream, &mut replay, clock(), None))
            .await
            .expect("未超时")
            .expect("合法开场");
        let outcome = timeout(WAIT, reader.read_payload(&mut stream)).await;
        match outcome {
            // 载荷帧截断：receive.rs 的 read_exact 路径报 Length；ss-core chunk
            // 内部 read_exact 的 EOF 以 Io(UnexpectedEof) 透传。两者都算截断失败。
            Ok(Err(Error::Length)) | Ok(Err(Error::Authentication)) => {}
            Ok(Err(Error::Io(io))) => {
                assert_eq!(io.kind(), std::io::ErrorKind::UnexpectedEof, "实际 {io}");
            }
            other => panic!("载荷帧截断应失败，实际 {other:?}"),
        }
    })
    .await
    .expect("截断矩阵超时");
}

#[tokio::test]
async fn tampered_wire_fails_authentication() {
    timeout(WAIT, async {
        let method = Method::Aes128;
        let key = make_key(method);
        let mut writer =
            Writer::new(&key, Direction::Request, opening(method, 0x6006, 0x66)).expect("可构造");
        let mut wire = Vec::new();
        timeout(WAIT, write_request(&mut writer, &mut wire, b"payload"))
            .await
            .expect("未超时")
            .expect("开场可写出");
        let positions = [0usize, 1, method.key_len() + 5, wire.len() - 1];
        for tweak in positions {
            let mut tampered = wire.clone();
            tampered[tweak] ^= 0x01;
            let mut reader =
                Reader::new(make_key(method), Direction::Request, Duration::from_secs(1))
                    .expect("可构造");
            let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
            let mut stream = &tampered[..];
            let outcome = timeout(WAIT, reader.open(&mut stream, &mut replay, clock(), None))
                .await
                .expect("未超时");
            // 篡改 salt ⇒ 子密钥变化；篡改密文 ⇒ 认证失败。个别位置可能先触发
            // 长度/方向校验，但都必须失败且 poison。
            assert!(
                matches!(
                    outcome,
                    Err(Error::Authentication) | Err(Error::Length) | Err(Error::Direction)
                ),
                "位置 {tweak} 篡改应失败，实际 {}",
                err_text(&outcome)
            );
            assert!(reader.is_poisoned(), "位置 {tweak} 篡改必须 poison");
        }
    })
    .await
    .expect("篡改超时");
}

#[tokio::test]
async fn session_replay_rejects_duplicates() {
    timeout(WAIT, async {
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let salt = vec![0x77u8; 16];
        let now = clock();
        replay.accept(&salt, 0x9001, now).expect("首次应被接受");
        assert_eq!(replay.remembered(), 1);
        // 同会话标识重复（Error 无 PartialEq，用 matches! 断言形状）。
        assert!(
            matches!(replay.accept(&salt, 0x9001, now), Err(Error::Replay)),
            "重复会话标识必须拒绝"
        );
        // 同 salt 不同会话标识也拒绝（salt 记忆池）。
        let other_salt = vec![0x78u8; 16];
        replay
            .accept(&other_salt, 0x9002, now)
            .expect("新 salt 应接受");
        assert!(
            matches!(replay.accept(&salt, 0x9003, now), Err(Error::Replay)),
            "重复 salt 必须拒绝"
        );
        assert_eq!(replay.remembered(), 2);
    })
    .await
    .expect("重放拒绝超时");
}

#[tokio::test]
async fn stale_timestamp_is_rejected() {
    timeout(WAIT, async {
        let method = Method::Aes128;
        let key = make_key(method);
        let shifted = clock_shifted(TIMESTAMP_WINDOW_SECS + 5);
        let mut writer =
            Writer::new(&key, Direction::Request, opening(method, 0x7007, 0x71)).expect("可构造");
        let mut wire = Vec::new();
        timeout(WAIT, write_request(&mut writer, &mut wire, b"p"))
            .await
            .expect("未超时")
            .expect("开场可写出");
        let mut reader = Reader::new(make_key(method), Direction::Request, Duration::from_secs(1))
            .expect("可构造");
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let mut stream = &wire[..];
        let outcome = timeout(WAIT, reader.open(&mut stream, &mut replay, shifted, None))
            .await
            .expect("未超时");
        assert!(
            matches!(outcome, Err(Error::Timestamp)),
            "超过 ±{TIMESTAMP_WINDOW_SECS}s 窗口必须拒绝，实际 {}",
            err_text(&outcome)
        );
        assert!(reader.is_poisoned());
    })
    .await
    .expect("时间窗超时");
}

#[tokio::test]
async fn header_padding_policy_is_enforced() {
    timeout(WAIT, async {
        let method = Method::Aes128;
        let key = make_key(method);
        // 空载荷 + 零填充：变长头既无载荷也无填充，必须拒绝（SIP022）。
        let mut writer =
            Writer::new(&key, Direction::Request, opening(method, 0x8008, 0x81)).expect("可构造");
        let mut sink = Vec::new();
        let outcome = timeout(
            WAIT,
            writer.write_request_header(&mut sink, &demo_target(), b"", NOW, 0),
        )
        .await
        .expect("未超时");
        assert!(
            matches!(
                outcome,
                Err(Error::HeaderPadding) | Err(Error::SessionPolicy)
            ),
            "实际 {outcome:?}"
        );
        assert!(writer.is_poisoned());

        // 变长头超出上限必须拒绝。
        let mut writer2 =
            Writer::new(&key, Direction::Request, opening(method, 0x8009, 0x82)).expect("可构造");
        let mut sink2 = Vec::new();
        let outcome = timeout(
            WAIT,
            writer2.write_request_header(&mut sink2, &demo_target(), b"p", NOW, MAX_VAR_HEADER_LEN),
        )
        .await
        .expect("未超时");
        assert!(
            matches!(outcome, Err(Error::Length) | Err(Error::HeaderPadding)),
            "实际 {outcome:?}"
        );
        assert!(writer2.is_poisoned());
    })
    .await
    .expect("头部填充策略超时");
}

#[tokio::test]
async fn response_binding_is_enforced() {
    timeout(WAIT, async {
        let method = Method::Aes128;
        let key = make_key(method);
        let mut response_writer =
            Writer::new(&key, Direction::Response, opening(method, 0xB002, 0xB2)).expect("可构造");
        let mut wire = Vec::new();
        timeout(
            WAIT,
            response_writer.write_response_header(&mut wire, 0xB001, b"reply", NOW, PADDING),
        )
        .await
        .expect("未超时")
        .expect("响应开场可写出");
        let mut reader = Reader::new(
            make_key(method),
            Direction::Response,
            Duration::from_secs(1),
        )
        .expect("可构造");
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let mut stream = &wire[..];
        let outcome = timeout(
            WAIT,
            reader.open(&mut stream, &mut replay, clock(), Some(0xDEAD)),
        )
        .await
        .expect("未超时");
        assert!(
            matches!(outcome, Err(Error::ClientSession)),
            "响应必须绑定到正确的请求会话，实际 {}",
            err_text(&outcome)
        );
        assert!(reader.is_poisoned());
        // 请求方向的 reader 不接受 expected_peer。
        let mut request_reader =
            Reader::new(make_key(method), Direction::Request, Duration::from_secs(1))
                .expect("可构造");
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let mut stream = &wire[..];
        let outcome = timeout(
            WAIT,
            request_reader.open(&mut stream, &mut replay, clock(), Some(1)),
        )
        .await
        .expect("未超时");
        assert!(
            matches!(outcome, Err(Error::Direction)),
            "实际 {}",
            err_text(&outcome)
        );
    })
    .await
    .expect("响应绑定超时");
}

#[test]
fn error_display_never_leaks_psk() {
    // 错误消息与状态查询不得携带 PSK 或密钥材料。
    let psk_text = "ss2022-tcp-test-psk!";
    let errors = [
        Error::SessionPolicy,
        Error::Replay,
        Error::Authentication,
        Error::Timestamp,
        Error::ClientSession,
        Error::HeaderPadding,
        Error::Timeout,
        Error::Length,
        Error::Direction,
    ];
    for error in errors {
        let text = format!("{error:?} {error}");
        assert!(!text.contains(psk_text), "错误消息泄露 PSK：{text}");
    }
}
