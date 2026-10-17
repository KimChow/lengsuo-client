//! VLESS XEL 记录层的 Rust↔Rust 跨进程互通（真实回环 TCP）。
//!
//! **为什么不是与 Xray 互通**：Xray v26.3.27（`d2758a0`）里 XEL 只能作为
//! `mlkem768x25519plus.*` 会话握手的一部分上线——`proxy/vless/encryption/xor.go`
//! 的 `NewXorConn` 只在 `ServerInstance`/`ClientInstance` 握手内部建立，密钥与 IV 都
//! 来自握手派生的 `UnitedKey`；`common.go` 的记录密钥同样由
//! `NewAEAD(握手 ctx, UnitedKey, useAES)` 派生。配置里没有"注入会话密钥"或
//! "只开记录层"的路径：`encryption`/`decryption` 取 `"xor"` 会被配置解析直接拒绝
//! （可执行留证见 `tests/xray_xel_blocker.rs`）。因此本文件两端都用本 crate 实现，
//! 验证记录层在跨进程字节流上的语义；**与 Xray 的 XEL 互通状态为未互通**，
//! 阻塞点与解锁条件记录在 `docs/vless-status.md`。
//!
//! 拓扑：父进程 = client 角色；对端 = 同一个测试二进制用 `--exact --ignored`
//! 再启动一次的子进程（server 角色），用例名与端口经 `LENGSUO_XEL_CASE` /
//! `LENGSUO_XEL_PORT` 交接；子进程输出写入系统临时目录日志，失败时回读并 panic。
//! 密钥全部是测试假密钥，且不写入日志。
//!
//! 每个读操作都由 `tokio::time::timeout` 约束；接收端只有在对端已关闭写半之后
//! 才把流读到 EOF。`aead-xor` / `xor-only` 用 XOR 掩蔽器覆盖整条双向流，
//! 分块切分点刻意不规则（1/3/4/5/997/2048 字节），迫使跨进程流在任意切分下
//! 都保持分帧与密钥流连续。

use lengsuo_vless::xel::{
    aead::XelCipher,
    frame::{RecordFramer, RecordHeader},
    record::{RecordReader, RecordWriter},
    xor::XorMask,
    Error, XelKey,
};
use std::{
    net::Ipv4Addr,
    process::{Child, Command, ExitStatus, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{timeout, Instant},
};

/// 用例总超时：对端是本地进程，20 秒足够冷启动。
const WAIT: Duration = Duration::from_secs(20);
/// 对端角色测试名（子进程用 `--exact` 只跑它）。
const PEER_TEST: &str = "xel_peer_server";

/// client → server 方向的记录密钥（假密钥）。
fn key_up() -> XelKey {
    XelKey::new(&[0xA1; 32]).unwrap()
}
/// server → client 方向的记录密钥（假密钥）。
fn key_down() -> XelKey {
    XelKey::new(&[0xB2; 32]).unwrap()
}
/// 与 [`key_up`] 不匹配的密钥，用于错钥用例。
fn key_evil() -> XelKey {
    XelKey::new(&[0x99; 32]).unwrap()
}
/// XOR 头部掩蔽的 CTR IV（16 字节 = AES 块长）。
const IV_UP: [u8; 16] = [0x11; 16];
const IV_DOWN: [u8; 16] = [0x22; 16];

fn cipher_of(case: &str) -> XelCipher {
    match case {
        "aead-chacha" => XelCipher::ChaCha20Poly1305,
        "aead-aes" | "aead-xor" | "wrong-key" | "nonce-gap" | "bad-magic" => XelCipher::Aes256Gcm,
        other => unreachable!("未知 AEAD 用例 {other}"),
    }
}

/// 线上是否叠加 XOR 头部掩蔽（对应参考端 `random` 模式 + AEAD 记录）。
fn uses_xor(case: &str) -> bool {
    matches!(case, "aead-xor" | "xor-only")
}

/// 记录体是否 AEAD 认证（`xor-only` 只验证分帧，记录体明文透传）。
fn uses_aead(case: &str) -> bool {
    case != "xor-only"
}

/// 期望对端 fail-closed 且不得回显任何条目的用例。
fn expects_reject(case: &str) -> bool {
    matches!(case, "wrong-key" | "nonce-gap" | "bad-magic")
}

/// AEAD 用例的应用明文：1 字节、最小记录、4096、超过 8192 分片边界。
fn payloads() -> Vec<Vec<u8>> {
    vec![
        vec![0xF0u8],
        vec![0x11; 1],
        vec![0xAB; 4096],
        vec![0xCD; 8200],
        vec![0x42; 17],
    ]
}

/// `xor-only` 用例的记录体（XEL 记录体最小 17 字节）。
fn xor_bodies() -> Vec<Vec<u8>> {
    vec![
        vec![0x7Fu8; 17],
        vec![0x31; 24],
        vec![0xAB; 4096],
        vec![0xCD; 8200],
    ]
}

/// 明文记录 = 5 字节头（魔数 + BE16 = 记录体长度）+ 记录体。
fn plain_records() -> Vec<Vec<u8>> {
    xor_bodies()
        .into_iter()
        .map(|body| {
            let mut record = RecordHeader::new(body.len()).unwrap().encode().to_vec();
            record.extend_from_slice(&body);
            record
        })
        .collect()
}

fn expected_items(case: &str) -> Vec<Vec<u8>> {
    if uses_aead(case) {
        payloads()
    } else {
        plain_records()
    }
}

/// 用给定密钥密封成连续线上字节。
fn sealed(cipher: XelCipher, key: XelKey, items: &[Vec<u8>]) -> Vec<u8> {
    let mut writer = RecordWriter::new(cipher, key);
    let mut wire = Vec::new();
    for item in items {
        wire.extend_from_slice(&writer.seal(item).unwrap());
    }
    wire
}

/// 本端（client 角色）发送的线上字节；失效用例刻意构造坏流。
fn outgoing_wire(case: &str) -> Vec<u8> {
    match case {
        // 魔数不符但长度合法：帧器必须判非法头并 poison。
        "bad-magic" => {
            let mut wire = vec![24, 3, 3, 0, 17];
            wire.resize(wire.len() + 17, 0x5A);
            wire
        }
        // 丢掉第一条记录的线上字节：期望 nonce 从此失步。
        "nonce-gap" => {
            let all = sealed(cipher_of(case), key_up(), &payloads());
            let first = RecordHeader::new(payloads()[0].len() + 16)
                .unwrap()
                .record_len();
            all[first..].to_vec()
        }
        "wrong-key" | "aead-aes" | "aead-chacha" | "aead-xor" => {
            sealed(cipher_of(case), key_up(), &payloads())
        }
        "xor-only" => plain_records().concat(),
        other => unreachable!("未知用例 {other}"),
    }
}

/// 回显：AEAD 用例用本方向密钥重新密封；`xor-only` 原样回送还原出的记录。
fn echo_wire(case: &str) -> Vec<u8> {
    if uses_aead(case) {
        sealed(cipher_of(case), key_down(), &payloads())
    } else {
        plain_records().concat()
    }
}

/// 接收侧状态：AEAD 记录读取器，或纯帧器（`xor-only`）。
enum Sink {
    Aead(RecordReader),
    Plain(RecordFramer),
}

impl Sink {
    fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        match self {
            Self::Aead(reader) => reader.push(bytes),
            Self::Plain(framer) => framer.push(bytes),
        }
    }

    fn next_item(&mut self) -> Result<Option<Vec<u8>>, Error> {
        match self {
            Self::Aead(reader) => reader.next_plaintext(),
            Self::Plain(framer) => framer.next_record(),
        }
    }

    fn finish(&mut self) -> Result<(), Error> {
        match self {
            Self::Aead(reader) => reader.finish(),
            Self::Plain(framer) => framer.finish(),
        }
    }

    fn is_poisoned(&self) -> bool {
        match self {
            Self::Aead(reader) => reader.is_poisoned(),
            Self::Plain(framer) => framer.is_poisoned(),
        }
    }
}

fn recv_sink(case: &str, key: XelKey) -> Sink {
    if uses_aead(case) {
        Sink::Aead(RecordReader::new(cipher_of(case), key))
    } else {
        Sink::Plain(RecordFramer::new())
    }
}

fn up_mask() -> XorMask {
    XorMask::new(&key_up(), &IV_UP, &key_down(), &IV_DOWN).expect("XOR 掩蔽器建立失败")
}

fn down_mask() -> XorMask {
    XorMask::new(&key_down(), &IV_DOWN, &key_up(), &IV_UP).expect("XOR 掩蔽器建立失败")
}

/// 不规则分块：迫使每一段字节都落在跨记录/跨头的任意切分点上。
fn splits(total: usize) -> Vec<usize> {
    const PATTERN: [usize; 6] = [1, 4, 3, 5, 997, 2048];
    let mut sizes = Vec::new();
    let mut left = total;
    let mut index = 0;
    while left > 0 {
        let size = PATTERN[index % PATTERN.len()].min(left);
        sizes.push(size);
        left -= size;
        index += 1;
    }
    sizes
}

async fn send_wire(stream: &mut TcpStream, wire: &[u8], mut mask: Option<&mut XorMask>) {
    let mut piece = wire.to_vec();
    let mut position = 0;
    for size in splits(wire.len()) {
        let end = position + size;
        // 掩蔽器原地改写：只推进密钥流到被掩蔽的头部字节上。
        if let Some(mask) = mask.as_deref_mut() {
            mask.mask_outgoing(&mut piece[position..end])
                .unwrap_or_else(|error| panic!("发送侧掩蔽失败：{error}"));
        }
        stream.write_all(&piece[position..end]).await.unwrap();
        position = end;
    }
    stream.flush().await.unwrap();
}

/// 收完整条流（对端已关闭写半）：`(还原条目, 首个致命错误, 是否被中止)`。
///
/// `mask` 按借用推进分段，因此各段共享同一方向的密钥流状态。
async fn collect(
    stream: &mut TcpStream,
    sink: &mut Sink,
    mut mask: Option<&mut XorMask>,
) -> (Vec<Vec<u8>>, Option<Error>, bool) {
    let mut items = Vec::new();
    let mut buffer = vec![0u8; 997];
    let mut aborted = false;
    let mut failure = None;
    while failure.is_none() {
        let read = match timeout(WAIT, stream.read(&mut buffer)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(size)) => size,
            // 对端在读完之前退出会发 RST：只记"流被中止"，不断言具体错误码。
            Ok(Err(_)) => {
                aborted = true;
                break;
            }
            Err(_) => panic!("接收超时：对端未按约定关闭写半"),
        };
        let slice = &mut buffer[..read];
        if let Some(mask) = mask.as_mut() {
            if let Err(error) = mask.unmask_incoming(slice) {
                failure = Some(error);
                break;
            }
        }
        if let Err(error) = sink.push(slice) {
            failure = Some(error);
            break;
        }
        loop {
            match sink.next_item() {
                Ok(Some(item)) => items.push(item),
                Ok(None) => break,
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
    }
    if failure.is_none() {
        failure = sink.finish().err();
    }
    (items, failure, aborted)
}

/// 把剩余字节读到 EOF：让对端干净退出（避免残字节变成 RST）。
async fn drain_to_eof(stream: &mut TcpStream) {
    let mut buffer = [0u8; 512];
    loop {
        match timeout(WAIT, stream.read(&mut buffer)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
            Ok(Ok(_)) => continue,
        }
    }
}

/// client 角色：发送用例线上字节 → 关闭写半 → 校验对端回显或失效拒绝。
async fn parent_role(case: &str, stream: &mut TcpStream) {
    let wire = outgoing_wire(case);
    let mut out_mask = if uses_xor(case) {
        Some(up_mask())
    } else {
        None
    };
    send_wire(stream, &wire, out_mask.as_mut()).await;
    stream.shutdown().await.unwrap();

    // 接收方向用的是 client 侧的正确密钥：失效用例只会安静地收到 EOF。
    let mut sink = recv_sink(case, key_down());
    let mut in_mask = if uses_xor(case) {
        Some(up_mask())
    } else {
        None
    };
    let (items, failure, aborted) = collect(stream, &mut sink, in_mask.as_mut()).await;
    assert_eq!(failure, None, "{case} 本端接收不应出现协议错误");
    assert!(!aborted, "{case} 对端应正常关闭写半而非中止");
    if expects_reject(case) {
        assert!(items.is_empty(), "{case} 失效流不得还原出任何条目");
    } else {
        assert_eq!(
            items,
            expected_items(case),
            "{case} 跨进程往返必须逐字节一致"
        );
    }
}

/// server 角色（子进程）：收 client 记录 → 校验 → 用本方向密钥回显。
async fn serve(case: &str, port: u16) {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let key = if case == "wrong-key" {
        key_evil()
    } else {
        key_up()
    };
    let mut sink = recv_sink(case, key);
    let mut in_mask = if uses_xor(case) {
        Some(down_mask())
    } else {
        None
    };
    let (items, failure, aborted) = collect(&mut stream, &mut sink, in_mask.as_mut()).await;
    if expects_reject(case) {
        let expected = if case == "bad-magic" {
            Error::InvalidHeader
        } else {
            // XEL 线上不携带序号：nonce 失步与错钥在 AEAD 层不可区分。
            Error::AuthFailed
        };
        assert_eq!(
            failure,
            Some(expected),
            "{case} 必须以 {expected} fail-closed，实际 {failure:?}"
        );
        assert!(items.is_empty(), "{case} 失效流不得还原出任何明文");
        assert!(!aborted, "{case} 本端已关闭写半，不应看到中止");
        assert!(sink.is_poisoned(), "{case} 失效后方向必须永久 poison");
        drain_to_eof(&mut stream).await;
        return;
    }
    assert_eq!(failure, None, "{case} 正常流不得失败");
    assert!(!aborted, "{case} 本端已关闭写半，不应看到中止");
    assert_eq!(
        items,
        expected_items(case),
        "{case} 收到的条目必须与发送侧一致"
    );
    let wire = echo_wire(case);
    let mut out_mask = if uses_xor(case) {
        Some(down_mask())
    } else {
        None
    };
    send_wire(&mut stream, &wire, out_mask.as_mut()).await;
    stream.shutdown().await.unwrap();
    // 等 client 写完再退出，避免残字节变成 RST。
    drain_to_eof(&mut stream).await;
}

fn peer_log_path(port: u16) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "lengsuo-xel-peer-{}-{port}.log",
        std::process::id()
    ))
}

fn spawn_server(case: &str, port: u16) -> Child {
    let log = std::fs::File::create(peer_log_path(port)).unwrap();
    let error_log = log.try_clone().unwrap();
    Command::new(std::env::current_exe().unwrap())
        .args([PEER_TEST, "--exact", "--ignored", "--nocapture"])
        .env("LENGSUO_XEL_CASE", case)
        .env("LENGSUO_XEL_PORT", port.to_string())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(error_log))
        .stdin(Stdio::null())
        .spawn()
        .unwrap()
}

async fn reap(child: &mut Child, port: u16, case: &str) -> ExitStatus {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            // 回读子进程日志（含 panic 断言文本），失败时一并呈现。
            let path = peer_log_path(port);
            let output = std::fs::read_to_string(&path).unwrap_or_default();
            let _ = std::fs::remove_file(&path);
            println!("对端 {case} 日志尾部：{}", tail(&output));
            return status;
        }
        assert!(Instant::now() < deadline, "对端进程超时未退出");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn tail(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let keep = lines.len().min(40);
    lines[lines.len() - keep..].join("\n")
}

async fn run_case(case: &str) {
    timeout(WAIT, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut child = spawn_server(case, port);
        let (mut stream, _) = timeout(WAIT, listener.accept())
            .await
            .expect("对端进程未在超时内连接")
            .unwrap();
        parent_role(case, &mut stream).await;
        drop(stream);
        let status = reap(&mut child, port, "port").await;
        assert!(
            status.success(),
            "对端进程以 {status} 失败退出（见上方日志）"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn xel_aead_aes_records_interop_between_processes() {
    run_case("aead-aes").await;
}

#[tokio::test]
async fn xel_aead_chacha_records_interop_between_processes() {
    run_case("aead-chacha").await;
}

#[tokio::test]
async fn xel_xor_masked_aead_records_interop_between_processes() {
    run_case("aead-xor").await;
}

#[tokio::test]
async fn xel_xor_header_only_framing_interop_between_processes() {
    run_case("xor-only").await;
}

#[tokio::test]
async fn xel_wrong_key_is_rejected_between_processes() {
    run_case("wrong-key").await;
}

#[tokio::test]
async fn xel_skipped_record_breaks_nonce_between_processes() {
    run_case("nonce-gap").await;
}

#[tokio::test]
async fn xel_bad_magic_is_rejected_between_processes() {
    run_case("bad-magic").await;
}

/// 对端角色：由上面的用例以 `--exact --ignored` 启动为独立进程。
#[tokio::test]
#[ignore = "由互通测试作为对端子进程显式启动（LENGSUO_XEL_CASE / LENGSUO_XEL_PORT）"]
async fn xel_peer_server() {
    let case = std::env::var("LENGSUO_XEL_CASE")
        .expect("对端进程必须由 xel_interop 父测试启动，缺少 LENGSUO_XEL_CASE");
    let port: u16 = std::env::var("LENGSUO_XEL_PORT")
        .expect("对端进程缺少 LENGSUO_XEL_PORT")
        .parse()
        .expect("LENGSUO_XEL_PORT 必须是端口号");
    timeout(WAIT, serve(&case, port)).await.unwrap();
}
