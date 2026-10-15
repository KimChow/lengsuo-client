//! 传统 Shadowsocks AEAD 的 TCP 双向 Xray 真实互通测试（仅回环、假口令）。
//!
//! 本文件把 `src/tcp.rs` 的字节 chunk 层接到固定基线 Xray（v26.3.27 /
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）上跑真实 TCP 中继，两个方向各自
//! spawn 一次参考进程并在结束时 `kill`（`support::Reference` 的 `Drop`）：
//!
//! 1. `rust_client_to_xray_server_tcp`：本端 `TcpWriter` 写 salt +
//!    `TargetAddr::encode_checked` 的目标地址 + 载荷，Xray 的 shadowsocks 入站
//!    解出地址并经 freedom 出站连到本仓 spawn 的 echo 服务，回程由
//!    `TcpReader` 读取，逐字节核对等于 echo 内容。
//! 2. `xray_client_to_rust_server_tcp`：Xray 的 socks 入站接收本端 SOCKS5 请求，
//!    shadowsocks 出站连到本端监听器；本端用 `TcpReader`（服务端视角）解请求
//!    方向、中继到 echo 目标，再用 `TcpWriter` 写回程，核对端到端载荷。
//!
//! 载荷规格取 1 / 512 / 8158（= `MAX_SEGMENT_PAYLOAD`，单 chunk 明文上限）/
//! 8158+4096（超上限，必须跨 chunk）。所有异步读写都由 `tokio::time::timeout`
//! 约束，读到 EOF 之前先关写半；不修改任何产品代码来迁就互通。
//!
//! 首段明文本就是上层写的地址（本层不解析），所以测试侧自己负责在重组字节上
//! 续读地址；地址未读满时 `TargetAddr::decode` 报错即继续取下一个 chunk。

#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use lengsuo_shadowsocks::{CipherSuite, TargetAddr, TcpReader, TcpWriter, MAX_SEGMENT_PAYLOAD};
use serde_json::json;
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// 测试假口令，与任何生产凭据无关。
const PASSWORD: &str = "ss-tcp-reference-test-password";
/// 只绑回环，不接受任何外部地址。
const LOOPBACK: [u8; 4] = [127, 0, 0, 1];
const BIND: &str = "127.0.0.1:0";

/// 单个测试（含多次 spawn Xray 与全部套件）的总超时。
const OVERALL: Duration = Duration::from_secs(120);
/// 一个方向最多取多少个 chunk，避免测试自身陷入无限读取。
const MAX_CHUNKS: usize = 32;
/// echo 单行载荷上限，超出即判定测试跑偏。
const ECHO_LIMIT: usize = 1 << 20;
/// SOCKS5 回程响应（VER+REP+RSV+ATYP 4 字节 + 最长 IPv6 地址 + 端口）的最大长度。
const SOCKS5_RESPONSE_MAX: usize = 4 + 16 + 2;

fn methods() -> [&'static str; 4] {
    [
        "aes-128-gcm",
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305",
    ]
}

fn suite_of(name: &str) -> CipherSuite {
    CipherSuite::from_name(name).expect("测试套件名应可解析")
}

/// 字节规格：1、512、单 chunk 上限、超上限（必须分块）。
fn sizes() -> [usize; 4] {
    [1, 512, MAX_SEGMENT_PAYLOAD, MAX_SEGMENT_PAYLOAD + 4096]
}

/// 生成一段以 `\n` 结尾的可打印载荷，长度恰为 `size`。
///
/// 换行让测试侧可以用“一行请求”这个应用语义判断请求结束，不需要依赖 EOF
/// 时序（`size >= 1` 保证末位覆盖不会改写中间内容）。
fn line(size: usize) -> Vec<u8> {
    assert!(size >= 1, "载荷至少要放得下换行符");
    let mut payload = vec![0u8; size];
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = b'!' + (index % 90) as u8;
    }
    payload[size - 1] = b'\n';
    payload
}

/// 本测试只用 IPv4 目标，其余地址族一律拒绝而不是悄悄连错地方。
fn socket_addr(target: &TargetAddr) -> SocketAddr {
    match target {
        TargetAddr::V4(ip, port) => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), *port)
        }
        other => panic!("测试目标只支持 IPv4 回环，实际 {other:?}"),
    }
}

/// echo 服务：每条连接读满一行后原样回写，再关写半让参考实现看到干净 EOF。
async fn serve_echo(listener: TcpListener, connections: usize) {
    for _ in 0..connections {
        let (mut conn, _peer) = timeout(WAIT, listener.accept())
            .await
            .expect("echo 服务接受连接超时")
            .expect("echo 服务应可接受连接");
        let mut request: Vec<u8> = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            let got = timeout(WAIT, conn.read(&mut buffer))
                .await
                .expect("echo 读超时")
                .expect("echo 读失败");
            assert!(got > 0, "echo 目标在读满一行前就看到 EOF");
            request.extend_from_slice(&buffer[..got]);
            assert!(request.len() <= ECHO_LIMIT, "echo 载荷超出测试上限");
            if request.last() == Some(&b'\n') {
                break;
            }
        }
        timeout(WAIT, conn.write_all(&request))
            .await
            .expect("echo 回写超时")
            .expect("echo 回写失败");
        timeout(WAIT, conn.shutdown())
            .await
            .expect("echo 关闭超时")
            .expect("echo 关闭失败");
    }
}

// 取回一个方向的全部 chunk：`Ok(None)`（干净 EOF 或终止帧）时结束。
async fn drain_direction<R>(mut reader: TcpReader<R>) -> (Vec<u8>, Vec<usize>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut bytes: Vec<u8> = Vec::new();
    let mut chunk_lens: Vec<usize> = Vec::new();
    for _ in 0..MAX_CHUNKS {
        let chunk = timeout(WAIT, reader.recv())
            .await
            .expect("读取 chunk 超时")
            .expect("读取 chunk 失败");
        let Some(chunk) = chunk else {
            return (bytes, chunk_lens);
        };
        chunk_lens.push(chunk.len());
        bytes.extend_from_slice(&chunk);
    }
    panic!("一个方向的 chunk 数量超过测试上限 {MAX_CHUNKS}");
}

/// 方向一：本端写请求方向（salt + 地址 + 载荷）后关写半，再读回 Xray 的回程方向。
async fn rust_client_roundtrip(
    stream: TcpStream,
    suite: CipherSuite,
    target: &TargetAddr,
    payload: &[u8],
) -> (Vec<u8>, Vec<usize>) {
    let (mut read_half, mut write_half) = stream.into_split();
    let mut request: Vec<u8> = Vec::new();
    target
        .encode_checked(&mut request)
        .expect("IPv4 回环目标可编码");
    request.extend_from_slice(payload);

    let mut writer =
        TcpWriter::new(&mut write_half, suite, PASSWORD.as_bytes(), WAIT).expect("应可构造写端");
    timeout(WAIT, writer.send(&request))
        .await
        .expect("send 未被外层超时")
        .expect("请求方向应可写出");
    // 读到回程 EOF 之前必须先关写半：Xray 要看到请求方向结束才会收尾回程。
    timeout(WAIT, writer.shutdown())
        .await
        .expect("shutdown 未被外层超时")
        .expect("请求方向应可半关闭");

    let reader =
        TcpReader::new(&mut read_half, suite, PASSWORD.as_bytes(), WAIT).expect("应可构造读端");
    drain_direction(reader).await
}

/// 服务端视角解出请求方向的一个 chunk 序列：地址 + 以 `\n` 结尾的一行请求。
struct Served {
    target: TargetAddr,
    request: Vec<u8>,
    chunk_lens: Vec<usize>,
}

/// 方向二的服务端一半：解请求方向、中继到 echo 目标、写回程方向。
async fn serve_rust_side(stream: TcpStream, suite: CipherSuite) -> Served {
    let (mut read_half, mut write_half) = stream.into_split();
    let mut reader =
        TcpReader::new(&mut read_half, suite, PASSWORD.as_bytes(), WAIT).expect("应可构造读端");
    let mut pending: Vec<u8> = Vec::new();
    let mut chunk_lens: Vec<usize> = Vec::new();
    let mut target: Option<TargetAddr> = None;
    for _ in 0..MAX_CHUNKS {
        let chunk = timeout(WAIT, reader.recv())
            .await
            .expect("读请求超时")
            .expect("读请求失败");
        // 请求方向的一行请求不该靠 EOF 结束：EOF 说明对端提前收尾。
        let Some(chunk) = chunk else {
            panic!("请求方向在收满一行前就看到 EOF");
        };
        assert!(
            chunk.len() <= MAX_SEGMENT_PAYLOAD,
            "参考实现写出的 chunk 超过单块上限 {MAX_SEGMENT_PAYLOAD}：{}",
            chunk.len()
        );
        chunk_lens.push(chunk.len());
        pending.extend_from_slice(&chunk);
        // 地址字节可能跨 chunk：解不出来就继续取下一个 chunk。
        if target.is_none() {
            if let Ok((addr, used)) = TargetAddr::decode(&pending) {
                pending = pending[used..].to_vec();
                target = Some(addr);
            }
        }
        if target.is_some() && pending.last() == Some(&b'\n') {
            break;
        }
    }
    let target = target.expect("应能解出目标地址");
    assert!(
        pending.last() == Some(&b'\n'),
        "请求方向未在 chunk 上限内收满一行"
    );

    // 中继到本仓 spawn 的 echo 目标，取回同一行后写回程方向。
    let address = socket_addr(&target);
    let mut upstream = timeout(WAIT, TcpStream::connect(address))
        .await
        .expect("连接 echo 目标超时")
        .expect("应可连接 echo 目标");
    timeout(WAIT, upstream.write_all(&pending))
        .await
        .expect("写 echo 目标超时")
        .expect("写 echo 目标失败");
    let mut reply: Vec<u8> = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let got = timeout(WAIT, upstream.read(&mut buffer))
            .await
            .expect("读 echo 目标超时")
            .expect("读 echo 目标失败");
        assert!(got > 0, "echo 目标在回写完整行前就关闭");
        reply.extend_from_slice(&buffer[..got]);
        assert!(reply.len() <= ECHO_LIMIT, "echo 回包超出测试上限");
        if reply.last() == Some(&b'\n') {
            break;
        }
    }
    assert_eq!(reply, pending, "echo 目标应原样回写同一行");

    let mut writer = TcpWriter::new(&mut write_half, suite, PASSWORD.as_bytes(), WAIT)
        .expect("应可构造回程写端");
    timeout(WAIT, writer.send(&reply))
        .await
        .expect("回程 send 未被外层超时")
        .expect("回程应可写出");
    timeout(WAIT, writer.shutdown())
        .await
        .expect("回程 shutdown 未被外层超时")
        .expect("回程应可半关闭");
    drop(upstream);
    Served {
        target,
        request: pending,
        chunk_lens,
    }
}

async fn rust_server(listener: TcpListener, suite: CipherSuite, connections: usize) -> Vec<Served> {
    let mut served: Vec<Served> = Vec::new();
    for _ in 0..connections {
        let (stream, _peer) = timeout(WAIT, listener.accept())
            .await
            .expect("本端监听器接受超时")
            .expect("本端监听器应可接受连接");
        served.push(serve_rust_side(stream, suite).await);
    }
    served
}

/// 最小 SOCKS5 客户端（no-auth）：拨参考入站、握手、发出 CONNECT 目标请求。
async fn socks5_connect(proxy_port: u16, target: &TargetAddr) -> TcpStream {
    let mut stream = timeout(WAIT, TcpStream::connect((Ipv4Addr::LOCALHOST, proxy_port)))
        .await
        .expect("连接 SOCKS 入站超时")
        .expect("应可连接 SOCKS 入站");
    // greeting：VER=5、NMETHODS=1、METHOD=0x00（无需认证）。
    timeout(WAIT, stream.write_all(&[0x05, 0x01, 0x00]))
        .await
        .expect("SOCKS greeting 超时")
        .expect("SOCKS greeting 失败");
    let mut choice = [0u8; 2];
    timeout(WAIT, stream.read_exact(&mut choice))
        .await
        .expect("SOCKS 认证选择超时")
        .expect("SOCKS 认证选择失败");
    assert_eq!(choice, [0x05, 0x00], "参考实现应选中 no-auth");

    // request：VER=5、CMD=CONNECT、RSV=0 + ATYP/ADDR/PORT。
    let mut message: Vec<u8> = vec![0x05, 0x01, 0x00];
    target
        .encode_checked(&mut message)
        .expect("IPv4 回环目标可编码");
    timeout(WAIT, stream.write_all(&message))
        .await
        .expect("SOCKS 请求超时")
        .expect("SOCKS 请求失败");
    // 响应长度由 ATYP 决定：先读固定 4 字节头，再按地址族补齐 BND.ADDR/PORT。
    let mut head = [0u8; 4];
    timeout(WAIT, stream.read_exact(&mut head))
        .await
        .expect("SOCKS 响应头超时")
        .expect("SOCKS 响应头失败");
    assert_eq!(
        &head[..2],
        &[0x05, 0x00],
        "SOCKS CONNECT 应被接受：{head:?}"
    );
    let trailing = match head[3] {
        0x01 => 4 + 2,
        0x03 => 1 + head[..1][0] as usize + 2,
        0x04 => 16 + 2,
        other => panic!("SOCKS 响应未知 ATYP：{other:#04x}"),
    };
    assert!(
        trailing <= SOCKS5_RESPONSE_MAX,
        "SOCKS 响应长度越界：{trailing}"
    );
    let mut bound = vec![0u8; trailing];
    timeout(WAIT, stream.read_exact(&mut bound))
        .await
        .expect("SOCKS 响应地址超时")
        .expect("SOCKS 响应地址失败");
    stream
}

#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn rust_client_to_xray_server_tcp() {
    timeout(OVERALL, async {
        for name in methods() {
            let suite = suite_of(name);
            let echo = TcpListener::bind(BIND).await.expect("echo 应可监听");
            let echo_port = echo.local_addr().expect("echo 应有地址").port();
            let specs = sizes();
            let echo_task = tokio::spawn(serve_echo(echo, specs.len()));
            let port = free_port();
            let reference = launch(
                json!({
                    "log": {"loglevel": "warning"},
                    "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "shadowsocks",
                        "settings": {"method": name, "password": PASSWORD, "network": "tcp"}}],
                    "outbounds": [{"protocol": "freedom"}]
                }),
                port,
            )
            .await;
            let target = TargetAddr::V4(LOOPBACK, echo_port);
            for size in specs {
                let payload = line(size);
                let stream = timeout(WAIT, TcpStream::connect((Ipv4Addr::LOCALHOST, port)))
                    .await
                    .expect("连接参考服务超时")
                    .expect("应可连接参考服务");
                let (reply, chunk_lens) = timeout(
                    WAIT,
                    rust_client_roundtrip(stream, suite, &target, &payload),
                )
                .await
                .expect("请求与回程往返超时");
                assert_eq!(reply.len(), size, "{name} / {size} 字节回程长度不符");
                assert_eq!(
                    reply, payload,
                    "{name} / {size} 字节回程内容不等于 echo 内容"
                );
                assert!(
                    chunk_lens
                        .iter()
                        .all(|&len| len > 0 && len <= MAX_SEGMENT_PAYLOAD),
                    "{name} / {size} 回程 chunk 规格不符：{chunk_lens:?}"
                );
                if size > MAX_SEGMENT_PAYLOAD {
                    assert!(
                        chunk_lens.len() >= 2,
                        "{name} / {size} 超上限载荷应由参考实现分块，实际 {chunk_lens:?}"
                    );
                }
            }
            drop(reference);
            echo_task.await.expect("echo 服务任务");
        }
    })
    .await
    .expect("Rust 客户端 → Xray 服务端 TCP 互通超时")
}

#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn xray_client_to_rust_server_tcp() {
    timeout(OVERALL, async {
        for name in methods() {
            let suite = suite_of(name);
            let server = TcpListener::bind(BIND).await.expect("本端应可监听");
            let rust_port = server.local_addr().expect("本端应有地址").port();
            let echo = TcpListener::bind(BIND).await.expect("echo 应可监听");
            let echo_port = echo.local_addr().expect("echo 应有地址").port();
            let specs = sizes();
            let echo_task = tokio::spawn(serve_echo(echo, specs.len()));
            let served_task = tokio::spawn(rust_server(server, suite, specs.len()));
            let port = free_port();
            let reference = launch(
                json!({
                    "log": {"loglevel": "warning"},
                    "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                        "settings": {"auth": "noauth", "udp": false}}],
                    "outbounds": [{"protocol": "shadowsocks", "settings": {"servers": [{
                        "address": "127.0.0.1", "port": rust_port, "method": name, "password": PASSWORD}]}}]
                }),
                port,
            )
            .await;
            let target = TargetAddr::V4(LOOPBACK, echo_port);
            for size in specs {
                let payload = line(size);
                let mut stream = socks5_connect(port, &target).await;
                timeout(WAIT, stream.write_all(&payload))
                    .await
                    .expect("SOCKS 写载荷超时")
                    .expect("SOCKS 写载荷失败");
                let mut reply = vec![0u8; size];
                timeout(WAIT, stream.read_exact(&mut reply))
                    .await
                    .expect("SOCKS 读回包超时")
                    .expect("SOCKS 读回包失败");
                assert_eq!(reply, payload, "{name} / {size} 字节端到端载荷不符");
                drop(stream);
            }
            let served = served_task.await.expect("本端服务任务");
            assert_eq!(served.len(), specs.len(), "本端应处理每条互通连接");
            for (index, one) in served.iter().enumerate() {
                let size = specs[index];
                assert_eq!(one.target, target, "{name} / {size} 解出的目标地址不符");
                assert_eq!(one.request, line(size), "{name} / {size} 请求方向载荷不符");
                if size > MAX_SEGMENT_PAYLOAD {
                    assert!(
                        one.chunk_lens.len() >= 2,
                        "{name} / {size} 超上限载荷应由参考实现分块，实际 {:?}",
                        one.chunk_lens
                    );
                }
            }
            drop(reference);
            echo_task.await.expect("echo 服务任务");
        }
    })
    .await
    .expect("Xray 客户端 → Rust 服务端 TCP 互通超时")
}
