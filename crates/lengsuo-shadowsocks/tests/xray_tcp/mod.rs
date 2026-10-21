//! 传统 Shadowsocks AEAD 的 TCP 双向 Xray 真实互通测试的**共享辅助**。
//!
//! 被 `tests/xray_tcp.rs` 以 `#[path]` 引入；两个方向的互通用例分别在
//! [`rust_to_xray`] / [`xray_to_rust`] 子模块里（见 `tests/xray_tcp.rs` 的模块文档）。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::support::WAIT;
use lengsuo_shadowsocks::{CipherSuite, TargetAddr, TcpReader, TcpWriter, MAX_SEGMENT_PAYLOAD};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// 测试假口令，与任何生产凭据无关。
pub const PASSWORD: &str = "ss-tcp-reference-test-password";
/// 只绑回环，不接受任何外部地址。
pub const LOOPBACK: [u8; 4] = [127, 0, 0, 1];
pub const BIND: &str = "127.0.0.1:0";

/// 单个测试（含多次 spawn Xray 与全部套件）的总超时。
pub const OVERALL: Duration = Duration::from_secs(120);
/// 一个方向最多取多少个 chunk，避免测试自身陷入无限读取。
const MAX_CHUNKS: usize = 32;
/// echo 单行载荷上限，超出即判定测试跑偏。
const ECHO_LIMIT: usize = 1 << 20;
/// SOCKS5 回程响应（VER+REP+RSV+ATYP 4 字节 + 最长 IPv6 地址 + 端口）的最大长度。
const SOCKS5_RESPONSE_MAX: usize = 4 + 16 + 2;

pub fn methods() -> [&'static str; 4] {
    [
        "aes-128-gcm",
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305",
    ]
}

pub fn suite_of(name: &str) -> CipherSuite {
    CipherSuite::from_name(name).expect("测试套件名应可解析")
}

/// 字节规格：1、512、单 chunk 上限、超上限（必须分块）。
pub fn sizes() -> [usize; 4] {
    [1, 512, MAX_SEGMENT_PAYLOAD, MAX_SEGMENT_PAYLOAD + 4096]
}

/// 生成一段以 `\n` 结尾的可打印载荷，长度恰为 `size`。
///
/// 换行让测试侧可以用“一行请求”这个应用语义判断请求结束，不需要依赖 EOF
/// 时序（`size >= 1` 保证末位覆盖不会改写中间内容）。
pub fn line(size: usize) -> Vec<u8> {
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
pub async fn serve_echo(listener: TcpListener, connections: usize) {
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
pub async fn rust_client_roundtrip(
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
pub struct Served {
    pub target: TargetAddr,
    pub request: Vec<u8>,
    pub chunk_lens: Vec<usize>,
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

pub async fn rust_server(
    listener: TcpListener,
    suite: CipherSuite,
    connections: usize,
) -> Vec<Served> {
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
pub async fn socks5_connect(proxy_port: u16, target: &TargetAddr) -> TcpStream {
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
pub mod rust_to_xray;
pub mod xray_to_rust;
