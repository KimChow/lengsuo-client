//! wireguard-go 参考适配器的测试专用脚手架：固定假凭据、回环 socket、子进程
//! 回收与一次成功握手的会话材料。**只服务于参考验收测试**，不是生产解析器，
//! 也不充当互通 fixture。
//!
//! 超时链条全部有限：Rust socket 6s 读写超时；Go 侧 socket 8s deadline、
//! `-test.timeout 12s`；子进程由 [`Reference::drop`] 回收。
#![allow(dead_code)]

use lengsuo_wireguard::handshake::{Handshake, PSK_LEN};
use lengsuo_wireguard::transport::TransportKey;
use std::process::{Child, Command, Output, Stdio};
use std::{
    net::UdpSocket,
    time::{Duration, Instant},
};
use x25519_dalek::{PublicKey, StaticSecret};

/// 固定假静态私钥：仅测试用，非任何真实凭据。
pub const CLIENT_STATIC: [u8; 32] = [0x11; 32];
pub const SERVER_STATIC: [u8; 32] = [0x22; 32];
/// 与参考适配器一致的 PSK。
pub const PSK_ON: [u8; PSK_LEN] = [0x33; PSK_LEN];
/// 与参考端不同的 PSK。
pub const PSK_WRONG: [u8; PSK_LEN] = [0x44; PSK_LEN];
pub const LOCAL_INDEX: u32 = 0x1234_5678;
pub const EPHEMERAL_SEED: [u8; 32] = [0xaa; 32];
/// 与参考适配器期望一致的合法载荷。
pub const RUST_PAYLOAD: &[u8] = b"rust-go-payload!";

/// 已启动的参考适配器子进程。
pub struct Reference(Option<Child>);

impl Reference {
    /// 启动固定二进制内的官方核心适配器；`psk` 决定是否注入参考端 PSK。
    pub fn spawn(psk: Option<&[u8; PSK_LEN]>, client: &str) -> Self {
        let binary = std::env::var_os("LENGSUO_WG_REFERENCE_BIN")
            .expect("需要固定 wireguard-go 参考二进制 LENGSUO_WG_REFERENCE_BIN");
        let child = Command::new(binary)
            .args([
                "-test.run",
                "^TestLengsuoUDPReference$",
                "-test.timeout",
                "12s",
                "-test.v",
            ])
            .env("LENGSUO_WG_CLIENT", client)
            .env("LENGSUO_WG_PSK", if psk.is_some() { "1" } else { "0" })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("参考适配器可启动");
        Reference(Some(child))
    }

    /// 等待适配器退出：受 Go 侧 8s socket deadline 与 12s test.timeout 约束。
    pub fn finish(mut self) -> Output {
        let child = self.0.take().expect("子进程句柄存在");
        let started = Instant::now();
        let output = child
            .wait_with_output()
            .expect("参考适配器应在有限超时内退出");
        assert!(
            started.elapsed() < Duration::from_secs(25),
            "参考适配器退出耗时异常：{:?}",
            started.elapsed()
        );
        output
    }
}

impl Drop for Reference {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub fn server_public() -> [u8; 32] {
    *PublicKey::from(&StaticSecret::from(SERVER_STATIC)).as_bytes()
}

/// 回环 socket + 有限读写超时。
pub fn loopback_socket() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("回环 UDP 可绑定");
    socket
        .set_read_timeout(Some(Duration::from_secs(6)))
        .expect("读超时可设置");
    socket
        .set_write_timeout(Some(Duration::from_secs(6)))
        .expect("写超时可设置");
    socket
}

/// 适配器输出文本：只含 Go 测试自身日志，不含密钥或载荷字节。
pub fn output_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// 一次成功握手后的会话材料。
pub struct Session {
    pub socket: UdpSocket,
    pub reference: Reference,
    pub send: TransportKey,
    pub remote_index: u32,
    pub receive: TransportKey,
    pub local_index: u32,
}

/// 与真实 Go 核心握手到 transport key 就绪；`psk` 同时注入两侧。
pub fn establish(psk: Option<[u8; PSK_LEN]>) -> Session {
    let socket = loopback_socket();
    let addr = socket.local_addr().unwrap().to_string();
    let reference = Reference::spawn(psk.as_ref(), &addr);
    let mut buffer = [0u8; 2048];
    let (n, peer) = socket.recv_from(&mut buffer).expect("ready 报文");
    assert!(peer.ip().is_loopback(), "参考端必须是回环地址");
    assert_eq!(&buffer[..n], b"wireguard-reference-ready");
    socket.connect(peer).expect("回环 connect");
    let mut handshake = Handshake::new(&CLIENT_STATIC, &server_public(), psk, LOCAL_INDEX)
        .expect("假密钥可构造发起方");
    socket
        .send(
            &handshake
                .create_initiation(EPHEMERAL_SEED)
                .expect("initiation"),
        )
        .expect("发 initiation");
    let n = socket.recv(&mut buffer).expect("response 报文");
    let keys = handshake
        .consume_response(&buffer[..n])
        .expect("参考端 response 必须可消费");
    Session {
        socket,
        reference,
        send: TransportKey::new(&keys.send).expect("send 密钥长度"),
        remote_index: keys.remote_index,
        receive: TransportKey::new(&keys.receive).expect("receive 密钥长度"),
        local_index: keys.local_index,
    }
}

/// 收到参考端 reply，或在有限超时内明确失败。
pub fn recv_reply(socket: &UdpSocket, buffer: &mut [u8; 2048]) -> usize {
    match socket.recv(buffer) {
        Ok(n) => n,
        Err(error) => panic!("未在有限超时内收到参考端 reply：{error}"),
    }
}

/// 「没有 response」的合法表现：有限超时内无数据，或参考端已退出导致端口不可达。
pub fn no_response(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionRefused
    )
}

/// 错误读数：只用于断言文本，不含密钥或载荷字节。
pub fn name_of(error: Option<&lengsuo_wireguard::transport::Error>) -> String {
    match error {
        Some(error) => format!("{error:?}"),
        None => "未返回错误".to_string(),
    }
}
