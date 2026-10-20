//! **多安全档**反向互通：Xray 客户端 → 本仓 VMess 入站（`#[ignore]`，需 `LENGSUO_XRAY`）。
//!
//! 运行方式：
//! ```text
//! LENGSUO_XRAY=~/ref/bin/xray cargo test -p lengsuo-vmess --test xray_multitier_server --locked -- --ignored --nocapture
//! ```
//!
//! 拓扑：
//! ```text
//! 测试进程 --SOCKS5--> Xray（SOCKS 入站 + VMess 出站，security=<档位>）
//!                --VMess--> 本仓入站夹具 --TCP--> 本地回显后端
//! ```
//!
//! 判据：回程与发送载荷**逐字节一致**（1B / 4KiB / 256KiB 三段，跨越参考
//! 8192 字节单帧边界）；入站处理线程不得 panic；全程有超时上限。
//!
//! 参考事实（固定 commit `d2758a02`）：
//! - 参考**出口**按账号安全档分派数据段：`proxy/vmess/outbound/outbound.go`
//!   的 `request.Security = account.Security`，再由
//!   `proxy/vmess/encoding/client.go` 的 `EncodeRequestBody` 落成具体套件。
//! - 参考出口的默认 option 是 `ChunkStream | ChunkMasking | GlobalPadding`
//!   （`outbound.go`：`shouldEnablePadding` 对 AES/ChaCha/AUTO 为真）；
//!   `none` 档则**不带** `GlobalPadding`（`shouldEnablePadding` 对 NONE 为假），
//!   但**带** `ChunkStream`（参考 NONE 分支需要它）。
//! - 请求头 / 响应头两段 AEAD **恒为 AES-128-GCM**，与档位无关。
//!
//! 本仓入站侧的档位处理（对齐参考 `proxy/vmess/encoding/server.go`）：
//! - 头里的 security 低 4 位决定数据段套件（`parseSecurityType`）；
//! - `none` 档 + `ChunkStream` + TCP ⇒ `ChunkStreamReader`（明文载荷、无 padding）；
//! - 其余档位 ⇒ `AuthenticationReader`（AEAD 载荷 + 三种长度段形态）。

#[path = "support/mod.rs"]
mod support;

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lengsuo_vmess::bodyframe::{BodyFrame, BodySuite, ChunkStreamFrame};
use lengsuo_vmess::server::{
    decode_request_header, encode_response_header, response_key_iv, HeaderSecurity, ResponseHeader,
};
use ss_core::target::TargetAddr;
use support::codec::{cmd_key_from_uuid, generate_uuid_bytes, uuid_string};
use support::tiercodec::Tier;

/// 单次读写的超时上限（避免挂死）。
const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// 入站监听端口就绪的等待上限。
const START_TIMEOUT: Duration = Duration::from_secs(15);

/// 惰性获取参考二进制；未设置时打印原因并返回 `None`（调用方 `return` 跳过）。
fn xray_bin() -> Option<PathBuf> {
    match std::env::var_os("LENGSUO_XRAY") {
        Some(path) => Some(PathBuf::from(path)),
        None => {
            eprintln!(
                "SKIP: 环境变量 LENGSUO_XRAY 未设置，跳过多安全档反向互通用例。\
                 原因：没有参考二进制可拉起，无法证明 Xray→Rust 的档位互通。"
            );
            None
        }
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时钟在 UNIX 纪元之后")
        .as_secs() as i64
}

/// 本地 raw TCP 回显后端（读到关闭即关闭）。
fn spawn_echo_backend() -> (SocketAddr, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("回显后端绑定");
    let addr = listener.local_addr().expect("回显后端地址");
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                let mut buffer = [0u8; 16384];
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buffer[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = stream.shutdown(Shutdown::Both);
            });
        }
    });
    (addr, handle)
}

/// Xray 客户端进程：SOCKS 入站 → VMess 出站（指定安全档）指向本仓入站。
struct XrayClient {
    child: Child,
    socks_port: u16,
    dir: PathBuf,
}

impl XrayClient {
    /// 拉起 Xray 客户端；`security` 是参考的账号安全档字符串。
    fn start(bin: &Path, uuid: &str, vmess_port: u16, security: &str) -> Result<Self, String> {
        Self::start_with_experiments(bin, uuid, vmess_port, security, false)
    }

    /// 同 [`Self::start`]，并可选打开参考的 `AuthenticatedLength` 实验开关
    /// （参考 `proxy/vmess/account.go` 的 `AuthenticatedLengthExperiment` →
    /// 出口置上 `RequestOptionAuthenticatedLength`）。
    fn start_with_experiments(
        bin: &Path,
        uuid: &str,
        vmess_port: u16,
        security: &str,
        auth_len: bool,
    ) -> Result<Self, String> {
        let probe = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
        let socks_port = probe.local_addr().map_err(|e| e.to_string())?.port();
        drop(probe);

        let dir = std::env::temp_dir().join(format!(
            "lengsuo-vmess-xcli-{}-{socks_port}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let experiments = if auth_len {
            ",\"experiments\":\"AuthenticatedLength\""
        } else {
            ""
        };
        let config = format!(
            "{{\"log\":{{\"loglevel\":\"warning\"}},\
             \"inbounds\":[{{\"listen\":\"127.0.0.1\",\"port\":{socks_port},\
             \"protocol\":\"socks\",\"settings\":{{\"udp\":false,\"auth\":\"noauth\"}}}}],\
             \"outbounds\":[{{\"protocol\":\"vmess\",\"settings\":{{\"vnext\":[{{\
             \"address\":\"127.0.0.1\",\"port\":{vmess_port},\
             \"users\":[{{\"id\":\"{uuid}\",\"alterId\":0,\"security\":\"{security}\"{experiments}}}]\
             }}]}}}}]}}"
        );
        std::fs::write(dir.join("config.json"), &config).map_err(|e| e.to_string())?;
        let child = std::process::Command::new(bin)
            .arg("run")
            .arg("-c")
            .arg(dir.join("config.json"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;

        let client = XrayClient {
            child,
            socks_port,
            dir,
        };
        let deadline = Instant::now() + START_TIMEOUT;
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", client.socks_port)).is_ok() {
                return Ok(client);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(format!(
            "xray 客户端 {:?} 内未在 127.0.0.1:{socks_port} 就绪",
            START_TIMEOUT
        ))
    }
}

impl Drop for XrayClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// 本仓 VMess 入站夹具：每连接一个线程；解码失败即 drop（关闭）连接，
/// 处理体包在 catch_unwind 里，panic 记入标志。
struct VmessInbound {
    addr: SocketAddr,
    panicked: Arc<AtomicBool>,
}

/// 启动入站；`suite_override` 为 `Some` 时**强制**用该套件（忽略请求头里的
/// 档位），用于「档位错配必须失败」的负例。
fn start_vmess_inbound(
    users: Vec<[u8; 16]>,
    echo: Option<SocketAddr>,
    suite_override: Option<BodySuite>,
) -> VmessInbound {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("入站绑定 127.0.0.1:0");
    let addr = listener.local_addr().expect("入站地址");
    let sessions: Arc<Mutex<Vec<[u8; 48]>>> = Arc::new(Mutex::new(Vec::new()));
    let panicked = Arc::new(AtomicBool::new(false));
    let panic_flag = panicked.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let users = users.clone();
            let sessions = sessions.clone();
            let panic_flag = panic_flag.clone();
            let echo = echo;
            std::thread::spawn(move || {
                if std::panic::catch_unwind(move || {
                    handle_connection(stream, &users, &sessions, echo, suite_override)
                })
                .is_err()
                {
                    panic_flag.store(true, Ordering::SeqCst);
                }
            });
        }
    });
    VmessInbound { addr, panicked }
}

/// 本仓入站的单连接处理。
fn handle_connection(
    mut stream: TcpStream,
    users: &[[u8; 16]],
    sessions: &Mutex<Vec<[u8; 48]>>,
    echo: Option<SocketAddr>,
    suite_override: Option<BodySuite>,
) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));

    let decoded = {
        let mut seen = sessions.lock().expect("会话表锁");
        let mut take = |user: &[u8; 16], key: &[u8; 16], iv: &[u8; 16]| {
            let mut entry = [0u8; 48];
            entry[..16].copy_from_slice(user);
            entry[16..32].copy_from_slice(key);
            entry[32..].copy_from_slice(iv);
            if seen.contains(&entry) {
                false
            } else {
                seen.push(entry);
                true
            }
        };
        decode_request_header(users, &mut stream, now_unix(), &mut take)
    };
    let decoded = match decoded {
        Ok(decoded) => decoded,
        Err(error) => {
            eprintln!("[vmess-in] 拒绝：{error}");
            return; // drop 即关闭：认证失败不回任何字节
        }
    };

    if echo.is_none() {
        eprintln!("[vmess-in] 未配置后端，关闭");
        return;
    }
    // 档位：请求头里的 security 低 4 位（参考 `parseSecurityType`）。
    let suite = match suite_override {
        Some(forced) => forced,
        None => match decoded.security {
            HeaderSecurity::None => BodySuite::None,
            HeaderSecurity::Aes128Gcm => BodySuite::Aes128Gcm,
            HeaderSecurity::ChaCha20Poly1305 => BodySuite::ChaCha20Poly1305,
            HeaderSecurity::Zero => {
                eprintln!("[vmess-in] ZERO 档在体阶段拒绝");
                return;
            }
        },
    };
    let Some(TargetAddr::V4(ip, port)) = decoded.target.clone() else {
        eprintln!("[vmess-in] 夹具只接受 IPv4 目标");
        return;
    };
    let mut echo_sock = match TcpStream::connect(SocketAddrV4::new(ip.into(), port)) {
        Ok(sock) => sock,
        Err(error) => {
            eprintln!("[vmess-in] 连接后端失败：{error}");
            return;
        }
    };

    // 响应头先于任何体数据（对齐参考 `transferResponse` 顺序）。
    let mut header_wire = Vec::new();
    encode_response_header(
        decoded.response_header,
        &decoded.request_body_key,
        &decoded.request_body_iv,
        &ResponseHeader::new(),
        &mut header_wire,
    )
    .expect("响应头封装");
    if stream.write_all(&header_wire).is_err() {
        return;
    }

    let req_key = decoded.request_body_key;
    let req_iv = decoded.request_body_iv;
    let (resp_key, resp_iv) = response_key_iv(&req_key, &req_iv);
    let option = decoded.option;

    // 上行：客户端分帧 → 明文 → 后端。
    let mut up_reader = match stream.try_clone() {
        Ok(sock) => sock,
        Err(_) => return,
    };
    let mut echo_writer = match echo_sock.try_clone() {
        Ok(sock) => sock,
        Err(_) => return,
    };
    let up = std::thread::spawn(move || {
        if suite == BodySuite::None {
            // 参考的 NONE 分支：chunk-stream（明文载荷、无 padding）。
            let mut frame = ChunkStreamFrame::with_iv(option, &req_iv);
            loop {
                match frame.read_sync(&mut up_reader) {
                    Ok(Some(plain)) => {
                        if echo_writer.write_all(&plain).is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        let _ = echo_writer.shutdown(Shutdown::Write);
                        break;
                    }
                    Err(error) => {
                        eprintln!("[vmess-in] 上行解帧失败：{error}");
                        break;
                    }
                }
            }
        } else {
            let mut frame =
                match BodyFrame::for_request(suite, &req_key, &req_iv, &req_key, &req_iv, option) {
                    Ok(frame) => frame,
                    Err(error) => {
                        eprintln!("[vmess-in] 构造数据段帧失败：{error}");
                        return;
                    }
                };
            loop {
                match frame.read_sync(&mut up_reader) {
                    Ok(Some(plain)) => {
                        if echo_writer.write_all(&plain).is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        let _ = echo_writer.shutdown(Shutdown::Write);
                        break;
                    }
                    Err(error) => {
                        eprintln!("[vmess-in] 上行解帧失败：{error}");
                        break;
                    }
                }
            }
        }
    });

    // 下行：后端明文 → 分帧 → 客户端。
    if suite == BodySuite::None {
        let mut resp_frame = ChunkStreamFrame::with_iv(option, &resp_iv);
        let mut buffer = vec![0u8; 8192];
        loop {
            match echo_sock.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let mut frame = Vec::with_capacity(n + 2);
                    if resp_frame.seal(&mut frame, &buffer[..n]).is_err() {
                        return;
                    }
                    if stream.write_all(&frame).is_err() {
                        return;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = up.join();
        let mut eof_frame = Vec::new();
        if resp_frame.seal_eof(&mut eof_frame).is_ok() {
            let _ = stream.write_all(&eof_frame);
        }
        return;
    }

    let mut resp_frame =
        match BodyFrame::for_request(suite, &resp_key, &resp_iv, &req_key, &req_iv, option) {
            Ok(frame) => frame,
            Err(error) => {
                eprintln!("[vmess-in] 构造响应帧失败：{error}");
                return;
            }
        };
    let mut buffer = vec![0u8; 8192];
    loop {
        match echo_sock.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                let mut frame = Vec::with_capacity(n + 80);
                if resp_frame.seal(&mut frame, &buffer[..n]).is_err() {
                    return;
                }
                if stream.write_all(&frame).is_err() {
                    return;
                }
            }
            Err(_) => break,
        }
    }
    let _ = up.join();
    let mut eof_frame = Vec::new();
    if resp_frame.seal(&mut eof_frame, b"").is_ok() {
        let _ = stream.write_all(&eof_frame);
    }
}

/// 最小 socks5 CONNECT（无认证）。
fn socks5_connect(socks_port: u16, target: SocketAddrV4) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", socks_port))?;
    let _ = stream.set_nodelay(true);
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method)?;
    if method != [0x05, 0x00] {
        return Err(std::io::Error::other("socks 握手被拒"));
    }
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request)?;
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply)?;
    if reply[1] != 0x00 {
        return Err(std::io::Error::other(format!(
            "socks CONNECT 失败：{}",
            reply[1]
        )));
    }
    Ok(stream)
}

/// 三段载荷：1B / 4KiB / 256KiB。
fn payloads() -> Vec<u8> {
    let total = 1 + 4 * 1024 + 256 * 1024;
    (0..total).map(|i| (i % 251) as u8).collect()
}

/// 方向 B：**Xray 客户端 → 本仓入站**，逐档位跑一遍完整回显。
#[test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
fn xray_client_to_rust_server_every_tier() {
    let Some(bin) = xray_bin() else { return };
    run_reverse_every_tier(&bin, false);
}

/// 方向 B'：**认证长度段**（`RequestOptionAuthenticatedLength`）下的逐档位互通。
///
/// 参考出口在账号开 `experiments: "AuthenticatedLength"` 时置上该选项
/// （`proxy/vmess/outbound/outbound.go`），此时长度段走 AEAD 认证
/// （`proxy/vmess/encoding/client.go` 的 `EncodeRequestBody`）。
#[test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
fn xray_client_to_rust_server_authenticated_length_every_tier() {
    let Some(bin) = xray_bin() else { return };
    run_reverse_every_tier(&bin, true);
}

/// 逐档位跑一遍「Xray 客户端 → 本仓入站 → 回显后端」的全链路。
fn run_reverse_every_tier(bin: &Path, auth_len: bool) {
    for tier in Tier::ALL {
        let uuid = generate_uuid_bytes();
        let (echo_addr, _echo) = spawn_echo_backend();
        let echo_v4 = match echo_addr {
            SocketAddr::V4(addr) => addr,
            _ => panic!("回显后端必须是 IPv4"),
        };
        let inbound = start_vmess_inbound(vec![cmd_key_from_uuid(&uuid)], Some(echo_addr), None);
        let xray = XrayClient::start_with_experiments(
            bin,
            &uuid_string(&uuid),
            inbound.addr.port(),
            tier.xray_name(),
            auth_len,
        )
        .expect("xray 客户端启动");

        let mut tunnel = socks5_connect(xray.socks_port, echo_v4).expect("socks 隧道建立");
        let payload = payloads();
        tunnel.set_read_timeout(Some(IO_TIMEOUT)).expect("读超时");
        tunnel.write_all(&payload).expect("写出载荷");
        tunnel.shutdown(Shutdown::Write).expect("半关闭写端");

        let mut echoed = Vec::new();
        tunnel.read_to_end(&mut echoed).expect("读到对端关闭");
        assert_eq!(
            echoed.len(),
            payload.len(),
            "档位 {} 回程长度必须相等",
            tier.xray_name()
        );
        assert_eq!(
            echoed,
            payload,
            "档位 {} 回程必须逐字节一致",
            tier.xray_name()
        );
        assert!(
            !inbound.panicked.load(Ordering::SeqCst),
            "档位 {} 入站处理线程不得 panic",
            tier.xray_name()
        );
        eprintln!(
            "OK: 方向 B 档位 {}（认证长度段={auth_len}）回程 {} 字节逐字节一致。",
            tier.xray_name(),
            echoed.len()
        );
    }
}

/// 负例：档位错配必须失败——本仓入站按 **AES-128-GCM** 解，但参考出口发
/// **ChaCha20-Poly1305**；载荷必须解不出来（回程为空 / 连接被关）。
#[test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
fn xray_chacha_client_against_forced_aes_server_is_rejected() {
    let Some(bin) = xray_bin() else { return };

    let uuid = generate_uuid_bytes();
    let (echo_addr, _echo) = spawn_echo_backend();
    let echo_v4 = match echo_addr {
        SocketAddr::V4(addr) => addr,
        _ => panic!("回显后端必须是 IPv4"),
    };
    // 强制按 AES 解（忽略请求头里的档位）。
    let inbound = start_vmess_inbound(
        vec![cmd_key_from_uuid(&uuid)],
        Some(echo_addr),
        Some(BodySuite::Aes128Gcm),
    );
    let xray = XrayClient::start(
        &bin,
        &uuid_string(&uuid),
        inbound.addr.port(),
        Tier::ChaCha.xray_name(),
    )
    .expect("xray 客户端启动");

    let Ok(mut tunnel) = socks5_connect(xray.socks_port, echo_v4) else {
        eprintln!("OK: 档位错配在 socks CONNECT 阶段即被拒。");
        return;
    };
    let probe = b"must-not-echo";
    tunnel.write_all(probe).expect("写出探针");
    tunnel.shutdown(Shutdown::Write).expect("半关闭");
    tunnel.set_read_timeout(Some(IO_TIMEOUT)).expect("读超时");

    let mut got = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match tunnel.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buffer[..n]),
            Err(_) => break,
        }
    }
    assert!(
        !got.starts_with(probe),
        "档位错配不得得到探针回显（读到 {} 字节）",
        got.len()
    );
    assert!(
        !inbound.panicked.load(Ordering::SeqCst),
        "拒绝路径不得 panic"
    );
    eprintln!("OK: 档位错配（ChaCha 客户端 → 强制 AES 入站）被拒绝，无有效回程。");
}
