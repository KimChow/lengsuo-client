//! Xray 客户端 → 本仓 VMess 入站 互通用例（`#[ignore]`）。
//!
//! 拓扑：测试进程 --socks5--> Xray（socks 入站 + vmess outbound, aes-128-gcm）
//! --vmess/AEAD--> 本仓入站夹具 --raw TCP--> 本地回显后端。
//!
//! Xray outbound 对 AES-128-GCM 默认发 option = ChunkStream(0x01) |
//! ChunkMasking(0x04) | GlobalPadding(0x08)（outbound.go:102-114 +
//! `shouldEnablePadding`），因此本夹具覆盖「掩码 + 全局 padding」的真实默认
//! 数据面（客户端方向 option=0 简化路径之外的矩阵）。
//!
//! 断言口径（对齐 `inbound.go` 的断连时机，见 `docs/vmess-status.md`）：
//! - A：1B/4KiB/256KiB 连续载荷全链路回显，逐字节相等；
//! - B：Xray 侧配错 UUID → 本仓 `invalid user` 拒绝：隧道在 10s 内关闭且
//!   不出现请求字节的回显；不得只把「没读到」当通过；
//! - C：直连入站喂畸形头（错 cmdKey / 截断 / 错长度 tag / 错载荷 tag）：
//!   连接被关、一个字节都不回、处理线程不 panic。不依赖 Xray 二进制。

mod support;

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lengsuo_vmess::aead::seal_vmess_aead_header;
use lengsuo_vmess::chunkframe::{
    open_padded_chunk, read_padded_size, seal_padded_chunk, DataCipher, DataSizeParser,
};
use lengsuo_vmess::consts::SECURITY_AES_128_GCM;
use lengsuo_vmess::request::{HeaderPlanner, KeySource, RequestHeader};
use lengsuo_vmess::server::{
    decode_request_header, encode_response_header, response_key_iv, HeaderSecurity, ResponseHeader,
};
use lengsuo_vmess::{Command as ProxyCommand, SecurityOption};
use ss_core::target::TargetAddr;
use support::codec::{cmd_key_from_uuid, generate_uuid_bytes, uuid_string};

/// 选项位（`common/protocol/headers.go`；本仓 consts 的 OPTION_* 是旧命名，勿混用）。
const OPT_CHUNK_STREAM: u8 = 0x01;
const OPT_CHUNK_MASKING: u8 = 0x04;
const OPT_GLOBAL_PADDING: u8 = 0x08;
const OPT_AUTHENTICATED_LENGTH: u8 = 0x10;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时钟在 UNIX 纪元之后")
        .as_secs() as i64
}

fn xray_bin() -> Option<PathBuf> {
    let path: PathBuf = std::env::var_os("LENGSUO_XRAY")?.into();
    path.is_file().then_some(path)
}

fn payload_1b_4kib_256kib() -> Vec<u8> {
    let total = 1 + 4 * 1024 + 256 * 1024;
    (0..total).map(|i| (i % 251) as u8).collect()
}

/// 本地 raw TCP 回显后端（读到关闭即关闭）。
fn spawn_echo_backend() -> (SocketAddr, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("回显后端绑定");
    let addr = listener.local_addr().expect("回显后端地址");
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(60)));
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

/// Xray 客户端进程：socks 入站 → vmess outbound 指向本仓入站。
struct XrayClient {
    child: Child,
    socks_port: u16,
    dir: PathBuf,
}

impl XrayClient {
    fn start(bin: &PathBuf, uuid: &str, vmess_port: u16) -> Result<Self, String> {
        let probe = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
        let socks_port = probe.local_addr().map_err(|e| e.to_string())?.port();
        drop(probe);

        let dir = std::env::temp_dir().join(format!(
            "lengsuo-vmess-xcli-{}-{socks_port}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let config = format!(
            "{{\"log\":{{\"loglevel\":\"warning\"}},\
             \"inbounds\":[{{\"listen\":\"127.0.0.1\",\"port\":{socks_port},\
             \"protocol\":\"socks\",\"settings\":{{\"udp\":false,\"auth\":\"noauth\"}}}}],\
             \"outbounds\":[{{\"protocol\":\"vmess\",\"settings\":{{\"vnext\":[{{\
             \"address\":\"127.0.0.1\",\"port\":{vmess_port},\
             \"users\":[{{\"id\":\"{uuid}\",\"alterId\":0,\"security\":\"aes-128-gcm\"}}]\
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
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", client.socks_port)).is_ok() {
                return Ok(client);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(format!(
            "xray 客户端 10s 内未在 127.0.0.1:{} 就绪",
            client.socks_port
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

fn start_vmess_inbound(users: Vec<[u8; 16]>, echo: Option<SocketAddr>) -> VmessInbound {
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
                    handle_connection(stream, &users, &sessions, echo)
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

fn handle_connection(
    mut stream: TcpStream,
    users: &[[u8; 16]],
    sessions: &Mutex<Vec<[u8; 48]>>,
    echo: Option<SocketAddr>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

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

    let Some(echo_addr) = echo else {
        eprintln!("[vmess-in] 未配置后端，关闭");
        return;
    };
    if decoded.security != HeaderSecurity::Aes128Gcm {
        eprintln!("[vmess-in] 夹具仅支持 AES-128-GCM 数据面");
        return;
    }
    let must = OPT_CHUNK_STREAM | OPT_CHUNK_MASKING | OPT_GLOBAL_PADDING;
    if decoded.option & must != must || decoded.option & OPT_AUTHENTICATED_LENGTH != 0 {
        eprintln!(
            "[vmess-in] 不支持的 option 组合：0x{:02x}",
            decoded.option
        );
        return;
    }
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

    // 响应头先于任何体数据（对齐 transferResponse 顺序）。
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
        let mut cipher = DataCipher::new(SECURITY_AES_128_GCM, &req_key, &req_iv);
        let mut mask = DataSizeParser::new(&req_iv);
        loop {
            let mut size_wire = [0u8; 2];
            if up_reader.read_exact(&mut size_wire).is_err() {
                break;
            }
            let (declared, padding) = read_padded_size(&mut mask, size_wire);
            let mut body = vec![0u8; declared as usize];
            if up_reader.read_exact(&mut body).is_err() {
                break;
            }
            match open_padded_chunk(&mut cipher, &body, padding) {
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
    });

    // 下行：后端明文 → 分帧 → 客户端。
    let mut resp_cipher = DataCipher::new(SECURITY_AES_128_GCM, &resp_key, &resp_iv);
    let mut resp_mask = DataSizeParser::new(&resp_iv);
    let mut buffer = vec![0u8; 8192 - 2 - 16 - 64]; // 参考单帧净载荷上限
    loop {
        match echo_sock.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                let mut frame = Vec::with_capacity(n + 80);
                if seal_padded_chunk(&mut resp_cipher, &mut resp_mask, &mut frame, &buffer[..n])
                    .is_err()
                {
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
    if seal_padded_chunk(&mut resp_cipher, &mut resp_mask, &mut eof_frame, &[]).is_ok() {
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

/// 用例 A：1B/4KiB/256KiB 经 Xray socks→vmess 全链路回显，逐字节一致。
#[test]
#[ignore = "需要 LENGSUO_XRAY 指向真实 xray 二进制"]
fn xray_client_to_rust_server_echo() {
    let Some(bin) = xray_bin() else {
        eprintln!("LENGSUO_XRAY 未设置或不存在，跳过");
        return;
    };
    let uuid = generate_uuid_bytes();
    let (echo_addr, _echo) = spawn_echo_backend();
    let echo_v4 = match echo_addr {
        SocketAddr::V4(addr) => addr,
        _ => panic!("回显后端必须是 IPv4"),
    };
    let inbound = start_vmess_inbound(vec![cmd_key_from_uuid(&uuid)], Some(echo_addr));
    let xray = XrayClient::start(&bin, &uuid_string(&uuid), inbound.addr.port())
        .expect("xray 客户端启动");

    let mut tunnel = socks5_connect(xray.socks_port, echo_v4).expect("socks 隧道建立");
    let payload = payload_1b_4kib_256kib();
    tunnel
        .set_read_timeout(Some(Duration::from_secs(60)))
        .expect("读超时");
    tunnel.write_all(&payload).expect("写出载荷");
    tunnel.shutdown(Shutdown::Write).expect("半关闭写端");

    let mut echoed = Vec::new();
    tunnel.read_to_end(&mut echoed).expect("读到对端关闭");
    assert_eq!(echoed.len(), payload.len(), "回显长度必须相等");
    assert_eq!(echoed, payload, "回显内容必须逐字节一致");
    assert!(
        !inbound.panicked.load(Ordering::SeqCst),
        "入站处理线程不得 panic"
    );
}

/// 用例 B：Xray 侧配错 UUID → 本仓 invalid user 拒绝：断连且无回显。
#[test]
#[ignore = "需要 LENGSUO_XRAY 指向真实 xray 二进制"]
fn xray_client_wrong_uuid_is_rejected() {
    let Some(bin) = xray_bin() else {
        eprintln!("LENGSUO_XRAY 未设置或不存在，跳过");
        return;
    };
    let server_uuid = generate_uuid_bytes();
    let mut client_uuid = generate_uuid_bytes();
    client_uuid[0] ^= 0xFF;
    let (echo_addr, _echo) = spawn_echo_backend();
    let echo_v4 = match echo_addr {
        SocketAddr::V4(addr) => addr,
        _ => panic!("回显后端必须是 IPv4"),
    };
    let inbound = start_vmess_inbound(vec![cmd_key_from_uuid(&server_uuid)], Some(echo_addr));
    let xray = XrayClient::start(&bin, &uuid_string(&client_uuid), inbound.addr.port())
        .expect("xray 客户端启动");

    // CONNECT 可能成功（xray 先建链再发 vmess 头），失败也是有效拒绝证据。
    let Ok(mut tunnel) = socks5_connect(xray.socks_port, echo_v4) else {
        assert!(!inbound.panicked.load(Ordering::SeqCst));
        eprintln!("socks CONNECT 即被拒（同样构成拒绝证据）");
        return;
    };
    let probe = b"must-not-echo";
    tunnel.write_all(probe).expect("写出探针");
    tunnel.shutdown(Shutdown::Write).expect("半关闭");

    let mut got = Vec::new();
    let mut buffer = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let now = Instant::now();
        if now >= deadline {
            panic!("错误 UUID 的连接 10s 内未被关闭");
        }
        tunnel
            .set_read_timeout(Some(deadline - now))
            .expect("读超时");
        match tunnel.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buffer[..n]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                panic!("错误 UUID 的连接 10s 内未被关闭（读超时）");
            }
            Err(_) => break, // RST/ABORT 等强制关闭
        }
    }
    assert!(
        !got.starts_with(probe),
        "错误 UUID 不得得到探针回显（读到 {} 字节）",
        got.len()
    );
    assert!(
        !inbound.panicked.load(Ordering::SeqCst),
        "拒绝路径不得 panic"
    );
}

/// 用例 C：直连本仓入站，截断/篡改请求头被拒不 panic、不回任何字节。
/// 不依赖 Xray 二进制。
#[test]
#[ignore = "直接打击本仓入站的畸形输入矩阵"]
fn malformed_direct_headers_are_rejected() {
    let uuid = generate_uuid_bytes();
    let cmd_key = cmd_key_from_uuid(&uuid);
    let (echo_addr, _echo) = spawn_echo_backend();
    let inbound = start_vmess_inbound(vec![cmd_key], Some(echo_addr));

    let keys = KeySource::generate().expect("会话密钥");
    let target = TargetAddr::V4([127, 0, 0, 1], echo_addr.port());
    let plain = HeaderPlanner::new(keys)
        .plan_with(
            &RequestHeader {
                target: Some(target),
                command: ProxyCommand::Tcp,
                security: SecurityOption::Aes128Gcm,
                option: OPT_CHUNK_STREAM | OPT_CHUNK_MASKING | OPT_GLOBAL_PADDING,
                padding_len: 0,
            },
            &[],
        )
        .expect("头明文");

    let good = seal_vmess_aead_header(&cmd_key, &plain).expect("合法头");
    let junk_tail = vec![0x41u8; 8192];

    // C1 错误 UUID（cmdKey 不符）。
    let mut evil_key = cmd_key;
    evil_key[0] ^= 0xFF;
    let wrong_user = seal_vmess_aead_header(&evil_key, &plain).expect("可封");
    let mut c1 = wrong_user;
    c1.extend_from_slice(&junk_tail);
    assert_rejected(inbound.addr, &c1, "C1 错误 cmdKey");

    // C2 半截头（AuthID + 12 字节后断连）。
    let mut c2 = good[..16 + 12].to_vec();
    c2.extend_from_slice(&junk_tail);
    assert_rejected(inbound.addr, &c2, "C2 截断头");

    // C3 长度段 tag 篡改。
    let mut c3 = good.clone();
    c3[17] ^= 0x01;
    c3.extend_from_slice(&junk_tail);
    assert_rejected(inbound.addr, &c3, "C3 长度段 tag");

    // C4 载荷段 tag 篡改。
    let mut c4 = good;
    let last = c4.len() - 1;
    c4[last] ^= 0x01;
    c4.extend_from_slice(&junk_tail);
    assert_rejected(inbound.addr, &c4, "C4 载荷段 tag");

    assert!(
        !inbound.panicked.load(Ordering::SeqCst),
        "畸形输入不得导致 panic"
    );
}

fn assert_rejected(addr: SocketAddr, bytes: &[u8], case: &str) {
    let mut stream = TcpStream::connect(addr).expect("连接入站");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("读超时");
    stream.write_all(bytes).expect("写出畸形输入");
    stream.shutdown(Shutdown::Write).expect("半关闭");

    let mut got = Vec::new();
    let mut buffer = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let now = Instant::now();
        if now >= deadline {
            panic!("{case}：10s 内未被关闭");
        }
        stream
            .set_read_timeout(Some(deadline - now))
            .expect("读超时");
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buffer[..n]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                panic!("{case}：10s 内未被关闭（读超时）");
            }
            Err(_) => break,
        }
    }
    assert!(
        got.is_empty(),
        "{case}：不得回任何字节（实得 {} 字节）",
        got.len()
    );
}
