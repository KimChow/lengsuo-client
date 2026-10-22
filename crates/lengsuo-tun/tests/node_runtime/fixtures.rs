//! 夹具：真实回程服务、参考实现对端（Xray）、报文构造器与节点配置构造器。
//!
//! # 与既有 `runtime_entry` 套件的区别
//!
//! 本目录下的用例**建真实 socket、并与参考实现互通**：回程服务是真实 TCP 服务，
//! 对端是参考实现（Xray）。因此它证明的是**真实协议出口**能不能把字节送出去并
//! 原样收回来，**不是**「接线语义自洽」的证据。
//!
//! # 凭据
//!
//! 全部凭据都是**测试专用假值**：口令是本文件里的常量，不对应任何真实节点。
//! 日志与断言输出里只出现端口与字节数，**不出现**口令。

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use lengsuo_node::config::{AuthConfig, Endpoint, NodeConfig, Protocol};
use lengsuo_tun::tcp::segment::{self, Flags};

/// 参考实现（Xray）二进制位置：环境变量优先，其次默认路径。
pub const XRAY_BIN: &str = "/home/ubuntu/ref/bin/xray";

/// 测试专用假口令。**不是**任何真实凭据。
pub const TEST_PASSWORD: &str = "lengsuo-test-only-password";

/// 回程服务：把收到的字节原样送回。
///
/// 三个计数分别回答三个问题：
/// - `accepted()`：对端连了几次 ⇒ 「有没有发生直连回落」。
/// - `received()`：一共收到多少字节 ⇒ 「载荷是否原样送达」。
/// - `closed()`：有几条连接被对端正常关闭 ⇒ 「会话释放后链路是否真的断开」。
pub struct EchoServer {
    port: u16,
    shutdown: Arc<AtomicBool>,
    accepted: Arc<AtomicUsize>,
    received: Arc<AtomicUsize>,
    closed: Arc<AtomicUsize>,
    join: Option<JoinHandle<()>>,
}

impl EchoServer {
    /// 启动回程服务，监听 127.0.0.1 的随机端口。
    pub fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("回程服务应能监听");
        let port = listener.local_addr().expect("应能取到本地地址").port();
        let shutdown = Arc::new(AtomicBool::new(false));
        let accepted = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let join = {
            let shutdown = Arc::clone(&shutdown);
            let accepted = Arc::clone(&accepted);
            let received = Arc::clone(&received);
            let closed = Arc::clone(&closed);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    let Ok(stream) = stream else { break };
                    accepted.fetch_add(1, Ordering::Relaxed);
                    let received = Arc::clone(&received);
                    let closed = Arc::clone(&closed);
                    std::thread::spawn(move || {
                        let mut stream = stream;
                        let mut buf = [0u8; 4096];
                        loop {
                            match stream.read(&mut buf) {
                                Ok(0) => {
                                    closed.fetch_add(1, Ordering::Relaxed);
                                    break;
                                }
                                Ok(n) => {
                                    received.fetch_add(n, Ordering::Relaxed);
                                    if stream.write_all(&buf[..n]).is_err() {
                                        closed.fetch_add(1, Ordering::Relaxed);
                                        break;
                                    }
                                }
                                Err(_) => {
                                    closed.fetch_add(1, Ordering::Relaxed);
                                    break;
                                }
                            }
                        }
                    });
                }
            })
        };
        Self {
            port,
            shutdown,
            accepted,
            received,
            closed,
            join: Some(join),
        }
    }

    /// 监听端口。
    pub fn port(&self) -> u16 {
        self.port
    }

    /// 已接受的连接数。
    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::Relaxed)
    }

    /// 已收到的字节数。
    pub fn received(&self) -> usize {
        self.received.load(Ordering::Relaxed)
    }

    /// 已正常关闭的连接数。
    pub fn closed(&self) -> usize {
        self.closed.load(Ordering::Relaxed)
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // 唤醒阻塞在 accept 的线程，否则 join 会一直等。
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// 参考实现对端：Xray 的 shadowsocks 入站 + freedom 出站。
///
/// - 入站：`127.0.0.1:<ss_port>`，`aes-128-gcm` + 测试口令。
/// - 出站：`freedom`。给出 `redirect` 时，freedom 把目标改写到该地址——用于
///   「代理要访问的目标与真实目标不同」的场景（真设备用例里，内核必须把
///   非本机地址的报文路由进 TUN，代理却要访问本机的回程服务）。
pub struct XrayPeer {
    child: Child,
    ss_port: u16,
    config_path: PathBuf,
}

impl XrayPeer {
    /// 启动一个参考实现对端。`redirect` 为 `None` 时目标原样透传。
    pub fn start(password: &str, redirect: Option<u16>) -> Self {
        let ss_port = free_port();
        let freedom = match redirect {
            Some(port) => format!(r#"{{"redirect": "127.0.0.1:{port}"}}"#),
            None => "{}".to_string(),
        };
        let config = format!(
            r#"{{
  "log": {{"loglevel": "warning"}},
  "inbounds": [
    {{
      "listen": "127.0.0.1",
      "port": {ss_port},
      "protocol": "shadowsocks",
      "settings": {{"method": "aes-128-gcm", "password": "{password}", "network": "tcp"}}
    }}
  ],
  "outbounds": [
    {{"protocol": "freedom", "settings": {freedom}}}
  ]
}}"#
        );
        let config_path = std::env::temp_dir().join(format!(
            "lengsuo-xray-{}-{}.json",
            std::process::id(),
            next_serial()
        ));
        std::fs::write(&config_path, config).expect("应能写出参考实现配置");
        let binary = std::env::var("LENGSUO_XRAY").unwrap_or_else(|_| XRAY_BIN.to_string());
        let child = Command::new(&binary)
            .arg("run")
            .arg("-c")
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|error| panic!("应能启动参考实现 {binary}: {error}"));
        let peer = Self {
            child,
            ss_port,
            config_path,
        };
        peer.wait_ready();
        peer
    }

    /// shadowsocks 入站端口。
    pub fn port(&self) -> u16 {
        self.ss_port
    }

    /// 等参考实现把入站端口监听起来。
    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", self.ss_port)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("参考实现未在时限内监听 127.0.0.1:{}", self.ss_port);
    }
}

impl Drop for XrayPeer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.config_path);
    }
}

/// 取一个当前没人监听的端口（先占后放）。
pub fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("应能取到空闲端口")
        .local_addr()
        .expect("应能取到本地地址")
        .port()
}

/// 构造一个走 shadowsocks 的节点配置（口令是测试专用假值）。
pub fn shadowsocks_node(name: &str, port: u16, password: &str) -> NodeConfig {
    let config = NodeConfig {
        name: name.to_owned(),
        protocol: Protocol::Shadowsocks,
        endpoint: Endpoint {
            host: "127.0.0.1".to_owned(),
            port,
        },
        probe_target: None,
        tls: None,
        auth: AuthConfig {
            password: String::new(),
            secret_key: Some(password.to_owned()),
            private_key: None,
            public_key: None,
        },
        method: Some("aes-128-gcm".to_owned()),
        reality: None,
        vision: None,
        encryption: None,
        xel: None,
        mux: None,
        forward: None,
    };
    config
        .validate()
        .expect("测试用节点配置应当合法（否则下面的失败会被误读成出口故障）");
    config
}

/// 构造一条 IPv4+TCP 报文（源 → 目的），带正确的 IP 与 TCP 校验和。
///
/// 复用库内的 `segment::build` 做传输段，IP 头在这里包一层：地址可参数化，
/// 才能让用例把「目标」指到任意地址（例如 127.0.0.1 的直连探针）。
// 参数个数与库内 `segment::build` 同构（同一份语义），故同样放行该 lint。
#[allow(clippy::too_many_arguments)]
pub fn tcp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: Flags,
    payload: &[u8],
) -> Vec<u8> {
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src.octets());
    pseudo[4..8].copy_from_slice(&dst.octets());
    pseudo[9] = 6;
    pseudo[10..12].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    let built = segment::build(
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        4096,
        &[],
        payload,
        &pseudo,
    )
    .expect("传输段应可构造");
    let total = 20 + built.len();
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    packet[10..12].copy_from_slice(&0u16.to_be_bytes());
    let header_sum = !ones_complement_sum(&[&packet[..20]]);
    packet[10..12].copy_from_slice(&header_sum.to_be_bytes());
    packet[20..].copy_from_slice(&built);
    packet
}

/// RFC 1071 一补码和。
fn ones_complement_sum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for part in parts {
        let mut index = 0;
        while index + 1 < part.len() {
            sum = sum.wrapping_add(u32::from(u16::from_be_bytes([
                part[index],
                part[index + 1],
            ])));
            index += 2;
        }
        if let Some(odd) = part.get(index) {
            sum = sum.wrapping_add(u32::from(*odd) << 8);
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    (sum & 0xffff) as u16
}

/// 进程内自增序号（用于临时文件名）。
fn next_serial() -> u64 {
    static SERIAL: AtomicUsize = AtomicUsize::new(0);
    SERIAL.fetch_add(1, Ordering::Relaxed) as u64
}

/// 目标地址（IPv4 回环 + 端口）。
pub fn loopback_target(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}
