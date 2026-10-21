use serde_json::Value;
use std::{
    path::PathBuf,
    process::{Child, Command as Process, Stdio},
    time::Duration,
};
use tokio::{net::TcpStream, time::Instant};
pub const WAIT: Duration = Duration::from_secs(8);
#[allow(dead_code)]
pub const ID: &str = "11111111-1111-1111-1111-111111111111";
#[allow(dead_code)] // 共享测试夹具：各测试文件用到的符号不同
pub const KEY: [u8; 16] = [0x11; 16];
#[allow(dead_code)]
pub struct Reference {
    child: Child,
    directory: PathBuf,
}
impl Drop for Reference {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // 失败诊断：默认清理临时目录；设 LENGSUO_KEEP_REF_LOG=1 时保留日志。
        if std::env::var("LENGSUO_KEEP_REF_LOG").is_ok() {
            if let Ok(log) = std::fs::read_to_string(self.directory.join("xray.log")) {
                eprintln!("--- 参考日志 {} ---\n{log}", self.directory.display());
            }
            return;
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[allow(dead_code)]
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// 一次性预留 `count` 个**互不相同**的回环空闲端口：同时持有 `count` 个
/// 监听套接字，读取各自端口后一并释放。
///
/// 用途：同一测试要在参考端开多个入站，若像 `free_port() + 1` 那样推相邻端口，
/// 相邻口可能被系统/其他进程占用，导致参考端某个入站绑定失败（表现为主测
/// 用例偶发 `read_exact` 连接被重置）。同时持有多套接字可保证取到的端口彼此不同。
#[allow(dead_code)]
pub fn free_ports(count: usize) -> Vec<u16> {
    let listeners: Vec<std::net::TcpListener> = (0..count)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").expect("预留空闲端口"))
        .collect();
    listeners
        .iter()
        .map(|listener| listener.local_addr().expect("读取端口").port())
        .collect()
}

/// 回环 DNS 服务器：只解析给定的假域名到给定 IPv4，其余查询一律 NXDOMAIN。
///
/// 用途：给参考端提供「域名→回环 IP」的**真实 DNS 解析路径**（卡片要求
/// 「假域名 + 回环 DNS 解析路径」），避免改 `/etc/hosts` 或依赖公网 DNS。
/// 只实现 A 查询的最小子集，足够 Xray 内部解析器使用。
#[allow(dead_code)]
pub struct LoopbackDns {
    pub port: u16,
    _socket: tokio::task::JoinHandle<()>,
}

#[allow(dead_code)]
impl LoopbackDns {
    /// 在 127.0.0.1 的随机端口上启动，把 `name` 解析为 `127.0.0.1`。
    ///
    /// 需要 tokio 运行时（测试内调用）。
    pub async fn start(name: &'static str) -> Self {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let mut buffer = [0u8; 1500];
            loop {
                let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                if let Some(response) = answer_a(&buffer[..length], name) {
                    let _ = socket.send_to(&response, peer).await;
                }
            }
        });
        Self {
            port,
            _socket: handle,
        }
    }
}

/// 解析一个 DNS 查询报文的 QNAME（忽略压缩指针，仅取首个问题）。
#[allow(dead_code)]
fn query_name(packet: &[u8]) -> Option<(String, usize)> {
    let mut offset = 12usize;
    let mut labels = Vec::new();
    loop {
        let length = usize::from(*packet.get(offset)?);
        offset += 1;
        if length == 0 {
            break;
        }
        let label = packet.get(offset..offset + length)?;
        labels.push(String::from_utf8_lossy(label).to_lowercase());
        offset += length;
    }
    Some((labels.join("."), offset))
}

/// 对 A 查询返回 `127.0.0.1`；名字不匹配或非 A 查询返回 NXDOMAIN。
#[allow(dead_code)]
fn answer_a(packet: &[u8], name: &str) -> Option<Vec<u8>> {
    let (qname, question_end) = query_name(packet)?;
    let qtype = u16::from_be_bytes([*packet.get(question_end)?, *packet.get(question_end + 1)?]);
    let matches = qname == name && qtype == 1;
    let mut response = Vec::with_capacity(64);
    response.extend_from_slice(&packet[0..2]); // ID
    response.extend_from_slice(&[0x81, if matches { 0x80 } else { 0x83 }]); // QR+RA / NXDOMAIN
    response.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    response.extend_from_slice(&[0x00, if matches { 0x01 } else { 0x00 }]); // ANCOUNT
    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NS/AR
    response.extend_from_slice(&packet[12..=question_end + 3]); // 原始问题段
    if matches {
        response.extend_from_slice(&[
            0xC0, 0x0C, // 指向 QNAME 的指针
            0x00, 0x01, // TYPE=A
            0x00, 0x01, // CLASS=IN
            0x00, 0x00, 0x00, 0x05, // TTL=5s
            0x00, 0x04, // RDLENGTH
            127, 0, 0, 1,
        ]);
    }
    Some(response)
}

#[allow(dead_code)]
pub async fn launch(config: Value, port: u16) -> Reference {
    let binary = std::env::var("LENGSUO_XRAY").expect("必须显式指定固定版本 Xray");
    let version = Process::new(&binary).arg("version").output().unwrap();
    let version = String::from_utf8(version.stdout).unwrap();
    assert!(
        version.contains("26.3.27") && version.contains("d2758a0"),
        "基线不匹配：{version}"
    );
    let directory =
        std::env::temp_dir().join(format!("lengsuo-vless-{}-{port}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("config.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let log = std::fs::File::create(directory.join("xray.log")).unwrap();
    let child = Process::new(binary)
        .args(["run", "-config"])
        .arg(path)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    let mut reference = Reference { child, directory };
    let end = Instant::now() + WAIT;
    loop {
        if let Some(status) = reference.child.try_wait().unwrap() {
            panic!(
                "参考进程提前退出 {status}：{}",
                std::fs::read_to_string(reference.directory.join("xray.log")).unwrap()
            );
        }
        if TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok()
        {
            break;
        }
        assert!(Instant::now() < end, "参考服务启动超时");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let inbound = config["inbounds"][0]["protocol"].as_str().unwrap_or("未知");
    let security = config["inbounds"][0]["streamSettings"]["security"]
        .as_str()
        .unwrap_or("none");
    println!("基线 {version}测试端口 {port}，入站 {inbound}，安全层 {security}");
    reference
}

/// 确定性熵源：`fill_bytes` 用 SHA-256 计数器模式展开种子（同
/// `reality_e2e` 夹具的 `SeededRng`；本目标不共享那个模块）。
#[allow(dead_code)]
pub struct SeededRng {
    seed: [u8; 32],
    counter: u64,
    buffer: Vec<u8>,
}

#[allow(dead_code)]
impl SeededRng {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            buffer: Vec::new(),
        }
    }

    pub fn from_label(label: &str) -> Self {
        let mut seed = [0u8; 32];
        seed[..label.len().min(32)].copy_from_slice(&label.as_bytes()[..label.len().min(32)]);
        Self::new(seed)
    }
}

#[allow(dead_code)]
impl aes_gcm::aead::rand_core::RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }
    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        while self.buffer.len() < dest.len() {
            let mut input = [0u8; 40];
            input[..32].copy_from_slice(&self.seed);
            input[32..].copy_from_slice(&self.counter.to_be_bytes());
            let digest = lengsuo_vless::reality::hash::sha::sha256(&input);
            self.buffer.extend_from_slice(&digest);
            self.counter = self.counter.wrapping_add(1);
        }
        let take = dest.len();
        dest.copy_from_slice(&self.buffer[..take]);
        self.buffer.drain(..take);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), aes_gcm::aead::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[allow(dead_code)]
impl aes_gcm::aead::rand_core::CryptoRng for SeededRng {}

/// base64 raw-url（RFC 4648 §5，无 padding）编码：给配置层喂「参考格式」的公钥文本。
#[allow(dead_code)]
pub fn base64_url(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 0x3f] as char);
        out.push(TABLE[(n >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(n >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            out.push(TABLE[n as usize & 0x3f] as char);
        }
    }
    out
}
