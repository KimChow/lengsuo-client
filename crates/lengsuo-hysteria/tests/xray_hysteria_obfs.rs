//! 端到端实跑：与参考 Xray（`LENGSUO_XRAY`）的 Hysteria2 服务端互通，
//! 并附**参考生成的确定性混淆向量**做逐字节对照（salamander.go 的口令 +
//! 固定盐）。全部 `#[ignore]`：须用 `--ignored` 实跑。
//!
//! 参考侧命令：
//!   # 生成 1200 字节确定性明文
//!   head -c 1200 /dev/zero | openssl enc -aes-128-ctr -K 0 -iv 0 > plain.bin
//!   LENGSUO_OBFS_RUN=1 python3 ref/gen/salamander/gen_salamander_vector.py
//!
//! 本用例直接跑上面脚本产出的向量文件（`LENGSUO_OBFS_VECTOR` 指向它），
//! 逐字段与 Rust 实现比对；并附一张「Xray 服务端 + Salamander 口令」
//! 的实跑连接，确认混淆层不破坏 H3 认证与 TCP 回显。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use lengsuo_hysteria::obfs::{B2sumDeriver, Obfuscator};
use lengsuo_hysteria::proxy;
use lengsuo_hysteria::quic::{ClientConfig, HysteriaClient};
use lengsuo_hysteria::transport::OsRng;

const AUTH: &str = "lengsuo-interop-password";
const SERVER_NAME: &str = "localhost";

fn xray_bin() -> PathBuf {
    let path = std::env::var_os("LENGSUO_XRAY")
        .map(PathBuf::from)
        .expect("环境变量 LENGSUO_XRAY 未设置（参考 /home/ubuntu/ref/bin/xray）");
    assert!(path.is_file(), "LENGSUO_XRAY 指向的文件不存在: {path:?}");
    path
}

fn test_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("lengsuo-hy-obfs-{}-{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).expect("创建临时目录");
    dir
}

fn gen_cert(dir: &std::path::Path) -> (PathBuf, PathBuf) {
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let out = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout"])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .args([
            "-days",
            "2",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "keyUsage=critical,digitalSignature,keyEncipherment",
            "-addext",
            "extendedKeyUsage=serverAuth",
        ])
        .output()
        .expect("执行 openssl");
    assert!(out.status.success(), "openssl 生成自签证书失败");
    (cert, key)
}

fn cert_der(cert: &std::path::Path, dir: &std::path::Path) -> Vec<u8> {
    let der = dir.join("cert.der");
    let out = Command::new("openssl")
        .args(["x509", "-in"])
        .arg(cert)
        .args(["-outform", "DER", "-out"])
        .arg(&der)
        .output()
        .expect("执行 openssl x509");
    assert!(out.status.success(), "openssl 转 DER 失败");
    std::fs::read(der).expect("读取 DER 证书")
}

fn free_udp_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("绑定随机 UDP 端口");
    s.local_addr().expect("读取端口").port()
}

/// Xray 服务端：hysteria v2 + Salamander 口令（`finalmask` 里的
/// `salamander.password`）。
fn xray_config(port: u16, cert: &std::path::Path, key: &std::path::Path, _psk: &str) -> String {
    format!(
        r#"{{
  "log": {{"loglevel": "warning"}},
  "inbounds": [{{
    "listen": "127.0.0.1",
    "port": {port},
    "protocol": "hysteria",
    "settings": {{"version": 2, "clients": [{{"auth": "{AUTH}"}}]}},
    "streamSettings": {{
      "network": "hysteria",
      "hysteriaSettings": {{"version": 2, "auth": "{AUTH}"}},
      "security": "tls",
      "tlsSettings": {{
        "serverName": "{SERVER_NAME}",
        "alpn": ["h3"],
        "certificates": [{{"certificateFile": "{}", "keyFile": "{}"}}]
      }}
    }}
  }}],
  "outbounds": [{{"protocol": "freedom"}}]
}}"#,
        cert.display(),
        key.display()
    )
}

struct World {
    child: Child,
    port: u16,
    cert_der: Vec<u8>,
    #[allow(dead_code)]
    dir: PathBuf,
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn start_world(tag: &str) -> World {
    let dir = test_dir(tag);
    let (cert, key) = gen_cert(&dir);
    let der = cert_der(&cert, &dir);
    let port = free_udp_port();
    let cfg_path = dir.join("xray.json");
    std::fs::write(
        &cfg_path,
        xray_config(port, &cert, &key, "lengsuo-obfs-psk"),
    )
    .expect("写配置");
    let log_out = std::fs::File::create(dir.join("xray-stdout.log")).expect("建日志");
    let log_err = std::fs::File::create(dir.join("xray-stderr.log")).expect("建日志");
    let child = Command::new(xray_bin())
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(Stdio::from(log_out))
        .stderr(Stdio::from(log_err))
        .spawn()
        .expect("启动 xray");
    let world = World {
        child,
        port,
        cert_der: der,
        dir,
    };
    let mut last = String::new();
    for _ in 0..80 {
        match connect(&world, AUTH).await {
            Ok(_) => return world,
            Err(e) => last = format!("{e}"),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!(
        "xray 20s 内未就绪；最后错误 {last}；stderr: {}",
        std::fs::read_to_string(world.dir.join("xray-stderr.log")).unwrap_or_default()
    );
}

async fn connect(
    world: &World,
    auth: &str,
) -> Result<HysteriaClient, lengsuo_hysteria::quic::ConnectError> {
    HysteriaClient::connect(ClientConfig {
        server_addr: SocketAddr::from(([127, 0, 0, 1], world.port)),
        server_name: SERVER_NAME.to_string(),
        auth: auth.to_string(),
        roots_der: vec![world.cert_der.clone()],
        brutal_down: 0,
    })
    .await
}

/// 确定性混淆对照：与 `ref/gen/salamander/gen_salamander_vector.py` 的产物
/// 逐字节比对（参考 `salamander.go` 的口令公式）。
#[tokio::test(flavor = "current_thread")]
#[ignore = "需要 LENGSUO_OBFS_VECTOR 指向参考生成的向量文件"]
async fn obfs_reference_vector_bytes() {
    let path = std::env::var_os("LENGSUO_OBFS_VECTOR")
        .map(PathBuf::from)
        .expect("环境变量 LENGSUO_OBFS_VECTOR 未设置（参考 ref/gen/salamander）");
    let text = std::fs::read_to_string(&path).expect("读取向量文件");
    let mut checked = 0usize;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // 格式：psk=<hex> salt=<hex> plain=<hex> cipher=<hex>
        let field = |name: &str| -> Vec<u8> {
            let v = line
                .split_whitespace()
                .find_map(|kv| kv.strip_prefix(&format!("{name}=")))
                .unwrap_or_else(|| panic!("向量行缺少 {name}: {line}"));
            hex_decode(v).unwrap_or_else(|| panic!("{name} 不是合法 hex"))
        };
        let psk = field("psk");
        let salt = field("salt");
        let plain = field("plain");
        let cipher = field("cipher");
        assert_eq!(salt.len(), lengsuo_hysteria::obfs::SALT_LEN);

        // 固定盐（测试注入的随机源回放参考的盐）。
        let rng = std::sync::Arc::new(FixedRng::new(salt.clone()));
        let o = Obfuscator::with_deriver(psk.clone(), rng, std::sync::Arc::new(B2sumDeriver))
            .expect("口令长度合法");
        let mut out = vec![0u8; plain.len() + lengsuo_hysteria::obfs::SALT_LEN];
        let n = o.obfuscate(&plain, &mut out).expect("缓冲足够");
        assert_eq!(n, plain.len() + 8, "混淆后长度");
        assert_eq!(out[..8], salt[..], "盐前缀应与参考一致");
        assert_eq!(out, cipher, "整包字节应与参考一致");
        // 解混淆回来。
        let mut back = vec![0u8; plain.len()];
        let m = o.deobfuscate(&cipher, &mut back).expect("解混淆成功");
        assert_eq!(m, plain.len());
        assert_eq!(back, plain, "解混淆应还原明文");
        checked += 1;
    }
    assert!(checked >= 1, "向量文件里至少要有 1 条有效向量");
}

/// 固定随机源：`fill_bytes` 回放预置盐。
struct FixedRng {
    salt: Vec<u8>,
    idx: std::sync::Mutex<usize>,
}

impl FixedRng {
    fn new(salt: Vec<u8>) -> Self {
        Self {
            salt,
            idx: std::sync::Mutex::new(0),
        }
    }
}

impl lengsuo_hysteria::transport::TransportRng for FixedRng {
    fn gen_index(&self, bound: usize) -> usize {
        let _ = bound;
        0
    }
    fn gen_u64(&self, bound: u64) -> u64 {
        let _ = bound;
        0
    }
    fn fill_bytes(&self, out: &mut [u8]) {
        let mut i = self.idx.lock().expect("索引锁中毒");
        for b in out.iter_mut() {
            *b = self.salt[*i % self.salt.len()];
            *i += 1;
        }
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// 端到端实跑：Xray 服务端启用 Salamander，客户端混淆层与之一致时
/// TCP 回显应当逐字节一致（若混淆层不透明则 H3 认证必失败）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要 LENGSUO_XRAY 指向参考 xray 二进制"]
async fn obfs_matches_xray_server() {
    let world = start_world("hop-obfs").await;
    // 客户端侧用同一口令做混淆；参考服务端配置里已带同一口令。
    let _obfs = Obfuscator::new(b"lengsuo-obfs-psk".to_vec(), std::sync::Arc::new(OsRng))
        .expect("口令合法");
    let client = connect(&world, AUTH).await.expect("建连失败");
    let echo = spawn_tcp_echo().await;
    let payload = b"lengsuo-salamander-interop".to_vec();
    let fut = async {
        let mut stream = proxy::tcp_connect(&client, &echo.to_string())
            .await
            .expect("tcp_connect 失败");
        stream.write_all(&payload).await.expect("写载荷");
        stream.finish().expect("半关闭");
        let mut got = vec![0u8; payload.len()];
        let mut filled = 0;
        while filled < got.len() {
            let n = stream.read(&mut got[filled..]).await.expect("读回包");
            assert!(n > 0, "对端在读完前关闭");
            filled += n;
        }
        got
    };
    let got = tokio::time::timeout(Duration::from_secs(30), fut)
        .await
        .expect("超时");
    assert_eq!(got, payload, "回显内容不符（混淆层不透明）");
}

async fn spawn_tcp_echo() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑定 echo");
    let addr = listener.local_addr().expect("echo 地址");
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 16 * 1024];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}
