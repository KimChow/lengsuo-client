// 共享夹具：参考二进制定位 / 临时目录 / openssl 自签 / 空闲端口 / Xray 客户端配置。
fn xray_bin() -> PathBuf {
    let path = std::env::var_os("LENGSUO_XRAY")
        .map(PathBuf::from)
        .expect("环境变量 LENGSUO_XRAY 未设置（参考 /home/ubuntu/ref/bin/xray）");
    assert!(path.is_file(), "LENGSUO_XRAY 指向的文件不存在: {path:?}");
    path
}

fn test_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("lengsuo-hy-srv-{}-{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).expect("创建临时目录");
    dir
}

/// openssl 现场自签（SAN=DNS:localhost），证书与私钥只写临时目录。
fn gen_cert(dir: &Path) -> (PathBuf, PathBuf) {
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
    assert!(
        out.status.success(),
        "openssl 生成自签证书失败: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (cert, key)
}

fn cert_der(cert: &Path, dir: &Path) -> Vec<u8> {
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

fn key_der(key: &Path) -> Vec<u8> {
    let out = Command::new("openssl")
        .args(["pkey", "-in"])
        .arg(key)
        .args(["-outform", "DER"])
        .output()
        .expect("执行 openssl pkey");
    assert!(out.status.success(), "openssl 转私钥 DER 失败");
    out.stdout
}

fn free_tcp_port() -> u16 {
    let s = std::net::TcpListener::bind("127.0.0.1:0").expect("绑定随机 TCP 端口");
    s.local_addr().expect("读取端口").port()
}

/// Xray 客户端配置：socks 入站 → hysteria v2 outbound（连本仓服务端）。
fn xray_client_config(socks_port: u16, server_port: u16, auth: &str, cert: &Path) -> String {
    format!(
        r#"{{
  "log": {{"loglevel": "warning"}},
  "inbounds": [{{
    "listen": "127.0.0.1",
    "port": {socks_port},
    "protocol": "socks",
    "settings": {{"udp": true}}
  }}],
  "outbounds": [{{
    "protocol": "hysteria",
    "settings": {{
      "version": 2,
      "address": "127.0.0.1",
      "port": {server_port}
    }},
    "streamSettings": {{
      "network": "hysteria",
      "hysteriaSettings": {{"version": 2, "auth": "{auth}"}},
      "security": "tls",
      "tlsSettings": {{
        "serverName": "{SERVER_NAME}",
        "alpn": ["h3"],
        "disableSystemRoot": true,
        "certificates": [{{"certificateFile": "{cert}"}}]
      }}
    }}
  }}]
}}"#,
        cert = support::json_escape(&cert.to_string_lossy())
    )
}

/// 本仓服务端 + 官方 Xray 客户端（socks）的世界。
struct World {
    client: Child,
    socks_port: u16,
    #[allow(dead_code)]
    server: Arc<HysteriaServer>,
    #[allow(dead_code)]
    dir: PathBuf,
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = self.client.kill();
        let _ = self.client.wait();
        self.server.close();
    }
}
