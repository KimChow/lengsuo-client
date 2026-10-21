// Xray 客户端进程夹具：socks 入站 → vmess outbound 指向本仓入站。
// 本文件由 `tests/xray_vmess_server.rs` 用 `include!` 文本并入同一模块（用例名
// 不带模块前缀，与拆分前逐字一致）；`use` 全部留在入口文件。

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
