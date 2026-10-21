// Xray 客户端进程：SOCKS 入站 → VMess 出站（指定安全档）指向本仓入站。
// 本文件由 `tests/xray_multitier_server.rs` 用 `include!` 文本并入同一模块（用例名
// 不带模块前缀，与拆分前逐字一致）；`use` 全部留在入口文件。

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
