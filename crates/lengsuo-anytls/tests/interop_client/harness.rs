//! 客户端方向互通的测试装配：定位官方 anytls-server 二进制、检查 openssl、
//! spawn 官方 server、现取其 TLS 证书，产出一次性 `Fixture`。
//! 缺二进制或缺 openssl 时打印原因并跳过（不得静默通过）；证书只用临时目录。
#![allow(dead_code)]
use crate::support::{self, Process};
use crate::tls;
use std::path::PathBuf;
use std::process::Command;

/// 本卡专用环境变量：指向官方 anytls-server 二进制文件（不是目录）。
pub const SERVER_BIN_ENV: &str = "LENGSUO_ANYTLS_SERVER";

/// 定位官方 anytls-server；不可用时打印原因并返回 `None`（对应测试跳过）。
pub fn server_binary() -> Option<PathBuf> {
    match std::env::var(SERVER_BIN_ENV) {
        Err(_) => {
            eprintln!(
                "SKIP: 未设置 {SERVER_BIN_ENV}，跳过官方 anytls-server 客户端方向互通 \
                 （需显式提供 v0.0.13 server 二进制才会执行此用例）"
            );
            None
        }
        Ok(value) if value.trim().is_empty() => {
            eprintln!("SKIP: {SERVER_BIN_ENV} 为空字符串，跳过官方 anytls-server 互通");
            None
        }
        Ok(value) => {
            let path = PathBuf::from(value);
            if path.is_file() {
                Some(path)
            } else {
                eprintln!(
                    "SKIP: {SERVER_BIN_ENV} 指向的二进制不存在或不可执行：{}",
                    path.display()
                );
                None
            }
        }
    }
}

/// 检查 openssl 是否可用；不可用时打印原因并返回 `false`。
pub fn openssl_available() -> bool {
    match Command::new("openssl").arg("version").output() {
        Ok(output) if output.status.success() => true,
        Ok(output) => {
            let text = String::from_utf8_lossy(&output.stderr);
            eprintln!("SKIP: openssl 不可用（退出码非 0：{}）", text.trim());
            false
        }
        Err(err) => {
            eprintln!("SKIP: openssl 不可用：{err}");
            false
        }
    }
}

/// 一次性互通夹具：spawn 官方 server 并持有其 TLS 自签叶子与收尾所需信息。
pub struct Fixture {
    process: Process,
    port: u16,
    cert: Vec<u8>,
    dir: PathBuf,
    log: PathBuf,
}

impl Fixture {
    /// 启动官方 server + 现取证书；缺前置条件时返回 `None`（已打印跳过原因）。
    /// `label` 用于隔离并行用例的临时目录，避免同进程多用例互相删除。
    pub async fn start(label: &str) -> Option<Self> {
        let bin = server_binary()?;
        if !openssl_available() {
            return None;
        }
        let dir = support::temp_dir(label);
        let port = support::free_port();
        let log = dir.join("server.log");
        let mut process = Process::server(&bin, &format!("127.0.0.1:{port}"), &log);
        support::wait_listening(
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            "anytls-server",
        )
        .await;
        let cert = match tls::capture_server_cert(port, &dir) {
            Ok(cert) => cert,
            Err(err) => {
                let _ = process.kill();
                support::remove_temp(&dir);
                panic!("官方 anytls-server TLS 证书现取失败：{err}");
            }
        };
        Some(Self {
            process,
            port,
            cert,
            dir,
            log,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// 参考进程日志路径；失败诊断用（内容不含口令）。
    pub fn log_path(&self) -> &std::path::Path {
        &self.log
    }

    /// 会校验服务端证书与名称的 tokio-rustls 客户端连接器。
    pub fn connector(&self) -> Result<tokio_rustls::TlsConnector, String> {
        tls::verifying_connector(self.cert.clone())
    }

    /// 收尾：kill 官方 server，返回 (退出码, server 日志全文)；删除临时目录。
    pub fn finish(&mut self) -> (Option<i32>, String) {
        let code = self.process.kill();
        let log = support::read_log(&self.log);
        support::remove_temp(&self.dir);
        (code, log)
    }
}

/// 回环 echo 目标：连接后原样回写直到 EOF，返回其地址。
pub async fn spawn_echo() -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("echo 监听失败");
    let addr = echo.local_addr().expect("echo 地址");
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = echo.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(count) => {
                            if socket.write_all(&buffer[..count]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}
