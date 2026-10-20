//! 转发器端到端测试的夹具：回环 echo、本仓 trojan / shadowsocks 服务端、
//! SOCKS5 客户端助手。
//!
//! 全部只绑回环、只用临时端口（`127.0.0.1:0` 交给内核分配）、只用假凭据。
//! **参考服务端用本仓的协议实现**（`lengsuo_trojan::server::Server` 与
//! `lengsuo_shadowsocks::RelayService`），它们与 Xray 的互通结论见各自 crate 的
//! docs；本文件不声称与 Xray 直接互通，只验证「转发器 ↔ 本仓协议服务端」的
//! 端到端转发。

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use lengsuo_node::config::NodeConfig;
use lengsuo_shadowsocks::{CipherSuite, RelayConfig, RelayConfigParts, RelayService};
use lengsuo_tls::PrivatePkcs8KeyDer;
use lengsuo_trojan::server::{
    Inbound as TrojanInbound, Server as TrojanServer, Timeouts, Validator,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// 单步等待。
pub const WAIT: Duration = Duration::from_secs(5);
/// trojan 测试口令（与任何生产凭据无关）。
pub const TROJAN_PASSWORD: &str = "forward-e2e-trojan-password";
/// trojan 错口令用例用（必须被服务端拒绝）。
pub const TROJAN_WRONG_PASSWORD: &str = "forward-e2e-trojan-wrong";
/// shadowsocks 测试口令。
pub const SS_PASSWORD: &str = "forward-e2e-ss-password";
/// shadowsocks 错口令用例用。
pub const SS_WRONG_PASSWORD: &str = "forward-e2e-ss-wrong";

/// 回环 echo：把收到的字节原样回写，直到对端关闭。
///
/// 返回（地址, 已被拨到的连接数）。连接数用于断言「转发器**没有**直连目标」。
pub struct Echo {
    pub addr: SocketAddr,
    pub hits: Arc<AtomicUsize>,
}

/// 起一个回环 echo 服务（绑 `127.0.0.1`）。
pub async fn spawn_echo() -> Echo {
    spawn_echo_on("127.0.0.1:0").await
}

/// 起一个绑在**指定回环 IP** 的 echo 服务。
///
/// 路由用例要用不同 IP 区分目标（`127.0.0.2` / `127.0.0.3`）⇒ 监听器必须
/// 绑在那个 IP 上，回环的 `127.0.0.0/8` 整段都属本机（Linux `lo`）。
pub async fn spawn_echo_on(bind: &str) -> Echo {
    let listener = TcpListener::bind(bind).await.expect("bind echo");
    let addr = listener.local_addr().expect("echo 地址");
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                let _ = stream.shutdown().await;
            });
        }
    });
    Echo { addr, hits }
}

/// 回环 echo：读满一行后回**固定内容**，再关写半。
///
/// 用于路由用例：两个节点各回不同内容，据此断言选对了节点。
pub struct FixedEcho {
    pub addr: SocketAddr,
    pub hits: Arc<AtomicUsize>,
}

/// 起一个「回固定内容」的 echo（绑 `127.0.0.1`）。
pub async fn spawn_fixed_echo(content: &'static [u8]) -> FixedEcho {
    spawn_fixed_echo_on("127.0.0.1:0", content).await
}

/// 起一个绑在**指定回环 IP** 的「回固定内容」echo。
pub async fn spawn_fixed_echo_on(bind: &str, content: &'static [u8]) -> FixedEcho {
    let listener = TcpListener::bind(bind).await.expect("bind echo");
    let addr = listener.local_addr().expect("echo 地址");
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                // 读一点再回，模拟「请求到达才回」。
                let _ = stream.read(&mut buf).await;
                let _ = stream.write_all(content).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    FixedEcho { addr, hits }
}

/// 回环 echo：**读到 EOF 才回内容**（验证「请求方向半关闭后回程仍然通」）。
pub struct DelayedEcho {
    pub addr: SocketAddr,
    pub hits: Arc<AtomicUsize>,
}

/// 起一个「读到 EOF 才回」的 echo。
pub async fn spawn_delayed_echo(content: &'static [u8]) -> DelayedEcho {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo 地址");
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                // 读到对端 EOF（请求方向被半关闭）才回内容。
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
                let _ = stream.write_all(content).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    DelayedEcho { addr, hits }
}

/// 本仓 trojan 服务端（TLS + 多用户校验 + CONNECT 中继）。返回（端口, CA PEM）。
pub async fn trojan_server(password: &'static str) -> (u16, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut validator = Validator::new();
    validator
        .add("user@example.com", password)
        .expect("注册用户");
    let inbound = TrojanInbound::new(
        vec![cert.cert.der().clone()],
        PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        WAIT,
    )
    .expect("TLS 接入配置");
    let server = TrojanServer::with_tls(
        validator,
        Timeouts::new(WAIT, WAIT).expect("超时配置"),
        inbound,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = server.accept_loop(listener).await;
    });
    (port, cert.cert.pem())
}

/// 本仓 shadowsocks 中继服务端。返回（端口）。
///
/// 中继用 `spawn_local`，必须跑在 `LocalSet` 里 ⇒ 放到独立线程 + 单线程 runtime。
pub async fn shadowsocks_server() -> u16 {
    let service = RelayService::bind(
        "127.0.0.1:0".parse().unwrap(),
        RelayConfig::new(
            RelayConfigParts {
                suite: CipherSuite::Aes128Gcm,
                idle_timeout: WAIT,
                replay: None,
            },
            SS_PASSWORD.as_bytes(),
        ),
    )
    .await
    .expect("中继绑定");
    let addr = service.local_addr().expect("中继地址");
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&runtime, async move {
            let handle = service.start().await.expect("中继启动");
            // 保持中继运行到测试进程结束。
            let _handle = handle;
            std::future::pending::<()>().await;
        });
    });
    addr.port()
}

/// trojan 节点配置。
pub fn trojan_node(name: &str, port: u16, ca_pem: &str, password: &str) -> NodeConfig {
    node_from_json(json!({
        "name": name,
        "protocol": "trojan",
        "endpoint": { "host": "127.0.0.1", "port": port },
        "tls": { "server_name": "localhost", "ca_pem": ca_pem },
        "auth": { "password": password }
    }))
}

/// shadowsocks 节点配置。
pub fn shadowsocks_node(name: &str, port: u16, password: &str) -> NodeConfig {
    node_from_json(json!({
        "name": name,
        "protocol": "shadowsocks",
        "endpoint": { "host": "127.0.0.1", "port": port },
        "auth": { "secret_key": password },
        "method": "aes-128-gcm"
    }))
}

/// 由 JSON 构造节点配置（走 serde，与真实配置路径同一条）。
pub fn node_from_json(value: serde_json::Value) -> NodeConfig {
    let nodes: Vec<NodeConfig> = serde_json::from_value(json!([value])).expect("节点配置");
    nodes.into_iter().next().expect("恰好一个节点")
}

/// SOCKS5 CONNECT 请求头（`ATYP=IPv4`）。
pub fn socks5_connect_v4(target: SocketAddr) -> Vec<u8> {
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    let v4 = match target.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        std::net::IpAddr::V6(_) => unreachable!("测试只用 IPv4"),
    };
    request.extend_from_slice(&v4);
    request.extend_from_slice(&target.port().to_be_bytes());
    request
}

/// SOCKS5 CONNECT 请求头（`ATYP=Domain`）。
pub fn socks5_connect_domain(host: &str, port: u16) -> Vec<u8> {
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    request
}

/// SOCKS5 交互的结果。
#[derive(Debug)]
pub enum Socks5Result {
    /// 收到完整回复（`rep` = 回复码），其后的回程载荷是 `payload`。
    Replied { rep: u8, payload: Vec<u8> },
    /// 连接在给出完整回复前就结束（`payload` 是已收到的字节，可能为空）。
    Closed { payload: Vec<u8> },
}

/// 命中计数（echo 被拨到的次数）。
pub fn hits(counter: &AtomicUsize) -> usize {
    counter.load(Ordering::SeqCst)
}

/// 断言 fail-closed：不得报成功、不得有回程字节、目标一次都不能被直连。
pub fn assert_fail_closed(result: &Socks5Result, counter: &AtomicUsize, label: &str) {
    match result {
        Socks5Result::Replied { rep, payload } => {
            assert_ne!(*rep, 0x00, "{label}：不得报成功");
            assert!(payload.is_empty(), "{label}：不得有回程字节：{payload:?}");
        }
        Socks5Result::Closed { payload } => {
            assert!(payload.is_empty(), "{label}：不得有回程字节：{payload:?}");
        }
    }
    assert_eq!(hits(counter), 0, "{label}：不得直连目标");
}

/// 断言「认证被拒」场景：不得有明文回退内容、目标一次都不能被直连。
///
/// **不**断言 SOCKS5 回复码：trojan / shadowsocks **没有**认证成功的正向回执
/// （参考 `proxy/trojan/client.go` 写完头即转发，服务端拒绝的唯一表达是关闭
/// 连接），拒绝在**中继阶段**暴露。
pub fn assert_no_fallback(result: &Socks5Result, counter: &AtomicUsize, label: &str) {
    let payload = match result {
        Socks5Result::Replied { payload, .. } => payload,
        Socks5Result::Closed { payload } => payload,
    };
    assert!(
        payload.is_empty(),
        "{label}：不得收到明文回退内容：{payload:?}"
    );
    assert_eq!(hits(counter), 0, "{label}：不得直连目标");
}

/// 走一遍本地 SOCKS5 转发。
///
/// 写请求头 + 载荷 ⇒ 读回复（最多 10 字节）⇒ 关写半 ⇒ 读回程到 EOF。
///
/// 失败不 panic：返回 `Closed`（连接被断开）或 `Replied{rep}`（失败码）。
pub async fn socks5_roundtrip(proxy: SocketAddr, request: Vec<u8>, payload: &[u8]) -> Socks5Result {
    let Ok(Ok(mut stream)) = timeout(WAIT, TcpStream::connect(proxy)).await else {
        return Socks5Result::Closed {
            payload: Vec::new(),
        };
    };
    if timeout(WAIT, stream.write_all(&request)).await.is_err() {
        return Socks5Result::Closed {
            payload: Vec::new(),
        };
    }
    if timeout(WAIT, stream.write_all(payload)).await.is_err() {
        return Socks5Result::Closed {
            payload: Vec::new(),
        };
    }
    // 读回复（VER|REP|RSV|ATYP|ADDR(4)|PORT = 10 字节）。
    // **必须精确读 10 字节**：多读会把紧随其后的回程载荷吞掉（TCP 不保边界）。
    let mut head = Vec::new();
    let mut buf = [0u8; 10];
    while head.len() < buf.len() {
        let Ok(Ok(n)) = timeout(WAIT, stream.read(&mut buf[head.len()..])).await else {
            return Socks5Result::Closed { payload: head };
        };
        if n == 0 {
            return Socks5Result::Closed { payload: head };
        }
        head.extend_from_slice(&buf[..n]);
    }
    let rep = head[1];
    // 读载荷前先关写半：请求方向结束。
    let _ = stream.shutdown().await;
    let mut got = Vec::new();
    loop {
        match timeout(WAIT, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
            Ok(Err(_)) => break,
            Err(_) => break,
        }
    }
    Socks5Result::Replied { rep, payload: got }
}

/// 只发 SOCKS5 请求头，然后**保持读侧**（用于「本地提前关写半，回程仍通」）。
///
/// 返回（回复码, 连接)。
pub async fn socks5_handshake(
    proxy: SocketAddr,
    request: Vec<u8>,
) -> Result<(u8, TcpStream), String> {
    let mut stream = timeout(WAIT, TcpStream::connect(proxy))
        .await
        .map_err(|_| "连接转发器超时".to_owned())?
        .map_err(|err| format!("连接转发器失败：{err}"))?;
    timeout(WAIT, stream.write_all(&request))
        .await
        .map_err(|_| "写 SOCKS5 请求头超时".to_owned())?
        .map_err(|err| err.to_string())?;
    let mut head = [0u8; 10];
    timeout(WAIT, stream.read_exact(&mut head))
        .await
        .map_err(|_| "读 SOCKS5 回复超时".to_owned())?
        .map_err(|err| err.to_string())?;
    Ok((head[1], stream))
}
