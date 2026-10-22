//! 本仓协议服务端夹具：vless(TLS) / vmess / ss2022 / anytls / hysteria 的
//! 回环服务端与对应节点配置（trojan / shadowsocks / REALITY 复用既有夹具）。
//!
//! 全部只绑回环、临时端口、假凭据。服务端实现全部来自协议 crate 的**公开**
//! 服务端原语；本文件只做「accept → 握手 → 连目标 → 双向回显」的编排，
//! 不复制任何密码学分帧。
//!
//! **不声称与参考实现互通**：这里验证的是「本仓服务端 ↔ 本仓转发器」的
//! 端到端转发；与参考的互通结论见各协议 crate 的文档。

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lengsuo_anytls::server as anytls_server;
use lengsuo_hysteria::quic::server::{HysteriaServer, ServerConfig as HysteriaServerConfig};
use lengsuo_node::config::NodeConfig;
use lengsuo_ss2022::crypto::{Key, Method};
use lengsuo_ss2022::tcp::receive::{clock_at, Association, Reader, SessionReplay};
use lengsuo_ss2022::tcp::{Direction, Opening, Writer};
use lengsuo_tls::{PrivatePkcs8KeyDer, TlsServer};
use lengsuo_vless::stream as vless_stream;
use lengsuo_vmess::chunkframe::{self, DataCipher};
use lengsuo_vmess::consts::SECURITY_AES_128_GCM;
use lengsuo_vmess::server::decode::parse_request_payload;
use lengsuo_vmess::server::{encode_response_header, ResponseHeader};
use md5::Digest as _;
use serde_json::json;
use ss_core::target::TargetAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// 单步等待。
pub const WAIT: Duration = Duration::from_secs(5);
/// 测试 UUID（vless / vmess 共用，假凭据）。
pub const TEST_UUID: &str = "22222222-2222-2222-2222-222222222222";
/// anytls 口令（假凭据）。
pub const ANYTLS_PASSWORD: &str = "anytls-forward-fixture-password";
/// hysteria 认证串（假凭据）。
pub const HYSTERIA_PASSWORD: &str = "hysteria-forward-fixture-auth";
/// ss2022 PSK（16 字节 0x11 的 base64，与 [`SS2022_PSK_BYTES`] 同值）。
pub const SS2022_PSK_B64: &str = "EREREREREREREREREREREQ==";
/// [`SS2022_PSK_B64`] 解码后的原始字节。
pub const SS2022_PSK_BYTES: [u8; 16] = [0x11; 16];

/// 当前 Unix 秒（SIP022 时间戳）。
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("时钟在 Unix 纪元之后")
        .as_secs()
}

/// UUID 文本 → 16 字节（连字符剥掉后按十六进制解析）。
#[must_use]
pub fn uuid_bytes(text: &str) -> [u8; 16] {
    let hex: String = text.chars().filter(|ch| *ch != '-').collect();
    let mut out = [0u8; 16];
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        out[index] = u8::from_str_radix(std::str::from_utf8(chunk).expect("UTF-8"), 16)
            .expect("十六进制字节");
    }
    out
}

/// vmess cmdKey：`MD5(uuid_bytes || "c48619fe-8f02-49e0-b9e9-edf763e17e21")`
/// （参考 `common/protocol/id.go` 的 `NewID`；与服务端校验同一条公式）。
#[must_use]
pub fn vmess_cmd_key(uuid: &str) -> [u8; 16] {
    let mut hasher = md5::Md5::default();
    hasher.update(uuid_bytes(uuid));
    hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    hasher.finalize().into()
}

/// `TargetAddr` → 回环 `SocketAddr`（夹具目标只可能是回环地址）。
#[must_use]
pub fn target_addr(target: &TargetAddr) -> SocketAddr {
    match target {
        TargetAddr::V4(ip, port) => SocketAddr::from((*ip, *port)),
        TargetAddr::V6(ip, port) => SocketAddr::from((*ip, *port)),
        TargetAddr::Domain(host, port) => format!("{host}:{port}")
            .parse()
            .expect("夹具目标是可解析的回环地址"),
    }
}

/// 自签证书（SAN=localhost），返回证书与私钥。
fn self_signed() -> rcgen::CertifiedKey {
    rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("自签证书")
}

/// TLS 服务端接入（TLS1.2/1.3，ring provider，不要求客户端证书）。
fn tls_server(cert: &rcgen::CertifiedKey, wait: Duration) -> Arc<TlsServer> {
    Arc::new(
        TlsServer::new(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
            wait,
        )
        .expect("TLS 服务端配置"),
    )
}

/// vless(TLS) 服务端：TLS → 读 VLESS 请求头 → 连目标 → 回成功头 → 双向回显。
///
/// 返回（端口, CA PEM）。
pub async fn vless_tls_server(uuid: &'static str) -> (u16, String) {
    let cert = self_signed();
    let tls = tls_server(&cert, WAIT);
    let credential = uuid_bytes(uuid);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind vless");
    let port = listener.local_addr().expect("vless 地址").port();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let tls = Arc::clone(&tls);
            tokio::spawn(async move {
                let Ok(mut stream) = tls.accept(socket).await else {
                    return;
                };
                let Ok(request) =
                    vless_stream::receive_request(&mut stream, &credential, WAIT).await
                else {
                    return;
                };
                let Ok(mut target) = TcpStream::connect(target_addr(&request.target)).await else {
                    return;
                };
                // 目标建立成功才回成功头（主链路契约，与参考一致）。
                if vless_stream::send_response(&mut stream, WAIT)
                    .await
                    .is_err()
                {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut target).await;
            });
        }
    });
    (port, cert.cert.pem())
}

/// 服务端侧读 vmess 请求头。
///
/// `decode_request_header` 是同步 `std::io::Read` 接口，异步流没法直接喂；
/// 这里用公开的分段解密原语（`aead::open_request_header_*`）按线序
/// `AuthID(16) + 长度段(18) + nonce(8) + 载荷段(len+16)` 异步读，
/// 再交给公开的纯解析段 `server::parse_request_payload`（重放过滤注入恒真，
/// 每条连接只来一次，不存在重放窗口）。
async fn read_vmess_header<S: AsyncRead + Unpin>(
    stream: &mut S,
    cmd_key: &[u8; 16],
) -> Result<lengsuo_vmess::server::DecodedRequest, String> {
    async fn read_exact<S: AsyncRead + Unpin>(
        stream: &mut S,
        buf: &mut [u8],
    ) -> Result<(), String> {
        timeout(WAIT, stream.read_exact(buf))
            .await
            .map_err(|_| "读请求头超时".to_owned())?
            .map_err(|err| err.to_string())?;
        Ok(())
    }
    let mut auth_id = [0u8; 16];
    read_exact(stream, &mut auth_id).await?;
    let mut length_ct = [0u8; 18];
    read_exact(stream, &mut length_ct).await?;
    let mut nonce = [0u8; 8];
    read_exact(stream, &mut nonce).await?;
    let plain_len =
        lengsuo_vmess::aead::open_request_header_length(cmd_key, &auth_id, &length_ct, &nonce)
            .map_err(|err| err.to_string())?;
    let mut payload_ct = vec![0u8; usize::from(plain_len) + 16];
    read_exact(stream, &mut payload_ct).await?;
    let plain =
        lengsuo_vmess::aead::open_request_header_payload(cmd_key, &auth_id, &nonce, &payload_ct)
            .map_err(|err| err.to_string())?;
    let mut filter = |_: &[u8; 16], _: &[u8; 16], _: &[u8; 16]| true;
    parse_request_payload(std::slice::from_ref(cmd_key), 0, &plain, &mut filter)
        .map_err(|err| err.to_string())
}

/// vmess 服务端：TLS → 解请求头 → 回响应头 → 数据段双向回显（join! 两方向）。
///
/// 请求方向解 chunk 写目标；回程读目标封 chunk；任一侧 EOF 对另一侧半关闭
/// （与转发器 `relay.rs` 的 `join!` 语义对称）。
pub async fn vmess_server(uuid: &'static str) -> (u16, String) {
    let cert = self_signed();
    let tls = tls_server(&cert, WAIT);
    let cmd_key = vmess_cmd_key(uuid);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind vmess");
    let port = listener.local_addr().expect("vmess 地址").port();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let tls = Arc::clone(&tls);
            tokio::spawn(async move {
                let Ok(mut stream) = tls.accept(socket).await else {
                    return;
                };
                let Ok(request) = read_vmess_header(&mut stream, &cmd_key).await else {
                    return;
                };
                let Some(target) = request.target else {
                    return;
                };
                let Ok(target_stream) = TcpStream::connect(target_addr(&target)).await else {
                    return;
                };
                let mut head = Vec::new();
                if encode_response_header(
                    request.response_header,
                    &request.request_body_key,
                    &request.request_body_iv,
                    &ResponseHeader::new(),
                    &mut head,
                )
                .is_err()
                {
                    return;
                }
                if stream.write_all(&head).await.is_err() {
                    return;
                }
                let (mut read_half, mut write_half) = tokio::io::split(stream);
                let (mut target_read, mut target_write) = tokio::io::split(target_stream);
                let mut request_cipher = DataCipher::new(
                    SECURITY_AES_128_GCM,
                    &request.request_body_key,
                    &request.request_body_iv,
                );
                let (resp_key, resp_iv) = lengsuo_vmess::server::respond::response_key_iv(
                    &request.request_body_key,
                    &request.request_body_iv,
                );
                let mut response_cipher =
                    DataCipher::new(SECURITY_AES_128_GCM, &resp_key, &resp_iv);
                let to_target = async {
                    loop {
                        match chunkframe::read_data_chunk(&mut request_cipher, None, &mut read_half)
                            .await
                        {
                            Ok(Some(chunk)) => {
                                if target_write.write_all(&chunk).await.is_err() {
                                    return;
                                }
                            }
                            // 请求方向 EOF ⇒ 半关闭目标写侧，回程继续。
                            Ok(None) => {
                                let _ = target_write.shutdown().await;
                                return;
                            }
                            Err(_) => return,
                        }
                    }
                };
                let to_client = async {
                    let mut buf = [0u8; 8192];
                    loop {
                        match target_read.read(&mut buf).await {
                            Ok(0) | Err(_) => {
                                let _ = chunkframe::write_eof(
                                    &mut response_cipher,
                                    None,
                                    &mut write_half,
                                )
                                .await;
                                return;
                            }
                            Ok(n) => {
                                if chunkframe::write_data_chunk(
                                    &mut response_cipher,
                                    None,
                                    &mut write_half,
                                    &buf[..n],
                                )
                                .await
                                .is_err()
                                {
                                    return;
                                }
                            }
                        }
                    }
                };
                tokio::join!(to_target, to_client);
            });
        }
    });
    (port, cert.cert.pem())
}

/// ss2022 服务端：读请求流开场（真实目标）→ 连目标 → 回响应流开场 → 双向回显。
///
/// 返回端口。`Reader` / `Writer` 是对称原语：服务端请求方向用 `Direction::Request`
/// 读、响应方向用 `Direction::Response` 写，响应固定头原样回带请求 salt。
pub async fn ss2022_server() -> u16 {
    let key = Key::new(Method::Aes128, &SS2022_PSK_BYTES).expect("ss2022 密钥");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind ss2022");
    let port = listener.local_addr().expect("ss2022 地址").port();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let key = key.clone();
            tokio::spawn(async move {
                let (mut read_half, mut write_half) = tokio::io::split(socket);
                let Ok(mut reader) = Reader::new(key.clone(), Direction::Request, WAIT) else {
                    return;
                };
                let Ok(mut replay) = SessionReplay::new(Duration::from_secs(60)) else {
                    return;
                };
                let clock = clock_at(now_secs(), Instant::now());
                let Ok(opened) = reader.open(&mut read_half, &mut replay, clock, None).await else {
                    return;
                };
                let Association::Request(target) = &opened.association else {
                    return;
                };
                let Ok(mut target_stream) = TcpStream::connect(target_addr(target)).await else {
                    return;
                };
                let Ok(mut writer) = Writer::new(
                    &key,
                    Direction::Response,
                    Opening::injected(&opened.request_salt),
                ) else {
                    return;
                };
                if writer
                    .write_response_header(&mut write_half, &opened.request_salt, &[], now_secs())
                    .await
                    .is_err()
                {
                    return;
                }
                if !opened.payload.is_empty()
                    && target_stream.write_all(&opened.payload).await.is_err()
                {
                    return;
                }
                let (mut target_read, mut target_write) = tokio::io::split(target_stream);
                let to_target = async {
                    loop {
                        match reader.read_payload(&mut read_half).await {
                            Ok(Some(chunk)) => {
                                if target_write.write_all(&chunk).await.is_err() {
                                    return;
                                }
                            }
                            // 终止 chunk ⇒ 半关闭目标写侧，回程继续。
                            Ok(None) => {
                                let _ = target_write.shutdown().await;
                                return;
                            }
                            Err(_) => return,
                        }
                    }
                };
                let to_client = async {
                    let mut buf = [0u8; 8192];
                    loop {
                        match target_read.read(&mut buf).await {
                            Ok(0) | Err(_) => {
                                let _ = writer.write_finish(&mut write_half).await;
                                return;
                            }
                            Ok(n) => {
                                if writer
                                    .write_payload(&mut write_half, &buf[..n])
                                    .await
                                    .is_err()
                                {
                                    return;
                                }
                            }
                        }
                    }
                };
                tokio::join!(to_target, to_client);
            });
        }
    });
    port
}

/// anytls 服务端：TLS → 本仓 `server::serve`（认证 / SYN / PUSH 地址解析 / 帧中继）。
///
/// 返回（端口, CA PEM）。
pub async fn anytls_server(password: &'static str) -> (u16, String) {
    let cert = self_signed();
    let tls = tls_server(&cert, WAIT);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind anytls");
    let port = listener.local_addr().expect("anytls 地址").port();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let tls = Arc::clone(&tls);
            tokio::spawn(async move {
                let Ok(stream) = tls.accept(socket).await else {
                    return;
                };
                let _ = anytls_server::serve(
                    stream,
                    anytls_server::ServerConfig::new(password.as_bytes(), WAIT),
                )
                .await;
            });
        }
    });
    (port, cert.cert.pem())
}

/// hysteria 服务端：QUIC/H3 → 本仓 `HysteriaServer::accept_loop`
/// （认证 + TCP 承载请求 + 连目标）。返回（UDP 端口, CA PEM）。
pub async fn hysteria_server(auth: &'static str) -> (u16, String) {
    let cert = self_signed();
    let server = Arc::new(
        HysteriaServer::bind(HysteriaServerConfig::new(
            "127.0.0.1:0".parse().expect("回环地址"),
            vec![cert.cert.der().clone().to_vec()],
            cert.key_pair.serialize_der(),
            auth.to_owned(),
        ))
        .expect("hysteria 服务端"),
    );
    let port = server.local_addr().expect("hysteria 地址").port();
    tokio::spawn(async move {
        server.accept_loop().await;
    });
    (port, cert.cert.pem())
}

/// vless(TLS) 节点配置。
#[must_use]
pub fn vless_node(name: &str, port: u16, ca_pem: &str, uuid: &str) -> NodeConfig {
    node_from_json(json!({
        "name": name,
        "protocol": "vless",
        "endpoint": { "host": "127.0.0.1", "port": port },
        "tls": { "server_name": "localhost", "ca_pem": ca_pem },
        "auth": { "password": uuid }
    }))
}

/// vmess 节点配置。
#[must_use]
pub fn vmess_node(name: &str, port: u16, ca_pem: &str, uuid: &str) -> NodeConfig {
    node_from_json(json!({
        "name": name,
        "protocol": "vmess",
        "endpoint": { "host": "127.0.0.1", "port": port },
        "tls": { "server_name": "localhost", "ca_pem": ca_pem },
        "auth": { "password": uuid }
    }))
}

/// ss2022 节点配置。
#[must_use]
pub fn ss2022_node(name: &str, port: u16) -> NodeConfig {
    node_from_json(json!({
        "name": name,
        "protocol": "ss2022",
        "endpoint": { "host": "127.0.0.1", "port": port },
        "auth": { "secret_key": SS2022_PSK_B64 },
        "method": "2022-blake3-aes-128-gcm"
    }))
}

/// anytls 节点配置。
#[must_use]
pub fn anytls_node(name: &str, port: u16, ca_pem: &str, password: &str) -> NodeConfig {
    node_from_json(json!({
        "name": name,
        "protocol": "anytls",
        "endpoint": { "host": "127.0.0.1", "port": port },
        "tls": { "server_name": "localhost", "ca_pem": ca_pem },
        "auth": { "password": password }
    }))
}

/// hysteria 节点配置（endpoint 是 UDP 端口）。
#[must_use]
pub fn hysteria_node(name: &str, port: u16, ca_pem: &str, password: &str) -> NodeConfig {
    node_from_json(json!({
        "name": name,
        "protocol": "hysteria",
        "endpoint": { "host": "127.0.0.1", "port": port },
        "tls": { "server_name": "localhost", "ca_pem": ca_pem },
        "auth": { "password": password }
    }))
}

/// wireguard 节点配置（仅用于「结构性不可转发 ⇒ 显式拒绝」反例；
/// 密钥是假值，转发层在建会话前就拒绝，不发起任何连接）。
#[must_use]
pub fn wireguard_node(name: &str, port: u16) -> NodeConfig {
    node_from_json(json!({
        "name": name,
        "protocol": "wireguard",
        "endpoint": { "host": "127.0.0.1", "port": port },
        "auth": {
            "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        }
    }))
}

/// 由 JSON 构造节点配置（走 serde，与真实配置路径同一条）。
#[must_use]
pub fn node_from_json(value: serde_json::Value) -> NodeConfig {
    let nodes: Vec<NodeConfig> = serde_json::from_value(json!([value])).expect("节点配置");
    nodes.into_iter().next().expect("恰好一个节点")
}
