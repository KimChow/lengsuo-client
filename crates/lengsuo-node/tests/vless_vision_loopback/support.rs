//! VLESS Vision 回环夹具：本仓 Vision 服务端 + node 侧节点配置。
//!
//! 服务端编排照抄 `crates/lengsuo-vless/tests/vision_wire/session.rs`：
//! TLS 握手 → 读 VLESS 请求头（`header::decode_vision`）→ [`VisionServer`] 解
//! 上行 vision 块 → 写 VLESS 响应头（`[0, 0]`）+ 下行 vision 块。
//!
//! **本文件不声称与参考实现互通**：它只提供「本仓服务端 ↔ 本仓客户端」的端到端
//! 夹具。与参考的互通结论见 `crates/lengsuo-vless/tests/xray_vision.rs`（库层
//! 已有真实对端证据），**node 侧**尚未与参考对端互通（见本卡报告偏离清单）。
//!
//! 全部只绑回环、只用临时端口（`127.0.0.1:0` 交给内核分配）、只用假凭据。
//! 每个网络操作都有截止时间；日志不输出任何密钥材料。

#![allow(dead_code)]

use std::time::Duration;

use lengsuo_node::config::NodeConfig;
use lengsuo_tls::{PrivatePkcs8KeyDer, TlsServer};
use lengsuo_vless::header::{self, Command};
use lengsuo_vless::vision::server::VisionServer;
use lengsuo_vless::vision_wire::{RecordConfig, RecordStream};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

/// 单步截止时间（建流 / 帧读写）。
pub const WAIT: Duration = Duration::from_secs(8);
/// 用例总截止时间。
pub const DEADLINE: Duration = Duration::from_secs(30);
/// 测试用 UUID（假凭据；服务端与 node 侧共用同一份）。
pub const UUID: &str = "11111111-1111-1111-1111-111111111111";
/// 服务端读 VLESS 头时用的凭据（与 UUID 文本的 16 字节一致）。
pub const KEY: [u8; 16] = [0x11; 16];
/// 回环载荷（含二进制字节）。
pub const PAYLOAD: &[u8] = b"node vless vision payload\0\xff\xfe binary";
/// 记录层测试用的假密钥材料（十六进制文本，运行时生成 ⇒ 不是真凭据）。
pub const RECORD_KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
/// 记录层测试用的派生上下文。
pub const RECORD_CTX: &str = "node-vision-ctx";

/// 双向流抽象（读 + 写）。
pub trait Duplex: AsyncRead + AsyncWrite + Unpin {}
impl<T> Duplex for T where T: AsyncRead + AsyncWrite + Unpin {}

/// 装箱后的双向流。
pub type BoxedDuplex = Box<dyn Duplex>;

/// 命令常量（回环服务端只接受 TCP 命令）。
pub const COMMAND_TCP: Command = Command::Tcp;

/// 参考 `EncodeResponseHeader`：版本字节 + addons 长度字节（响应的 addons 恒为空）。
pub fn encode_response_header(version: u8) -> Vec<u8> {
    vec![version, 0u8]
}

/// 从承载流读出 VLESS 请求头，返回 `(请求头字节, 剩余的 vision 块字节)`。
///
/// 参考服务端 `DecodeRequestHeader`：先读版本、UUID、addons，再读 command 与地址。
pub async fn read_request_header(reader: &mut (impl AsyncRead + Unpin)) -> (Vec<u8>, Vec<u8>) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        let read = tokio::time::timeout(WAIT, reader.read(&mut chunk))
            .await
            .expect("读超时")
            .unwrap();
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Ok((_, _, consumed)) = header::decode_vision(&buffer) {
            let head = buffer[..consumed].to_vec();
            let rest = buffer[consumed..].to_vec();
            return (head, rest);
        }
    }
    panic!("请求头未读全");
}

/// node 配置：vless + Vision 流量层（可选记录层）。
///
/// `record` 为 `None` ⇒ 只走流量层（与参考互通时的普通 vision 流：
/// `decryption: "none"`）；`Some((cipher, ctx, key_hex))` ⇒ 追加记录层配置段。
#[must_use]
pub fn vision_node(port: u16, ca_pem: &str, record: Option<(&str, &str, &str)>) -> NodeConfig {
    let mut value = json!([{
        "name": "vless-vision-loopback",
        "protocol": "vless",
        "endpoint": { "host": "127.0.0.1", "port": port },
        "tls": {
            "server_name": "localhost",
            "ca_pem": ca_pem
        },
        "auth": { "password": UUID },
        "vision": { "flow": "xtls-rprx-vision" }
    }]);
    if let Some((cipher, ctx, key_hex)) = record {
        value[0]["encryption"] = json!({
            "cipher": cipher,
            "ctx": ctx,
            "key": key_hex
        });
    }
    let nodes: Vec<NodeConfig> = serde_json::from_value(value).expect("节点配置");
    nodes.into_iter().next().expect("恰好一个节点")
}

/// 回环服务端的三件套：端口、信任锚 PEM、监听器 + TLS 服务端。
pub struct VisionServerFixture {
    /// 监听端口（node 侧连它）。
    pub port: u16,
    /// 自签证书的 PEM（node 侧的信任锚）。
    pub ca_pem: String,
    listener: TcpListener,
    tls: TlsServer,
}

/// 备好一个只服务一次连接的 TLS + Vision 服务端（尚未 accept）。
pub async fn vision_server_fixture() -> VisionServerFixture {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let ca_pem = cert.cert.pem().to_owned();
    let tls = TlsServer::new(
        vec![cert.cert.der().clone()],
        PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        WAIT,
    )
    .expect("TLS 服务端");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("回环监听");
    let port = listener.local_addr().unwrap().port();
    VisionServerFixture {
        port,
        ca_pem,
        listener,
        tls,
    }
}

/// 服务端：TLS 握手 → 读 VLESS 请求头 → 写响应头 → 解上行 → 回环写下行。
///
/// `record` 为 `Some` ⇒ 承载流外套 AEAD 记录层（与 node 侧对称；参考里
/// `CommonConn` 同时管读写，响应头也走记录层）。
///
/// `uuid` 用来模拟「**错 UUID 被拒**」：请求头里的 UUID 与服务端不匹配时，
/// 服务端直接断开（fail-closed），不回成功响应头。
pub async fn serve_vision(
    fixture: VisionServerFixture,
    uuid: [u8; 16],
    record: Option<RecordConfig>,
) -> Result<Vec<u8>, String> {
    let VisionServerFixture { listener, tls, .. } = fixture;
    let (socket, _) = listener.accept().await.map_err(|e| e.to_string())?;
    let tls_stream = tls.accept(socket).await.map_err(|e| e.to_string())?;

    // 承载流：可选地套 AEAD 记录层（参考 `CommonConn` 同时管读写）。
    let mut stream: BoxedDuplex = match record {
        Some(config) => {
            Box::new(RecordStream::new(tls_stream, &config).map_err(|e| e.to_string())?)
        }
        None => Box::new(tls_stream),
    };

    let (head, rest) = read_request_header(&mut stream).await;

    // 请求头里的 UUID 必须与本服务端一致（参考服务端按用户 UUID 路由）。
    let client_uuid: [u8; 16] = head[1..17].try_into().expect("16 字节 UUID");
    if client_uuid != uuid {
        // 认证失败 ⇒ 断开（参考服务端的行为：认证不过直接关连接）。
        return Err("UUID 不匹配".to_owned());
    }
    if header::decode_vision(&head).is_err() {
        return Err("请求头不是 vision 形态".to_owned());
    }

    // 参考服务端（`proxy/vless/inbound/inbound.go:619`）：**响应头先写并刷出**，
    // 目标连上后才有的下游数据随后写。此处不插空 padding 块：参考的响应头本身就
    // 是一次独立写出，下行 vision 块由后续 `WriteMultiBuffer` 产生。
    stream
        .write_all(&encode_response_header(0))
        .await
        .map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;

    // 等客户端载荷（上行 vision 块），回环写回。
    //
    // ⚠️ `VisionServer` 的随机源不是 `Send`（`vision/server.rs` 的 RNG 边界）
    // ⇒ 它**不能**跨 `.await` 存活。本夹具因此**不在 `tokio::spawn` 里跑**，
    // 而是让调用方用 `tokio::join!` 与客户端并发驱动（同一任务 ⇒ 无 `Send` 要求）。
    //
    // 解块是**有状态**的（padding 状态机跨块延续）⇒ 同一个 `VisionServer` 必须
    // 活过整个上行解包过程。故这里把「读字节」与「解块」放在**同一个**作用域里，
    // 作用域内**没有** `.await`（await 全部在作用域外）。
    let mut uplink = Vec::new();
    let mut chunk = [0u8; 4096];
    {
        let mut reader = VisionServer::new_with_os_rng(uuid, None);
        // 先把随请求头一同到达的首块解掉。
        reader.decode_uplink(&rest, &mut uplink);
        loop {
            let read = tokio::time::timeout(WAIT, stream.read(&mut chunk))
                .await
                .map_err(|_| "读上行超时".to_owned())?
                .map_err(|e| e.to_string())?;
            if read == 0 {
                break;
            }
            // ⛔ 这里不能有 `.await`：`reader` 不是 `Send`。
            reader.decode_uplink(&chunk[..read], &mut uplink);
            if uplink.len() >= PAYLOAD.len() {
                break;
            }
        }
    }

    // 写下行 vision 块（回环：把上行明文原样回送）。
    let down = {
        let mut writer = VisionServer::new_with_os_rng(uuid, None);
        let mut out = writer.encode_downlink(&uplink, false);
        out.extend_from_slice(&writer.encode_downlink_finish());
        out
    };
    stream.write_all(&down).await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;
    Ok(uplink)
}

/// 起一个**只 accept** 的监听器：用于「坏配置下没有建立连接」的判定。
///
/// 返回（端口，accept 计数句柄，观察任务）。观察任务在**没有连接**时一直挂着
/// （直到调用方的截止时间到），有连接则记一次数并立刻返回。
pub async fn accept_only_watcher() -> (
    u16,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = std::sync::Arc::clone(&accepted);
    let watcher = tokio::spawn(async move {
        if let Ok((socket, _)) = listener.accept().await {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            drop(socket);
        }
    });
    (port, accepted, watcher)
}

/// 记录层配置（服务端侧）：与 node 侧用同一份 ctx / key / cipher。
#[must_use]
pub fn record_config(cipher: &str, ctx: &str, key_hex: &str) -> RecordConfig {
    let bytes: Vec<u8> = (0..key_hex.len() / 2)
        .map(|index| u8::from_str_radix(&key_hex[index * 2..index * 2 + 2], 16).expect("十六进制"))
        .collect();
    let cipher = match cipher {
        "aes-256-gcm" => lengsuo_vless::vision::record::Cipher::Aes256Gcm,
        _ => lengsuo_vless::vision::record::Cipher::ChaCha20Poly1305,
    };
    RecordConfig {
        ctx: ctx.to_owned(),
        key: bytes,
        cipher,
    }
}
