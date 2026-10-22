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

// 各协议服务端夹具按协议拆到 `servers/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样 `pub` 可见性与拆分前逐字一致，调用方 `use servers::{...}`
// 无需改动。分文件里不写 `use`，全部留在本入口文件。
include!("servers/vless.rs");
include!("servers/vmess.rs");
include!("servers/ss2022.rs");
include!("servers/tls_servers.rs");
include!("servers/nodes.rs");
