//! WireGuard 出口：UDP → Noise IK 握手 → transport 会话密钥。
//!
//! 语义来源（只读参考，**wireguard-go** commit
//! `2631ce99a06f27120d581611cf125d68bc6aa565` 的 `device/noise-protocol.go`，
//! 由本仓 `lengsuo-wireguard::handshake` 转写；Xray 侧只有出站承载、没有
//! WireGuard 协议实现，因此本协议的对齐对象是 wireguard-go）：
//! 发起方 `CreateMessageInitiation`（148B：type/sender/ephemeral/encrypted_static/
//! encrypted_timestamp/mac1/mac2）→ 收 `MessageResponse`（92B）→
//! `ConsumeMessageResponse` 认证解封并派生 transport 收发密钥与两侧 index。
//!
//! **认证完成的正向证据**：`Handshake::consume_response` 返回 `Ok(TransportKeys)`
//! ——响应里的 `empty` 段是在握手 hash 上下文下用派生密钥 AEAD 封装的，
//! 只有持有对端静态私钥的真实对端才可能构造出通过认证的响应；错密钥（对端
//! 公钥不匹配本端配置 / 响应被篡改）一律 `AuthFailed` 并 poison 握手对象。
//!
//! 本卡范围：建立到握手完成（transport 密钥已就绪）。keepalive 计时、
//! 密钥轮换、COOKIE 重试状态机与 TUN 设备不在本卡（对齐 crate 的未实现清单）。
//!
//! 偏离：本卡**只做到握手完成**，不发送 transport 载荷帧；因此「认证完成」
//! 是正向证据（响应已通过 AEAD 认证），不是 trojan 那种负向排除。

use std::net::SocketAddr;
use std::time::Duration;

use lengsuo_wireguard::handshake::{Handshake, TransportKeys};
use lengsuo_wireguard::wire::{INIT_LEN, RESPONSE_LEN};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::config::NodeConfig;
use crate::outbound::{resolve_public, DialError};

/// Noise 响应帧长度（`RESPONSE_LEN`，92 字节）。
const RESPONSE_LEN_USIZE: usize = RESPONSE_LEN;
/// 握手 initiation 帧长度（148 字节），仅用于断言。
const INIT_LEN_USIZE: usize = INIT_LEN;

/// WireGuard 出站会话：Noise 响应已认证，transport 密钥已派生。
pub struct WireguardOutbound {
    /// 派生的 transport 收发密钥与两侧 index（不含口令，Debug 只输出 index）。
    pub keys: TransportKeys,
}

impl std::fmt::Debug for WireguardOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 密钥材料不得进入日志；只报告 index。
        f.debug_struct("WireguardOutbound")
            .field("local_index", &self.keys.local_index)
            .field("remote_index", &self.keys.remote_index)
            .finish_non_exhaustive()
    }
}

/// WireGuard 出站：UDP → initiation → 收 response → 认证解封并派生密钥。
pub async fn dial_wireguard(
    config: &NodeConfig,
    wait: Duration,
) -> Result<WireguardOutbound, DialError> {
    let private = base64_key(config.auth.private_key.as_deref())?;
    let public = base64_key(config.auth.public_key.as_deref())?;
    // PSK 复用 `auth.secret_key`（可选）；长度必须恰为 32。
    let psk = match config.auth.secret_key.as_deref() {
        None => None,
        Some(raw) => {
            let psk = base64_key(Some(raw))?;
            Some(psk)
        }
    };
    let remote: SocketAddr = resolve_public(&config.endpoint.host, config.endpoint.port, wait)
        .await
        .map_err(|err| match err {
            DialError::Timeout => DialError::Timeout,
            other => DialError::Resolve(other.to_string()),
        })?;

    let socket = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .map_err(|err| DialError::Resolve(format!("本机 UDP 端口绑定失败：{err}")))?;
    socket
        .connect(remote)
        .await
        .map_err(|err| DialError::Resolve(format!("UDP connect 失败：{err}")))?;

    // 本地 sender index：WireGuard 参考用随机 u32（`device.NewIndex` 取 32 位随机）。
    let local_index = random_index()?;
    let mut handshake = Handshake::new(&private, &public, psk, local_index).map_err(|err| {
        // crate 的 `transport::Error::AuthFailed` 表示密钥非法（全零 / 不可贡献）。
        DialError::Rejected(format!("WireGuard 静态密钥非法：{err}"))
    })?;
    let initiation = handshake
        .create_initiation(random_seed()?)
        .map_err(|err| DialError::Rejected(format!("WireGuard initiation 构造失败：{err}")))?;
    debug_assert_eq!(initiation.len(), INIT_LEN_USIZE);
    timeout(wait, socket.send(&initiation))
        .await
        .map_err(|_| DialError::Timeout)?
        .map_err(|err| DialError::Rejected(format!("initiation 发送失败：{err}")))?;

    // 正向证据：只有真实对端（持有与配置公钥对应的静态私钥）才能构造出通过
    // AEAD 认证的响应；错密钥在此 fail-closed。
    // 缓冲上界取固定 2048：既覆盖 RESPONSE_LEN(92)，又避免在常量里调用
    // 非 const 的 Ord::max。实际收到的字节数由 `received` 约束。
    let mut buffer = [0u8; 2048];
    debug_assert!(RESPONSE_LEN_USIZE <= buffer.len());
    let received = timeout(wait, socket.recv(&mut buffer))
        .await
        .map_err(|_| DialError::Timeout)?
        .map_err(|err| DialError::Rejected(format!("等待握手响应失败：{err}")))?;
    let keys = handshake
        .consume_response(&buffer[..received])
        .map_err(|err| DialError::Rejected(format!("WireGuard 握手响应认证失败：{err}")))?;
    Ok(WireguardOutbound { keys })
}

/// base64 静态密钥 → 32 字节。长度不符或非法字符一律 fail-closed。
fn base64_key(raw: Option<&str>) -> Result<[u8; 32], DialError> {
    let Some(text) = raw else {
        return Err(DialError::Rejected("WireGuard 缺少静态密钥".to_owned()));
    };
    let decoded = crate::outbound_ss2022::base64_decode_public(text)
        .ok_or_else(|| DialError::Rejected("WireGuard 密钥不是合法 base64".to_owned()))?;
    decoded
        .try_into()
        .map_err(|_| DialError::Rejected("WireGuard 密钥长度不是 32 字节".to_owned()))
}

/// 32 字节 CSPRNG 种子（临时密钥）。
fn random_seed() -> Result<[u8; 32], DialError> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|_| DialError::Rejected("系统随机数不可用".to_owned()))?;
    Ok(seed)
}

/// 本端 sender index（随机 u32，非 0）。全零 index 在参考里是保留值。
fn random_index() -> Result<u32, DialError> {
    loop {
        let mut bytes = [0u8; 4];
        getrandom::getrandom(&mut bytes)
            .map_err(|_| DialError::Rejected("系统随机数不可用".to_owned()))?;
        let index = u32::from_le_bytes(bytes);
        if index != 0 {
            return Ok(index);
        }
    }
}
