//! SIP023 可扩展身份头（EIH）的 **UDP 侧** 编解码。
//!
//! 逐字节对齐固定参考 sing-shadowsocks v0.2.7
//! （`33d53914d77baed427af52075dceb4a9756183f4`）：
//! - 客户端 `shadowaead_2022/protocol.go:468` `clientPacketConn.WritePacket`；
//! - 服务端 `shadowaead_2022/service_multi.go:269` `MultiService.newPacket`。
//!
//! 线上布局（AES 路径，链长 N）：
//!
//! ```text
//! [ separate header 16 ][ 身份头 × N（每层 16） ][ AEAD 密文 ]
//! ```
//!
//! - separate header 的**明文**是 `session id(u64be) || packet id(u64be)`；
//!   请求方向用**服务端身份 PSK** 的 AES 块密码加密（参考
//!   `udpBlockEncryptCipher` = `aes.NewCipher(pskList[0])`），响应方向用**最终用户
//!   PSK**（参考 `uCipher[user]`）。
//! - 第 i 层身份头（`0 <= i < N`）为
//!   `AES-ECB-encrypt(PSK_i, BLAKE3-512(PSK_{i+1})[0..16] XOR separate_header_明文)`。
//!   **加密用第 i 层的 PSK，指纹取第 i+1 层的 PSK**（参考 `protocol.go:511-519`），
//!   两者不可混淆；XOR 对象恒为 separate header 的**明文**前 16 字节。
//! - AEAD 会话密钥由**最终用户 PSK** 与 session id 派生，nonce 取 separate header
//!   明文的后 12 字节（`separate_header[4..16]`）。
//!
//! **层数语义**：参考服务端只剥**一层**身份头（`service_multi.go:277-289` 只取第 2
//! 个 16 字节块；`binary.Read` 读走 separate header 后 `Advance(16)` 跳过身份头），
//! 多用户是**逐跳剥离**（中继每跳剥一层），**不是**服务端一次性剥 N 层。
//! 本模块把期望层数显式化：[`EihUdpServer::new`] 的 `layers == 1` 与参考逐字节
//! 一致；`layers > 1` 是逐层剥离的**显式推广**，不等价于参考实现（见偏离清单）。
//!
//! **ChaCha 多用户**：参考 `protocol.go:495-497` 直接
//! `panic("unsupported chacha extended header")`；本实现 **fail-closed** 返回
//! [`Error::Unsupported`]，既不 panic 也不按 AES 处理。
//!
//! 失败一律 fail-closed：错误与 `Debug` 均不含 PSK、身份指纹或密文。
use crate::{
    crypto::Key,
    eih::{require_aes, UserTable},
    packet::{self, Decoded},
    receiver::{Clock, Sessions},
    replay_store::ReplayStore,
    Error,
};
use ss_core::target::TargetAddr;
use std::{net::SocketAddr, time::Duration};

/// UDP separate header 长度（AES 块）。
pub const UDP_SEPARATE_HEADER_LEN: usize = 16;
/// 身份头层数策略上限，与 TCP 侧 [`crate::eih::MAX_IDENTITY_LAYERS`] 一致。
pub const MAX_UDP_IDENTITY_LAYERS: usize = crate::eih::MAX_IDENTITY_LAYERS;
/// UDP 数据报上限（与既有 `packet` 模块一致）。
const MAX_DATAGRAM: usize = 65507;
/// AEAD 体的最小长度：方向(1) + 时间戳(8) + padding 长度(2) + ATYP(1) + tag(16)。
const MIN_AEAD_BODY: usize = 1 + 8 + 2 + 1 + 16;

/// 客户端 UDP 身份链：`psks[0]` 是服务端身份 PSK，`psks[last]` 是最终用户 PSK。
///
/// 线上写入 `psks.len() - 1` 层身份头（参考 `protocol.go:508-525` 的 `break`
/// 使实际写入层数等于 `pskLen - 1`）。
pub struct EihUdpChain {
    psks: Vec<Key>,
}
impl EihUdpChain {
    /// 至少两个 PSK；层数 = `psks.len() - 1`；全部同套件且必须是 AES。
    ///
    /// ChaCha 多用户被拒绝（[`Error::Unsupported`]）：参考实现直接 panic，
    /// 本实现 fail-closed，绝不静默按 AES 处理。
    pub fn new(psks: Vec<Key>) -> Result<Self, Error> {
        if psks.len() < 2 {
            return Err(Error::EihMissing);
        }
        if psks.len() - 1 > MAX_UDP_IDENTITY_LAYERS {
            return Err(Error::EihChainTooLong);
        }
        // ChaCha 多用户：参考实现直接 panic，本实现 fail-closed。
        require_aes(psks[0].method())?;
        let method = psks[0].method();
        for psk in &psks {
            if psk.method() != method {
                return Err(Error::KeyLength);
            }
        }
        Ok(Self { psks })
    }
    /// 线上身份头层数。
    pub fn layers(&self) -> usize {
        self.psks.len() - 1
    }
    /// 最终用户 PSK：AEAD 会话密钥由它派生。
    pub fn final_key(&self) -> &Key {
        &self.psks[self.psks.len() - 1]
    }
}

/// UDP 客户端发送端：持有身份链、会话 id 与发包计数器。
pub struct EihUdpSender {
    chain: EihUdpChain,
    session_id: [u8; 8],
    next: Option<u64>,
}
impl EihUdpSender {
    /// 会话 id 取自系统随机源。
    pub fn new(chain: EihUdpChain) -> Result<Self, Error> {
        let mut session_id = [0u8; 8];
        getrandom::getrandom(&mut session_id).map_err(|_| Error::Entropy)?;
        Ok(Self {
            chain,
            session_id,
            next: Some(0),
        })
    }
    /// 本端会话 id（响应方向必须回带）。
    pub fn session_id(&self) -> [u8; 8] {
        self.session_id
    }
    /// 身份链层数。
    pub fn layers(&self) -> usize {
        self.chain.layers()
    }
    /// 封包：`[separate header][身份头 × N][AEAD 密文]`。
    ///
    /// AEAD 明文体：`方向(0=客户端) | 时间戳 | padding 长度 | padding | addrport | 载荷`。
    pub fn seal(
        &mut self,
        target: &TargetAddr,
        payload: &[u8],
        now: u64,
        padding: u16,
    ) -> Result<Vec<u8>, Error> {
        let id = self.next.ok_or(Error::Exhausted)?;
        let layers = self.chain.layers();
        let mut header = [0u8; UDP_SEPARATE_HEADER_LEN];
        header[..8].copy_from_slice(&self.session_id);
        header[8..].copy_from_slice(&id.to_be_bytes());
        // 身份头：第 i 层用 PSK_i 加密，指纹取 PSK_{i+1}；XOR 对象恒为
        // separate header 的**明文**前 16 字节（参考 `header.To(aes.BlockSize)`）。
        let mut identity = Vec::with_capacity(layers * UDP_SEPARATE_HEADER_LEN);
        for index in 0..layers {
            let mut block = self.chain.psks[index + 1].identity_hash();
            for (byte, sep) in block.iter_mut().zip(header.iter()) {
                *byte ^= sep;
            }
            identity.extend_from_slice(&self.chain.psks[index].header(block, true)?);
        }
        let mut plain = Vec::new();
        plain.push(0);
        plain.extend_from_slice(&now.to_be_bytes());
        plain.extend_from_slice(&padding.to_be_bytes());
        plain.resize(plain.len() + padding as usize, 0);
        target.encode_checked(&mut plain)?;
        plain.extend_from_slice(payload);
        let total = plain
            .len()
            .checked_add(UDP_SEPARATE_HEADER_LEN + layers * UDP_SEPARATE_HEADER_LEN)
            .and_then(|n| n.checked_add(16))
            .ok_or(Error::Length)?;
        if total > MAX_DATAGRAM {
            return Err(Error::Length);
        }
        let final_key = self.chain.final_key();
        let subkey = final_key.subkey(&self.session_id);
        let ciphertext = final_key.body(&subkey, &header[4..16], &plain, true)?;
        // separate header 用服务端身份 PSK 的 AES 块密码加密（参考
        // `udpBlockEncryptCipher`，即 `pskList[0]`）。
        let mut packet = self.chain.psks[0].header(header, true)?.to_vec();
        packet.extend_from_slice(&identity);
        packet.extend_from_slice(&ciphertext);
        self.next = id.checked_add(1);
        Ok(packet)
    }
}

/// 服务端解出的 UDP 请求：归属用户、目标地址与载荷。
///
/// 不派生 `Debug`：载荷不进入日志。
pub struct EihUdpDecoded {
    pub session_id: [u8; 8],
    pub packet_id: u64,
    /// 最后一层身份命中的用户（最终用户）。
    pub uid: u64,
    /// 逐层剥离命中的 uid 链。
    pub uids: Vec<u64>,
    pub target: TargetAddr,
    pub payload: Vec<u8>,
}

/// UDP 多用户 EIH 服务端：逐层剥离身份头后用命中用户的 PSK 解 AEAD。
///
/// `identity` 是服务端身份 PSK（链上的 PSK_0）；`layers` 是期望剥离的层数。
/// `layers == 1` 与参考 `MultiService.newPacket` 逐字节一致。
pub struct EihUdpServer {
    identity: Key,
    users: UserTable,
    layers: usize,
    sessions: Sessions,
}
impl EihUdpServer {
    /// 身份 PSK 与用户表必须同套件且为 AES；层数不得为 0。
    pub fn new(
        identity: Key,
        users: UserTable,
        layers: usize,
        capacity: usize,
        retention: Duration,
    ) -> Result<Self, Error> {
        require_aes(identity.method())?;
        if identity.method() != users.method() {
            return Err(Error::KeyLength);
        }
        if layers == 0 {
            return Err(Error::EihMissing);
        }
        if layers > MAX_UDP_IDENTITY_LAYERS {
            return Err(Error::EihChainTooLong);
        }
        Ok(Self {
            identity,
            users,
            layers,
            sessions: Sessions::new(capacity, retention)?,
        })
    }
    /// 期望剥离的身份头层数。
    pub fn layers(&self) -> usize {
        self.layers
    }
    /// 挂接跨重启重放集合；调用方负责以互斥量串行化本服务端与存储，
    /// 并在每次接受后调用 [`EihUdpServer::flush_replay`] 落盘。
    #[must_use]
    pub fn with_replay_store(mut self, store: ReplayStore) -> Self {
        self.sessions = self.sessions.with_replay_store(store);
        self
    }
    /// 将跨重启重放集合落盘；未挂接存储时为空操作。
    pub fn flush_replay(&self) -> Result<(), Error> {
        self.sessions.flush_replay()
    }
    /// 收包：解身份头 → 命中用户 → 解 AEAD → 登记会话（含重放窗口）。
    ///
    /// 失败一律 fail-closed：身份头截断、指纹未知、链长不符、AEAD 失败都返回
    /// [`Error`]，绝不回退到单用户 PSK。
    pub fn receive(
        &mut self,
        packet: &[u8],
        peer: SocketAddr,
        now: Clock,
    ) -> Result<EihUdpDecoded, Error> {
        self.sessions.check_clock(now)?;
        match self.decode(packet, now.unix_seconds, self.layers) {
            Ok(decoded) => {
                // 认证与解码全部通过后才登记会话（含重放窗口）。
                self.sessions
                    .accept(decoded.session_id, decoded.packet_id, peer, now)?;
                Ok(decoded)
            }
            Err(primary) => {
                // 链长不匹配要给出明确错误：试用其它层数定位真实层数。
                // 试用只解码不登记状态，因此不会污染会话表。
                for layers in 1..=MAX_UDP_IDENTITY_LAYERS {
                    if layers == self.layers {
                        continue;
                    }
                    if self.decode(packet, now.unix_seconds, layers).is_ok() {
                        return Err(Error::EihChainMismatch);
                    }
                }
                Err(primary)
            }
        }
    }
    /// 解一个指定层数的身份链并解密 AEAD 体；不触碰会话表。
    fn decode(&self, packet: &[u8], now: u64, layers: usize) -> Result<EihUdpDecoded, Error> {
        let header_len = UDP_SEPARATE_HEADER_LEN * (1 + layers);
        if packet.len() < header_len + MIN_AEAD_BODY {
            return Err(Error::EihTruncated);
        }
        let separate = self.identity.header(
            packet[..UDP_SEPARATE_HEADER_LEN]
                .try_into()
                .expect("已校验长度"),
            false,
        )?;
        // 逐层剥离：第 i 层用第 i 层的 PSK 解密，与 separate header 明文异或后
        // 得到指纹（参考 `service_multi.go:277-289`）。
        let mut current = self.identity.clone();
        let mut uids = Vec::with_capacity(layers);
        for index in 0..layers {
            let start = UDP_SEPARATE_HEADER_LEN * (1 + index);
            let block = packet[start..start + UDP_SEPARATE_HEADER_LEN]
                .try_into()
                .expect("已校验长度");
            let mut decrypted = current.header(block, false)?;
            for (byte, sep) in decrypted.iter_mut().zip(separate.iter()) {
                *byte ^= sep;
            }
            let user = self
                .users
                .lookup(&decrypted)
                .ok_or(Error::IdentityUnknown)?;
            uids.push(user.uid);
            current = user.key.clone();
        }
        let session_id: [u8; 8] = separate[..8].try_into().expect("固定长度");
        let packet_id = u64::from_be_bytes(separate[8..].try_into().expect("固定长度"));
        // 会话密钥用**命中用户**的 PSK 派生（参考 `SessionKey(uPSK, packetHeader[:8])`），
        // nonce 取 separate header 的后 12 字节。
        let subkey = current.subkey(&session_id);
        let plaintext = current.body(&subkey, &separate[4..16], &packet[header_len..], false)?;
        let decoded: Decoded = packet::decode_body(plaintext, session_id, packet_id, now, None)?;
        Ok(EihUdpDecoded {
            session_id,
            packet_id,
            uid: uids[uids.len() - 1],
            uids,
            target: decoded.target,
            payload: decoded.payload,
        })
    }
}
