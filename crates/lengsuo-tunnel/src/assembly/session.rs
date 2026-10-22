//! 会话状态机：装配层的**协议侧**（密钥落地 + 数据面）。
//!
//! # 分层位置
//!
//! **装配层**（L1 传输 × L2 密钥 × L3 帧 的接线处）。它**不重写**任何密码学：
//! 握手状态机来自 `lengsuo_wireguard::handshake`，AEAD 来自
//! `lengsuo_wireguard::transport`，帧编解码来自 `lengsuo_link_core::frame`。
//! 本模块只做**编排**：什么时候把派生出的密钥装进 [`Device`]、收到报文后
//! 怎么路由、漫游怎么判定。
//!
//! # 线上格式（一句话）
//!
//! **一个 UDP 数据报 = 一个 L3 帧**；帧的**载荷**是 WireGuard 报文
//! （握手 initiation/response/cookie，或运输数据消息）。
//!
//! 这条对应关系有三处硬证据：
//! - `lengsuo_link_core::frame::MAX_PLAIN_LEN = MAX_FRAME_PAYLOAD_LEN - 32`
//!   （帧载荷上限减 32 ＝ 运输消息的头 16 + 标签 16）⇒ 帧载荷**就是**运输报文；
//! - `lengsuo_link_core::frame::seal_frame` / `open_frame` 本就是
//!   「WG `Sender`/`Receiver` ⇒ L3 帧」的现成接线；
//! - [`Device::receive`] 走 `wire::parse`，只认**运输报文** ⇒ 它拿到的必须是
//!   帧的载荷，而不是整个数据报。
//!
//! # fail-closed 清单
//!
//! | 场景 | 行为 |
//! |---|---|
//! | 认证失败的入站报文 | 丢弃，⛔ **不更新** endpoint |
//! | 会话未建立就收发数据 | [`AssemblyError::SessionNotEstablished`] |
//! | 无可用发送 keypair | [`AssemblyError::NoSendKeypair`]（⛔ 不回落旧 keypair） |
//! | 明文超长 / AEAD 失败 | [`AssemblyError::HandshakeRejected`]（⛔ 不截断） |

use std::net::SocketAddr;
use std::time::Instant;

use lengsuo_link_core::frame::{Frame, FrameType};
use lengsuo_link_core::session::Generation;
use lengsuo_wireguard::device::{Device, Output};
use lengsuo_wireguard::keypair::{Keypair, KeypairSet};
use lengsuo_wireguard::peers::{PeerConfig, PeerSet};

use crate::assembly::config::{AssemblyConfig, Role};
use crate::assembly::error::AssemblyError;
use crate::assembly::event::AssemblyEvent;
use crate::assembly::handshake::SessionKeys;
use crate::assembly::keepalive::KeepaliveDriver;
use crate::assembly::reason::seal_reason;
use crate::negotiate::NegotiateDriver;
use crate::udp::UdpEndpoint;

/// 装配层的会话状态机。
///
/// 持有：配置 + [`Device`]（承载 keypair 三元组与定时器）+ [`PeerSet`]
/// （承载 peer 与其 endpoint）+ 在途握手状态机。
///
/// ⚠️ 持有本端静态私钥 ⇒ **绝不派生 `Debug`**。
pub struct Assembly {
    /// 配置（静态密钥材料）。
    config: AssemblyConfig,
    /// 设备（承载 keypair 与定时器；**纯逻辑**，无 socket）。
    device: Device,
    /// peer 表（承载 peer 与其 endpoint）。
    peers: PeerSet,
    /// 本端在 `peers` 里的编号。
    peer_id: usize,
    /// 会话是否已建立（握手成功**且**密钥已落地）。
    established: bool,
    /// 本端 index（本轮握手使用的）。
    local_index: u32,
    /// 本轮连接的**世代号**（L2 拥有；首次握手成功仍是初始值，每次重新握手 +1）。
    pub(super) generation: Generation,
    /// 已成功建立的握手轮数（用于世代号推进）。
    established_rounds: u32,
    /// L4 协商驱动器（`None` ⇒ 本端没配 L4 协商）。
    pub(super) negotiator: Option<NegotiateDriver>,
}

impl Assembly {
    /// 用配置建立装配层（**尚未**握手）。
    ///
    /// # Errors
    /// 密钥材料非法（对端公钥 / 本端私钥为全零）⇒ [`AssemblyError::HandshakeRejected`]。
    pub fn new(config: AssemblyConfig) -> Result<Self, AssemblyError> {
        config.validate()?;
        let mut device = Device::new(Instant::now());
        device.set_running(true);
        let mut peers = PeerSet::new();
        let peer_id = peers
            .add(PeerConfig {
                public_key: config.remote_static_public,
                preshared_key: config.preshared_key,
                keepalive: config.keepalive_interval.map_or(0, |interval| {
                    interval.as_secs().min(u64::from(u16::MAX)) as u16
                }),
            })
            .map_err(AssemblyError::Peer)?;
        let mut assembly = Self {
            config,
            device,
            peers,
            peer_id,
            established: false,
            local_index: 0,
            generation: Generation::INITIAL,
            established_rounds: 0,
            negotiator: None,
        };
        assembly.refresh_negotiator();
        Ok(assembly)
    }

    /// 配置（只读）。
    #[must_use]
    pub fn config(&self) -> &AssemblyConfig {
        &self.config
    }

    /// 本端角色。
    #[must_use]
    pub fn role(&self) -> Role {
        self.config.role
    }

    /// 会话是否已建立（握手成功**且**密钥已落地）。
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.established
    }

    /// 本端 index（本轮握手使用的）。
    #[must_use]
    pub fn local_index(&self) -> u32 {
        self.local_index
    }

    /// 对端当前的 endpoint（`None` = 尚未建立）。
    #[must_use]
    pub fn peer_endpoint(&self) -> Option<SocketAddr> {
        self.peers.endpoint(self.peer_id)
    }

    /// 本端的 [`Device`]（只读）。供上层推进定时器、读 keypair 状态。
    #[must_use]
    pub fn device(&self) -> &Device {
        &self.device
    }

    /// 本端的 [`Device`]（可变）。供上层推进定时器。
    pub fn device_mut(&mut self) -> &mut Device {
        &mut self.device
    }

    /// 本端的 peer 表（只读）。
    #[must_use]
    pub fn peers(&self) -> &PeerSet {
        &self.peers
    }

    /// 设置对端 endpoint（首次建链或漫游后）。
    ///
    /// # Errors
    /// peer 不存在 ⇒ [`AssemblyError::Peer`]（fail-closed，不静默忽略）。
    pub fn set_peer_endpoint(&mut self, endpoint: Option<SocketAddr>) -> Result<(), AssemblyError> {
        self.peers
            .set_peer_endpoint(self.peer_id, endpoint)
            .map_err(AssemblyError::Peer)
    }

    // ------------------------------------------------------------ 数据面

    /// 封装一个明文载荷，返回**待发送的 L3 帧**。
    ///
    /// 步骤：`Keypair::seal`（AEAD 封密文 ⇒ 运输报文）→ 装进 L3 帧载荷。
    ///
    /// # Errors
    /// - 会话未建立 ⇒ [`AssemblyError::SessionNotEstablished`]；
    /// - 没有可用发送 keypair ⇒ [`AssemblyError::NoSendKeypair`]；
    /// - 明文超长 / AEAD 失败 ⇒ [`AssemblyError::HandshakeRejected`]。
    pub fn seal_frame(
        &mut self,
        frame_type: FrameType,
        seq: u64,
        plain: &[u8],
    ) -> Result<Frame, AssemblyError> {
        if !self.established {
            return Err(AssemblyError::SessionNotEstablished);
        }
        let now = self.device.timers().now_secs(Instant::now());
        let keypairs = self.device.keypairs_mut();
        let Some(keypair) = keypairs.for_send_mut(now) else {
            return Err(AssemblyError::NoSendKeypair);
        };
        let payload = keypair
            .seal(plain)
            .map_err(|error| AssemblyError::HandshakeRejected {
                reason: seal_reason(error),
            })?;
        Ok(Frame::new(frame_type, seq, payload))
    }

    /// 处理一个入站**数据报**（L3 帧字节）。
    ///
    /// 步骤：解帧（fail-closed）→ [`Device::receive`]（AEAD 认证解密）→
    /// 漫游判定 → 更新 endpoint。
    ///
    /// ⛔ **数据面只收 L3 帧**：裸握手报文（148/92/64B）在这里必然报
    /// [`AssemblyError::BadDatagram`]——握手由
    /// [`crate::assembly::handshake::InitiatorHandshake`] /
    /// [`crate::assembly::handshake::ResponderHandshake`] 消费，⛔ 不要让数据面
    /// 接受裸握手（那会把未认证的字节送进数据通路）。
    ///
    /// `src` 是该数据报的**源地址**（漫游判定的输入）。
    ///
    /// # Errors
    /// - 会话未建立 ⇒ [`AssemblyError::SessionNotEstablished`]；
    /// - 数据报不是合法 L3 帧 ⇒ [`AssemblyError::BadDatagram`]（**单包级**：
    ///   只丢这一包，链路继续）。
    pub fn receive_datagram(
        &mut self,
        src: SocketAddr,
        bytes: &[u8],
    ) -> Result<AssemblyEvent, AssemblyError> {
        let frame = lengsuo_link_core::frame::decode_exact(bytes)
            .map_err(|_| AssemblyError::BadDatagram("帧头非法或长度不符"))?;
        self.receive_frame(src, frame)
    }

    /// 处理一个已解码的入站**帧**。
    ///
    /// ⛔ **认证失败的报文绝不更新 endpoint**：漫游判定只认 `Deliver`，
    /// 见 [`lengsuo_wireguard::device::endpoint_after_receive`]（本层**不**另写
    /// 一套判定，否则会与 `peers::should_roam` 漂移）。
    ///
    /// # Errors
    /// - 会话未建立 ⇒ [`AssemblyError::SessionNotEstablished`]。
    pub fn receive_frame(
        &mut self,
        src: SocketAddr,
        frame: Frame,
    ) -> Result<AssemblyEvent, AssemblyError> {
        if !self.established {
            return Err(AssemblyError::SessionNotEstablished);
        }
        // keepalive 帧是**零长载荷**的 L3 帧（不带运输报文）：
        // 它只用来穿过 NAT 的空闲回收，**不做**认证解密，⛔ 不更新 endpoint
        // （它没有携带任何被认证的身份信息）。
        if frame.frame_type == FrameType::Keepalive {
            return Ok(AssemblyEvent::Keepalive);
        }
        let output = self.device.receive(Instant::now(), &frame.payload);
        let current = self.peers.endpoint(self.peer_id);
        let new_endpoint = lengsuo_wireguard::device::endpoint_after_receive(&output, current, src);
        if let Some(endpoint) = new_endpoint {
            self.peers
                .set_peer_endpoint(self.peer_id, Some(endpoint))
                .map_err(AssemblyError::Peer)?;
        }
        Ok(match output {
            Output::Deliver { payload, .. } => {
                // 控制帧**只**走 L4 协商驱动器：⛔ 绝不作为数据交给上层。
                if frame.frame_type == FrameType::Control {
                    return self.route_control(&payload);
                }
                AssemblyEvent::Delivered {
                    frame_type: frame.frame_type,
                    seq: frame.seq,
                    plaintext_len: payload.len(),
                    roamed: new_endpoint.is_some(),
                }
            }
            Output::DroppedExpiredKeypair { .. } => AssemblyEvent::Dropped {
                reason: "keypair 已过期或不存在",
            },
            Output::DroppedUnparsable => AssemblyEvent::Dropped {
                reason: "报文非法或认证失败",
            },
        })
    }

    /// 把派生出的会话密钥装进 [`Device`] 的 keypair 三元组。
    ///
    /// 对照参考 `BeginSymmetricSession` 的两条分支：发起方 ⇒ 新 keypair 直接
    /// 上位为 current；响应方 ⇒ 新 keypair 进 next，等第一个用它的数据报文
    /// 确认后再晋升（[`Device::receive`] 内部会做这个晋升）。
    ///
    /// ⛔ **角色由本端配置决定**（[`Role::Initiator`] ⇒ 发起方分支），
    /// 不由调用方传标志 ⇒ 不会装错分支。
    ///
    /// # Errors
    /// 密钥长度非法（理论不可达：固定 32B）⇒ [`AssemblyError::HandshakeRejected`]。
    pub fn install_keys(&mut self, keys: &SessionKeys) -> Result<(), AssemblyError> {
        let is_initiator = self.role() == Role::Initiator;
        let now = self.device.timers().now_secs(Instant::now());
        let Some(keypair) = Keypair::new(
            keys.local_index,
            keys.remote_index,
            is_initiator,
            now,
            &keys.send,
            &keys.receive,
        ) else {
            // 密钥长度固定 32B ⇒ 理论不可达；不落地 ⇒ 会话保持未建立（fail-closed）。
            return Err(AssemblyError::HandshakeRejected {
                reason: "会话密钥长度非法",
            });
        };
        let keypairs: &mut KeypairSet = self.device.keypairs_mut();
        if is_initiator {
            keypairs.install_as_initiator(keypair);
        } else {
            keypairs.install_as_responder(keypair);
        }
        self.local_index = keys.local_index;
        self.established = true;
        // 世代号：**首次**握手成功仍是初始值；每次**重新**握手成功 +1
        // （失败的握手不推进）。见 `docs/link-session-spec.md` §2.3。
        self.established_rounds += 1;
        if self.established_rounds > 1 {
            self.generation = self.generation.next();
        }
        // 换了一代连接 ⇒ 换一台协商状态机（`Failed` 是吸收态，不可复用）。
        self.refresh_negotiator();
        Ok(())
    }

    /// 会话**就绪**后启动 keepalive 驱动。
    ///
    /// ⛔ **会话未就绪 ⇒ 拒绝**（[`AssemblyError::SessionNotEstablished`]）：
    /// 这就是「未就绪不发 keepalive」的判定点——握手没完成时既**不启动**
    /// 任务，也**不**留下一个会在就绪后自己跑起来的定时器。
    ///
    /// # Errors
    /// - 会话未就绪 ⇒ [`AssemblyError::SessionNotEstablished`]；
    /// - keepalive 未配置 / 间隔非法 ⇒ [`AssemblyError::KeepaliveDisabled`]；
    /// - 驱动已在运行 ⇒ [`AssemblyError::KeepaliveAlreadyRunning`]。
    pub fn start_keepalive(
        &mut self,
        driver: &mut KeepaliveDriver,
        endpoint: UdpEndpoint,
    ) -> Result<(), AssemblyError> {
        if !self.established {
            return Err(AssemblyError::SessionNotEstablished);
        }
        driver.activate(endpoint)
    }
}

impl core::fmt::Debug for Assembly {
    /// **只输出角色与状态**，绝不输出密钥、载荷。
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Assembly")
            .field("role", &self.config.role)
            .field("established", &self.established)
            .field("local_index", &self.local_index)
            .field("generation", &self.generation.value())
            .field("peer_endpoint", &self.peer_endpoint())
            .field("keys", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// 由种子派生本端 index（**非**密码学随机：只要求同一轮握手内唯一且非零）。
///
/// 对照参考 `device.indexTable.NewIndexForHandshake`：随机 uint32 + 冲突重试。
/// 本层**单 peer**，无需全局 index 表 ⇒ 直接从种子派生（可复现、无随机源依赖）。
pub(crate) fn local_index_from(seed: &[u8; 32]) -> u32 {
    let mut value = u32::from_le_bytes([seed[0], seed[1], seed[2], seed[3]]);
    if value == 0 {
        value = 1;
    }
    value
}
