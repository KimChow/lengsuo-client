//! 握手编排：把 `Handshake` / `Responder` 接到装配层上。
//!
//! # 两条路径
//!
//! ```text
//! 发起方：create_initiation ──▶ send_raw ──▶ [对端]
//!                                  ◀── consume_response（认证通过才落地密钥）
//!
//! 响应方：consume_initiation ──▶ create_response ──▶ send_raw ──▶ [对端]
//! ```
//!
//! # COOKIE 路径（**不得**丢包了事）
//!
//! 对照 wireguard-go `device/receive.go` 的 `RoutineHandshake`（commit
//! `2631ce99a06f27120d581611cf125d68bc6aa565`）：MAC2 无效 / 过载时
//! **签发 cookie reply**（`SendHandshakeCookie`）让对端带 cookie 重试，
//! ⛔ **不**把报文丢掉——否则大包场景下双方永远握手不上。
//!
//! ⛔ cookie 的 `src` 输入必须是**对端源地址的字节表示**（参考
//! `conn.Endpoint.DstToBytes`）：签发与校验两侧必须一致。
//!
//! # fail-closed
//!
//! 握手失败（MAC 不符 / 长度非法 / 类型不符 / 响应认证失败）⇒ **明确报错**
//! [`AssemblyError::HandshakeRejected`]，⛔ **不回退到明文**、⛔ **不静默重试到底**。
//!
//! # 密钥落地
//!
//! 握手成功后由调用方把 [`SessionKeys`] 装进 [`Assembly`]
//! （见 [`Assembly::install_keys`]）——本模块**只派生**，不落地。

use lengsuo_link_core::frame::{Frame, FrameType};
use lengsuo_wireguard::handshake::{Handshake, Responder, ResponderKeys, TransportKeys};

use crate::assembly::config::Role;
use crate::assembly::error::AssemblyError;
use crate::assembly::reason::{initiator_reason, responder_reason};
use crate::assembly::session::{local_index_from, Assembly};

/// 握手报文在 **L3 帧**里的类型。
///
/// ⚠️ 握手报文**不**走 `FrameType::Data`：它们不是运输数据消息，
/// [`lengsuo_wireguard::device::Device::receive`] 只认运输报文
/// （`wire::parse` 的 type 4）。⇒ 握手走 [`FrameType::Control`]，
/// 数据走 [`FrameType::Data`]。
pub const HANDSHAKE_FRAME_TYPE: FrameType = FrameType::Control;

/// 派生出的会话密钥（收发两把 + 两侧 index）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionKeys {
    /// 本端发送密钥。
    pub send: [u8; 32],
    /// 本端接收密钥。
    pub receive: [u8; 32],
    /// 本端 index。
    pub local_index: u32,
    /// 对端 index。
    pub remote_index: u32,
}

impl SessionKeys {
    /// 从发起方的 [`TransportKeys`] 构造。
    #[must_use]
    pub fn from_initiator(keys: &TransportKeys) -> Self {
        Self {
            send: keys.send,
            receive: keys.receive,
            local_index: keys.local_index,
            remote_index: keys.remote_index,
        }
    }

    /// 从响应方的 [`ResponderKeys`] 构造。
    #[must_use]
    pub fn from_responder(keys: &ResponderKeys) -> Self {
        Self {
            send: keys.send,
            receive: keys.receive,
            local_index: keys.local_index,
            remote_index: keys.remote_index,
        }
    }
}

/// 发起方的握手编排。
///
/// 持有一个在途 [`Handshake`] 状态机；握手成功后由调用方把密钥装进
/// [`Assembly`]（见 [`Assembly::install_keys`]）。
pub struct InitiatorHandshake {
    /// 在途握手状态机。
    handshake: Handshake,
    /// 本端 index（本轮使用的）。
    local_index: u32,
}

impl InitiatorHandshake {
    /// 构造发起方握手上下文。
    ///
    /// `seed` 是本轮临时密钥种子（**由调用方提供**）：本层不引随机源，
    /// 便于测试确定性。
    ///
    /// # Errors
    /// - 角色不是发起方 ⇒ [`AssemblyError::WrongRole`]；
    /// - 静态密钥非法 ⇒ [`AssemblyError::HandshakeRejected`]。
    pub fn new(assembly: &Assembly, seed: [u8; 32]) -> Result<Self, AssemblyError> {
        if assembly.role() != Role::Initiator {
            return Err(AssemblyError::WrongRole {
                expected: "initiator",
                actual: assembly.role().as_str(),
            });
        }
        // 本端 index：配置里指定了就用它，否则按种子派生（单 peer 无需全局 index 表）。
        let local_index = assembly
            .config()
            .local_index
            .unwrap_or_else(|| local_index_from(&seed));
        let handshake = Handshake::new(
            &assembly.config().local_static_private,
            &assembly.config().remote_static_public,
            assembly.config().preshared_key,
            local_index,
        )
        .map_err(|_| AssemblyError::HandshakeRejected {
            reason: "握手上下文构造失败（静态密钥非法）",
        })?;
        Ok(Self {
            handshake,
            local_index,
        })
    }

    /// 本端 index。
    #[must_use]
    pub fn local_index(&self) -> u32 {
        self.local_index
    }

    /// 构造 initiation 报文（148 字节）。
    ///
    /// ⚠️ **本方法不自动加 MAC1/MAC2**：握手报文上线前必须带 MAC1
    /// （否则对端的 `check_mac1` 必然失败）。MAC 由
    /// [`lengsuo_wireguard::handshake::CookieGenerator`] 负责——
    /// 对照参考 `peer.cookieGenerator.AddMacs`。本层**不重写** MAC 计算。
    ///
    /// # Errors
    /// 状态机失步 / 密钥非法 ⇒ [`AssemblyError::HandshakeRejected`]。
    pub fn create_initiation(&mut self, seed: [u8; 32]) -> Result<[u8; 148], AssemblyError> {
        self.handshake
            .create_initiation(seed)
            .map_err(|_| AssemblyError::HandshakeRejected {
                reason: "initiation 构造失败（状态机失步或密钥非法）",
            })
    }

    /// 消费响应方返回的 response 报文（92 字节），拿到派生的会话密钥。
    ///
    /// # Errors
    /// 长度非法 / 认证失败 / 状态机失步 ⇒ [`AssemblyError::HandshakeRejected`]
    /// （⛔ **不回退明文**、⛔ 不静默重试到底）。
    pub fn consume_response(&mut self, wire: &[u8]) -> Result<SessionKeys, AssemblyError> {
        self.handshake
            .consume_response(wire)
            .map(|keys| SessionKeys::from_initiator(&keys))
            .map_err(|error| AssemblyError::HandshakeRejected {
                reason: initiator_reason(error),
            })
    }
}

impl core::fmt::Debug for InitiatorHandshake {
    /// **只输出本端 index**，绝不输出密钥材料。
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("InitiatorHandshake")
            .field("local_index", &self.local_index)
            .finish_non_exhaustive()
    }
}

/// 响应方的握手编排。
pub struct ResponderHandshake {
    /// 在途握手状态机（`begin_symmetric_session` 会消费它）。
    responder: Option<Responder>,
    /// 本端静态材料（供重新构造 responder：cookie checker 是设备级状态，
    /// 与握手状态无关）。
    static_private: [u8; 32],
    /// 对端静态公钥。
    remote_static: [u8; 32],
    /// 可选预共享密钥。
    preshared_key: Option<[u8; 32]>,
}

impl ResponderHandshake {
    /// 构造响应方握手上下文。
    ///
    /// # Errors
    /// - 角色不是响应方 ⇒ [`AssemblyError::WrongRole`]。
    pub fn new(assembly: &Assembly) -> Result<Self, AssemblyError> {
        if assembly.role() != Role::Responder {
            return Err(AssemblyError::WrongRole {
                expected: "responder",
                actual: assembly.role().as_str(),
            });
        }
        Ok(Self {
            responder: None,
            static_private: assembly.config().local_static_private,
            remote_static: assembly.config().remote_static_public,
            preshared_key: assembly.config().preshared_key,
        })
    }

    /// 消费对端发来的 initiation 报文（148 字节）。
    ///
    /// 本方法负责 **MAC1 校验**（对照参考把 MAC 检查放在剥壳之前）与剥壳。
    /// MAC1 不符 ⇒ 返回 [`AssemblyError::HandshakeRejected`]——**由上层据此
    /// 签发 cookie reply**（见 [`Self::create_cookie_reply`]），⛔ 不得直接丢弃。
    ///
    /// # Errors
    /// - 长度非法 ⇒ [`AssemblyError::HandshakeRejected`]；
    /// - MAC1 不符 ⇒ [`AssemblyError::HandshakeRejected`]；
    /// - 剥壳失败（未知对端 / 重放 / 洪水）⇒ [`AssemblyError::HandshakeRejected`]。
    pub fn consume_initiation(&mut self, wire: &[u8]) -> Result<(), AssemblyError> {
        // **长度先于 MAC1**：`check_mac1` 会按报文尾部长度切片，
        // 短报体会越界。
        if wire.len() != 148 {
            return Err(AssemblyError::HandshakeRejected {
                reason: "initiation 长度非法",
            });
        }
        let mut responder = self.build_responder()?;
        // MAC1 先于剥壳（对齐参考实现的接收顺序）。
        if !responder.check_mac1(wire) {
            return Err(AssemblyError::HandshakeRejected {
                reason: "MAC1 校验失败",
            });
        }
        responder
            .consume_initiation(wire)
            .map_err(|error| AssemblyError::HandshakeRejected {
                reason: responder_reason(error),
            })?;
        self.responder = Some(responder);
        Ok(())
    }

    /// 构造 response 报文（92 字节）并派生会话密钥。
    ///
    /// `seed` 是本轮临时私钥种子（**由调用方提供**）；`local_index` 是本轮
    /// 的本端 index。
    ///
    /// # Errors
    /// 没有在途 initiation / 状态机失步 ⇒ [`AssemblyError::HandshakeRejected`]。
    pub fn create_response(
        &mut self,
        seed: [u8; 32],
        local_index: u32,
    ) -> Result<([u8; 92], SessionKeys), AssemblyError> {
        let Some(mut responder) = self.responder.take() else {
            return Err(AssemblyError::HandshakeState("没有在途 initiation"));
        };
        let mut response = responder.create_response(seed, local_index).map_err(|_| {
            AssemblyError::HandshakeRejected {
                reason: "response 构造失败（状态机失步）",
            }
        })?;
        // MAC 由 cookie generator 加在 response 上（对照参考 `AddMacs`）。
        responder.add_macs(&mut response);
        // `begin_symmetric_session` 消费 responder ⇒ 密钥只能在此刻落地。
        let keys =
            responder
                .begin_symmetric_session()
                .map_err(|_| AssemblyError::HandshakeRejected {
                    reason: "对称会话派生失败（状态机失步）",
                })?;
        Ok((response, SessionKeys::from_responder(&keys)))
    }

    /// 为 MAC1/MAC2 校验失败的 initiation 签发 cookie reply（64 字节）。
    ///
    /// 对照 wireguard-go `device/send.go` 的 `SendHandshakeCookie`：
    /// 过载 / 要求 MAC2 时**不得丢弃**报文，而是签发 cookie reply 让对端重试。
    ///
    /// `src` 是**对端源地址**的字节表示（cookie 的输入，签发与校验两侧必须一致）。
    ///
    /// # Errors
    /// 静态密钥非法 ⇒ [`AssemblyError::HandshakeRejected`]。
    pub fn create_cookie_reply(
        &mut self,
        wire: &[u8],
        src: &[u8],
        secret_seed: [u8; 32],
        nonce: [u8; 24],
    ) -> Result<[u8; 64], AssemblyError> {
        let mut responder = self.build_responder()?;
        Ok(responder.create_cookie_reply(wire, src, secret_seed, nonce))
    }

    /// 造一个响应方状态机（cookie checker 是设备级状态，与握手状态无关）。
    fn build_responder(&self) -> Result<Responder, AssemblyError> {
        Responder::new(
            &self.static_private,
            &self.remote_static,
            self.preshared_key,
            0,
        )
        .map_err(|_| AssemblyError::HandshakeRejected {
            reason: "响应方上下文构造失败（静态密钥非法）",
        })
    }
}

impl core::fmt::Debug for ResponderHandshake {
    /// **只输出状态**，绝不输出密钥材料。
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ResponderHandshake")
            .field("has_in_flight_initiation", &self.responder.is_some())
            .finish_non_exhaustive()
    }
}

/// 握手编解码：把 WireGuard 握手报文装进 / 取出 L3 帧。
pub struct HandshakeCodec;

impl HandshakeCodec {
    /// 把一段握手报文装进 L3 帧。
    ///
    /// `seq` 由调用方给（握手报文没有帧序号语义，用它区分**本轮**）。
    ///
    /// # Errors
    /// 帧编码失败（载荷超上限）⇒ [`AssemblyError::HandshakeRejected`]。
    pub fn encode(seq: u64, bytes: &[u8]) -> Result<Frame, AssemblyError> {
        let frame = Frame::new(HANDSHAKE_FRAME_TYPE, seq, bytes.to_vec());
        frame
            .encode()
            .map_err(|_| AssemblyError::HandshakeRejected {
                reason: "握手报文装帧失败（载荷超上限）",
            })?;
        Ok(frame)
    }

    /// 从 L3 帧里取出握手报文（**借用**载荷，不复制）。
    ///
    /// # Errors
    /// 帧类型不是控制帧 ⇒ [`AssemblyError::UnexpectedMessage`]。
    pub fn decode(frame: &Frame) -> Result<&[u8], AssemblyError> {
        if frame.frame_type != HANDSHAKE_FRAME_TYPE {
            return Err(AssemblyError::UnexpectedMessage("握手报文必须装在控制帧里"));
        }
        Ok(&frame.payload)
    }
}
