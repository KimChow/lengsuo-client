//! L1 ↔ L2 的**接线胶水层**：把会话（`Session`）接到搬运（`Transport`）上。
//!
//! # 接线流程
//!
//! ```text
//!  发送：明文 ──seal_frame──▶ 密文字节 ──transport.send──▶ 链路
//!  接收：链路 ──transport.recv──▶ 密文字节 ──open_frame──▶ 明文
//! ```
//!
//! ⛔ **明文与密文的分界线只有一处**：[`Link::send_frame`] 里的
//! `session.seal_frame(...)`。搬运层（[`Transport`]）**只**拿到密文字节，
//! **永远**拿不到明文；⛔ **没有**任何明文旁路。
//!
//! # fail-closed 清单
//!
//! | 场景 | 行为 |
//! |---|---|
//! | 会话未建立 / 已失效 | 收发**立即被拒**（`SessionError::InvalidState` / `Invalidated`），**不碰**传输层 |
//! | AEAD 认证失败 | 错误**原样透出**（`SessionError::AuthFailed`），会话转入失效态，⛔ **不回退明文** |
//! | 收到的字节超长 | **明确报错**（`TransportError::TooLong`），⛔ 不截断、⛔ 不当合法帧往下传 |
//! | 传输层失败 | 错误**原样透出**，⛔ 不改写成成功、⛔ 不让会话失效 |
//! | 暂时没有数据 | `TransportError::WouldBlock`（**不是**失败），会话仍然有效 |

use crate::frame::{FrameType, OpenedFrame, MAX_FRAME_LEN};
use crate::session::{Session, SessionError};

use super::error::TransportError;
use super::trait_def::{check_frame_len, Transport};

/// 一条**已接线的链路**：会话（L2）+ 搬运（L1）。
///
/// 持有：L2 会话对象 + L1 搬运实现。
/// **不持有**任何 socket / 线程 / 计时器——搬运怎么实现由 `T` 决定。
pub struct Link<T> {
    /// L2 会话对象。
    session: Session,
    /// L1 搬运实现。
    transport: T,
}

impl<T> Link<T>
where
    T: Transport,
{
    /// 用会话与搬运实现接一条链路。
    #[must_use]
    pub fn new(session: Session, transport: T) -> Self {
        Self { session, transport }
    }

    /// 本端的会话对象（只读）。
    #[must_use]
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// 本端的搬运实现（只读）。
    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// 发一帧**明文**：封密文 → 交给搬运层。
    ///
    /// # Errors
    /// - 会话未建立 / 已失效 ⇒ `SessionError::InvalidState` / `Invalidated`
    ///   （**原样透出**，且**不碰**传输层）。
    /// - 明文超长 ⇒ `SessionError::Frame(..)`（**写入前**拒绝，一个字节都不发）。
    /// - 搬运失败 ⇒ `TransportError`（**原样透出**）。
    pub fn send_frame(
        &mut self,
        frame_type: FrameType,
        seq: u64,
        plain: &[u8],
    ) -> Result<(), TransportError> {
        self.ensure_usable()?;
        // ⛔ 明文只在下一行变成密文；搬运层拿到的**只有**密文字节。
        let sealed = self.session.seal_frame(frame_type, seq, plain)?;
        self.transport.send(&sealed)
    }

    /// 收一帧：从搬运层取回字节 → 解封 → 交还明文。
    ///
    /// # Errors
    /// - 会话未建立 / 已失效 ⇒ `SessionError::InvalidState` / `Invalidated`
    ///   （**原样透出**）。
    /// - 暂时没有数据 ⇒ `TransportError::WouldBlock`（**不是**失败）。
    /// - 收到的字节超长 ⇒ `TransportError::TooLong`（**不截断**、
    ///   ⛔ 不当作合法帧往下传）。
    /// - 认证失败 ⇒ `SessionError::AuthFailed`（**不回退明文**）。
    /// - 帧格式非法 ⇒ `SessionError::Frame(..)`（**不返回部分数据**）。
    pub fn recv_frame(&mut self) -> Result<OpenedFrame, TransportError> {
        self.ensure_usable()?;
        let bytes = self.transport.recv()?;
        // 长度检查在**交给会话层之前**：超长字节不当合法帧往下传。
        let limit = self.transport.max_frame_len().min(MAX_FRAME_LEN);
        check_frame_len(bytes.len(), limit)?;
        Ok(self.session.open_frame(&bytes)?)
    }

    /// 收发前的会话可用性检查（**不碰**传输层）。
    fn ensure_usable(&self) -> Result<(), TransportError> {
        if self.session.is_invalidated() {
            return Err(TransportError::Session(SessionError::Invalidated));
        }
        if !self.session.is_established() {
            return Err(TransportError::Session(SessionError::invalid_state(
                self.session.state(),
                self.session.role(),
            )));
        }
        Ok(())
    }
}

impl<T> core::fmt::Debug for Link<T> {
    /// **只输出状态与世代号**，绝不输出明文、密文或密钥。
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Link")
            .field("state", &self.session.state())
            .field("role", &self.session.role())
            .field("generation", &self.session.generation())
            .field("session", &"[redacted]")
            .finish_non_exhaustive()
    }
}
