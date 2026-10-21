//! 两端状态机：客户端 `fetchOutput` 与服务端 `handleFrame`。
//!
//! 从父模块拆出以保持单文件 ≤400 行（软约束）。语义逐条对齐参考
//! `common/mux/{client,server}.go`（固定 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）。

use crate::mux::frame::{FrameError, FrameMetadata, SessionStatus, TargetNetwork};

use super::action::Action;
use super::session::{SessionManager, SessionState};

/// 客户端状态机（`ClientWorker.fetchOutput`）。`handleStatusNew` 在客户端侧只丢弃
/// 数据（下行 New 帧不承载新会话，服务端从不主动开新会话）。
#[derive(Debug, Default)]
pub struct MuxClient {
    pub manager: SessionManager,
}

impl MuxClient {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 处理一个已解码帧头 + 其数据段（`data` 为 `OptionData` 时读出的数据）。
    ///
    /// 返回 `Err` 表示**终止整条 Mux 连接**（未知状态；参考 `default` 分支
    /// `errors.LogError` 后 `return`）。
    pub fn handle(
        &mut self,
        meta: &FrameMetadata,
        data: Option<Vec<u8>>,
    ) -> Result<Action, FrameError> {
        match meta.status {
            SessionStatus::KeepAlive | SessionStatus::New => {
                // 参考 handleStatueKeepAlive/handleStatusNew：置位 OptionData 则丢弃。
                Ok(Action::None)
            }
            SessionStatus::Keep => {
                let Some(data) = data else {
                    return Ok(Action::None);
                };
                if self.manager.get(meta.session_id).is_none() {
                    return Ok(Action::SendEnd {
                        id: meta.session_id,
                    });
                }
                Ok(Action::Deliver {
                    id: meta.session_id,
                    payload: data,
                    new: false,
                })
            }
            SessionStatus::End => {
                if self.manager.get(meta.session_id).is_some() {
                    return Ok(Action::CloseSession {
                        id: meta.session_id,
                    });
                }
                Ok(Action::None)
            }
        }
    }
}

/// 服务端状态机（`ServerWorker.handleFrame`）。
#[derive(Debug, Default)]
pub struct MuxServer {
    pub manager: SessionManager,
    /// 允许的目标网络（`session.AllowedNetworkFromContext`）；`None` 表示不限制。
    pub allowed_network: Option<TargetNetwork>,
}

impl MuxServer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `handleStatusNew` 的会话登记部分：校验网络、登记会话。
    ///
    /// 返回需要**断开整条 Mux 连接**的错误时，调用方必须终止连接（参考在
    /// `handleStatusNew` 里直接返回 error，`run` 随即退出）。
    pub fn handle_new(&mut self, meta: &FrameMetadata) -> Result<u16, FrameError> {
        let Some((_target, network)) = meta.target.as_ref() else {
            // 参考对 `New` 帧必然解析出 Target；缺失即协议错误。
            return Err(FrameError::ShortMeta { got: 0 });
        };
        if let Some(allowed) = self.allowed_network {
            if *network != allowed {
                // 参考：`unexpected network`，会断开整条 Mux 连接。
                return Err(FrameError::UnknownNetwork {
                    network: network.to_byte(),
                });
            }
        }
        if self.manager.get(meta.session_id).is_some() {
            // 参考在 `SessionManager.Add` 里直接覆盖；此处保持同样的宽松语义，
            // 由调用方决定是否先关闭旧会话（服务端侧目标相同，覆盖等价）。
            self.manager.remove(meta.session_id);
        }
        let state = SessionState {
            target: meta.target.clone().expect("上面已校验存在"),
        };
        if !self.manager.add(meta.session_id, state) {
            // 参考 `failed to add new session`。
            return Err(FrameError::MetaTooLong);
        }
        Ok(meta.session_id)
    }

    /// 处理一个已解码帧头（非 `New` 分支；`New` 走 [`MuxServer::handle_new`]）。
    pub fn handle(
        &mut self,
        meta: &FrameMetadata,
        data: Option<Vec<u8>>,
    ) -> Result<Action, FrameError> {
        match meta.status {
            SessionStatus::KeepAlive => Ok(Action::None),
            SessionStatus::Keep => {
                let Some(data) = data else {
                    return Ok(Action::None);
                };
                if self.manager.get(meta.session_id).is_none() {
                    return Ok(Action::SendEnd {
                        id: meta.session_id,
                    });
                }
                Ok(Action::Deliver {
                    id: meta.session_id,
                    payload: data,
                    new: false,
                })
            }
            SessionStatus::End => {
                if self.manager.get(meta.session_id).is_some() {
                    return Ok(Action::CloseSession {
                        id: meta.session_id,
                    });
                }
                Ok(Action::None)
            }
            SessionStatus::New => Ok(Action::None),
        }
    }
}
