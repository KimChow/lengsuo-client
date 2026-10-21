//! 会话方向的数据写入端（`Writer`）。
//!
//! 从父模块拆出以保持单文件 ≤400 行（软约束）。语义逐条对齐参考
//! `common/mux/writer.go`（固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）。

use std::io::Write;

use crate::mux::frame::{
    encode_data_into, FrameError, FrameMetadata, SessionStatus, TargetNetwork, OPTION_ERROR,
    STREAM_CHUNK_SIZE,
};
use ss_core::target::TargetAddr;

use super::write_all;

/// 会话方向的数据写入端（`Writer`），负责按会话状态生成帧。
///
/// 参考的 `NewWriter`（请求侧）与 `NewResponseWriter`（响应侧）分别对应
/// [`SessionWriter::request`] 与 [`SessionWriter::response`]。
#[derive(Debug)]
pub struct SessionWriter {
    /// 目标地址（`FrameMetadata.Target`）；响应侧保持 `None`（参考里为零值）。
    dest: Option<(TargetAddr, TargetNetwork)>,
    /// 会话数据方向是否按分组（UDP）语义走，决定是否写「续帧目标地址」。
    packet: bool,
    id: u16,
    followup: bool,
    pub has_error: bool,
    stream: bool,
}

impl SessionWriter {
    /// `NewWriter`：请求侧，首帧 `New`（带目标地址），后续 `Keep`。
    #[must_use]
    pub fn request(id: u16, dest: (TargetAddr, TargetNetwork), network: TargetNetwork) -> Self {
        Self {
            id,
            dest: Some(dest),
            packet: network == TargetNetwork::Udp,
            followup: false,
            has_error: false,
            stream: network == TargetNetwork::Tcp,
        }
    }

    /// `NewResponseWriter`：响应侧，无目标地址，首帧即 `Keep`。
    #[must_use]
    pub fn response(id: u16, network: TargetNetwork) -> Self {
        Self {
            id,
            // 参考的 response writer `dest` 为零值（`net.Destination{}`）：响应方向
            // 不写目标地址，仅在分组会话续帧时写 `b.UDP`（本层无 GlobalID，见模块头）。
            dest: None,
            packet: network == TargetNetwork::Udp,
            followup: true,
            has_error: false,
            stream: network == TargetNetwork::Tcp,
        }
    }

    /// `getNextFrameMeta`。
    fn next_meta(&mut self) -> FrameMetadata {
        let status = if self.followup {
            SessionStatus::Keep
        } else {
            self.followup = true;
            SessionStatus::New
        };
        // 参考 `getNextFrameMeta` 只区分 followup，UDP 状态由其自身的 `followup`
        // 构造器参数决定；本层让 `udp_continuation` 仅在**续帧**上生效，
        // 避免把 `New` 帧的地址段误当成续帧分支（`New` 分支本就写地址）。
        let udp_continuation = self.followup && self.packet;
        FrameMetadata {
            session_id: self.id,
            status,
            option: 0,
            target: self.dest.clone(),
            source: None,
            local: None,
            // 参考 `b.UDP != nil`：分组会话的续帧也写目标地址。
            udp_continuation,
        }
    }

    /// 构造本会话的下一个帧头（含 `OptionData` 时由调用方置位）。
    ///
    /// 与 [`SessionWriter::write_data`] 同源，供需要自行拼帧的 tokio 调用方使用
    /// （例如把 `Keep` 帧连同数据一次写出）。
    #[must_use]
    pub fn next_keep(&mut self) -> FrameMetadata {
        let mut meta = self.next_meta();
        meta.option |= crate::mux::frame::OPTION_DATA;
        meta
    }

    /// `writeMetaOnly`：只发一个元数据帧（无数据段），用于空载荷/首包欺骗窗口。
    pub fn write_meta_only<W: Write>(&mut self, out: &mut W) -> Result<(), FrameError> {
        let meta = self.next_meta();
        let mut wire = Vec::new();
        meta.encode_into(&mut wire)?;
        write_all(out, &wire)
    }

    /// `writeData`：`OptionData` 置位 + `BE16 长度 || 数据`。
    pub fn write_data<W: Write>(&mut self, out: &mut W, payload: &[u8]) -> Result<(), FrameError> {
        let mut meta = self.next_meta();
        meta.option |= crate::mux::frame::OPTION_DATA;
        let mut wire = Vec::new();
        meta.encode_into(&mut wire)?;
        encode_data_into(&mut wire, payload)?;
        write_all(out, &wire)
    }

    /// `WriteMultiBuffer`：空载荷 => 只发元数据；`Stream` 按 8192 分片，
    /// 分组（Packet）侧由调用方保证「一帧一包」。
    pub fn write_multi<W: Write>(&mut self, out: &mut W, payload: &[u8]) -> Result<(), FrameError> {
        if payload.is_empty() {
            return self.write_meta_only(out);
        }
        if self.stream {
            for chunk in payload.chunks(STREAM_CHUNK_SIZE) {
                self.write_data(out, chunk)?;
            }
            Ok(())
        } else {
            self.write_data(out, payload)
        }
    }

    /// `Close`：发 `End` 帧。
    pub fn close<W: Write>(&mut self, out: &mut W) -> Result<(), FrameError> {
        let mut meta = FrameMetadata {
            session_id: self.id,
            status: SessionStatus::End,
            option: 0,
            target: None,
            source: None,
            local: None,
            udp_continuation: false,
        };
        if self.has_error {
            meta.option |= OPTION_ERROR;
        }
        let mut wire = Vec::new();
        meta.encode_into(&mut wire)?;
        write_all(out, &wire)
    }
}

/// `NewResponseWriter(...).Close()`：会话不存在时通知对端关闭。
pub fn write_closing_end<W: Write>(
    out: &mut W,
    id: u16,
    network: TargetNetwork,
) -> Result<(), FrameError> {
    SessionWriter::response(id, network).close(out)
}
