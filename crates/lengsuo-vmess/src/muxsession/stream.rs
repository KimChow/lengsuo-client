//! Mux 的输入侧封装器（`fetchInput` + `Writer`）与读端帧迭代器。
//!
//! 语义来源：参考 `common/mux/{client,writer,reader}.go`，固定 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。

use std::io::Read;

use ss_core::target::TargetAddr;

use crate::muxframe::{
    decode_address_port, encode_address_port, encode_data_into, read_data, FrameError,
    FrameMetadata, SessionStatus, TargetNetwork, OPTION_DATA, OPTION_ERROR,
};

use super::server::ServerSession;

/// 输入侧封装器（`fetchInput` + `Writer`）：把本端字节流切成会话帧。
///
/// 关键语义对齐参考：**New 帧只在「本会话还没有任何输出」时出现**
/// （`getNextFrameMeta` 的 `followup` 标志），首包为空即 `writeMetaOnly`。
pub struct StreamSender {
    pub id: u16,
    pub network: TargetNetwork,
    pub target: TargetAddr,
    /// 已发出过 New（对端可能已建立会话）。
    pub new_sent: bool,
}

impl StreamSender {
    #[must_use]
    pub fn new(id: u16, network: TargetNetwork, target: TargetAddr) -> Self {
        StreamSender {
            id,
            network,
            target,
            new_sent: false,
        }
    }

    /// `writeFirstPayload`：`payload == None` 表示 100ms 内没有首包
    /// （参考 `ErrNotTimeoutReader` / `ErrReadTimeout`）→ 只发 New 元数据帧。
    ///
    /// 参考 `writeMetaOnly`（`writer.go:62-69`）走 `getNextFrameMeta()`，
    /// 其 `Option` 为 0：**元数据帧不得带 `OptionData`**，否则对端会把下一帧
    /// 的长度字段误当作本帧数据长度读走（本卡实跑证据：Xray 报
    /// `unknown status: 108`）。
    ///
    /// `Some(bytes)` 对 Stream 按 8KiB 切分，且**每片各自成帧**
    /// （`WriteMultiBuffer` → 每片一次 `writeData`：首片 New，其余 Keep）；
    /// 对 UDP（Packet）一次调用即一个数据报、一帧。
    pub fn send_new(
        &mut self,
        out: &mut Vec<u8>,
        payload: Option<&[u8]>,
    ) -> Result<(), FrameError> {
        let pieces = payload.map_or_else(Vec::new, |bytes| self.frame_payloads(bytes));
        let meta = FrameMetadata {
            session_id: self.id,
            status: SessionStatus::New,
            option: if pieces.is_empty() { 0 } else { OPTION_DATA },
            target: Some((self.target.clone(), self.network)),
            source: None,
            local: None,
        };
        meta.encode_into(out)?;
        self.new_sent = true;
        if let Some(first) = pieces.first().copied() {
            encode_data_into(out, first)?;
            for piece in &pieces[1..] {
                self.write_keep_data(out, piece)?;
            }
        }
        Ok(())
    }

    /// `writeData`：后续数据一律 Keep 帧（`getNextFrameMeta` 的 followup 分支）。
    pub fn send_keep(&mut self, out: &mut Vec<u8>, payload: &[u8]) -> Result<(), FrameError> {
        if !self.new_sent {
            return self.send_new(out, Some(payload));
        }
        for piece in self.frame_payloads(payload) {
            self.write_keep_data(out, piece)?;
        }
        Ok(())
    }

    /// 空 `WriteMultiBuffer`：只发元数据，不发数据段（`writeMetaOnly`，Option=0）。
    pub fn send_keep_meta_only(&mut self, out: &mut Vec<u8>) -> Result<(), FrameError> {
        let meta = FrameMetadata {
            session_id: self.id,
            status: SessionStatus::Keep,
            option: 0,
            target: None,
            source: None,
            local: None,
        };
        meta.encode_into(out)
    }

    /// `Writer.Close()`：`SessionStatusEnd`（出错时带 `OptionError`）。
    pub fn send_end(&mut self, out: &mut Vec<u8>, had_error: bool) -> Result<(), FrameError> {
        let option = if had_error { OPTION_ERROR } else { 0 };
        ServerSession::encode_frame(out, self.id, SessionStatus::End, option, None)
    }

    /// 参考 `Writer.WriteMultiBuffer` 的分片：Stream 用
    /// `buf.SplitSize(mb, 8*1024)`（每片一帧），Packet 用 `SplitFirst`
    /// （每次一个数据报、一帧）。
    fn frame_payloads<'a>(&self, payload: &'a [u8]) -> Vec<&'a [u8]> {
        if payload.is_empty() {
            Vec::new()
        } else if self.network == TargetNetwork::Udp {
            vec![payload]
        } else {
            payload
                .chunks(crate::muxframe::SESSION_CHUNK_SIZE)
                .collect()
        }
    }

    /// 一个 Keep 元数据 + 单段数据的完整帧。
    fn write_keep_data(&self, out: &mut Vec<u8>, payload: &[u8]) -> Result<(), FrameError> {
        let meta = FrameMetadata {
            session_id: self.id,
            status: SessionStatus::Keep,
            option: OPTION_DATA,
            target: None,
            source: None,
            local: None,
        };
        meta.encode_into(out)?;
        encode_data_into(out, payload)
    }
}

/// 读端帧迭代器（`ClientWorker.fetchOutput` / `ServerWorker.run` 的读循环）。
///
/// 每帧返回 `(meta, payload)`：`payload` 为 `Some` 表示该帧后跟数据段
/// （长度由帧内 `BE16` 给出），否则为 `None`。`stream` 决定数据段长度上限
/// （会话 transferType：stream=8192、packet=8192）。
pub struct FrameReader<R: Read> {
    reader: R,
    read_source_and_local: bool,
}

impl<R: Read> FrameReader<R> {
    #[must_use]
    pub fn new(reader: R, read_source_and_local: bool) -> Self {
        FrameReader {
            reader,
            read_source_and_local,
        }
    }

    /// 读一个帧（元数据 + 可选数据段）。
    pub fn next_frame(&mut self) -> Result<(FrameMetadata, Option<Vec<u8>>), FrameError> {
        let meta = FrameMetadata::decode_from(&mut self.reader, self.read_source_and_local)?;
        let payload = if meta.has_data() {
            Some(read_data(&mut self.reader, true)?)
        } else {
            None
        };
        Ok((meta, payload))
    }
}

/// 便捷：把「元数据 + 载荷」编成一条完整帧（New/Keep 带数据时用）。
pub fn encode_frame_with_payload(
    session_id: u16,
    status: SessionStatus,
    option: u8,
    target: Option<(&TargetAddr, TargetNetwork)>,
    payload: Option<&[u8]>,
) -> Result<Vec<u8>, FrameError> {
    let meta = FrameMetadata {
        session_id,
        status,
        option,
        target: target.map(|(addr, network)| (addr.clone(), network)),
        source: None,
        local: None,
    };
    let mut out = Vec::new();
    meta.encode_into(&mut out)?;
    if let Some(data) = payload {
        encode_data_into(&mut out, data)?;
    }
    Ok(out)
}

/// 供调用方复用的地址段辅助（与 [`crate::server::decode`] 的 PortThenAddress 同构，
/// 但本层必须独立实现以对齐 `protocol.PortThenAddress` 的字节推进语义）。
pub fn address_port_len(addr: &TargetAddr) -> usize {
    let mut sink = Vec::new();
    encode_address_port(&mut sink, addr).expect("地址可编码");
    sink.len()
}

/// 反向：从字节流直接读一个地址段（含端口），供调用方解析自定义扩展。
pub fn read_address_port(bytes: &[u8]) -> Result<(TargetAddr, usize), FrameError> {
    decode_address_port(bytes)
}
