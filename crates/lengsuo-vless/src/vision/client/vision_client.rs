//! 客户端流量层主体：上行写 / 下行读（参考 `VisionWriter` / `VisionReader`）。
//!
//! 从父模块拆出以保持单文件 ≤400 行（软约束）。逐条对齐参考 `proxy.go` 与
//! outbound `postRequest` 的首包直发决策；详见父模块文档。

use aes_gcm::aead::rand_core::RngCore;

use super::super::framing::{
    is_complete_record, reshape_payload, PADDING_OVERHEAD, TLS_APPLICATION_DATA_START,
};
use super::filter::{padding_length, xtls_filter_tls_single};
use super::state::TrafficState;
use super::{
    COMMAND_PADDING_CONTINUE, COMMAND_PADDING_DIRECT, COMMAND_PADDING_END, DEFAULT_TEST_SEED,
};

/// VLESS Vision 客户端：持有一条连接的上行/下行角色状态机与 padding 参数。
pub struct VisionClient {
    /// 流量状态（拆分前为私有字段；拆分后测试移入同级 `tests` 模块，
    /// 故放开到 `pub(super)` 以保持测试可见性，**对外可见性不变**）。
    pub(super) state: TrafficState,
    uuid: [u8; 16],
    uuid_once: Option<[u8; 16]>,
    testseed: [u32; 4],
    rng: Box<dyn RngCore>,
    /// 下行初始态缓冲：参考依赖「首个缓冲 ≥21 字节且以 UUID 开头」的软约定；
    /// 本实现把不足 21 字节的首块攒满再判定，避免 TCP 短读破坏初始同步。
    downlink: Vec<u8>,
}

impl core::fmt::Debug for VisionClient {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VisionClient")
            .field("state", &self.state)
            .field("uuid_once_written", &self.uuid_once.is_none())
            .field("testseed", &self.testseed)
            .finish_non_exhaustive()
    }
}

impl VisionClient {
    pub fn new(uuid: [u8; 16], testseed: Option<[u32; 4]>, rng: Box<dyn RngCore>) -> Self {
        Self {
            state: TrafficState::new(uuid),
            uuid,
            uuid_once: Some(uuid),
            testseed: testseed.unwrap_or(DEFAULT_TEST_SEED),
            rng,
            downlink: Vec::new(),
        }
    }

    /// 用系统 CSPRNG 建立客户端（生产/互通路径的便捷入口）。
    pub fn new_with_os_rng(uuid: [u8; 16], testseed: Option<[u32; 4]>) -> Self {
        Self::new(uuid, testseed, Box::new(aes_gcm::aead::OsRng))
    }

    /// 当前流量状态（诊断用；不含密钥）。
    pub fn traffic_state(&self) -> &TrafficState {
        &self.state
    }

    /// 参考 `XtlsPadding` 的 padding 块编码。
    ///
    /// 拆分前为私有方法；拆分后测试移入同级 `tests` 模块，故放开到
    /// `pub(super)` 以保持测试可见性，**对外可见性不变**。
    pub(super) fn xtls_padding(
        &mut self,
        command: u8,
        content: &[u8],
        long_padding: bool,
    ) -> Vec<u8> {
        let content_len = content.len() as i32;
        let padding_len = padding_length(content_len, long_padding, &self.testseed, &mut *self.rng);
        let mut out = Vec::with_capacity(PADDING_OVERHEAD + content.len() + padding_len as usize);
        if let Some(uuid) = self.uuid_once.take() {
            out.extend_from_slice(&uuid);
        }
        out.push(command);
        out.extend_from_slice(&(content_len as u16).to_be_bytes());
        out.extend_from_slice(&(padding_len as u16).to_be_bytes());
        out.extend_from_slice(content);
        out.resize(out.len() + padding_len as usize, 0);
        out
    }

    /// 参考 outbound `postRequest` 的首包直发决策：
    /// - `Some(payload)`：首包已就绪，直接随 VLESS 头一起发出（走 [`encode_uplink`]）。
    /// - `None`：500ms 内无首包，插入 0 内容 `Continue` 长 padding 块遮蔽头长度
    ///   （对应 `XtlsPadding(nil, COMMAND_PADDING_CONTINUE, &uuid, true, …)`；nil 块
    ///   不做 `XtlsFilterTls`，不消耗 `NumberOfPacketToFilter`）。
    pub fn encode_first_uplink(&mut self, payload: Option<&[u8]>) -> Vec<u8> {
        match payload {
            Some(payload) => self.encode_uplink(payload),
            None => {
                if self.state.outbound.is_padding && !self.state.outbound.uplink_writer_direct_copy
                {
                    self.xtls_padding(COMMAND_PADDING_CONTINUE, &[], true)
                } else {
                    Vec::new()
                }
            }
        }
    }

    /// 参考 `VisionWriter.WriteMultiBuffer` 的上行写（单入参扁平化为参考的一个
    /// MultiBuffer；`≥BUF_SIZE-21` 时先 [`reshape_payload`] 再逐段 padding，顺序、
    /// 分支与 (a) continue / (b) break 后余段原样透传均对齐参考）。
    pub fn encode_uplink(&mut self, payload: &[u8]) -> Vec<u8> {
        if self.state.outbound.uplink_writer_direct_copy {
            return payload.to_vec();
        }
        // 参考顺序：先对整批 XtlsFilterTls，再判定 padding。
        if self.state.number_of_packet_to_filter > 0 {
            xtls_filter_tls_single(&mut self.state, payload);
        }
        if !self.state.outbound.is_padding {
            return payload.to_vec();
        }

        // 参考在 reshape 前对整批缓冲算一次 IsCompleteRecord，拆出的每段共享该判定。
        let is_complete = is_complete_record(payload);
        let pieces = reshape_payload(payload);
        let mut out = Vec::with_capacity(payload.len() + PADDING_OVERHEAD * pieces.len());
        let piece_count = pieces.len();
        let mut long_padding = self.state.is_tls;
        let mut index = 0usize;
        while index < piece_count {
            let piece = pieces[index];
            let is_tls_record = self.state.is_tls
                && piece.len() >= 6
                && piece[..3] == TLS_APPLICATION_DATA_START
                && is_complete;
            if is_tls_record {
                if self.state.enable_xtls {
                    self.state.outbound.uplink_writer_direct_copy = true;
                }
                let command = if index == piece_count - 1 {
                    if self.state.enable_xtls {
                        COMMAND_PADDING_DIRECT
                    } else {
                        COMMAND_PADDING_END
                    }
                } else {
                    COMMAND_PADDING_CONTINUE
                };
                out.extend_from_slice(&self.xtls_padding(command, piece, true));
                self.state.outbound.is_padding = false;
                long_padding = false;
                index += 1;
                continue;
            }
            if !self.state.is_tls12_or_above && self.state.number_of_packet_to_filter <= 1 {
                self.state.outbound.is_padding = false;
                out.extend_from_slice(&self.xtls_padding(COMMAND_PADDING_END, piece, long_padding));
                index += 1;
                break;
            }
            let command = if index == piece_count - 1 && !self.state.outbound.is_padding {
                if self.state.enable_xtls {
                    COMMAND_PADDING_DIRECT
                } else {
                    COMMAND_PADDING_END
                }
            } else {
                COMMAND_PADDING_CONTINUE
            };
            out.extend_from_slice(&self.xtls_padding(command, piece, long_padding));
            index += 1;
        }
        // 参考 (b) break 后，尚未 padding 的剩余段保留在 MultiBuffer 中原样写出。
        for piece in &pieces[index..] {
            out.extend_from_slice(piece);
        }
        out
    }

    /// 上行结束收尾：若仍处于 padding 状态，补发 0 内容 `COMMAND_PADDING_END` 块
    /// （与参考 `XtlsPadding(…, COMMAND_PADDING_END, …, isTLS, …)` 字节一致），
    /// 使对端退出 padding；其余情况返回空。
    pub fn encode_uplink_finish(&mut self) -> Vec<u8> {
        if !self.state.outbound.is_padding || self.state.outbound.uplink_writer_direct_copy {
            return Vec::new();
        }
        let long_padding = self.state.is_tls;
        let block = self.xtls_padding(COMMAND_PADDING_END, &[], long_padding);
        self.state.outbound.is_padding = false;
        block
    }

    /// 参考 `VisionReader.ReadMultiBuffer` 的解包路径（客户端下行，`Outbound`）。
    /// 一行字节进、解包后的明文追加到 `out`；直拷贝状态下原样透传。
    pub fn decode_downlink(&mut self, wire: &[u8], out: &mut Vec<u8>) {
        if self.state.outbound.downlink_reader_direct_copy {
            out.extend_from_slice(&self.downlink);
            self.downlink.clear();
            out.extend_from_slice(wire);
            return;
        }
        let o = self.state.outbound;
        let do_padding_phase =
            o.within_padding_buffers || self.state.number_of_packet_to_filter > 0;
        if !do_padding_phase {
            out.extend_from_slice(&self.downlink);
            self.downlink.clear();
            out.extend_from_slice(wire);
            return;
        }
        self.downlink.extend_from_slice(wire);
        let o = self.state.outbound;
        let in_initial =
            o.remaining_command == -1 && o.remaining_content == -1 && o.remaining_padding == -1;
        if in_initial && self.downlink.len() < PADDING_OVERHEAD {
            return; // 首块头部（UUID+5 字节）未凑齐，攒满再判定。
        }
        let buffered = std::mem::take(&mut self.downlink);
        let mut scratch = Vec::with_capacity(buffered.len());
        self.xtls_unpadding(&buffered, &mut scratch);
        let o = &mut self.state.outbound;
        if o.remaining_content > 0 || o.remaining_padding > 0 || o.current_command == 0 {
            o.within_padding_buffers = true;
        } else if o.current_command == 1 {
            o.within_padding_buffers = false;
        } else if o.current_command == 2 {
            o.within_padding_buffers = false;
            o.downlink_reader_direct_copy = true;
        }
        if self.state.number_of_packet_to_filter > 0 && !scratch.is_empty() {
            xtls_filter_tls_single(&mut self.state, &scratch);
        }
        out.extend_from_slice(&scratch);
    }

    /// 参考 `XtlsUnpadding`：把一个（可能跨块）线上缓冲拆成明文。
    fn xtls_unpadding(&mut self, wire: &[u8], out: &mut Vec<u8>) {
        let uuid = self.uuid;
        let o = &mut self.state.outbound;
        let mut pos = 0usize;
        if o.remaining_command == -1 && o.remaining_content == -1 && o.remaining_padding == -1 {
            if wire.len() - pos >= PADDING_OVERHEAD && wire[pos..pos + 16] == uuid {
                pos += 16;
                o.remaining_command = 5;
            } else {
                out.extend_from_slice(&wire[pos..]);
                return;
            }
        }
        while pos < wire.len() {
            if o.remaining_command > 0 {
                let data = wire[pos];
                pos += 1;
                match o.remaining_command {
                    5 => o.current_command = i32::from(data),
                    4 => o.remaining_content = i32::from(data) << 8,
                    3 => o.remaining_content |= i32::from(data),
                    2 => o.remaining_padding = i32::from(data) << 8,
                    1 => o.remaining_padding |= i32::from(data),
                    _ => {}
                }
                o.remaining_command -= 1;
            } else if o.remaining_content > 0 {
                let mut len = o.remaining_content as usize;
                if wire.len() - pos < len {
                    len = wire.len() - pos;
                }
                out.extend_from_slice(&wire[pos..pos + len]);
                pos += len;
                o.remaining_content -= len as i32;
            } else {
                let mut len = o.remaining_padding as usize;
                if wire.len() - pos < len {
                    len = wire.len() - pos;
                }
                pos += len;
                o.remaining_padding -= len as i32;
            }
            if o.remaining_command <= 0 && o.remaining_content <= 0 && o.remaining_padding <= 0 {
                if o.current_command == 0 {
                    o.remaining_command = 5;
                } else {
                    o.remaining_command = -1;
                    o.remaining_content = -1;
                    o.remaining_padding = -1;
                    if pos < wire.len() {
                        out.extend_from_slice(&wire[pos..]);
                    }
                    break;
                }
            }
        }
    }
}
