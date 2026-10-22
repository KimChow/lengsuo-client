//! 服务端会话状态机：对齐 `proxy.go` 的 `VisionReader` / `VisionWriter`
//! （服务端方向：`isUplink=true` 读、`isUplink=false` 写）。
//!
//! 从 [`super`] 拆出以保持单文件 ≤400 行（软约束）；行为逐字节等价。

use aes_gcm::aead::rand_core::RngCore;

use super::super::client::{
    TrafficState, COMMAND_PADDING_CONTINUE, COMMAND_PADDING_DIRECT, COMMAND_PADDING_END,
    DEFAULT_TEST_SEED,
};
use super::super::framing::{
    is_complete_record, reshape_payload, PADDING_OVERHEAD, TLS_APPLICATION_DATA_START,
};
use super::super::unpad::Unpad;

/// VLESS Vision 服务端：持有一条连接**服务端方向**的流量层状态机与 padding 参数。
///
/// 状态组：
/// - 上行读（客户端 → 服务端）：`state.inbound` 的 `WithinPaddingBuffers` /
///   `UplinkReaderDirectCopy` + `InboundState` 的 `remaining_*` / `current_command`。
/// - 下行写（服务端 → 客户端）：`state.inbound` 的 `IsPadding` /
///   `DownlinkWriterDirectCopy`，与参考 `VisionWriter`（`isUplink=false`）一致。
pub struct VisionServer {
    /// 流量状态。对本模块的单元测试可见（`pub(super)` 不进入公开 API 面）。
    pub(super) state: TrafficState,
    uuid: [u8; 16],
    /// 下行首块一次性 UUID：与参考 `writeOnceUserUUID` 同义——只在下行**首个**
    /// 被 padding 的块前写一次，写后置 `None`。注意与服务端上行读的 UUID 校验
    /// （固定用 `self.uuid`）不同：那是校验而非写入。
    write_once_uuid: Option<[u8; 16]>,
    testseed: [u32; 4],
    rng: Box<dyn RngCore>,
    /// 上行解包状态直接落在 [`TrafficState::inbound`]（对齐参考把 `s.Inbound` 指针
    /// 传入 `XtlsUnpadding`），不另存副本。
    ///
    /// 上行初始态尚未凑齐 21 字节头（UUID + 5 字节块头）的线上缓存：参考依赖
    /// 「MultiBuffer 元素本身已是完整块」的软约定；本实现把不足 21 字节的首块攒满
    /// 再判定，避免 TCP 短读把首块误判为「非 Vision 直通」（与客户端侧
    /// [`super::super::client::VisionClient`] 的 `downlink` 缓冲同构）。
    uplink_head: Vec<u8>,
    /// 直拷贝建立前、尚未归属当前块的残余线上字节（对齐参考 `input` / `rawInput`）；
    /// 切直拷贝时随最后一段明文一起吐出。
    pending: Vec<u8>,
}

impl core::fmt::Debug for VisionServer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VisionServer")
            .field("state", &self.state)
            .field("write_once_uuid_written", &self.write_once_uuid.is_none())
            .finish_non_exhaustive()
    }
}

impl VisionServer {
    /// 建立服务端 Vision 实例。`testseed` 少于 4 项时回落参考默认 `{900,500,900,256}`。
    pub fn new(uuid: [u8; 16], testseed: Option<[u32; 4]>, rng: Box<dyn RngCore>) -> Self {
        Self {
            state: TrafficState::new(uuid),
            uuid,
            // 参考 `NewVisionWriter` 只在**首个被 padding 的块**写 UUID；构造时持有。
            write_once_uuid: Some(uuid),
            testseed: testseed.unwrap_or(DEFAULT_TEST_SEED),
            rng,
            uplink_head: Vec::new(),
            pending: Vec::new(),
        }
    }

    /// 用系统 CSPRNG 建立（生产路径便捷入口）。
    pub fn new_with_os_rng(uuid: [u8; 16], testseed: Option<[u32; 4]>) -> Self {
        Self::new(uuid, testseed, Box::new(aes_gcm::aead::OsRng))
    }

    /// 当前流量状态（诊断用；不含密钥）。
    pub fn traffic_state(&self) -> &TrafficState {
        &self.state
    }

    /// 是否已切直拷贝（上行读）。
    pub fn uplink_direct_copy(&self) -> bool {
        self.state.inbound.uplink_reader_direct_copy
    }

    /// 是否已切直拷贝（下行写）。
    pub fn downlink_direct_copy(&self) -> bool {
        self.state.inbound.downlink_writer_direct_copy
    }

    /// 参考 `XtlsPadding`：按命令 / 内容 / 长 padding 造一条 padding 块。
    /// 首个被 padding 的块前写一次 UUID（`write_once_uuid`）。
    fn xtls_padding(&mut self, command: u8, content: &[u8], long_padding: bool) -> Vec<u8> {
        let content_len = content.len() as i32;
        let padding_len = super::super::client::padding_length(
            content_len,
            long_padding,
            &self.testseed,
            &mut *self.rng,
        );
        let mut out = Vec::with_capacity(PADDING_OVERHEAD + content.len() + padding_len as usize);
        if let Some(uuid) = self.write_once_uuid.take() {
            out.extend_from_slice(&uuid);
        }
        out.push(command);
        out.extend_from_slice(&(content_len as u16).to_be_bytes());
        out.extend_from_slice(&(padding_len as u16).to_be_bytes());
        out.extend_from_slice(content);
        out.resize(out.len() + padding_len as usize, 0);
        out
    }

    /// 参考 `VisionReader.ReadMultiBuffer`（服务端上行读，`isUplink=true`）。
    ///
    /// 输入线上已解 AEAD 记录的明文字节 `wire`，输出解 padding 后的明文追加到 `out`。
    /// 直拷贝态下原样透传（含此前挂起的 `pending`，对齐参考把 `input` / `rawInput`
    /// 合并后切直拷贝）。
    pub fn decode_uplink(&mut self, wire: &[u8], out: &mut Vec<u8>) {
        if self.state.inbound.uplink_reader_direct_copy {
            flush_pending(&mut self.pending, out);
            out.extend_from_slice(wire);
            return;
        }
        // 与参考一致的 padding 阶段判据；**报告偏离（补强）**：参考
        // `VisionReader.ReadMultiBuffer` 的 `*WithinPaddingBuffers` 更新
        // （`remainingContent>0 || remainingPadding>0 || currentCommand==0`）依赖
        // 「MultiBuffer 元素 = 完整块」这一软约定。本接口接收的是可任意切分的线上
        // 字节，故在以上判据外**额外**把「块头尚未读完」（`remaining_command > 0`）
        // 也视为仍在 padding 阶段，否则短读到块头中段会把剩余字节误判为直通明文。
        let mid_block =
            !self.state.inbound.is_initial() && self.state.inbound.remaining_command > 0;
        let do_padding_phase = self.state.inbound.within_padding_buffers
            || self.state.number_of_packet_to_filter > 0
            || mid_block;
        if !do_padding_phase {
            flush_pending(&mut self.pending, out);
            out.extend_from_slice(wire);
            return;
        }

        // 初始态把不足 21 字节的首块攒满再判定；否则 TCP 短读会让 `unpad` 误判
        // 「首块非 UUID」而原样透传（对齐参考「元素即完整块」的软约定）。
        let initial = self.state.inbound.is_initial();
        let buffered: &[u8] = if initial && self.uplink_head.len() + wire.len() < PADDING_OVERHEAD {
            self.uplink_head.extend_from_slice(wire);
            return;
        } else if initial && !self.uplink_head.is_empty() {
            self.uplink_head.extend_from_slice(wire);
            &self.uplink_head
        } else {
            wire
        };

        // 参考对**每个** MultiBuffer 元素逐个 XtlsUnpadding；本接口接收的是一段可跨块的
        // 线上字节，交给同一状态机连续解包（与客户端侧 `decode_downlink` 对称）。
        let mut scratch = Vec::with_capacity(buffered.len());
        let uuid = self.uuid;
        self.state.inbound.unpad(buffered, &uuid, &mut scratch);
        if !self.uplink_head.is_empty() {
            self.uplink_head.clear();
        }

        let o = &mut self.state.inbound;
        if o.remaining_command > 0
            || o.remaining_content > 0
            || o.remaining_padding > 0
            || o.current_command == 0
        {
            o.within_padding_buffers = true;
        } else if o.current_command == 1 {
            o.within_padding_buffers = false;
        } else if o.current_command == 2 {
            o.within_padding_buffers = false;
            o.uplink_reader_direct_copy = true;
        }

        if self.state.number_of_packet_to_filter > 0 && !scratch.is_empty() {
            super::super::client::xtls_filter_tls_single(&mut self.state, &scratch);
        }

        if self.state.inbound.uplink_reader_direct_copy {
            // 切直拷贝：把此前挂起的残余与本次明文一起吐出（参考合并 input / rawInput）。
            flush_pending(&mut self.pending, out);
        }
        out.extend_from_slice(&scratch);
    }

    /// 参考 `VisionWriter.WriteMultiBuffer`（服务端下行写，`isUplink=false`）。
    ///
    /// 返回需要写到线上的字节：padding 期按参考规则包块，随后回到 `is_padding=false`
    /// 原样透传；直拷贝态原样透传。
    ///
    /// `first_empty` 对应该参考里 `mb[0] == nil` 的场景（首包为空）：插入一条 0 内容
    /// `Continue` 长 padding 块遮蔽 VLESS 头长度；否则按 `is_complete_record` /
    /// `reshape_payload` 分支处理。
    pub fn encode_downlink(&mut self, payload: &[u8], first_empty: bool) -> Vec<u8> {
        if self.state.inbound.downlink_writer_direct_copy {
            return payload.to_vec();
        }
        if self.state.number_of_packet_to_filter > 0 && !payload.is_empty() {
            super::super::client::xtls_filter_tls_single(&mut self.state, payload);
        }

        if !self.state.inbound.is_padding {
            return payload.to_vec();
        }

        if first_empty {
            // 参考：`len(mb)==1 && mb[0]==nil` → 0 内容 Continue 长 padding 块。
            return self.xtls_padding(COMMAND_PADDING_CONTINUE, &[], true);
        }

        let is_complete = is_complete_record(payload);
        let pieces = reshape_payload(payload);
        let piece_count = pieces.len();
        let mut out = Vec::with_capacity(payload.len() + PADDING_OVERHEAD * piece_count);
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
                    self.state.inbound.downlink_writer_direct_copy = true;
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
                self.state.inbound.is_padding = false;
                long_padding = false;
                index += 1;
                continue;
            }
            if !self.state.is_tls12_or_above && self.state.number_of_packet_to_filter <= 1 {
                self.state.inbound.is_padding = false;
                out.extend_from_slice(&self.xtls_padding(COMMAND_PADDING_END, piece, long_padding));
                index += 1;
                break;
            }
            let command = if index == piece_count - 1 && !self.state.inbound.is_padding {
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
        for piece in &pieces[index..] {
            out.extend_from_slice(piece);
        }
        out
    }

    /// 下行结束收尾：若仍处于 padding 状态，补发 0 内容 `COMMAND_PADDING_END` 块，
    /// 使对端退出 padding（对称于客户端侧
    /// [`super::super::client::VisionClient::encode_uplink_finish`]；
    /// 参考在服务端下行 EOF 不显式补发，属报告的**有意补强**）。
    pub fn encode_downlink_finish(&mut self) -> Vec<u8> {
        if !self.state.inbound.is_padding || self.state.inbound.downlink_writer_direct_copy {
            return Vec::new();
        }
        let long_padding = self.state.is_tls;
        let block = self.xtls_padding(COMMAND_PADDING_END, &[], long_padding);
        self.state.inbound.is_padding = false;
        block
    }
}

/// 把挂起缓冲吐到 `out` 并清空。
fn flush_pending(pending: &mut Vec<u8>, out: &mut Vec<u8>) {
    out.extend_from_slice(pending);
    pending.clear();
}
