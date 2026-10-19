//! VLESS Vision **服务端侧**流量层：对齐 `proxy.go` 的 `VisionReader` /
//! `VisionWriter`（服务端：上行读 = `Inbound` 状态组，下行写 = `Inbound` 状态组；
//! [客户端侧](super::client)对称地走上行写 / 下行读 = `Outbound` 状态组）。
//!
//! 场景：官方 Xray 客户端（outbound vless `flow=xtls-rprx-vision`）→ 本仓服务端。
//! - 上行（服务端读）：解 `XtlsPadding` 块（命令 + 内容 + padding），首块含 16 字节
//!   UUID；命令 `Continue(0)` 继续、`End(1)` 结束 padding、`Direct(2)` 结束并切直拷贝。
//! - 下行（服务端写）：在 padding 期按参考规则给下行数据加 padding 块，`IsTLS` /
//!   `IsTLS12orAbove` 决定是否走 TLS 应用数据捷径与长 padding；首包为空时插入一条
//!   0 内容 `Continue` 长 padding 块。
//!
//! 与客户端侧共用 [`super::client`] 的状态模型、[`super::framing`] 的
//! `is_complete_record` / `reshape_payload`、[`super::rand_below`] 与
//! [`super::padding`] 的握手 padding 参数，故本模块只补「服务端方向」这一层。
//!
//! 对齐口径：本模块只实现**流量层**（padding / 解帧 / 直拷贝切换判据），不含
//! REALITY、通用多会话 Mux / XUDP 跨连接、也不做 splice 内核直拷贝——
//! `enable_xtls` 判据按参考转写，真机直拷贝切换留给呼叫方（与客户端侧一致）。
//!
//! 本模块不含 `unsafe`。

use aes_gcm::aead::rand_core::RngCore;

use super::client::{
    TrafficState, COMMAND_PADDING_CONTINUE, COMMAND_PADDING_DIRECT, COMMAND_PADDING_END,
    DEFAULT_TEST_SEED,
};
use super::framing::{
    is_complete_record, reshape_payload, PADDING_OVERHEAD, TLS_APPLICATION_DATA_START,
};
use super::unpad::Unpad;

/// VLESS Vision 服务端：持有一条连接**服务端方向**的流量层状态机与 padding 参数。
///
/// 状态组：
/// - 上行读（客户端 → 服务端）：`state.inbound` 的 `WithinPaddingBuffers` /
///   `UplinkReaderDirectCopy` + [`InboundState`] 的 `remaining_*` / `current_command`。
/// - 下行写（服务端 → 客户端）：`state.inbound` 的 `IsPadding` /
///   `DownlinkWriterDirectCopy`，与参考 `VisionWriter`（`isUplink=false`）一致。
pub struct VisionServer {
    state: TrafficState,
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
    /// [`super::client::VisionClient`] 的 `downlink` 缓冲同构）。
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
        let padding_len = super::client::padding_length(
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
            super::client::xtls_filter_tls_single(&mut self.state, &scratch);
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
            super::client::xtls_filter_tls_single(&mut self.state, payload);
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
    /// 使对端退出 padding（对称于客户端侧 [`super::client::VisionClient::encode_uplink_finish`]；
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

#[cfg(test)]
mod tests {
    use super::super::client::{InboundState, VisionClient};
    use super::super::test_util::CounterRng;
    use super::*;

    const UUID: [u8; 16] = [0x22; 16];

    fn server() -> VisionServer {
        VisionServer::new(UUID, None, Box::new(CounterRng(0)))
    }

    /// 从 padding 块解析 `(command, content, padding)`（剥可选 16 字节 UUID）。
    fn parse_block(block: &[u8]) -> (u8, &[u8], &[u8]) {
        let tail = if block.len() >= 16 && block[..16] == UUID {
            &block[16..]
        } else {
            block
        };
        let command = tail[0];
        let content_len = (usize::from(tail[1]) << 8) | usize::from(tail[2]);
        let padding_len = (usize::from(tail[3]) << 8) | usize::from(tail[4]);
        assert_eq!(tail[5..].len(), content_len + padding_len);
        let (content, padding) = tail[5..].split_at(content_len);
        (command, content, padding)
    }

    #[test]
    fn unpad_roundtrips_single_continue_block_with_uuid() {
        // 造：UUID + Continue + content "hello" + 0 padding。
        let mut block = UUID.to_vec();
        block.push(COMMAND_PADDING_CONTINUE);
        block.extend_from_slice(&5u16.to_be_bytes());
        block.extend_from_slice(&0u16.to_be_bytes());
        block.extend_from_slice(b"hello");
        let mut state = InboundState::default();
        let mut out = Vec::new();
        state.unpad(&block, &UUID, &mut out);
        assert_eq!(out, b"hello");
        // Continue 后进入下一块头读取（块未结束）。
        assert_eq!(state.remaining_command, 5);
        assert_eq!(state.current_command, 0);
    }

    #[test]
    fn unpad_strips_padding_and_ends_on_end_command() {
        // Continue 块 + End 块：应只吐内容，End 后回初始态。
        let mut wire = UUID.to_vec();
        wire.push(COMMAND_PADDING_CONTINUE);
        wire.extend_from_slice(&3u16.to_be_bytes());
        wire.extend_from_slice(&4u16.to_be_bytes());
        wire.extend_from_slice(b"abc");
        wire.extend_from_slice(&[0u8; 4]);
        wire.push(COMMAND_PADDING_END);
        wire.extend_from_slice(&0u16.to_be_bytes());
        wire.extend_from_slice(&2u16.to_be_bytes());
        wire.extend_from_slice(&[0u8; 2]);
        let mut state = InboundState::default();
        let mut out = Vec::new();
        state.unpad(&wire, &UUID, &mut out);
        assert_eq!(out, b"abc");
        assert!(state.is_initial());
        assert_eq!(state.current_command, COMMAND_PADDING_END as i32);
    }

    #[test]
    fn unpad_returns_raw_when_first_block_lacks_uuid() {
        // 初始态但首 16 字节不是 UUID → 原样返回，不解析块。
        let wire = b"not a vision block at all";
        let mut state = InboundState::default();
        let mut out = Vec::new();
        state.unpad(wire, &UUID, &mut out);
        assert_eq!(out, wire);
        assert!(state.is_initial());
    }

    #[test]
    fn unpad_reassembles_content_crossing_block_boundary() {
        // Continue 块（无 padding，内容 11 字节）紧接 End 块：`unpad` 需跨块重组，
        // 两个块命令不同但内容应连续吐出。
        let mut wire = UUID.to_vec();
        wire.push(COMMAND_PADDING_CONTINUE);
        wire.extend_from_slice(&11u16.to_be_bytes());
        wire.extend_from_slice(&0u16.to_be_bytes());
        wire.extend_from_slice(b"hello world");
        wire.push(COMMAND_PADDING_END);
        wire.extend_from_slice(&0u16.to_be_bytes());
        wire.extend_from_slice(&0u16.to_be_bytes());
        let mut state = InboundState::default();
        let mut out = Vec::new();
        state.unpad(&wire, &UUID, &mut out);
        assert_eq!(out, b"hello world");
        assert!(state.is_initial());
        assert_eq!(state.current_command, COMMAND_PADDING_END as i32);
    }

    #[test]
    fn server_decode_uplink_roundtrips_client_encode() {
        // 本仓客户端上行编码 → 本仓服务端上行解码，逐字节一致。
        let payloads: Vec<Vec<u8>> = vec![
            b"request one".to_vec(),
            b"request two".to_vec(),
            b"request three".to_vec(),
        ];
        let mut wire = Vec::new();
        let mut expected = Vec::new();
        {
            let mut client = VisionClient::new(UUID, None, Box::new(CounterRng(0)));
            for (i, payload) in payloads.iter().enumerate() {
                let mut block = client.encode_uplink(payload);
                if i == payloads.len() - 1 {
                    block.extend_from_slice(&client.encode_uplink_finish());
                }
                wire.extend_from_slice(&block);
                expected.extend_from_slice(payload);
            }
        }
        let mut server = server();
        let mut got = Vec::new();
        for chunk in wire.chunks(7) {
            server.decode_uplink(chunk, &mut got);
        }
        assert_eq!(got, expected);
        assert!(!server.state.inbound.within_padding_buffers);
    }

    #[test]
    fn server_downlink_roundtrips_client_decode_downlink() {
        // 本仓服务端下行编码 → 本仓客户端下行解码，逐字节一致。
        let payloads: Vec<Vec<u8>> = vec![
            b"response one".to_vec(),
            b"response two".to_vec(),
            b"".to_vec(),
        ];
        let mut client = VisionClient::new(UUID, None, Box::new(CounterRng(0)));
        let mut server = server();
        let mut wire = Vec::new();
        let mut expected = Vec::new();
        for (i, payload) in payloads.iter().enumerate() {
            let first_empty = payload.is_empty();
            let mut block = if first_empty {
                server.encode_downlink(payload, true)
            } else {
                server.encode_downlink(payload, false)
            };
            if i == payloads.len() - 1 {
                block.extend_from_slice(&server.encode_downlink_finish());
            }
            wire.extend_from_slice(&block);
            expected.extend_from_slice(payload);
        }
        let mut got = Vec::new();
        for chunk in wire.chunks(5) {
            client.decode_downlink(chunk, &mut got);
        }
        assert_eq!(got, expected);
    }

    #[test]
    fn downlink_empty_first_write_uses_long_padding_rule() {
        let mut server = server();
        let block = server.encode_downlink(&[], true);
        let (command, content, padding) = parse_block(&block);
        assert_eq!(command, COMMAND_PADDING_CONTINUE);
        assert!(content.is_empty());
        // CounterRng 首值 0：padding = 900 + 0 - 0。
        assert_eq!(padding.len(), 900);
        assert!((900..1400).contains(&padding.len()));
    }

    #[test]
    fn downlink_first_block_carries_uuid_once() {
        let mut server = server();
        let first = server.encode_downlink(b"first", false);
        assert_eq!(&first[..16], &UUID[..]);
        let second = server.encode_downlink(b"second", false);
        assert!(second.len() < 16 || second[..16] != UUID[..]);
    }

    #[test]
    fn downlink_direct_command_switches_direct_copy() {
        // 构造 TLS ServerHello 使 IsTLS / EnableXtls 打开，随后一条完整 TLS 应用数据块
        // 应触发 Direct 命令并切直拷贝。
        let mut server = server();
        // 第 1 次：ServerHello（控制 IsTLS/EnableXtls）。
        let mut hello = vec![0x16, 0x03, 0x03, 0x00, 0x4E, 0x02];
        hello.resize(80, 0);
        hello[50] = 0x00;
        hello[51] = 0x2b;
        hello[52] = 0x00;
        hello[53] = 0x02;
        hello[54] = 0x03;
        hello[55] = 0x04;
        let suite_start = 43 + 1;
        hello[suite_start] = 0x13;
        hello[suite_start + 1] = 0x01;
        let _ = server.encode_downlink(&hello, false);
        assert!(server.state.is_tls && server.state.enable_xtls);
        // 第 2 次：完整 TLS 应用数据记录（头 17 03 03 + BE16 长 = 体长，体为 8 字节）。
        let body = b"hello123";
        let mut record = vec![0x17, 0x03, 0x03, 0x00, body.len() as u8];
        record.extend_from_slice(body);
        assert!(is_complete_record(&record));
        let block = server.encode_downlink(&record, false);
        let (command, content, _) = parse_block(&block);
        assert_eq!(command, COMMAND_PADDING_DIRECT);
        assert_eq!(content, &record[..]);
        assert!(server.downlink_direct_copy());
        assert!(!server.state.inbound.is_padding);
    }

    #[test]
    fn uplink_direct_command_switches_direct_copy() {
        // 服务端上行：客户端发来 Direct 命令块后进入直拷贝，后续字节原样透传。
        let mut server = server();
        let mut wire = UUID.to_vec();
        wire.push(COMMAND_PADDING_DIRECT);
        wire.extend_from_slice(&3u16.to_be_bytes());
        wire.extend_from_slice(&0u16.to_be_bytes());
        wire.extend_from_slice(b"abc");
        let mut out = Vec::new();
        server.decode_uplink(&wire, &mut out);
        assert_eq!(out, b"abc");
        assert!(server.uplink_direct_copy());
        let mut more = Vec::new();
        server.decode_uplink(b"raw tail", &mut more);
        assert_eq!(more, b"raw tail");
    }
}
