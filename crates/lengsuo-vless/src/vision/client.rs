//! VLESS Vision 客户端流量层：对齐 `proxy.go` 的 `TrafficState` / `VisionWriter` /
//! `VisionReader` / `XtlsPadding` / `XtlsUnpadding` / `XtlsFilterTls` /
//! `IsCompleteRecord` / `ReshapeMultiBuffer`，以及 outbound `postRequest` 的
//! **首包直发决策**（有数据 → 立即随 VLESS 头一起发；无数据 → 插入 0 内容长
//! padding 块遮蔽头长度）。
//!
//! 本模块只做客户端一侧：上行写、下行读都落在 [`TrafficState`] 的
//! `Outbound` 状态组（客户端对端是 Xray 入站的 `Inbound` 状态组）。
//! 不含 REALITY、多会话 Mux / XUDP 跨连接，也不做 splice 内核直拷贝——
//! `EnableXtls` 判据虽按参考转写，但真机直拷贝切换是呼叫方的事。
//!
//! 与参考的一处**有意补强（报告偏离清单）**：参考客户端在上行 EOF 时不会显式补发
//! `COMMAND_PADDING_END`，依赖 `NumberOfPacketToFilter` 倒数（>7 块）或 TLS inner
//! 记录边界来结束 padding；本实现提供 [`VisionClient::encode_uplink_finish`]，若
//! 半关闭时仍处于 padding 状态，则补发一条 0 内容 `End` 块，使 Xray 入站尽早退出
//! padding 状态（协议层字节与参考 `XtlsPadding(…, COMMAND_PADDING_END, …)` 完全一致）。
//!
//! 本模块不含 `unsafe`。

use aes_gcm::aead::rand_core::RngCore;

pub use super::framing::is_complete_record;
use super::framing::{reshape_payload, PADDING_OVERHEAD, TLS_APPLICATION_DATA_START};
use super::rand_below;

/// 参考 `proxy.go` 事件字节。
pub const COMMAND_PADDING_CONTINUE: u8 = 0x00;
/// 参考 `proxy.go` 事件字节。
pub const COMMAND_PADDING_END: u8 = 0x01;
/// 参考 `proxy.go` 事件字节。
pub const COMMAND_PADDING_DIRECT: u8 = 0x02;

/// 参考 `common/buf.Size`。
pub const BUF_SIZE: usize = 8192;

/// TLS 握手识别常量（`proxy.go` 全局变量，逐字一致；`TlsApplicationDataStart` 见
/// [`super::framing::TLS_APPLICATION_DATA_START`]）。
const TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
/// `TLS_AES_128_CCM_8_SHA256` 是参考唯一**不**视为可直拷贝的 TLS 1.3 套件。
const TLS_AES_128_CCM_8_SHA256: u16 = 0x1305;

/// 参考默认测试种子（`{900, 500, 900, 256}`）。
pub const DEFAULT_TEST_SEED: [u32; 4] = [900, 500, 900, 256];

/// 参考 `InboundState`（本客户端不使用，保留完整状态模型以便将来做入站侧）。
#[derive(Debug, Clone, Copy)]
pub struct InboundState {
    pub within_padding_buffers: bool,
    pub uplink_reader_direct_copy: bool,
    pub remaining_command: i32,
    pub remaining_content: i32,
    pub remaining_padding: i32,
    pub current_command: i32,
    pub is_padding: bool,
    pub downlink_writer_direct_copy: bool,
}

impl Default for InboundState {
    fn default() -> Self {
        Self {
            within_padding_buffers: true,
            uplink_reader_direct_copy: false,
            remaining_command: -1,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
            is_padding: true,
            downlink_writer_direct_copy: false,
        }
    }
}

/// 参考 `OutboundState`；客户端上行写 / 下行读都落在这里。
#[derive(Debug, Clone, Copy)]
pub struct OutboundState {
    pub within_padding_buffers: bool,
    pub downlink_reader_direct_copy: bool,
    pub remaining_command: i32,
    pub remaining_content: i32,
    pub remaining_padding: i32,
    pub current_command: i32,
    pub is_padding: bool,
    pub uplink_writer_direct_copy: bool,
}

impl Default for OutboundState {
    fn default() -> Self {
        Self {
            within_padding_buffers: true,
            downlink_reader_direct_copy: false,
            remaining_command: -1,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
            is_padding: true,
            uplink_writer_direct_copy: false,
        }
    }
}

/// 参考 `NewTrafficState`：单连接上下行共享的流量状态。
#[derive(Debug, Clone, Copy)]
pub struct TrafficState {
    pub user_uuid: [u8; 16],
    pub number_of_packet_to_filter: i32,
    pub enable_xtls: bool,
    pub is_tls12_or_above: bool,
    pub is_tls: bool,
    pub cipher: u16,
    pub remaining_server_hello: i32,
    pub inbound: InboundState,
    pub outbound: OutboundState,
}

impl TrafficState {
    pub fn new(user_uuid: [u8; 16]) -> Self {
        Self {
            user_uuid,
            number_of_packet_to_filter: 8,
            enable_xtls: false,
            is_tls12_or_above: false,
            is_tls: false,
            cipher: 0,
            remaining_server_hello: -1,
            inbound: InboundState::default(),
            outbound: OutboundState::default(),
        }
    }
}

/// 参考 `XtlsFilterTls`（单 buffer 形态：`payload` 非 nil 时才调用，且只降一档）。
pub(crate) fn xtls_filter_tls_single(state: &mut TrafficState, payload: &[u8]) {
    state.number_of_packet_to_filter -= 1;
    if payload.len() >= 6 {
        let starts = &payload[..6];
        if starts[..3] == TLS_SERVER_HANDSHAKE_START && starts[5] == TLS_HANDSHAKE_TYPE_SERVER_HELLO
        {
            state.remaining_server_hello = (i32::from(starts[3]) << 8 | i32::from(starts[4])) + 5;
            state.is_tls12_or_above = true;
            state.is_tls = true;
            if payload.len() >= 79 && state.remaining_server_hello >= 79 {
                let session_id_len = i32::from(payload[43]);
                let suite_start = 43 + session_id_len as usize + 1;
                let suite_end = suite_start + 2;
                if payload.len() >= suite_end {
                    state.cipher = (u16::from(payload[suite_start]) << 8)
                        | u16::from(payload[suite_start + 1]);
                }
            }
        } else if starts[..2] == TLS_CLIENT_HANDSHAKE_START
            && starts[5] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO
        {
            state.is_tls = true;
        }
    }
    if state.remaining_server_hello > 0 {
        let end = std::cmp::min(state.remaining_server_hello as usize, payload.len());
        state.remaining_server_hello -= payload.len() as i32;
        let version_window = payload[..end]
            .windows(TLS13_SUPPORTED_VERSIONS.len())
            .any(|window| window == TLS13_SUPPORTED_VERSIONS);
        if version_window {
            if state.cipher != TLS_AES_128_CCM_8_SHA256 {
                state.enable_xtls = true;
            }
            state.number_of_packet_to_filter = 0;
        } else if state.remaining_server_hello <= 0 {
            state.number_of_packet_to_filter = 0;
        }
    }
}

/// 参考 `XtlsPadding` 的 padding 长度决策（纯函数，rng 注入）。
pub(crate) fn padding_length(
    content_len: i32,
    long_padding: bool,
    testseed: &[u32; 4],
    rng: &mut dyn RngCore,
) -> i32 {
    let mut padding_len = if content_len < testseed[0] as i32 && long_padding {
        rand_below(rng, testseed[1] as u64) as i32 + testseed[2] as i32 - content_len
    } else {
        rand_below(rng, testseed[3] as u64) as i32
    };
    let max = BUF_SIZE as i32 - PADDING_OVERHEAD as i32 - content_len;
    if padding_len > max {
        padding_len = max;
    }
    // 参考在 `XtlsPadding` 之后调用 `newbuffer.Extend(paddingLen)`，而
    // `buf.Buffer.Extend` 并不校验负值（`end := b.end + n` 会**回退** end），参考侧
    // 之所以安全，是因为调用点用 `NumberOfPacketToFilter` 把进 padding 的块约束在
    // `contentLen < 900`（`testseed[0]`），该下溢分支在 Go 里不可达。本仓接口不保证
    // 该不变量，故显式把负值夹到 0：这是唯一不会缩短 `b.end` 的选择，否则
    // `padding_len as usize` 会在调试构建下 panic（overflow check）。
    if padding_len < 0 {
        padding_len = 0;
    }
    padding_len
}

/// VLESS Vision 客户端：持有一条连接的上行/下行角色状态机与 padding 参数。
pub struct VisionClient {
    state: TrafficState,
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

    fn xtls_padding(&mut self, command: u8, content: &[u8], long_padding: bool) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use super::super::test_util::CounterRng;
    use super::*;

    const UUID: [u8; 16] = [0x11; 16];

    fn client() -> VisionClient {
        VisionClient::new(UUID, None, Box::new(CounterRng(0)))
    }

    /// 从 padding 块解析出 `(command, content, padding)`（已剥离可选的 16 字节 UUID）。
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
    fn first_packet_empty_uses_long_padding_rule() {
        let mut c = client();
        let block = c.encode_first_uplink(None);
        // CounterRng 第一次 next_u64=0：padding = 900 + 0 - 0。
        let (command, content, padding) = parse_block(&block);
        assert_eq!(command, COMMAND_PADDING_CONTINUE);
        assert!(content.is_empty());
        assert_eq!(padding.len(), 900);
        // 独立复算的参考规则边界：[900, 1400)，且 ≤ 8171 - content。
        assert!((900..1400).contains(&(padding.len())));
    }

    #[test]
    fn first_packet_large_uses_direct_small_padding_rule() {
        let mut c = client();
        let payload = vec![0xABu8; 900];
        let block = c.encode_first_uplink(Some(&payload));
        let (command, content, padding) = parse_block(&block);
        assert_eq!(command, COMMAND_PADDING_CONTINUE);
        assert_eq!(content, &payload[..]);
        // contentLen >= testseed[0] 且 longPadding=false → rand(0, 256)，CounterRng 首值 0。
        assert_eq!(padding.len(), 0);
        assert!(padding.len() < 256);
    }

    #[test]
    fn seven_writes_end_padding_then_direct_passthrough() {
        let mut c = client();
        let mut commands = Vec::new();
        for i in 0..8u8 {
            let payload = [i; 3];
            let block = c.encode_uplink(&payload);
            if block.as_slice() == &payload[..] {
                commands.push(0xFF); // 直通标记（不再包块）
            } else {
                let (command, content, _) = parse_block(&block);
                assert_eq!(content, &payload[..], "第 {} 次写入内容", i);
                commands.push(command);
            }
        }
        // 前 6 次 Continue，第 7 次 End，第 8 次直通（无 padding 块）。
        assert_eq!(
            commands,
            vec![
                COMMAND_PADDING_CONTINUE,
                COMMAND_PADDING_CONTINUE,
                COMMAND_PADDING_CONTINUE,
                COMMAND_PADDING_CONTINUE,
                COMMAND_PADDING_CONTINUE,
                COMMAND_PADDING_CONTINUE,
                COMMAND_PADDING_END,
                0xFF,
            ]
        );
    }

    #[test]
    fn uplink_finish_emits_end_once() {
        let mut c = client();
        let payload = b"lonely request".to_vec();
        let block = c.encode_uplink(&payload);
        let (command, content, _) = parse_block(&block);
        assert_eq!(command, COMMAND_PADDING_CONTINUE);
        assert_eq!(content, &payload[..]);
        assert!(c.state.outbound.is_padding);
        let tail = c.encode_uplink_finish();
        assert!(!tail.is_empty());
        let (command, content, _) = parse_block(&tail);
        assert_eq!(command, COMMAND_PADDING_END);
        assert!(content.is_empty());
        assert!(!c.state.outbound.is_padding);
        assert!(c.encode_uplink_finish().is_empty());
    }

    #[test]
    fn uuid_appears_only_in_the_first_block() {
        let mut c = client();
        let first = c.encode_uplink(b"first");
        assert_eq!(&first[..16], &UUID[..]);
        let second = c.encode_uplink(b"second");
        assert!(second.len() < 16 || second[..16] != UUID[..]);
    }

    #[test]
    fn writer_reader_roundtrip_padding_blocks() {
        let payloads: Vec<Vec<u8>> = vec![
            b"shard one".to_vec(),
            b"shard two".to_vec(),
            b"shard three".to_vec(),
        ];
        let mut writer = client();
        let mut wire = Vec::new();
        let mut expected = Vec::new();
        for (i, payload) in payloads.iter().enumerate() {
            let mut block = writer.encode_uplink(payload);
            if i == payloads.len() - 1 {
                block.extend_from_slice(&writer.encode_uplink_finish());
            }
            wire.extend_from_slice(&block);
            expected.extend_from_slice(payload);
        }
        let mut reader = client();
        let mut got = Vec::new();
        for chunk in wire.chunks(7) {
            reader.decode_downlink(chunk, &mut got);
        }
        assert_eq!(got, expected);
        assert!(!reader.state.outbound.within_padding_buffers);
    }

    #[test]
    fn reader_skips_padding_and_stops_after_continue_then_end() {
        let mut writer = client();
        // 首块带 UUID + Continue + content + padding，末块 End + 0 内容 + padding。
        let mut wire = writer.xtls_padding(COMMAND_PADDING_CONTINUE, b"abc", false);
        wire.extend_from_slice(&writer.xtls_padding(COMMAND_PADDING_END, b"", false));
        let mut reader = client();
        let mut out = Vec::new();
        // 一条消息切开喂给状态机，仍须只产出 "abc"。
        for chunk in wire.chunks(5) {
            reader.decode_downlink(chunk, &mut out);
        }
        assert_eq!(out, b"abc");
        assert!(!reader.state.outbound.within_padding_buffers);
    }

    #[test]
    fn is_complete_record_accepts_only_whole_tls_records() {
        // 完整单记录：头 17 03 03 + BE16=3 + 3 字节体。
        let ok = vec![0x17, 0x03, 0x03, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
        assert!(is_complete_record(&ok));
        // 体被截断。
        let truncated = vec![0x17, 0x03, 0x03, 0x00, 0x03, 0xAA];
        assert!(!is_complete_record(&truncated));
        // 魔数不符。
        let bad_magic = vec![0x18, 0x03, 0x03, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
        assert!(!is_complete_record(&bad_magic));
    }

    #[test]
    fn filter_recognizes_tls_13_server_hello() {
        // 构造最小可识别的 ServerHello：头 16 03 03 + BE16 长度 + 0x02。
        let mut state = TrafficState::new(UUID);
        let mut hello = vec![0x16, 0x03, 0x03, 0x00, 0x4E, 0x02];
        hello.resize(80, 0);
        // 嵌入 TLS 1.3 supported_versions 扩展（魔数 00 2b 00 02 03 04）。
        hello[50] = 0x00;
        hello[51] = 0x2b;
        hello[52] = 0x00;
        hello[53] = 0x02;
        hello[54] = 0x03;
        hello[55] = 0x04;
        // session_id_len 置 0；cipher suite 置 TLS_AES_128_GCM_SHA256（0x1301）。
        let session_id_len = 0usize;
        let suite_start = 43 + session_id_len + 1;
        hello[suite_start] = 0x13;
        hello[suite_start + 1] = 0x01;
        xtls_filter_tls_single(&mut state, &hello);
        assert!(state.is_tls && state.is_tls12_or_above);
        assert!(state.enable_xtls, "AES-128-GCM-SHA256 应开启直拷贝判据");
        assert_eq!(state.number_of_packet_to_filter, 0);
        assert_eq!(state.cipher, 0x1301);
    }

    #[test]
    fn padding_length_respects_reference_clamp() {
        // contentLen < 900 且 longPadding：p=900+[0,500)-contentLen。
        assert_eq!(
            padding_length(100, true, &DEFAULT_TEST_SEED, &mut CounterRng(0)),
            800
        ); // 900 + 0 - 100
           // 短 padding 分支超上限时夹紧到 8192-21-contentLen。
        assert_eq!(
            padding_length(8000, false, &DEFAULT_TEST_SEED, &mut CounterRng(255)),
            8192 - 21 - 8000
        );
        // 大 contentLen 未逼近上限：p=[0,256)，不夹紧。
        assert_eq!(
            padding_length(900, false, &DEFAULT_TEST_SEED, &mut CounterRng(5)),
            5
        );
    }

    #[test]
    fn padding_length_never_goes_negative() {
        // contentLen ≥ testseed[0]=900 但 longPadding 为真时，公式
        // `900 + rand(0,500) - contentLen` 会下溢成负数（参考用
        // NumberOfPacketToFilter 保证不可达，本仓接口不保证）。必须夹到 0：
        // 负值一旦 `as usize` 会在调试构建 panic。
        assert_eq!(
            padding_length(1200, true, &DEFAULT_TEST_SEED, &mut CounterRng(0)),
            0
        );
        // 夹紧与 0 下界共存：contentLen 撑爆 8192-21 上界时 max 本身为负。
        assert_eq!(
            padding_length(9000, false, &DEFAULT_TEST_SEED, &mut CounterRng(255)),
            0
        );
    }
}
