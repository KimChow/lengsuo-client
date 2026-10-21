//! TLS 识别与 padding 长度决策（参考 `XtlsFilterTls` / `XtlsPadding`）。
//!
//! 从父模块拆出以保持单文件 ≤400 行（软约束）。逐条对齐参考 `proxy.go`。

use aes_gcm::aead::rand_core::RngCore;

use super::super::framing::PADDING_OVERHEAD;
use super::super::rand_below;
use super::state::TrafficState;
use super::BUF_SIZE;

/// TLS 握手识别常量（`proxy.go` 全局变量，逐字一致；`TlsApplicationDataStart` 见
/// [`super::framing::TLS_APPLICATION_DATA_START`]）。
const TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
/// `TLS_AES_128_CCM_8_SHA256` 是参考唯一**不**视为可直拷贝的 TLS 1.3 套件。
const TLS_AES_128_CCM_8_SHA256: u16 = 0x1305;

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
