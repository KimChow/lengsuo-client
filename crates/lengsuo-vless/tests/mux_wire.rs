//! VLESS Mux 出站原语（`lengsuo_vless::mux_wire`）的具名用例。
//!
//! 覆盖任务书要求的三类：
//! 1. **正常往返**：既有原语 → 新 API → 还原 ⇒ 载荷逐字节一致；
//! 2. **错误输入 fail-closed**：非法参数/截断输入 ⇒ 显式报错；
//! 3. **与既有实现的等价性**：新 API 的输出与既有原语的输出逐字节相同。
//!
//! 全部用例只用回环地址、临时端口、假凭据；不打印任何密钥/明文。
//!
//! 显式执行：
//! `cargo test -p lengsuo-vless --test mux_wire -- --nocapture`

mod support;

use std::time::Duration;

use lengsuo_vless::mux::frame::{
    decode_from_async, read_data_async, FrameMetadata, SessionStatus, TargetNetwork, OPTION_DATA,
    OPTION_ERROR,
};
use lengsuo_vless::mux::worker::{Action, SessionWriter, Strategy};
use lengsuo_vless::mux_wire::{Error, MuxWire, DEFAULT_DEADLINE};
use ss_core::target::TargetAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

const TCP: TargetNetwork = TargetNetwork::Tcp;
const UDP: TargetNetwork = TargetNetwork::Udp;
const PAYLOAD: &[u8] = b"VLESS mux wire payload\0\xfe\xff";
const WAIT: Duration = Duration::from_secs(5);

fn target(port: u16) -> (TargetAddr, TargetNetwork) {
    (TargetAddr::V4([127, 0, 0, 1], port), TCP)
}

/// 造一条内存承载连接：本仓端 + 对端端。
fn carrier() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
    tokio::io::duplex(64 * 1024)
}

/// 从对端读一帧（帧头 + 可选数据段）。
///
/// 用既有 `mux::frame` 的异步原语解码，证明新 API 的下行帧与既有解码器兼容。
async fn read_frame<R: AsyncRead + Unpin>(
    peer: &mut R,
    stream: bool,
) -> (FrameMetadata, Option<Vec<u8>>) {
    let meta = decode_from_async(peer, false).await.expect("帧头可解");
    let data = if meta.has_data() {
        Some(read_data_async(peer, stream).await.expect("数据段可解"))
    } else {
        None
    };
    (meta, data)
}

/// 造一个 `Keep`（或 `KeepAlive`）帧：帧头 + `BE16 长度 || 数据`。
fn keep_frame(session_id: u16, status: SessionStatus, payload: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    let meta = FrameMetadata {
        session_id,
        status,
        option: if payload.is_some() { OPTION_DATA } else { 0 },
        target: None,
        source: None,
        local: None,
        udp_continuation: false,
    };
    meta.encode_into(&mut out).expect("可编码");
    if let Some(payload) = payload {
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
    }
    out
}
// 用例按主题拆到 `tests/mux_wire/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

include!("mux_wire/frames.rs");
include!("mux_wire/rejections.rs");
include!("mux_wire/sessions.rs");

// ============================================================================
// 参考互通用例（与固定版本参考端真实互跑，`#[ignore]` 显式实跑）已移至
// `tests/mux_interop/main.rs`——职责不同（参考互通 vs 本仓自洽），
// 分文件避免单文件超 700 行硬上限。
// ============================================================================
