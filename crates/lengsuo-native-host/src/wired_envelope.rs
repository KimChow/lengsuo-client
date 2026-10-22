//! 生产用信封编解码器：把 W3b-2a 的信封层接进 [`crate::io_loop::EnvelopeCodec`]。
//!
//! # 两层关系
//!
//! ```text
//! 管道帧载荷（JSON 文本）
//!   {"frame_b64":"<base64(整条业务帧)>"}
//!        │  decode_frame_b64（lengsuo-browser-extension，W3b-2a）
//!        ▼
//! 整条业务帧字节（8 字节帧头 + 载荷，契约 §5.2）
//! ```
//!
//! 本模块只做**转发**：⛔ 不复制 base64 / JSON 解析，⛔ 不改动契约 §5.2.1 的任何
//! 字节定义。信封文本与业务帧之间的映射规则全部由 `lengsuo-browser-extension` 决定。
//!
//! # 错误文本不含载荷字节
//!
//! [`crate::io_loop::EnvelopeCodec`] 的错误类型是 `String`。本模块直接把
//! `EnvelopeError` 的 `Display` 转成字符串；该 `Display` 只含字段名 / 字节偏移 /
//! 长度，**不含**任何业务帧或载荷字节（载荷可能承载凭据数据）。

use lengsuo_browser_extension::{decode_frame_b64, encode_frame_b64};

use crate::io_loop::EnvelopeCodec;

/// 生产用信封编解码器（W3b-2a 的信封层）。
///
/// [`EnvelopeCodec::decode`] 把信封 JSON 文本还原成**整条业务帧字节**
/// （含 8 字节帧头）；[`EnvelopeCodec::encode`] 把整条业务帧套回信封 JSON 文本。
/// 两者都直接转发 `lengsuo-browser-extension` 的
/// `decode_frame_b64` / `encode_frame_b64`。
///
/// 无状态、`Copy`，便于 [`crate::io_loop::run`] 以引用传入。
#[derive(Debug, Default, Clone, Copy)]
pub struct WiredEnvelope;

impl EnvelopeCodec for WiredEnvelope {
    fn decode(&self, text: &str) -> Result<Vec<u8>, String> {
        decode_frame_b64(text).map_err(|error| error.to_string())
    }

    fn encode(&self, frame: &[u8]) -> Result<String, String> {
        encode_frame_b64(frame).map_err(|error| error.to_string())
    }
}
