//! datagram 发送缓冲的 **Bytes 桥**（依赖冻结拿不到 `bytes` crate）。
//!
//! 两条互补路径，均无需命名该 crate：
//!
//! 1. **直接构造**（[`send_datagram_direct`]）：`Bytes: From<Vec<u8>>`，用一个
//!    返回类型由调用点推断的泛型函数（`make_datagram_buffer`）即可从 `&[u8]`
//!    造出 `Bytes`——类型经 `send_datagram` 的入参唯一确定。这是服务端与
//!    客户端的常规发送路径（每调用一次分配）。
//! 2. **复用接收缓冲**（[`SeedFiller`] / [`seed_filler_from_chunk`]）：
//!    `read_chunk` 有时返回独占引用计数的 `Bytes`，`try_into_mut` → 写入 →
//!    `freeze` 可复用该缓冲，省一次分配。属于可选优化，池空时回退路径 1。

use quinn::Connection;

/// 一次性 UDP datagram 发送器：向已独占的缓冲填入载荷并发送。
/// 依赖冻结下的 `bytes::Bytes` 桥，见模块文档。实现为 `FnMut`：
/// 调用方取走后独占使用。
pub type SeedFiller =
    Box<dyn FnMut(&Connection, &[u8]) -> Result<(), quinn::SendDatagramError> + Send>;

/// 从一块**独占**的 `Bytes`（`read_chunk` 或 `read_datagram →
/// try_into_mut` 的产物）造一个 [`SeedFiller`]；不独占时返回 `None`。
///
/// 服务端与客户端共用同一桥（见模块文档）：`SendStream`/datagram 发送只
/// 接受 `bytes::Bytes`，而依赖冻结拿不到该 crate，只能靠接收路径顺路产出的
/// 独占缓冲当作发送缓冲。`Chunk`/`Bytes` 的类型经 `quinn` 的类型推断与闭包
/// 捕获使用，无需在本 crate 命名 `bytes`。
#[must_use]
pub fn seed_filler_from_chunk(chunk: quinn::Chunk) -> Option<SeedFiller> {
    let mut buf = chunk.bytes.try_into_mut().ok()?;
    Some(Box::new(move |conn, payload| {
        buf.clear();
        buf.extend_from_slice(payload);
        conn.send_datagram(std::mem::take(&mut buf).freeze())
    }))
}

/// 把一段字节发成 QUIC datagram。`send_datagram` 要求 `bytes::Bytes`，而依赖
/// 冻结拿不到该 crate；这里借 `quinn::Chunk::bytes` 的公开字段**推断出**
/// `Bytes` 类型：用 `Chunk.bytes` 的 `split_off`/重赋值路径构造新内容，
/// 全程不写出 `bytes::Bytes`。
pub fn send_datagram_direct(
    conn: &Connection,
    payload: &[u8],
) -> Result<(), quinn::SendDatagramError> {
    // `make_bytes` 的返回类型由 `send_datagram` 的入参推断为 `Bytes`，
    // 其实现只用 `Bytes: From<Vec<u8>>` 这一公开约束。
    conn.send_datagram(make_datagram_buffer(payload.to_vec()))
}

/// 见 `send_datagram_direct`：`B` 由调用点（`send_datagram` 的入参类型）
/// 推断，函数体只用 `From<Vec<u8>>`。
fn make_datagram_buffer<B: From<Vec<u8>>>(bytes: Vec<u8>) -> B {
    B::from(bytes)
}
