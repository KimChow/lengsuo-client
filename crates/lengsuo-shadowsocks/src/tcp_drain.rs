//! `tcp::Reader` 的行为探测缓解接线（参考 `proxy/shadowsocks/protocol.go` 的
//! `ReadTCPSession` + `drain.WithError`）。
//!
//! 逻辑单独放这里是为了不让 `tcp.rs` 继续膨胀（它本来就超软目标）：`tcp.rs` 只保留
//! `drainer` 字段、三个转发方法与读取路径里的两处钩子。
//!
//! # 与参考的对应
//!
//! `ReadTCPSession` 的顺序是：读 50 字节头 → `validator.Get(...)` 认证 →
//! 失败就 `AcknowledgeReceive(已读)` 后 `drain.WithError(...)`。这里的对应是：
//!
//! | 参考 | 本模块 |
//! |---|---|
//! | 读 IV（`ReadTCPResponse`）后 `AcknowledgeReceive(ivLen)` | salt 读满后 [`credit_salt`] |
//! | `drain.WithError`（失败时 `io.CopyN` 丢弃） | [`drain_handshake`] |
//! | `GetBehaviorSeed` 惰性闩锁 | [`attach`]（`seed_source` 由调用方共享） |
//!
//! # 唯一的语义偏离
//!
//! 参考是**同步阻塞** `io.CopyN`；本层是异步的，丢弃读因此受同一个 `wait` 截止时间
//! 约束，超时即停。对 mitigation 的效果等价（该读的字节仍然读掉），差别只在
//! 「病态慢的对端不会被无限期读下去」——本仓认为这是更安全的默认值。

use tokio::io::AsyncReadExt;

use crate::drain::{BehaviorSeedLimitedDrainer, BehaviorSeedSource, HandshakeError};
use crate::tcp::{Error, Reader};

/// 挂上 drainer，seed 取自调用方共享的 [`BehaviorSeedSource`]。
///
/// `None` 时退回 `seed = 0`：仍是一个固定、与口令无关的预算，只是不随部署变化。
pub fn attach<R>(mut reader: Reader<R>, seed_source: Option<&mut BehaviorSeedSource>) -> Reader<R> {
    let seed = seed_source.map_or(0, |s| s.get_behavior_seed_i64());
    reader.drainer = Some(BehaviorSeedLimitedDrainer::new_shadowsocks(seed));
    reader
}

/// 直接指定 seed（测试与可复现部署用）。
pub fn attach_seed<R>(mut reader: Reader<R>, seed: i64) -> Reader<R> {
    reader.drainer = Some(BehaviorSeedLimitedDrainer::new_shadowsocks(seed));
    reader
}

/// 当前 drain 预算；未挂 drainer 时为 `None`。
pub fn budget<R: tokio::io::AsyncRead + Unpin>(reader: &Reader<R>) -> Option<i64> {
    reader.drainer.as_ref().map(|d| d.drain_size)
}

/// salt 读满后的 `AcknowledgeReceive`（参考 `ReadTCPResponse` 的 `ivLen` 抵扣）。
///
/// 这是「正常客户端不必为缓解付代价」的那一半：已认证前缀从不变量里扣掉。
pub fn credit_salt<R: tokio::io::AsyncRead + Unpin>(reader: &mut Reader<R>) {
    // 先取出只读值再可变借用（避免同时借用 `reader`）。
    let salt_len = reader.salt_len();
    if let Some(d) = reader.drainer.as_mut() {
        d.acknowledge_receive(salt_len);
    }
}

/// 握手失败时的缓解钩子，对应参考 `drain.WithError` → `Drain`。
///
/// 未挂 drainer 时原样返回 `err`，行为与不带本特性逐字节一致。
///
/// 挂上时按 seed 限量**真的读出并丢弃**对端字节（`io.CopyN(io.Discard, r, n)` 的
/// 异步等价），再把原错误包成 [`Error::Drained`] 返回。丢弃量只由部署 seed 与
/// 已认证前缀决定、与口令无关，因此观察者无法用「服务端多读了多少」区分口令。
///
/// 对端先走（EOF）按参考语义视为 “unable to drain connection”：仍然报错，绝不
/// 当作成功，也绝不静默放行。
pub async fn drain_handshake<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut Reader<R>,
    handshake: HandshakeError,
    err: Error,
) -> Error {
    let Some(drainer) = reader.drainer.as_mut() else {
        return err;
    };
    // 预算耗尽（≤ 0）时 Drain 是 no-op，与参考一致。
    if drainer.drain_size <= 0 {
        return err;
    }
    let budget = drainer.drain_size as usize;
    let mut remaining = budget;
    let mut buf = [0u8; 512];
    while remaining > 0 {
        let want = remaining.min(buf.len());
        match reader.buffered.read(&mut buf[..want]).await {
            Ok(0) | Err(_) => break,
            Ok(n) => remaining -= n,
        }
    }
    // 实际丢弃的字节记入预算；余量仍留在预算里，与参考的两分支同构。
    let drained = budget - remaining;
    if let Some(d) = reader.drainer.as_mut() {
        d.acknowledge_receive(drained);
    }
    Error::Drained(handshake)
}
