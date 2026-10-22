//! 把 Salamander 混淆与端口跳跃接到 **quinn 的 UDP 通道**上。
//!
//! 参考的包装顺序（`transport/internet/hysteria/dialer.go:206-217`）：
//!   1. `udphop.NewUDPHopPacketConn(...)` —— 端口跳跃层（**内层**）
//!   2. `c.udpmaskManager.WrapPacketConnClient(pktConn)` —— 混淆层（**外层**）
//!
//! ⇒ 数据方向是「先混淆、再由跳跃层选端口写出」。
//!
//! 服务端（`hub.go:379-386`）**只包混淆**，没有跳跃层。
//!
//! # 参考的 salamander 是「header conn」，不是 socket conn
//!
//! `finalmask/salamander/config.go:18` 实现了 `HeaderConn()` 标记接口，
//! 因此 `finalmask.go:28-56` 走 **header 分支**：`salamanderConn` 不做
//! socket 收发，只在 `headerManagerConn`（`finalmask.go:108-181`）读到的
//! 缓冲区上就地改写（`salamander.go` 的 `Obfuscate`/`Deobfuscate`）。
//! 线上格式 = `[8 字节 salt][payload ^ BLAKE2b256(PSK||salt)]`，
//! **每个 UDP datagram 独立加盐**。
//!
//! 本模块用 quinn 的 `AsyncUdpSocket` 抽象复刻同一语义：
//! `try_send` 里混淆后再发，`poll_recv` 里收完再解混淆。
//! 偏离（载体从 `net.PacketConn` 换成 `AsyncUdpSocket`）见
//! `docs/hysteria-obfs-hop.md` 的偏离清单。

use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use crate::obfs::SALT_LEN;
use crate::transport::wire::WireMask;

/// 带混淆/跳跃的 UDP socket 包装。
pub struct MaskedUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    mask: Arc<WireMask>,
    /// 发送缓冲（混淆后写入）。`try_send` 是同步调用，但 trait 给的是
    /// `&self` ⇒ 用锁保护。
    send_buf: Mutex<Vec<u8>>,
}

impl std::fmt::Debug for MaskedUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 不回显口令/密钥。
        f.debug_struct("MaskedUdpSocket")
            .field("obfuscated", &self.mask.obfuscated())
            .field("hopping", &self.mask.hopping())
            .field("remote", &self.mask.current_remote())
            .finish_non_exhaustive()
    }
}

impl MaskedUdpSocket {
    /// 包装真 socket。`mask` 决定混淆与跳跃行为。
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, mask: Arc<WireMask>) -> Self {
        Self {
            inner,
            mask,
            send_buf: Mutex::new(Vec::with_capacity(2048)),
        }
    }
}

impl AsyncUdpSocket for MaskedUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        // 写就绪由内层 socket 决定（掩码层不改变可写性）。
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> std::io::Result<()> {
        // 跳跃层在内层 ⇒ 目标端口取当前跳跃目标。
        // 仅**启用跳跃**时改写目标：服务端没有跳跃层，它的回包目标必须
        // 保持 quinn 给出的客户端地址。
        let mut t = transmit.clone();
        if self.mask.hopping() {
            t.destination = self.mask.current_remote();
        }
        if !self.mask.obfuscated() {
            return self.inner.try_send(&t);
        }
        // 混淆：线上格式 = [salt][payload ^ key]。逐 datagram 独立加盐 ⇒
        // 分段卸载（GSO）无法表达，显式关掉。
        let mut buf = self.send_buf.lock().expect("发送缓冲锁中毒");
        buf.clear();
        buf.resize(transmit.contents.len() + SALT_LEN, 0);
        let n = self
            .mask
            .obfuscate(transmit.contents, &mut buf)
            .ok_or_else(|| std::io::Error::other("混淆缓冲不足"))?;
        buf.truncate(n);
        t.contents = &buf;
        t.segment_size = None;
        self.inner.try_send(&t)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        // 收：先由真 socket 收进 `bufs`，再**就地**解混淆。
        //
        // 每条 datagram 有独立盐 ⇒ 必须逐条处理。GRO 可能把多条 datagram
        // 聚合进同一个 `bufs[i]`（`meta.len` 总长、`meta.stride` 单条长度，
        // 见 quinn-udp unix.rs 的 `stride = len` 缺省）。解开后每条少
        // `SALT_LEN` 字节 ⇒ 各条逐个前移压实。
        let ready = self.inner.poll_recv(cx, bufs, meta);
        let Poll::Ready(Ok(msgs)) = ready else {
            return ready;
        };
        if !self.mask.obfuscated() {
            return Poll::Ready(Ok(msgs));
        }
        let mut kept = 0usize;
        for i in 0..msgs {
            let m = meta[i];
            // 跳跃后对端从新端口回包 ⇒ 归一到规范地址（quinn 客户端禁止迁移）。
            let Some(addr) = self.mask.normalize_peer(m.addr) else {
                continue;
            };
            let buf: &mut [u8] = &mut bufs[i];
            let stride = if m.stride == 0 { m.len } else { m.stride };
            let mut plain_stride = 0usize;
            let mut written = 0usize;
            let mut offset = 0usize;
            let mut ok = true;
            while offset < m.len {
                let end = (offset + stride).min(m.len);
                let Some(plain) = self.mask.deobfuscate(&buf[offset..end]) else {
                    // 结构性失败（长度不足 / 哈希不可用）：整段丢弃，绝不回退明文。
                    ok = false;
                    break;
                };
                if plain_stride == 0 {
                    plain_stride = plain.len();
                }
                buf[written..written + plain.len()].copy_from_slice(&plain);
                written += plain.len();
                offset = end;
            }
            if !ok || written == 0 {
                continue;
            }
            meta[kept] = RecvMeta {
                len: written,
                stride: plain_stride,
                addr,
                ..m
            };
            kept += 1;
        }
        Poll::Ready(Ok(kept))
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        // 逐 datagram 加盐 ⇒ 不能用分段卸载。
        1
    }

    fn max_receive_segments(&self) -> usize {
        // 收侧逐 datagram 处理；不依赖聚合语义。
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
