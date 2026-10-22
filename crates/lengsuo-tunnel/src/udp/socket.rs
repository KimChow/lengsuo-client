//! UDP socket 封装 + 对端地址管理。
//!
//! 本文件是 **L1 传输**的落地：把「一个 UDP socket + 一个 peer 地址」
//! 变成「能收能发的端点」。
//!
//! # 为什么 socket 是 **connected** 的
//!
//! UDP 本来是「无连接」的，但**本端点固定只跟一个 peer 通信**，
//! 所以我们把 socket `connect` 到对端。这带来两个**可实测**的好处：
//!
//! 1. **连接级错误可观测**：Linux 上对端端口无人监听时，内核会回 ICMP
//!    port-unreachable；**只有 connected 的 socket** 才把它以
//!    `ECONNREFUSED` 交给应用。未 connected 的 socket 会把它**静默丢弃**
//!    （实测：未连接 socket 发给死端口后再收，永远是超时，收不到任何错误）。
//!    本卡要求「socket 级错误 ⇒ 上报」，connected 是达成它的前提。
//! 2. **内核按来源过滤**：connected 的 socket 只接收来自对端的报文
//!    （实测：陌生源打进来的包进不来）。
//!
//! ⚠️ **代价**：connected 之后，**换对端**要重新 `connect`。
//! [`UdpEndpoint::set_peer_endpoint`] 就是干这个的（为漫游留口）。
//!
//! # MTU 预算
//!
//! `MAX_FRAME_LEN` = 1420（帧头 20 + 载荷 1400）⇒ **一帧恰好一个数据报**，
//! 不做 IP 分片（1420 + 20 IPv4 + 8 UDP = 1448 < 1500）。

use std::net::SocketAddr;
use std::sync::Arc;

use lengsuo_link_core::frame::{Frame, MAX_FRAME_LEN};
use tokio::net::UdpSocket;

use super::error::{SocketError, UdpError};

/// 接收缓冲的**最小长度**：装不下一个满帧就别收（否则会被内核截断，
/// 而截断后的数据报会被误判成「对端发了坏包」）。
pub const MIN_RECV_BUFFER_LEN: usize = MAX_FRAME_LEN;

/// 一个拥有 UDP socket 的端点。
///
/// - 内部 socket 是 **connected** 的（见模块文档），
///   所以 `send_frame` 只需要帧，不需要每次带地址；
/// - 对端地址**可更新**（[`UdpEndpoint::set_peer_endpoint`]），
///   为后续的 endpoint 漫游卡留好接口，本卡**不做**漫游协议。
///
/// `Debug` **不打印** socket 内部状态，只出本地地址与对端地址。
#[derive(Debug, Clone)]
pub struct UdpEndpoint {
    socket: Arc<UdpSocket>,
    peer: Option<SocketAddr>,
}

impl UdpEndpoint {
    /// 绑定一个本地 UDP socket（**尚未**设置对端）。
    ///
    /// 传 `127.0.0.1:0` 可让内核分配端口；用 [`UdpEndpoint::local_addr`] 取实际地址。
    ///
    /// # Errors
    /// 绑定失败（端口被占、地址非法等）⇒ [`UdpError::Socket`]。
    pub async fn bind(addr: SocketAddr) -> Result<Self, UdpError> {
        let socket = UdpSocket::bind(addr)
            .await
            .map_err(|source| UdpError::Socket {
                source: SocketError::new(source),
            })?;
        Ok(Self {
            socket: Arc::new(socket),
            peer: None,
        })
    }

    /// 本地实际地址（绑定时用了端口 0 时尤其有用）。
    ///
    /// # Errors
    /// 取地址失败 ⇒ [`UdpError::Socket`]。
    pub fn local_addr(&self) -> Result<SocketAddr, UdpError> {
        self.socket.local_addr().map_err(|source| UdpError::Socket {
            source: SocketError::new(source),
        })
    }

    /// 当前对端地址（未设置时为 `None`）。
    #[must_use]
    pub fn peer_endpoint(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// 设置 / 更新对端地址，并把 socket **重新 connect** 到新地址。
    ///
    /// 这是给 **endpoint 漫游**留的入口：上层（后续的漫游卡）探测到对端
    /// 换了地址（切 WiFi↔5G、NAT 重绑）时调用它，之后收发即打到新地址。
    ///
    /// ⚠️ 本卡**只提供这个入口**，不实现「什么时候该漫游」「怎么验证对端身份」
    /// ——那属于协议侧（后续 `wg-roam` 卡）。
    ///
    /// # Errors
    /// `connect` 失败（地址非法等）⇒ [`UdpError::Socket`]。
    pub async fn set_peer_endpoint(&mut self, addr: SocketAddr) -> Result<(), UdpError> {
        self.socket
            .connect(addr)
            .await
            .map_err(|source| UdpError::Socket {
                source: SocketError::new(source),
            })?;
        self.peer = Some(addr);
        Ok(())
    }

    /// 发一个帧：**一帧一个数据报**。
    ///
    /// # Errors
    /// - 未设置对端 ⇒ [`UdpError::NoPeer`]；
    /// - 载荷超上限 ⇒ [`UdpError::Encode`]（**不截断、不发出**）；
    /// - socket 级错误 ⇒ [`UdpError::Socket`]（连接级）。
    pub async fn send_frame(&self, frame: &Frame) -> Result<usize, UdpError> {
        let bytes = frame.encode().map_err(UdpError::Encode)?;
        self.send_bytes(&bytes).await
    }

    /// 发**原始字节**（不经帧编码）给当前对端。
    ///
    /// 存在的理由：连通性探测、NAT 打洞的握手包、测试里灌坏包，
    /// 都要发**不是帧**的字节。协议语义不在本卡判定。
    ///
    /// # Errors
    /// - 未设置对端 ⇒ [`UdpError::NoPeer`]；
    /// - socket 级错误 ⇒ [`UdpError::Socket`]。
    pub async fn send_raw(&self, bytes: &[u8]) -> Result<usize, UdpError> {
        self.send_bytes(bytes).await
    }

    /// 发**原始字节**给**任意**地址（不限于当前对端）。
    ///
    /// 这是 **NAT 打洞**要用的口子：打洞阶段对端地址还没定，
    /// 要往若干候选地址各发一份探测包。打洞之后的正常收发走
    /// [`UdpEndpoint::send_frame`]。
    ///
    /// ⚠️ 往**非 connected 对端**发包时，内核**不会**把 ICMP 错误
    /// 关联到这个 socket ⇒ 那条路径上的连接级错误观测不到。
    /// 打洞期的探测包本来就允许丢，不是问题。
    ///
    /// # Errors
    /// socket 级错误 ⇒ [`UdpError::Socket`]。
    pub async fn send_raw_to(&self, bytes: &[u8], addr: SocketAddr) -> Result<usize, UdpError> {
        self.socket
            .send_to(bytes, addr)
            .await
            .map_err(|source| UdpError::Socket {
                source: SocketError::new(source),
            })
    }

    /// 实际发包：走 socket 的 **connected 默认目的地**（即当前对端）。
    ///
    /// 用 `send` 而不是 `send_to` 是有意的：只有 connected 的 socket 才会
    /// 把「对端不可达」的 ICMP 错误关联到自己身上（见模块文档）。
    async fn send_bytes(&self, bytes: &[u8]) -> Result<usize, UdpError> {
        if self.peer.is_none() {
            return Err(UdpError::NoPeer);
        }
        self.socket
            .send(bytes)
            .await
            .map_err(|source| UdpError::Socket {
                source: SocketError::new(source),
            })
    }

    /// 收一个**原始数据报**（**不做** L3 帧解码）。
    ///
    /// 与 [`UdpEndpoint::send_raw`] 对称：发什么就收什么，**不替调用方**判断
    /// 「这是不是帧」。裸握手报文（initiation / response / cookie）就在裸
    /// 数据报里（见 [`crate::udp::datagram`]），由调用方按**首字节**分流。
    ///
    /// 返回 `(负载字节数, 来源地址)`：负载在 `buf[..len]` 里。
    ///
    /// # Errors
    /// - 缓冲装不下 ⇒ [`UdpError::BufferTooSmall`]（本地调用级）；
    /// - socket 级错误 ⇒ [`UdpError::Socket`]（**连接级**，应当上报并结束循环）。
    pub async fn recv_raw(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), UdpError> {
        if buf.len() < MIN_RECV_BUFFER_LEN {
            // 与 `recv_frame` 同一条本地调用级检查：缓冲太小 ⇒ 数据报会被内核
            // 截断，截断后的内容必然解不开。裸握手只有 148B，1420 的缓冲足够。
            return Err(UdpError::BufferTooSmall {
                needed: MIN_RECV_BUFFER_LEN,
                available: buf.len(),
            });
        }
        let (len, source) =
            self.socket
                .recv_from(buf)
                .await
                .map_err(|source| UdpError::Socket {
                    source: SocketError::new(source),
                })?;
        Ok((len, source))
    }

    /// 收一个帧。
    ///
    /// ⛔ **只解 L3 帧**：裸握手数据报在这里必然报
    /// [`UdpError::BadDatagram`]（魔数不符）——握手要走
    /// [`UdpEndpoint::recv_raw`] + [`crate::udp::datagram::classify`]。
    ///
    /// # Errors
    /// - 缓冲装不下一帧 ⇒ [`UdpError::BufferTooSmall`]（本地调用级）；
    /// - 数据报解不开 ⇒ [`UdpError::BadDatagram`]（**单包级**，只丢这一包）；
    /// - socket 级错误 ⇒ [`UdpError::Socket`]（**连接级**，应当上报并结束循环）。
    pub async fn recv_frame(&self, buf: &mut [u8]) -> Result<Frame, UdpError> {
        if buf.len() < MIN_RECV_BUFFER_LEN {
            // 缓冲不够 ⇒ 收来的数据报会被内核截断，截断后必然解不开帧。
            // 与其把「调用方缓冲太小」误报成「对端发了坏包」，
            // 不如在收之前就明确报**本地调用级**错误。
            return Err(UdpError::BufferTooSmall {
                needed: MIN_RECV_BUFFER_LEN,
                available: buf.len(),
            });
        }
        let (len, source) =
            self.socket
                .recv_from(buf)
                .await
                .map_err(|source| UdpError::Socket {
                    source: SocketError::new(source),
                })?;
        decode_datagram(buf, len, source)
    }
}

/// 把一个数据报解成帧。
///
/// 单独抽出来是为了让「收循环」与「一次性收」共用同一套解码语义。
///
/// ⛔ **严格**：一个数据报**恰好一帧**（`decode_exact`）——
/// 多出字节就是协议违例，报错而不是「取第一帧、把余下当没事」。
///
/// # Errors
/// - 解不开 ⇒ [`UdpError::BadDatagram`]（单包级）。
pub(crate) fn decode_datagram(
    buf: &[u8],
    len: usize,
    source: SocketAddr,
) -> Result<Frame, UdpError> {
    if len > buf.len() {
        // 理论上不会发生（内核按缓冲大小截断），但**不猜**：宁可报错。
        return Err(UdpError::BufferTooSmall {
            needed: len,
            available: buf.len(),
        });
    }
    match lengsuo_link_core::frame::decode_exact(&buf[..len]) {
        Ok(frame) => Ok(frame),
        Err(reason) => Err(UdpError::BadDatagram {
            origin: source,
            reason,
        }),
    }
}
