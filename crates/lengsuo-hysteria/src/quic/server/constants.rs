//! 服务端侧常量：会话 ID 长度、通道容量、UDP 空闲回收参数、QUIC 缺省值。

/// QUIC datagram 上的会话 ID 长度（字节），对齐 `udpSessionManagerServer.run`
/// 的 `len(d) < 4` 判据与 `binary.BigEndian.Uint32(d[:4])`。
pub const UDP_SESSION_ID_LEN: usize = 4;
/// 会话分发通道容量，对齐 `config.go` `udpMessageChanSize`。
pub const UDP_MESSAGE_CHAN_SIZE: usize = 1024;
/// 服务端 UDP 会话空闲回收周期，对齐 `hub.go` `idleCleanupInterval`。
pub const UDP_IDLE_CLEANUP_INTERVAL_SECS: u64 = 5;
/// 服务端 UDP 会话空闲超时缺省值（秒），对齐 `config.go` `UdpIdleTimeout`。
pub const DEFAULT_UDP_IDLE_TIMEOUT_SECS: u64 = 60;
/// QUIC 最大空闲超时缺省值（毫秒），对齐 `hub.go` `quicParams.MaxIdleTimeout`。
pub const DEFAULT_MAX_IDLE_TIMEOUT_MS: u32 = 30_000;
/// 最大入站流数缺省值，对齐 `hub.go` `quicParams.MaxIncomingStreams`。
pub const DEFAULT_MAX_INCOMING_STREAMS: u32 = 1024;
