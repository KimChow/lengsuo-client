//! H3 认证的线上常量：请求/响应头名、状态码、连接关闭码与 HTTP/3 帧/流类型。
//!
//! 全部来自参考实现的 `config.go` 常量组（见模块文档）。

/// 认证请求的伪主机名与路径（`config.go` `URLHost`/`URLPath`）。
pub const URL_HOST: &str = "hysteria";
pub const URL_PATH: &str = "/auth";
/// 请求头：认证密码。Go 侧常量是 `Hysteria-Auth`（http.Header 的
/// canonical 形式），但 RFC 9114 §4.2 要求线上字段名一律小写，Go 的
/// Header.Add/Get 双向 canonical 化恰好兜住；本 crate 手写编码，
/// 线上直接用小写。
pub const REQUEST_HEADER_AUTH: &str = "hysteria-auth";
/// 响应头：服务端是否支持 UDP datagram（线上小写，同上）。
pub const RESPONSE_HEADER_UDP_ENABLED: &str = "hysteria-udp";
/// 双向头：Brutal 拥塞控制的下行带宽（十进制 bps）。
pub const COMMON_HEADER_CC_RX: &str = "hysteria-cc-rx";
/// 双向头：随机填充字符串。
pub const COMMON_HEADER_PADDING: &str = "hysteria-padding";
/// 认证成功状态码。
pub const STATUS_AUTH_OK: u16 = 233;
/// 认证失败按参考走 masquerade 缺省处理器：`http.NotFoundHandler()` 的 404。
pub const STATUS_NOT_FOUND: u16 = 404;
/// 连接关闭码（`config.go`）。
pub const CLOSE_ERR_CODE_OK: u32 = 0x100;
pub const CLOSE_ERR_CODE_PROTOCOL_ERROR: u32 = 0x101;

/// HTTP/3 帧：HEADERS；DATA 与未知帧跳过载荷（RFC 9114 §7.2）。
pub(crate) const FRAME_HEADERS: u64 = 0x1;
/// 设置帧类型（控制流上，本端发送空设置）。
pub(crate) const FRAME_SETTINGS: u64 = 0x4;
/// 单向流类型。
pub(crate) const STREAM_TYPE_QPACK_ENCODER: u64 = 0x2;
/// 响应整体（含 masquerade 页面）读取上限。
pub(crate) const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
