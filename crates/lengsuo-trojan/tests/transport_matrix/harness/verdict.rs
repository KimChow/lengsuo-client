// 本仓服务端一条连接的处理**判定**变体。
//
// 本文件由 `tests/transport_matrix/harness.rs` 以 `include!` 拼入该模块。

/// 本仓服务端一条连接的处理**判定**。
///
/// `server::Error` 不实现 `PartialEq`（它包着 `ss_core::Error` 等非可比类型），
/// 因此这里把可判别的失败归一成一组**互斥**的变体，用 `matches!` 断言，
/// 既不依赖 `PartialEq`，也不放宽判据。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// 处理成功结束（正常往返、半关闭后的服务端侧收尾）。
    Completed,
    /// 首块协议判定线之前（参考 `proxy/trojan/server.go:176` 的
    /// `firstLen < 58 || first.Byte(56) != '\r'`）。
    NotTrojanProtocol,
    /// 认证失败（哈希不匹配）。
    Authentication,
    /// 握手截止内头部未读全。
    Timeout,
    /// 非法命令字节。
    InvalidCommand,
    /// 外层传输升级失败（路径/头不匹配）——发生在 trojan 协议层之前。
    UpgradeFailed,
    /// 其它错误。
    Other,
}

impl Verdict {
    /// 把 `server::Error` 归一成判定变体。
    pub fn of(error: &ServerError) -> Self {
        match error {
            ServerError::NotTrojanProtocol => Verdict::NotTrojanProtocol,
            ServerError::Authentication => Verdict::Authentication,
            ServerError::Timeout => Verdict::Timeout,
            ServerError::InvalidCommand(_) => Verdict::InvalidCommand,
            _ => Verdict::Other,
        }
    }
}
