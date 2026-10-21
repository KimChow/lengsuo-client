// 外层档位、客户端动作、观测结果与判定变体，以及全局判据常量。
//
// 本文件由 `tests/transport_matrix/harness.rs` 以 `include!` 拼入该模块，
// 因此共享的导入与常量都在入口文件里。

/// 测试专用假凭据；不打印、不进日志。
pub const PASSWORD: &str = "transport-matrix-good-password";
pub const BAD_PASSWORD: &str = "transport-matrix-wrong-password";
/// 请求载荷：回环业务目标按此长度读满后回写。
pub const PAYLOAD: &[u8] = b"transport-matrix-request-payload";
/// 正常往返的回程（小）。
pub const REPLY: &[u8] = b"transport-matrix-reply-payload";
/// 半关闭用例的回程（大，跨多个 TLS 记录）。
pub const REPLY_BULK_LEN: usize = 64 * 1024;
/// 外层升级路径（WS / HTTPUpgrade 共用）。
pub const PATH: &str = "/lengsuo-trojan-matrix";
/// 握手截止：截断用例据此得到**有界**拒绝（对齐参考 policy 的 `handshake`）。
pub const HANDSHAKE: Duration = Duration::from_secs(2);
/// 单次写入/flush 的有限预算。
pub const WRITE_BOUND: Duration = Duration::from_secs(3);
/// 观察对端结束连接的上限。
pub const CLOSE_BOUND: Duration = Duration::from_secs(8);
/// 单个用例的总预算。
pub const TOTAL: Duration = Duration::from_secs(90);

/// 截断点：覆盖参考 `proxy/trojan/server.go:176` 首块协议判定线的两侧。
///
/// - `30` 字节：不足 58 字节 ⇒ 落在判定线**之前**（`NotTrojanProtocol`）。
/// - `60` 字节：跨过判定线、头部仍不全 ⇒ 由握手截止给出有界拒绝。
pub const TRUNCATION_CUTS: [(usize, &str); 2] =
    [(30, "首块判定线之前"), (60, "跨过判定线、头部不全")];

/// 外层传输档位。`Tcp` 是**基线行**（raw，无任何升级层），其余两档是
/// TLS 之上的 HTTP/1.1 Upgrade 系列。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outer {
    /// raw / tcp：TLS 之后直接是 trojan 字节流。
    Tcp,
    /// websocket：TLS 之后是 RFC 6455 帧。
    Ws,
    /// httpupgrade：TLS 之后是裸字节流（只有 HTTP 升级握手）。
    HttpUpgrade,
}

impl Outer {
    /// 全部档位（矩阵的列）。
    pub const ALL: [Outer; 3] = [Outer::Tcp, Outer::Ws, Outer::HttpUpgrade];

    /// 档位名（同时用于用例名与文档表格）。
    pub fn name(self) -> &'static str {
        match self {
            Outer::Tcp => "tcp",
            Outer::Ws => "ws",
            Outer::HttpUpgrade => "httpupgrade",
        }
    }
}

/// 客户端动作：与外层无关的 trojan 侧动作。
#[derive(Debug, Clone, Copy)]
pub enum Action {
    /// 正常往返：写完整头部与载荷，**不**关写端，读满小回程。
    Normal,
    /// 错密码：写完整头部（错误口令），不得有任何回程。
    WrongPassword,
    /// 截断：只写头部的前 `cut` 字节，写端保持打开，等对端有界拒绝。
    Truncated { cut: usize },
    /// 半关闭：写完整头部与载荷后**关写端**，随后必须收完整个大回程。
    HalfClose,
}

impl Action {
    /// 用例名片段。
    pub fn name(self) -> &'static str {
        match self {
            Action::Normal => "normal",
            Action::WrongPassword => "wrong_password",
            Action::Truncated { .. } => "truncated",
            Action::HalfClose => "half_close",
        }
    }

    /// 该动作期望的回程长度。
    pub fn reply_len(self) -> usize {
        match self {
            Action::HalfClose => REPLY_BULK_LEN,
            _ => REPLY.len(),
        }
    }
}

/// 客户端观测到的结果。
#[derive(Debug, Default)]
pub struct Outcome {
    /// 读到的回程字节。
    pub reply: Vec<u8>,
    /// 读侧是否观察到对端正常结束连接（`Ok(0)`）。
    pub peer_closed: bool,
    /// 读侧是否观察到错误。
    pub peer_error: bool,
    /// 读侧是否读到了**不应出现**的数据（拒绝类用例里读到数据即失败）。
    pub unexpected_data: bool,
}

impl Outcome {
    /// 拒绝类用例的判据：必须观察到结束或错误，且**没有**任何数据字节。
    pub fn rejected_cleanly(&self) -> bool {
        (self.peer_closed || self.peer_error) && !self.unexpected_data
    }
}
