// 读方向的结果分类（干净 EOF / 残留半帧 / 读错误）与客户端会话表普查。
// ===========================================================================
// 读方向的结果分类
// ===========================================================================

/// 读方向的结果（区分「干净 EOF」与「协议错误」——任务书点名的关键坑）。
#[derive(Debug)]
pub(crate) enum ReadOutcome {
    /// 读到了 EOF 且**缓冲已空** = 干净 EOF（对齐参考 `common/buf/copy.go`
    /// 的 `Copy` 遇 `io.EOF` 正常返回 nil）。
    CleanEof {
        /// EOF 之前读到的字节。
        data: Vec<u8>,
    },
    /// 读到了 EOF 但**缓冲里还有残留字节** = 协议错误（残帧被当成了
    /// 干净 EOF 放行）。
    EofWithResidue {
        /// EOF 之前读到的字节。
        data: Vec<u8>,
    },
    /// 读方向报错（`Err(UnexpectedEof)` / `Err(Reset)` / `Err(ConnectionLost)`）。
    ReadError {
        /// 报错前读到的字节。
        #[allow(dead_code)]
        data: Vec<u8>,
        /// 错误文本（不含任何机密）。
        err: String,
    },
}

/// 读到底并分类结果。
///
/// 语义（**必须**区分两种 EOF）：
/// - EOF 且缓冲空 ⇒ [`ReadOutcome::CleanEof`]；
/// - EOF 且缓冲里还有字节 ⇒ [`ReadOutcome::EofWithResidue`]（协议错误）。
pub(crate) async fn read_to_eof(mut recv: quinn::RecvStream) -> ReadOutcome {
    let mut data: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match recv.read(&mut buf).await {
            Ok(None) => {
                return if data.is_empty() {
                    ReadOutcome::CleanEof { data }
                } else {
                    ReadOutcome::EofWithResidue { data }
                };
            }
            Ok(Some(n)) => data.extend_from_slice(&buf[..n]),
            Err(e) => {
                return ReadOutcome::ReadError {
                    data,
                    err: e.to_string(),
                };
            }
        }
    }
}

/// 读到底并分类结果（**应用层**，走 `proxy::TcpProxyStream`）。
///
/// 与 [`read_to_eof`] 同口径：EOF 且缓冲空 = 干净 EOF；EOF 且缓冲里有
/// 残留 = 协议错误；读报错 = 读错误。
pub(crate) async fn read_proxy_to_eof(stream: &mut proxy::TcpProxyStream) -> ReadOutcome {
    let mut data: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => {
                return if data.is_empty() {
                    ReadOutcome::CleanEof { data }
                } else {
                    ReadOutcome::EofWithResidue { data }
                };
            }
            Ok(n) => data.extend_from_slice(&buf[..n]),
            Err(e) => {
                return ReadOutcome::ReadError {
                    data,
                    err: e.to_string(),
                };
            }
        }
    }
}

// ===========================================================================
// 会话普查
// ===========================================================================

/// 客户端 UDP 会话表的状态（观测 `quic/client.rs` 的 `UdpManager`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientUdpTable {
    /// 表仍开着（可以开新会话）。
    Open,
    /// 表已被 `close_all()` **清空并关闭**（连接已死）。
    Closed,
    /// 服务端未启用 UDP datagram。
    Unsupported,
}

/// 采集客户端 UDP 会话表状态。
///
/// `open_udp()` 是**非破坏性**探针：表被 `close_all()` 清空后必然返回
/// `Err(Quic(LocallyClosed))`，而 `close_all()` 同时置 `closed = true` ⇒
/// 「已关闭」蕴含「表已清空」。
pub(crate) async fn client_udp_table(client: &HysteriaClient) -> ClientUdpTable {
    match tokio::time::timeout(IO_TIMEOUT, client.open_udp()).await {
        Err(_) => ClientUdpTable::Unsupported,
        Ok(Ok(_)) => ClientUdpTable::Open,
        Ok(Err(ConnectError::UdpUnsupported)) => ClientUdpTable::Unsupported,
        Ok(Err(ConnectError::Quic(_))) => ClientUdpTable::Closed,
        Ok(Err(_)) => ClientUdpTable::Closed,
    }
}
