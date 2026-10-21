// trojan 侧动作（写头、写载荷、关写端、读回程）与有界 IO。
//
// 本文件由 `tests/transport_matrix/harness.rs` 以 `include!` 拼入该模块。

/// trojan 请求（CONNECT 到回环业务目标）。
pub fn tcp_request(port: u16) -> Request {
    Request {
        command: Command::Tcp,
        target: TargetAddr::V4([127, 0, 0, 1], port),
    }
}

/// trojan 头部的线上字节（用于截断用例）。
pub fn header_bytes(target_port: u16, password: &str) -> Vec<u8> {
    lengsuo_trojan::codec::encode(&tcp_request(target_port), &Credential::new(password)).unwrap()
}

/// 有界写入。
pub async fn bounded_write<S: AsyncWrite + Unpin>(
    stream: &mut S,
    data: &[u8],
) -> std::io::Result<()> {
    match timeout(WRITE_BOUND, stream.write_all(data)).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "写入超时",
        )),
    }
}

/// 有界 flush。
pub async fn bounded_flush<S: AsyncWrite + Unpin>(stream: &mut S) -> std::io::Result<()> {
    match timeout(WRITE_BOUND, stream.flush()).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "flush 超时",
        )),
    }
}

/// 有界关写端（半关闭）。WS 下这一层会先发 `Close` 帧再关底层写端。
pub async fn bounded_shutdown<S: AsyncWrite + Unpin>(stream: &mut S) -> std::io::Result<()> {
    match timeout(WRITE_BOUND, stream.shutdown()).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "关写端超时",
        )),
    }
}

/// 客户端一次动作（与外层无关）。`stream` 必须是已完成外层升级的流。
pub async fn client_action<S>(stream: &mut S, action: Action, target_port: u16) -> Outcome
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match action {
        Action::Normal => {
            send_request(
                stream,
                &tcp_request(target_port),
                &Credential::new(PASSWORD),
                WAIT,
            )
            .await
            .expect("写 trojan 头失败");
            bounded_write(stream, PAYLOAD).await.expect("写载荷超时");
            bounded_flush(stream).await.expect("flush 超时");
            read_exact_outcome(stream, action.reply_len()).await
        }
        Action::WrongPassword => {
            send_request(
                stream,
                &tcp_request(target_port),
                &Credential::new(BAD_PASSWORD),
                WAIT,
            )
            .await
            .expect("写 trojan 头失败");
            bounded_write(stream, PAYLOAD).await.expect("写载荷超时");
            bounded_flush(stream).await.expect("flush 超时");
            observe_rejection(stream).await
        }
        Action::Truncated { cut } => {
            let header = header_bytes(target_port, PASSWORD);
            assert!(cut < header.len(), "截断点必须落在头部之内");
            bounded_write(stream, &header[..cut])
                .await
                .expect("写截断头超时");
            bounded_flush(stream).await.expect("flush 超时");
            // 写端**保持打开**：等对端按握手截止给出有界拒绝。
            observe_rejection(stream).await
        }
        Action::HalfClose => {
            send_request(
                stream,
                &tcp_request(target_port),
                &Credential::new(PASSWORD),
                WAIT,
            )
            .await
            .expect("写 trojan 头失败");
            bounded_write(stream, PAYLOAD).await.expect("写载荷超时");
            bounded_flush(stream).await.expect("flush 超时");
            // 关写端：WS 下发 Close 帧，其余走底层 FIN。
            bounded_shutdown(stream).await.expect("关写端超时");
            read_exact_outcome(stream, action.reply_len()).await
        }
    }
}

/// 读满定长回程；读不足或出错都如实记录**实际读到的字节数**。
///
/// 这里不用 `read_exact`：它在出错时不报告已读字节数，若把缓冲区整体当作
/// 回程，长度断言会变成空转（缓冲区是零填充的）。改成自己累加，得到的
/// `reply.len()` 就是线上真实回程长度。
async fn read_exact_outcome<S: AsyncRead + Unpin>(stream: &mut S, len: usize) -> Outcome {
    let mut reply = vec![0u8; len];
    let mut filled = 0usize;
    let mut peer_error = false;
    while filled < len {
        let read = match timeout(WAIT, stream.read(&mut reply[filled..])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(read)) => read,
            Ok(Err(_)) => {
                peer_error = true;
                break;
            }
            Err(_) => break,
        };
        filled += read;
    }
    reply.truncate(filled);
    Outcome {
        reply,
        peer_error,
        ..Outcome::default()
    }
}

/// 观察对端结束连接：读到 0 字节 = 正常结束；读到错误 = 异常结束；
/// 读到数据 = 不该发生（记录为 `unexpected_data`）。
async fn observe_rejection<S: AsyncRead + Unpin>(stream: &mut S) -> Outcome {
    let mut buf = [0u8; 64];
    match timeout(CLOSE_BOUND, stream.read(&mut buf)).await {
        Ok(Ok(0)) => Outcome {
            peer_closed: true,
            ..Outcome::default()
        },
        Ok(Ok(read)) => Outcome {
            reply: buf[..read].to_vec(),
            unexpected_data: true,
            ..Outcome::default()
        },
        Ok(Err(_)) => Outcome {
            peer_error: true,
            ..Outcome::default()
        },
        Err(_) => Outcome::default(),
    }
}
