// --------------------------------------------------------------------------------------
// Mux 承载服务端
// --------------------------------------------------------------------------------------

/// mux 承载服务端的运行结果。
pub struct MuxOutcome {
    /// VLESS 响应头 flush 之前收到的客户端 mux 帧数。
    ///
    /// ≥1 ⇒ 客户端**先发了 mux 帧**、再拿到响应头（参考的顺序要求）。
    pub frames_before_header: usize,
    /// 各会话收到的上行载荷（会话 ID → 载荷）。
    pub received: Vec<(u16, Vec<u8>)>,
}

/// mux 承载服务端的运行句柄。
pub struct MuxPeer {
    /// 触发承载断开（参考：承载连接被关闭 ⇒ 所有逻辑会话必须失败）。
    pub close: Option<oneshot::Sender<()>>,
    /// 服务端任务：返回承载上的观测结果。
    pub task: tokio::task::JoinHandle<Result<MuxOutcome, String>>,
}

/// 起一个 mux 承载服务端（TLS + VLESS `command=Mux` + mux 帧回显）。
pub fn spawn_mux_peer(fixture: ServerFixture, uuid: [u8; 16]) -> MuxPeer {
    let (close_tx, close_rx) = oneshot::channel();
    let task = tokio::spawn(async move { serve_mux(fixture, uuid, close_rx).await });
    MuxPeer {
        close: Some(close_tx),
        task,
    }
}

/// 会话回显时加的会话标签（`会话 ID ‖ 载荷`）：路由串扰会立刻暴露。
fn tag(id: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 2);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// 滞留的 VLESS 响应头（参考 `common/buf/writer.go` 的 `BufferedWriter` +
/// `SetFlushNext()`）。
///
/// 参考入站把响应头写进 `buf.BufferedWriter`，**之后**才 `SetFlushNext()`；而
/// `SetFlushNext()` 只让**下一次 Write** 触发 flush ⇒ **响应头滞留缓冲区**，
/// 要等**第一个 mux 帧写出**才一起 flush。
///
/// ⇒ 本夹具**照抄**这个时序：响应头先攒着，首个 mux 帧写出时才与它一起写出。
/// ⇒ 若 node 侧「先阻塞等响应头、再发 mux 帧」，本夹具就永远不会写出首个帧
/// （它在等帧）⇒ 互锁成死锁 ⇒ 用例超时失败。**这正是本卡要覆盖的那条语义。**
struct PendingHeader {
    /// 滞留的响应头字节（VLESS 成功响应头恒为 `00 00`）。
    bytes: Vec<u8>,
    /// 是否已经随某一帧 flush 过。
    flushed: bool,
    /// flush 之前收到的客户端 mux 帧数。
    frames_before_flush: Option<usize>,
}

impl PendingHeader {
    fn new() -> Self {
        Self {
            bytes: vec![0u8, 0u8],
            flushed: false,
            frames_before_flush: None,
        }
    }

    /// 把滞留的响应头拼到即将写出的帧前面（只在第一次生效）。
    fn prepend(&mut self, frame: &mut Vec<u8>, frames_seen: usize) {
        if !self.flushed {
            frame.splice(0..0, self.bytes.drain(..));
            self.flushed = true;
            self.frames_before_flush = Some(frames_seen);
        }
    }
}

/// mux 承载服务端。
///
/// ## ⛔ 响应头的 flush 时序（参考 `common/buf/writer.go`）
///
/// 见 [`PendingHeader`]：响应头滞留到**第一个 mux 帧写出**才一起 flush。
///
/// 参考的 mux 服务端（`common/mux/server.go` 的 `handleStatusNew`）在 `New` 帧上
/// **不写首帧**（目标产生产生数据时才写）⇒ 本夹具在 `New` 帧上**只登记会话、
/// 不写任何字节**，与参考一致。
async fn serve_mux(
    fixture: ServerFixture,
    uuid: [u8; 16],
    mut close_rx: oneshot::Receiver<()>,
) -> Result<MuxOutcome, String> {
    let ServerFixture { listener, tls, .. } = fixture;
    let (socket, _) = listener.accept().await.map_err(|e| e.to_string())?;
    let mut tls_stream = tls.accept(socket).await.map_err(|e| e.to_string())?;
    // 承载请求头：参考 `proxy/vless/outbound/outbound.go:218-232` 写 `command=Mux`。
    let request = receive_request(&mut tls_stream, &uuid, WAIT)
        .await
        .map_err(|e| format!("读承载请求头失败：{e}"))?;
    if request.command != Command::Mux {
        return Err(format!(
            "承载请求头 command 不是 Mux：{:?}",
            request.command
        ));
    }
    let (mut reader, mut writer) = tokio::io::split(tls_stream);
    // 响应头**滞留缓冲区**（参考 `buf.BufferedWriter` + `SetFlushNext()`）。
    let mut pending = PendingHeader::new();
    let mut server = MuxServer::new();
    let mut writers: HashMap<u16, SessionWriter> = HashMap::new();
    let mut received: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut frames_seen = 0usize;
    loop {
        let meta = tokio::select! {
            biased;
            // 承载断开（测试触发）：退出循环 ⇒ TLS 流析构 ⇒ TCP 关闭。
            _ = &mut close_rx => break,
            result = decode_from_async(&mut reader, false) => match result {
                Ok(meta) => meta,
                Err(error) => return Err(format!("解帧失败：{error:?}")),
            },
        };
        frames_seen += 1;
        // 参考的四个 handle* 分支在有 OptionData 时都会消费数据段 ⇒ 必须先读再派发。
        let data = if meta.has_data() {
            match read_data_async(&mut reader, true).await {
                Ok(data) => Some(data),
                Err(error) => return Err(format!("读数据段失败：{error:?}")),
            }
        } else {
            None
        };
        match meta.status {
            SessionStatus::New => {
                server
                    .handle_new(&meta)
                    .map_err(|error| format!("登记会话失败：{error:?}"))?;
                // 参考的 `handleStatusNew`（TCP 分支）**不写首帧**：目标产生产生
                // 数据时才写 ⇒ 这里只登记会话与响应侧 writer。
                writers.insert(
                    meta.session_id,
                    SessionWriter::response(meta.session_id, TargetNetwork::Tcp),
                );
            }
            SessionStatus::Keep => {
                match server
                    .handle(&meta, data)
                    .map_err(|error| format!("派发失败：{error:?}"))?
                {
                    Action::Deliver { id, payload, .. } => {
                        // 参考把数据写给该会话的下游；本夹具回环（并加会话标签）。
                        let session_writer = writers
                            .get_mut(&id)
                            .ok_or_else(|| format!("会话 {id} 不存在"))?;
                        // 先发一个**零长数据帧**（`OptionData` 置位 + BE16 长度 0）：
                        // 线格式合法，参考读取侧会把它当成「空写」交给下游
                        // （`common/mux/writer.go:100` 的 `writeMetaOnly`；空写 = no-op）。
                        // ⇒ 会话读⛔不得把它当成 EOF。若被当成 EOF，下面的回显就永远
                        // 读不到，本夹具的每条 mux 用例都会失败（这就是那条可跑的自检）。
                        let mut empty = Vec::new();
                        session_writer
                            .write_data(&mut empty, &[])
                            .map_err(|error| format!("写空帧失败：{error:?}"))?;
                        pending.prepend(&mut empty, frames_seen);
                        writer.write_all(&empty).await.map_err(|e| e.to_string())?;
                        writer.flush().await.map_err(|e| e.to_string())?;
                        let mut frame = Vec::new();
                        session_writer
                            .write_multi(&mut frame, &tag(id, &payload))
                            .map_err(|error| format!("写回失败：{error:?}"))?;
                        // 首个 mux 帧 ⇒ 把滞留的响应头与它一起写出（参考的 flush 时序）。
                        pending.prepend(&mut frame, frames_seen);
                        writer.write_all(&frame).await.map_err(|e| e.to_string())?;
                        writer.flush().await.map_err(|e| e.to_string())?;
                        received.push((id, payload));
                    }
                    Action::SendEnd { id } => {
                        let mut frame = Vec::new();
                        write_end(&mut frame, id)
                            .map_err(|error| format!("写 End 失败：{error:?}"))?;
                        pending.prepend(&mut frame, frames_seen);
                        writer.write_all(&frame).await.map_err(|e| e.to_string())?;
                        writer.flush().await.map_err(|e| e.to_string())?;
                    }
                    Action::CloseSession { id } => {
                        writers.remove(&id);
                    }
                    Action::None => {}
                }
            }
            SessionStatus::End => {
                if let Ok(Action::CloseSession { id }) = server.handle(&meta, None) {
                    writers.remove(&id);
                }
            }
            SessionStatus::KeepAlive => {}
        }
    }
    Ok(MuxOutcome {
        frames_before_header: pending.frames_before_flush.unwrap_or(frames_seen),
        received,
    })
}

/// 写一个 `End` 帧（会话不存在时通知对端关闭）。
fn write_end(out: &mut Vec<u8>, id: u16) -> Result<(), lengsuo_vless::mux::frame::FrameError> {
    let mut session_writer = SessionWriter::response(id, TargetNetwork::Tcp);
    session_writer.close(out)
}

// --------------------------------------------------------------------------------------
// 篡改搬运（记录层 ↔ 传输层之间）
// --------------------------------------------------------------------------------------

/// 原样转发。
async fn copy_plain(
    src: &mut (impl AsyncRead + Unpin),
    dst: &mut (impl AsyncWrite + Unpin),
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 4096];
    loop {
        let read = src.read(&mut buf).await?;
        if read == 0 {
            return Ok(());
        }
        dst.write_all(&buf[..read]).await?;
        dst.flush().await?;
    }
}

/// 转发并在第 `flip_offset` 个字节上翻一个比特。
async fn copy_flipping(
    src: &mut (impl AsyncRead + Unpin),
    dst: &mut (impl AsyncWrite + Unpin),
    flip_offset: usize,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 4096];
    let mut seen = 0usize;
    loop {
        let read = src.read(&mut buf).await?;
        if read == 0 {
            return Ok(());
        }
        let mut chunk = buf[..read].to_vec();
        if seen <= flip_offset && flip_offset < seen + read {
            chunk[flip_offset - seen] ^= 0xff;
        }
        seen += read;
        dst.write_all(&chunk).await?;
        dst.flush().await?;
    }
}
