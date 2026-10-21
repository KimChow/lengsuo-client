// 本地目标（TCP / UDP）：目标脚本、接入计数与事件观测。
// ===========================================================================
// 本地目标（TCP / UDP）
// ===========================================================================

/// 本地 TCP 目标的事件。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetEvent {
    /// 读到了一批字节。
    Read(usize),
    /// 读端收到 EOF（对端半关闭了写端）。
    Eof,
    /// 目标已关闭自己的写端（半关闭）。
    WriteClosed,
}

/// 本地 TCP 目标的脚本。
#[derive(Debug, Clone)]
pub(crate) enum TargetScript {
    /// 读到 EOF 后才回写 `reply`，随后关闭写端。
    /// ⇒ 用来验「客户端半关闭写端后，读方向仍然可继续收」。
    ReplyAfterEof(Vec<u8>),
    /// 读到第一批数据后：先回写 `reply`，再**半关闭写端**
    /// （`shutdown(Write)`），但继续读。
    /// ⇒ 用来验「对端半关闭的对称性」：客户端应先读到数据、再读到
    /// **干净 EOF**（`Ok(0)`），而不是读错误。
    ReplyThenHalfClose(Vec<u8>),
    /// 读到第一批数据后立刻回写 `reply`，随后读到 EOF 再关闭。
    ReplyThenDrain(Vec<u8>),
    /// 读到第一批数据后立刻**整条关闭**（读端 + 写端）。
    /// ⇒ 用来让服务端的出站连接及时收尾（否则承载任务会一直挂着）。
    CloseAfterFirstRead,
    /// 只读不写、**永不主动关闭**（读到 EOF 才结束）。
    /// ⇒ 用来观察「对端异常断开时，服务端的出站连接是否被释放」。
    KeepOpen,
}

/// 本地 TCP 目标（服务端直连出站的对象）。
pub(crate) struct TcpTarget {
    pub(crate) addr: SocketAddr,
    received: Arc<Mutex<Vec<u8>>>,
    accepts: Arc<AtomicUsize>,
    events: mpsc::UnboundedReceiver<TargetEvent>,
}

impl TcpTarget {
    /// 目标已从客户端读到的全部字节。
    pub(crate) fn received(&self) -> Vec<u8> {
        self.received.lock().expect("目标缓冲锁中毒").clone()
    }

    /// 目标被**接入**的连接数（服务端出站 TCP 连接的条数）。
    ///
    /// 用来区分「服务端把残帧当干净 EOF 放行」（会建立出站连接）与
    /// 「服务端把残帧当协议错误拒绝」（不建立任何出站连接）。
    pub(crate) fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    /// 等到出现满足 `pred` 的事件（带上限）。
    pub(crate) async fn wait_event(&mut self, pred: impl Fn(TargetEvent) -> bool) -> bool {
        tokio::time::timeout(IO_TIMEOUT, async {
            while let Some(ev) = self.events.recv().await {
                if pred(ev) {
                    return true;
                }
            }
            false
        })
        .await
        .unwrap_or(false)
    }
}

/// 起一个本地 TCP 目标。
pub(crate) async fn spawn_tcp_target(script: TargetScript) -> TcpTarget {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑定本地 TCP 目标");
    let addr = listener.local_addr().expect("目标地址");
    let received = Arc::new(Mutex::new(Vec::new()));
    let accepts = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::unbounded_channel();
    let sink = Arc::clone(&received);
    let counter = Arc::clone(&accepts);
    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        counter.fetch_add(1, Ordering::SeqCst);
        let _ = sock.set_nodelay(true);
        let mut buf = [0u8; 16 * 1024];
        let mut replied = false;
        loop {
            match sock.read(&mut buf).await {
                Ok(0) => {
                    let _ = tx.send(TargetEvent::Eof);
                    break;
                }
                Ok(n) => {
                    sink.lock()
                        .expect("目标缓冲锁中毒")
                        .extend_from_slice(&buf[..n]);
                    let _ = tx.send(TargetEvent::Read(n));
                    match &script {
                        TargetScript::ReplyAfterEof(_) => {}
                        TargetScript::ReplyThenHalfClose(reply) => {
                            if !replied {
                                replied = true;
                                let _ = sock.write_all(reply).await;
                                let _ = sock.flush().await;
                                // 半关闭写端：读方向保持打开。
                                let _ = sock.shutdown().await;
                                let _ = tx.send(TargetEvent::WriteClosed);
                            }
                        }
                        TargetScript::ReplyThenDrain(reply) => {
                            if !replied {
                                replied = true;
                                let _ = sock.write_all(reply).await;
                            }
                        }
                        TargetScript::CloseAfterFirstRead => {
                            break;
                        }
                        TargetScript::KeepOpen => {}
                    }
                }
                Err(_) => break,
            }
        }
        if let TargetScript::ReplyAfterEof(reply) = &script {
            let _ = sock.write_all(reply).await;
            let _ = sock.flush().await;
        }
        let _ = sock.shutdown().await;
    });
    TcpTarget {
        addr,
        received,
        accepts,
        events: rx,
    }
}

/// 一条被本地 UDP 目标收到的数据报：**源地址**（服务端出站 socket 的源
/// 端口 ⇒ 服务端 UDP 会话条目的身份）+ 载荷。
pub(crate) type UdpPacket = (SocketAddr, Vec<u8>);

/// 本地 UDP 目标：记录每个数据报的**源地址**（服务端出站 socket 的源端口
/// ⇒ 服务端 UDP 会话条目的身份）与载荷，并原样回送。
pub(crate) struct UdpTarget {
    pub(crate) addr: SocketAddr,
    packets: Arc<Mutex<Vec<UdpPacket>>>,
}

impl UdpTarget {
    /// 已收到的所有数据报（源地址 + 载荷）。
    pub(crate) fn packets(&self) -> Vec<UdpPacket> {
        self.packets.lock().expect("UDP 目标锁中毒").clone()
    }
}

/// 起一个本地 UDP 回送目标。
pub(crate) async fn spawn_udp_target() -> UdpTarget {
    let sock = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("绑定本地 UDP 目标");
    let addr = sock.local_addr().expect("UDP 目标地址");
    let packets = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&packets);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            sink.lock()
                .expect("UDP 目标锁中毒")
                .push((from, buf[..n].to_vec()));
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
    UdpTarget { addr, packets }
}
