//! 空闲池用例的夹具：回环目标 + 本仓服务端 + 客户端会话（含 [`ClientState`]）。
//!
//! 本仓**没有**客户端出站运行时（`src/` 只有纯状态机，见 `docs/anytls-status.md`），
//! 故这里在测试内组装一个最小客户端会话，扮演「客户端运行时」的角色：
//! 认证 → Settings → 每条流 SYN+PUSH → 按流编号分发回程数据。
//!
//! 客户端会话**驱动真正的 [`ClientState]`**：流编号由状态机分配，回程帧逐帧喂给
//! 状态机并按 `Event::Data(sid)` 归档到对应流 —— 串包会直接表现为
//! 「某条流收到别的流的数据」或状态机报错，而不是被夹具掩盖。状态机报错不
//! `panic!`（后台任务的 panic 不会让用例失败），而是**记录**下来，由用例断言。
//!
//! 协议版本取 **v2**：服务端在 v2 下**逐流**回 SYNACK（`StreamFlags` 是每流一份的
//! `reported` 位），且 `relay()` 先写 SYNACK 再 `flush_pending()` 把载荷发给目标，
//! 故 SYNACK 必然早于该流的数据 —— 状态机的「数据早于 SYNACK ⇒ 失效」不误伤。
//!
//! 约束：回环地址、临时端口、运行时生成的假凭据；口令只在本模块内流转，
//! 不进日志、不进断言文本。
use lengsuo_anytls::auth::Credential;
use lengsuo_anytls::client_state::{ClientState, Event};
use lengsuo_anytls::frame::{Command, Frame};
use lengsuo_anytls::padding::PaddingScheme;
use lengsuo_anytls::server::{self, ServerConfig, SessionStats};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// 单次网络操作的等待上限。
pub const WAIT: Duration = Duration::from_secs(5);
/// 整条会话（并发流全部收敛）的等待上限。
pub const TOTAL: Duration = Duration::from_secs(30);
/// 测试口令：仅本模块内部使用，不出现在任何日志或断言文本里。
pub const PASSWORD: &[u8] = b"idle-pool-fixture-password";
/// 客户端可同时打开的流上限（状态机容量）。
pub const MAX_STREAMS: usize = 256;

/// 客户端 Settings 文本：本仓服务端要求 `v` + `client` + `padding-md5`。
fn settings_text() -> String {
    format!(
        "v=2\nclient=lengsuo-test\npadding-md5={}",
        PaddingScheme::default_scheme().md5()
    )
}

/// 目标地址 + 载荷拼成首帧 PUSH（SOCKS5 家族地址，见 `lengsuo_anytls::socks`）。
fn push_with_target(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let std::net::IpAddr::V4(v4) = addr.ip() else {
        panic!("测试固定 IPv4 回环");
    };
    let mut data = vec![0x01];
    data.extend_from_slice(&v4.octets());
    data.extend_from_slice(&addr.port().to_be_bytes());
    data.extend_from_slice(payload);
    data
}

/// 回环目标：收到什么就回什么（逐字节回显），供「回程数据归属」判据使用。
pub struct EchoTarget {
    /// 目标地址（客户端首帧 PUSH 里携带）。
    pub addr: SocketAddr,
    /// 接受的目标连接数（应等于流数：每条流各自一条出站连接）。
    pub accepted: AtomicUsize,
    /// 收到的总字节数（跨全部连接）。
    pub received: AtomicUsize,
}

/// 启动回环回显目标。
pub async fn spawn_echo_target() -> Arc<EchoTarget> {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("目标监听");
    let addr = listener.local_addr().expect("目标地址");
    let target = Arc::new(EchoTarget {
        addr,
        accepted: AtomicUsize::new(0),
        received: AtomicUsize::new(0),
    });
    let handle = Arc::clone(&target);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            handle.accepted.fetch_add(1, Ordering::SeqCst);
            let handle = Arc::clone(&handle);
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(count) => {
                            handle.received.fetch_add(count, Ordering::SeqCst);
                            if socket.write_all(&buffer[..count]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    target
}

/// 本仓 AnyTLS 服务端（明文 TCP 回环）：TLS 装配不在本卡范围内。
pub struct RustServer {
    /// 监听地址。
    pub addr: SocketAddr,
    /// 接受的连接数（= 建立过的会话数；复用池应当让它显著少于流数）。
    pub accepted: Arc<AtomicUsize>,
    /// 每个已结束会话的统计。
    pub stats: Arc<Mutex<Vec<SessionStats>>>,
}

/// 启动本仓服务端，返回监听地址与观测计数。
pub async fn spawn_rust_server() -> RustServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("监听");
    let addr = listener.local_addr().expect("地址");
    let accepted = Arc::new(AtomicUsize::new(0));
    let stats = Arc::new(Mutex::new(Vec::new()));
    let counter = Arc::clone(&accepted);
    let collected = Arc::clone(&stats);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let password = PASSWORD.to_vec();
            let collected = Arc::clone(&collected);
            tokio::spawn(async move {
                if let Ok(stat) = server::serve(socket, ServerConfig::new(&password, WAIT)).await {
                    collected.lock().expect("统计锁").push(stat);
                }
            });
        }
    });
    RustServer {
        addr,
        accepted,
        stats,
    }
}

/// 一条流的回程结果。
#[derive(Debug)]
pub struct StreamResult {
    /// 流编号。
    pub stream_id: u32,
    /// 收到的回程字节。
    pub received: Vec<u8>,
    /// 期望的回程字节（发送出去的载荷）。
    pub expected: Vec<u8>,
}

/// 客户端会话：写半（共享）+ 读半（后台任务）+ 共享状态机 + 每流回程通道。
pub struct ClientSession {
    /// 写半：并发流各自写帧，锁必须跨 `.await` 持有 ⇒ 用异步感知的互斥量。
    writer: Arc<tokio::sync::Mutex<OwnedWriteHalf>>,
    /// 协议状态机（真正的 [`ClientState`]）：开流与收帧两处都要用，故共享。
    state: Arc<Mutex<ClientState>>,
    /// 流编号 → 回程数据通道。
    routes: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>>,
    /// 后台读任务（读帧 → 状态机 → 按流归档）。
    reader: JoinHandle<()>,
    /// 状态机拒绝过的帧（不 panic：后台任务的 panic 不会让用例失败）。
    errors: Arc<Mutex<Vec<String>>>,
}

impl ClientSession {
    /// 连接服务端并完成认证 + Settings 协商，随后起读任务。
    pub async fn connect(addr: SocketAddr) -> Self {
        let stream = timeout(WAIT, TcpStream::connect(addr))
            .await
            .expect("连接服务端超时")
            .expect("连接服务端失败");
        let _ = stream.set_nodelay(true);
        let (mut read_half, write_half) = stream.into_split();
        let state = Arc::new(Mutex::new(
            ClientState::new(MAX_STREAMS).expect("状态机可构造"),
        ));
        let routes: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let writer = Arc::new(tokio::sync::Mutex::new(write_half));
        let errors: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

        // 认证 → 客户端 Settings。
        Credential::new(PASSWORD)
            .send(&mut *writer.lock().await, b"", WAIT)
            .await
            .expect("认证发送");
        let settings = Frame {
            command: Command::Settings,
            stream_id: 0,
            data: settings_text().into_bytes(),
        };
        settings
            .write(&mut *writer.lock().await, WAIT)
            .await
            .expect("写 Settings");
        state
            .lock()
            .expect("状态锁")
            .mark_settings_sent()
            .expect("标记 Settings 已发出");

        // 等服务端 Settings（v2）：此时服务端还没有别的帧。
        loop {
            let frame = read_frame(&mut read_half).await.expect("读服务端 Settings");
            match state.lock().expect("状态锁").accept(&frame) {
                Ok(Event::Settings { version }) => {
                    assert_eq!(version, 2, "服务端应协商出版本 2");
                    break;
                }
                Ok(_) => continue,
                Err(err) => panic!("握手期收到非法帧：{err}"),
            }
        }

        // 读任务：此后所有服务端帧都由它喂给状态机。
        let reader_state = Arc::clone(&state);
        let reader_routes = Arc::clone(&routes);
        let reader_errors = Arc::clone(&errors);
        let reader = tokio::spawn(async move {
            loop {
                let Some(frame) = read_frame(&mut read_half).await else {
                    return;
                };
                let event = reader_state.lock().expect("状态锁").accept(&frame);
                match event {
                    Ok(Event::Data(stream_id)) => {
                        let sender = reader_routes
                            .lock()
                            .expect("路由锁")
                            .get(&stream_id)
                            .cloned();
                        if let Some(sender) = sender {
                            let _ = sender.send(frame.data);
                        }
                    }
                    Ok(_) => {}
                    Err(err) => {
                        // fail-closed：状态机一旦拒绝，本会话不再读帧。
                        reader_errors
                            .lock()
                            .expect("错误锁")
                            .push(format!("状态机拒绝服务端帧：{err}"));
                        return;
                    }
                }
            }
        });

        Self {
            writer,
            state,
            routes,
            reader,
            errors,
        }
    }

    /// 开一条流：状态机分配编号 → 写 SYN + 首帧 PUSH → 返回编号与回程接收端。
    pub async fn open_stream(
        &self,
        target: SocketAddr,
        payload: &[u8],
    ) -> (u32, mpsc::UnboundedReceiver<Vec<u8>>) {
        let stream_id = self
            .state
            .lock()
            .expect("状态锁")
            .open_stream()
            .expect("状态机开流");
        let (tx, rx) = mpsc::unbounded_channel();
        self.routes.lock().expect("路由锁").insert(stream_id, tx);
        let syn = Frame {
            command: Command::Syn,
            stream_id,
            data: Vec::new(),
        };
        syn.write(&mut *self.writer.lock().await, WAIT)
            .await
            .expect("写 SYN");
        let push = Frame {
            command: Command::Push,
            stream_id,
            data: push_with_target(target, payload),
        };
        push.write(&mut *self.writer.lock().await, WAIT)
            .await
            .expect("写 PUSH");
        (stream_id, rx)
    }

    /// 关闭一条流（协议层 FIN），并在本端状态机里释放该流的容量。
    pub async fn send_fin(&self, stream_id: u32) {
        let fin = Frame {
            command: Command::Fin,
            stream_id,
            data: Vec::new(),
        };
        fin.write(&mut *self.writer.lock().await, WAIT)
            .await
            .expect("写 FIN");
        // 本端关流：释放容量。编号不回收（状态机的规则）。
        self.state
            .lock()
            .expect("状态锁")
            .close_stream(stream_id)
            .expect("关闭本端流");
    }

    /// 状态机快照（供断言用）。
    pub fn peer_version(&self) -> u8 {
        self.state.lock().expect("状态锁").peer_version()
    }

    /// 状态机拒绝过的帧（空表示客户端侧一切正常）。
    pub fn errors(&self) -> Vec<String> {
        self.errors.lock().expect("错误锁").clone()
    }
}

impl Drop for ClientSession {
    fn drop(&mut self) {
        // 收尾：停掉后台读任务，免得它继续持有读半。
        self.reader.abort();
    }
}

/// 读一帧（跳过 Waste 填充）。
async fn read_frame(reader: &mut OwnedReadHalf) -> Option<Frame> {
    loop {
        match Frame::read(reader, u16::MAX, WAIT).await {
            Ok(frame) => {
                if frame.command != Command::Waste {
                    return Some(frame);
                }
            }
            Err(_) => return None,
        }
    }
}
