//! 多流并发压力：N ≥ 32 条流跑两轮，第二轮复用第一轮的连接。
//!
//! 断言：
//! - **无串包**：每条流收到的回程数据必须逐字节等于自己发出的载荷；
//! - **无死锁**：每条流都有超时上限，卡住即判失败；
//! - **复用成立**：客户端只建立过一条连接，服务端在**同一条会话**上开了 64 条流。
//!
//! 复用是「连接级」的：参考 anytls-go `proxy/session/client.go` 里
//! `session.Client` 同时持有 `sessions map[uint64]*Session` 与空闲表，命中空闲
//! 会话时复用的就是**同一个会话对象**（同一条 TLS 连接）。本仓的
//! [`ClientPool`] 只搬会话编号，故这里补一张「编号 → 连接」的表，让「复用」
//! 在连接层面可观测（`server.accepted() == 1` 即是复用的直接证据）。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use lengsuo_anytls::client_pool::{monotonic_ms, ClientPool, PoolConfig, ReleaseOutcome};
use tokio::time::{sleep, timeout};

use super::harness::{
    spawn_echo_target, spawn_rust_server, ClientSession, RustServer, StreamResult, TOTAL,
};

/// 并发流数（任务书要求 ≥ 32）。
const STREAMS: usize = 32;
/// 单条流的载荷长度。
const PAYLOAD_LEN: usize = 48;

/// 客户端运行时：把池里的「会话编号」与真正的传输层会话对上。
struct ClientRuntime {
    pool: ClientPool,
    /// 会话编号 → 连接（参考 `session.Client.sessions`）。
    sessions: HashMap<u64, ClientSession>,
}

impl ClientRuntime {
    fn new(config: PoolConfig) -> Self {
        Self {
            pool: ClientPool::new(config).expect("合法配置"),
            sessions: HashMap::new(),
        }
    }

    /// 取一条会话：命中空闲池则复用既有连接，未命中则新建连接。
    async fn acquire(&mut self, server: SocketAddr) -> u64 {
        let acquired = self.pool.acquire(monotonic_ms()).expect("取用");
        if acquired.reused {
            assert!(
                self.sessions.contains_key(&acquired.session_id),
                "命中的空闲会话必须还持有连接"
            );
            return acquired.session_id;
        }
        let session = ClientSession::connect(server).await;
        self.sessions.insert(acquired.session_id, session);
        acquired.session_id
    }

    /// 归还一条会话：入池则保留连接（复用时不必重建），否则关闭连接。
    fn release(&mut self, session_id: u64) {
        let outcome = self.pool.release(session_id, monotonic_ms()).expect("归还");
        match outcome {
            ReleaseOutcome::Pooled => {}
            ReleaseOutcome::PoolFull
            | ReleaseOutcome::ReuseDisabled
            | ReleaseOutcome::AlreadyClosed => {
                // 不入池：调用方必须关闭该会话的连接。
                self.sessions.remove(&session_id);
            }
        }
    }

    fn session(&self, session_id: u64) -> &ClientSession {
        self.sessions.get(&session_id).expect("会话在册")
    }

    /// 关闭全部连接（用例收尾）。
    fn close_all(&mut self) {
        self.sessions.clear();
    }
}

/// 跑一轮：并发开 `count` 条流，每条流发自己的载荷、收自己的回程。
async fn run_round(session: &ClientSession, target: SocketAddr, count: usize) -> Vec<StreamResult> {
    let mut receivers = Vec::new();
    for index in 0..count {
        let payload = format!("stream-{index:04}-{}", "x".repeat(PAYLOAD_LEN)).into_bytes();
        let (stream_id, rx) = session.open_stream(target, &payload).await;
        receivers.push((stream_id, rx, payload));
    }

    // 并发收：每条流一个任务，各自等自己的回程数据。
    let mut tasks = Vec::new();
    for (stream_id, mut rx, expected) in receivers {
        tasks.push(tokio::spawn(async move {
            let mut received = Vec::new();
            while received.len() < expected.len() {
                match timeout(TOTAL, rx.recv()).await {
                    Ok(Some(chunk)) => received.extend_from_slice(&chunk),
                    Ok(None) | Err(_) => break,
                }
            }
            StreamResult {
                stream_id,
                received,
                expected,
            }
        }));
    }

    let mut results = Vec::new();
    for task in tasks {
        results.push(
            timeout(TOTAL, task)
                .await
                .expect("流任务超时（死锁）")
                .expect("流任务 panic"),
        );
    }

    // 关流（协议层 FIN）。
    for result in &results {
        session.send_fin(result.stream_id).await;
    }
    results
}

/// 串包判据：每条流的回程数据必须逐字节等于自己的载荷。
fn assert_no_crosstalk(results: &[StreamResult]) {
    assert_eq!(results.len(), STREAMS, "并发流数不符");
    for result in results {
        assert_eq!(
            result.received, result.expected,
            "流 {} 的回程数据必须逐字节等于自己的载荷（串包判据）",
            result.stream_id
        );
        assert!(
            !result.received.is_empty(),
            "流 {} 没有回程数据",
            result.stream_id
        );
    }
}

/// 等服务端会话结束，取它开过的流数。
async fn wait_for_streams_opened(server: &RustServer) -> usize {
    timeout(TOTAL, async {
        loop {
            let opened = server
                .stats
                .lock()
                .expect("统计锁")
                .first()
                .map(|stat| stat.streams_opened);
            if let Some(opened) = opened {
                return opened;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("服务端会话未在超时内结束")
}

#[tokio::test]
async fn thirty_two_streams_are_multiplexed_over_one_reused_connection_without_crosstalk() {
    let target = spawn_echo_target().await;
    let server = spawn_rust_server().await;

    let mut runtime = ClientRuntime::new(PoolConfig {
        check_interval_ms: 30_000,
        idle_timeout_ms: 30_000,
        min_idle: 0,
        max_idle: 4,
        reuse: true,
    });

    // 第一轮：新建连接，跑 32 条流。
    let first = runtime.acquire(server.addr).await;
    assert_eq!(runtime.session(first).peer_version(), 2, "应协商出版本 2");
    let first_round = run_round(runtime.session(first), target.addr, STREAMS).await;
    assert_no_crosstalk(&first_round);

    // 归还 → 入池。
    runtime.release(first);
    assert_eq!(runtime.pool.idle_len(), 1, "归还后应有一条空闲会话");

    // 第二轮：必须命中同一个 session_id、复用同一条连接。
    let second = runtime.acquire(server.addr).await;
    assert_eq!(second, first, "第二轮必须命中同一个 session_id");
    let second_round = run_round(runtime.session(second), target.addr, STREAMS).await;
    assert_no_crosstalk(&second_round);

    // 连接层面的复用证据：客户端只建立过一条连接。
    assert_eq!(
        server.accepted.load(Ordering::SeqCst),
        1,
        "64 条流必须压在一条客户端连接上"
    );
    // 每条流各自一条出站连接。
    assert_eq!(
        target.accepted.load(Ordering::SeqCst),
        STREAMS * 2,
        "每条流各自一条出站连接"
    );
    // 目标收到的字节数必须等于发出的载荷总量（无丢字节、无重复字节）。
    let sent: usize = first_round
        .iter()
        .chain(second_round.iter())
        .map(|result| result.expected.len())
        .sum();
    assert_eq!(
        target.received.load(Ordering::SeqCst),
        sent,
        "目标收到的字节数必须与发出的载荷总量一致"
    );
    // 客户端状态机没有拒绝过任何帧。
    assert!(
        runtime.session(second).errors().is_empty(),
        "客户端状态机不得拒绝帧：{:?}",
        runtime.session(second).errors()
    );

    // 关闭连接后，服务端会话结束并给出统计：64 条流开在同一条会话上。
    runtime.close_all();
    assert_eq!(
        wait_for_streams_opened(&server).await,
        STREAMS * 2,
        "服务端必须在这条会话上开过 64 条流"
    );
}
