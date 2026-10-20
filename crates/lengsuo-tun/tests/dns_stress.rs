//! DNS **50 并发隔离**压力验收：`dns::upstream::Table` 按 environment 绑定显式上游。
//!
//! 本卡补上 W4 之前明确留待压力卡的未验收项：docs/tun-status.md 记「50 并发清单本卡
//! 未实跑，留待压力卡」。这里把 50 条查询**同时**发出，分属多个 environment（每个
//! environment 一个独立回环 `UdpSocket` 上游），逐条断言：
//!
//! 1. 每条响应回到**发起它的那个 environment**，零串扰——A 环境的响应绝不回给 B；
//! 2. 全部 50 条在总 deadline 内完成，失败条数为 0；
//! 3. 上游侧观察到**恰好**每个 environment 各 `k` 次收发、事务 ID 两两不重复，
//!    合起来恰好 50 个唯一事务 ID；
//! 4. 未参与的环境其上游一条查询都收不到（授权边界未被绕过）。
//!
//! 边界（必须准确理解，不得放大）：全部收发都在 `127.0.0.1` 随机端口上的**自建假
//! 上游**，地址与载荷均为测试专用假数据；不碰系统 DNS、不碰公网。本用例只证明
//! `Table::resolve` 在 50 路并发下的**原语级隔离与完成性**，不证明它已接入真实
//! 分流链路，也不构成与任何真实 DNS 服务的互通。收包只在测试进程内计数，断言与
//! 错误输出都不打印报文原始字节。全部异步等待都套 `tokio::time::timeout`，绝无
//! 无限 await；自建任务在用例结束统一回收。

use lengsuo_tun::dns::upstream::{Error, Table};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::timeout;

mod dns_isolation_support;
use dns_isolation_support::*;

/// 并发查询总条数：本卡要求的 50 路。
const TOTAL: usize = 50;
/// environment 数量：分属 5 个环境，每个环境 10 条，用于检验跨环境零串扰。
const ENVIRONMENTS: usize = 5;
/// 每个环境分到的查询条数。
const PER_ENV: usize = TOTAL / ENVIRONMENTS;
/// 总 deadline：50 路并发必须在它之内全部完成。
const FANOUT_DEADLINE: Duration = Duration::from_secs(5);
/// 单条交换的最外层兜底超时：正常路径远低于此，触顶即判失败。
const WAIT: Duration = Duration::from_secs(10);
/// 断言收包计数前的观察窗：让「本不该到达」的报文有机会被计入。
const SETTLE: Duration = Duration::from_millis(200);
/// 每个环境下发给它的每条查询，其响应标注的 A 记录 rdata 高字节前缀，用于识别
/// 「这条响应到底出自哪个 environment 的上游」。
fn env_tag(environment: usize) -> u8 {
    // 198.51.100.0/24 与 203.0.113.0/24 是 RFC 5737 文档专用网段，测试假数据。
    100 + environment as u8
}

/// 单路并发查询的返回：发起它的 environment、事务 ID、以及该路交换的结果。
type Job = (usize, u16, Result<Vec<u8>, Error>);

/// 一个服务固定 `count` 条查询的上游：每条查询按事务 ID 回一份**该环境专属**响应，
/// 并把收到的每个唯一事务 ID 记进共享集合。
struct EnvUpstream {
    upstream: Upstream,
    seen_ids: Arc<std::sync::Mutex<std::collections::HashSet<u16>>>,
}

impl EnvUpstream {
    async fn bind() -> Self {
        Self {
            upstream: Upstream::bind().await,
            seen_ids: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        }
    }
}

/// 服务固定 `count` 条查询：逐条收、记唯一事务 ID、按查询 ID 回对应响应。
/// 响应载荷由 `tag` 与查询 ID 共同决定，因此「谁答的」与「答的哪条」都可反查。
async fn serve_env(up: EnvUpstream, tag: u8, count: usize) {
    let EnvUpstream { upstream, seen_ids } = up;
    let Upstream {
        socket,
        addr: _,
        seen,
    } = upstream;
    let mut buffer = [0u8; MAX_DATAGRAM];
    let mut served = 0usize;
    while served < count {
        let Ok(Ok((read, peer))) = timeout(WAIT, socket.recv_from(&mut buffer)).await else {
            return;
        };
        seen.fetch_add(1, Ordering::SeqCst);
        // 事务 ID 是响应头部前两字节；查询与响应共用同一 ID。
        if read >= 2 {
            let id = u16::from_be_bytes([buffer[0], buffer[1]]);
            if let Ok(mut set) = seen_ids.lock() {
                set.insert(id);
            }
            // 以环境 tag 与低字节编码答案，便于逐条反查归属。
            let answer = [198, 51, 100, tag];
            let reply = response(id, &["stress", "example"], answer);
            let _ = socket.send_to(&reply, peer).await;
        }
        served += 1;
    }
}

/// 50 条并发查询分属 5 个 environment：每条响应只回到发起它的那个 environment，
/// 每个上游恰好收到自己那 10 个唯一事务 ID，合计恰好 50 个。
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn fifty_concurrent_queries_stay_within_their_environment() {
    // 先起 5 个 environment 各自的独立回环上游。
    let mut upstreams = Vec::with_capacity(ENVIRONMENTS);
    for _ in 0..ENVIRONMENTS {
        upstreams.push(EnvUpstream::bind().await);
    }
    // 另起一个未授权的替身出口：任何到达它的查询都算越权泄漏。
    let decoy = Upstream::bind().await;
    let seen_decoy = Seen::of(&decoy);

    // 登记表：environment i → 上游 i 的地址。同时留取每个上游的收包计数与
    // 唯一事务 ID 集合句柄，供收尾断言。
    let mut table = Table::default();
    let mut handles: Vec<JoinHandle<()>> = Vec::new();
    let mut seen_per_env: Vec<Seen> = Vec::with_capacity(ENVIRONMENTS);
    let mut ids_per_env: Vec<Arc<std::sync::Mutex<std::collections::HashSet<u16>>>> =
        Vec::with_capacity(ENVIRONMENTS);
    for (i, up) in upstreams.into_iter().enumerate() {
        let addr = up.upstream.addr;
        table.bind(i as u64, addr);
        seen_per_env.push(Seen::of(&up.upstream));
        ids_per_env.push(Arc::clone(&up.seen_ids));
        handles.push(tokio::spawn(serve_env(up, env_tag(i), PER_ENV)));
    }
    handles.push(tokio::spawn(only_count(decoy)));

    // 构造 50 条查询：environment = index % ENVIRONMENTS，每个 environment 10 条；
    // 事务 ID 全局唯一，让「唯一事务 ID 恰 50 个」的断言有意义。
    let mut jobs: Vec<(usize, u16, Vec<u8>)> = Vec::with_capacity(TOTAL);
    for index in 0..TOTAL {
        let environment = index % ENVIRONMENTS;
        let id = 0x4000u16.wrapping_add(index as u16);
        jobs.push((environment, id, query(id, &["stress", "example"])));
    }

    // 把 50 路 resolve 同时起飞；每一步都只碰自己 environment 绑定的上游。
    let table = Arc::new(table);
    let mut tasks: Vec<JoinHandle<Job>> = Vec::with_capacity(TOTAL);
    for (environment, id, payload) in jobs {
        let table = Arc::clone(&table);
        tasks.push(tokio::spawn(async move {
            let result = table
                .resolve(environment as u64, &payload, FANOUT_DEADLINE)
                .await;
            (environment, id, result)
        }));
    }

    // 总 deadline 覆盖全部 50 路：一次性 join，任一路触顶即失败。
    let joined = timeout(WAIT, async move {
        let mut outcomes = Vec::with_capacity(TOTAL);
        for task in tasks {
            outcomes.push(task.await.expect("并发任务不应 panic"));
        }
        outcomes
    })
    .await
    .expect("50 路并发在总超时内未全部结束");

    // 逐条断言：响应回到发起它的 environment，答案 tag 与之吻合，且事务 ID 未被改动。
    let mut returned_ids = std::collections::HashSet::new();
    for (environment, id, result) in &joined {
        match result {
            Ok(bytes) => {
                let tag = *bytes.last().expect("响应至少含 4 字节 rdata");
                assert_eq!(
                    tag,
                    env_tag(*environment),
                    "environment {environment} 收到了别处上游的响应（串扰）"
                );
                assert_eq!(
                    answer_of(bytes),
                    Some([198, 51, 100, env_tag(*environment)]),
                    "environment {environment} 的响应载荷不属于它"
                );
                let echoed = u16::from_be_bytes([bytes[0], bytes[1]]);
                assert_eq!(echoed, *id, "响应事务 ID 与查询漂移");
                returned_ids.insert(echoed);
            }
            Err(error) => panic!("environment {environment} 的查询失败：{error:?}"),
        }
    }
    assert_eq!(returned_ids.len(), TOTAL, "回注的唯一事务 ID 数不等于 50");

    // 让任何越权报文有机会抵达替身，再做收包断言。
    timeout(SETTLE, tokio::time::sleep(SETTLE)).await.ok();
    assert_eq!(seen_decoy.count(), 0, "未授权出口收到了本不该到达的查询");

    // 上游侧取证：每个 environment 的上游恰好收到 PER_ENV 次、事务 ID 两两不同，
    // 且各 environment 的事务 ID 集合互不相交、并集恰为 50。
    let mut union: std::collections::HashSet<u16> = std::collections::HashSet::new();
    for (i, seen) in seen_per_env.iter().enumerate() {
        assert_eq!(
            seen.count(),
            PER_ENV,
            "environment {i} 的上游收包次数不是 {PER_ENV}"
        );
        let set = ids_per_env[i].lock().expect("事务 ID 集合锁");
        assert_eq!(
            set.len(),
            PER_ENV,
            "environment {i} 的唯一事务 ID 数不是 {PER_ENV}"
        );
        for id in set.iter() {
            assert!(union.insert(*id), "事务 ID {id:#06x} 跨 environment 重复");
        }
    }
    assert_eq!(
        union.len(),
        TOTAL,
        "上游侧观察到的唯一事务 ID 总数不是 {TOTAL}"
    );

    reap(handles).await;
}
