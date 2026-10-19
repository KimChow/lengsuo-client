//! `dns::upstream::Table`（environment id → 上游绑定表）的环境隔离验收。
//!
//! 逐条落实绑定语义：
//! 1. A/B 各自登记后，A 的查询只到达 A 的上游、B 同域名同事务 ID 只到达 B 的上游，
//!    响应互不串台——服务端实际收包次数 + 应答 IP 双证据。
//! 2. 未登记的环境、撤销后的环境一律拒绝且一条查询都不外发；换绑后旧端点立即失权。
//! 3. 上游沉默：绑定层的失败以错误结束，绝不改发系统 DNS 替身或另一环境的上游。
//!
//! 边界（必须准确理解，不得放大）：全部收发都发生在 `127.0.0.1` 随机端口上的
//! **自建假上游**，地址与载荷均为测试专用假数据；这些用例只证明绑定表 + 每环境
//! 独占 socket 的原语级隔离，**不**证明可信浏览器环境的身份已接入分流，也**不**
//! 构成与任何真实 DNS 服务的互通。收包次数只在测试进程内部计数，不抓取任何系统或
//! 外部流量，断言与错误输出都不打印报文原始字节。异步收发全部套总超时，自建任务
//! 在用例结束统一回收。
//!
//! 与 `dns_environment_isolation.rs` 的分工：该文件验收 `exchange`（显式端点）本身，
//! 本文件验收 `Table` 的环境绑定层；两边的夹具共用 `tests/dns_isolation_support`。

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

/// 环境 A / B 的假上游应答 IP：绑定层隔离失败时两者会混同，断言可据此区分。
const IP_A: [u8; 4] = [198, 51, 100, 1];
const IP_B: [u8; 4] = [203, 0, 113, 2];

/// 未回环验证的本文件内部兜底：任何收发都不得长于它，触顶即判失败。
const EVERYTHING: Duration = Duration::from_secs(15);

/// 把环境 7 与 9 分别绑到两个假上游，并挂一个只收不答的替身出口监听器。
async fn two_environment_table() -> (Table, Seen) {
    let mut table = Table::default();
    let a = Upstream::bind().await;
    let b = Upstream::bind().await;
    table.bind(7, a.addr);
    table.bind(9, b.addr);
    let stand_in = Upstream::bind().await;
    let seen_stand_in = Seen::of(&stand_in);
    // 替身监听在内部窗口内持续收包计数；任何环境把查询发到这里都算泄漏。
    tokio::spawn(only_count(stand_in));
    (table, seen_stand_in)
}

/// A/B 各绑一个假上游：A 查询只到 A、B 同域名同事务 ID 只到 B，响应各自拿到。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bindings_are_isolated_per_environment() {
    let mut table = Table::default();
    let a = Upstream::bind().await;
    let b = Upstream::bind().await;
    table.bind(7, a.addr);
    table.bind(9, b.addr);
    let (seen_a, seen_b) = (Seen::of(&a), Seen::of(&b));

    let labels = ["isolated", "example"];
    let id = 0x1234u16;
    let q = query(id, &labels);
    let reply_a = response(id, &labels, IP_A);
    let reply_b = response(id, &labels, IP_B);
    let handles = vec![
        tokio::spawn(answer_once(a, reply_a.clone())),
        tokio::spawn(answer_once(b, reply_b.clone())),
    ];

    let (ra, rb) = timeout(EVERYTHING, {
        let qa = q.clone();
        let qb = q.clone();
        async move { tokio::try_join!(table.resolve(7, &qa, OPEN), table.resolve(9, &qb, OPEN)) }
    })
    .await
    .expect("两环境并发解析总超时")
    .expect("两环境都应各自拿到上游响应");

    assert_eq!(ra, reply_a, "A 环境拿到的不是 A 上游的响应");
    assert_eq!(rb, reply_b, "B 环境拿到的不是 B 上游的响应");
    assert_ne!(ra, rb, "A/B 拿到同一个答案：绑定表串了环境");
    assert_eq!(answer_of(&ra), Some(IP_A));
    assert_eq!(answer_of(&rb), Some(IP_B));
    assert_eq!(seen_a.count(), 1, "A 上游收包次数不是 1");
    assert_eq!(seen_b.count(), 1, "B 上游收包次数不是 1");

    reap(handles).await;
}

/// 未登记环境：拒绝且一条查询都不外发（两个已登记上游与系统 DNS 替身零收包）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unbound_environment_rejected_without_sending() {
    let (table, seen_stand_in) = two_environment_table().await;
    let system = Upstream::bind().await;
    let decoy = Upstream::bind().await;
    let (seen_system, seen_decoy) = (Seen::of(&system), Seen::of(&decoy));
    let handles = vec![
        tokio::spawn(only_count(system)),
        tokio::spawn(only_count(decoy)),
    ];

    let result = timeout(
        EVERYTHING,
        table.resolve(99, &query(0x0101, &["x", "example"]), OPEN),
    )
    .await
    .expect("未登记环境解析总超时")
    .expect_err("未登记环境必须被拒绝");
    assert!(
        matches!(result, Error::UnboundEnvironment),
        "实际 {result:?}"
    );
    timeout(SETTLE, tokio::time::sleep(SETTLE)).await.ok();
    assert_eq!(
        seen_stand_in.count(),
        0,
        "未登记环境被发往了已登记环境的替身上游"
    );
    assert_eq!(seen_system.count(), 0, "未登记环境回退了系统 DNS 替身");
    assert_eq!(seen_decoy.count(), 0, "未登记环境回退了其它出口");

    reap(handles).await;
}

/// 撤销后：环境的上游绑定失权，解析拒绝且一条查询都不外发。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unbound_after_unbind_is_rejected() {
    let mut table = Table::default();
    let up = Upstream::bind().await;
    let addr = up.addr;
    table.bind(7, addr);
    table.unbind(7);
    let seen_up = Seen::of(&up);
    let handles = vec![tokio::spawn(only_count(up))];

    let result = timeout(
        EVERYTHING,
        table.resolve(7, &query(0x0202, &["y", "example"]), OPEN),
    )
    .await
    .expect("撤销后解析总超时")
    .expect_err("撤销后必须被拒绝");
    assert!(
        matches!(result, Error::UnboundEnvironment),
        "实际 {result:?}"
    );
    timeout(SETTLE, tokio::time::sleep(SETTLE)).await.ok();
    assert_eq!(seen_up.count(), 0, "撤销后查询仍被发往旧上游");

    reap(handles).await;
}

/// 换绑后：旧端点立即失权，新端点生效。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebind_switches_endpoint_without_leaking_to_old() {
    let mut table = Table::default();
    let old = Upstream::bind().await;
    let new = Upstream::bind().await;
    table.bind(7, old.addr);
    table.bind(7, new.addr);
    let (seen_old, seen_new) = (Seen::of(&old), Seen::of(&new));

    let labels = ["rebind", "example"];
    let id = 0x0303u16;
    let q = query(id, &labels);
    let reply = response(id, &labels, [192, 0, 2, 7]);
    let handles = vec![
        tokio::spawn(answer_once(new, reply.clone())),
        tokio::spawn(only_count(old)),
    ];

    let result = timeout(EVERYTHING, table.resolve(7, &q, OPEN))
        .await
        .expect("换绑后解析总超时");
    assert!(
        matches!(&result, Ok(bytes) if bytes == &reply),
        "实际 {}",
        shape(&result)
    );
    timeout(SETTLE, tokio::time::sleep(SETTLE)).await.ok();
    assert_eq!(seen_new.count(), 1, "新上游收包次数不是 1");
    assert_eq!(seen_old.count(), 0, "换绑后旧上游仍收到查询");

    reap(handles).await;
}

/// 上游沉默：绑定层以错误结束，绝不改发系统 DNS 替身或另一环境的上游。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_upstream_fails_without_falling_back() {
    let mut table = Table::default();
    let up = Upstream::bind().await;
    table.bind(7, up.addr);
    let system = Upstream::bind().await;
    let other = Upstream::bind().await;
    let (seen_up, seen_system, seen_other) = (Seen::of(&up), Seen::of(&system), Seen::of(&other));
    let handles = vec![
        tokio::spawn(only_count(up)),
        tokio::spawn(only_count(system)),
        tokio::spawn(only_count(other)),
    ];

    let result = timeout(
        EVERYTHING,
        table.resolve(7, &query(0x0404, &["silent", "example"]), TIGHT),
    )
    .await
    .expect("沉默上游解析总超时");
    assert!(
        matches!(result, Err(Error::Timeout)),
        "实际 {}",
        shape(&result)
    );
    timeout(SETTLE, tokio::time::sleep(SETTLE)).await.ok();
    assert_eq!(seen_up.count(), 1, "显式上游只应收到那一条查询");
    assert_eq!(seen_system.count(), 0, "超时后回退了系统 DNS 替身");
    assert_eq!(seen_other.count(), 0, "超时后回退了另一环境的上游");

    reap(handles).await;
}
