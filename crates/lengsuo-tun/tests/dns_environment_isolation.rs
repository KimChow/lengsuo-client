//! 显式上游 DNS 交换的**环境隔离**验收：`dns::upstream::exchange`。
//!
//! 第一验收点逐条落实：
//! 1. 相同域名 + 相同 DNS 事务 ID，经两个显式上游返回**不同 IP**；并发与交错
//!    两种时序下响应都不得串到另一条交换。
//! 2. 错误来源、问题区不符、非法洪泛与期限耗尽这些失败路径都**不得回退**到系统
//!    DNS 替身或另一出口：用「服务端实际收包次数」直接证明未授权端点一条查询都
//!    没收到。
//! 3. 名字匹配按 RFC 1035 2.3.1 的大小写不敏感语义：上游把问题区名字规范化为
//!    小写回显是合法行为，不得因此判为不匹配而超时（与 `dns::rewrite::match_response`
//!    已采用的 `QuestionName::matches` 保持同一套语义）。
//!
//! 边界（必须准确理解，不得放大）：全部收发都发生在 `127.0.0.1` 随机端口上的
//! **自建假上游**，地址与载荷均为测试专用假数据；这些用例只证明「每次调用独占一个
//! socket、按显式上游配对收发」这一原语级隔离，**不**证明可信浏览器环境的身份已
//! 接入分流，也**不**构成与任何真实 DNS 服务的互通。收包次数只在测试进程内部计数，
//! 不抓取任何系统或外部流量，断言与错误输出都不打印报文原始字节。异步收发全部套
//! 总超时，自建任务在用例结束统一回收。

use lengsuo_tun::dns::upstream::{self, Error};
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

/// 相同域名、相同事务 ID，两个显式上游返回不同 IP：**并发**时序下各自只拿到自己的答案。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_name_and_id_two_upstreams_do_not_cross_when_concurrent() {
    let labels = ["isolated", "example"];
    let id = 0x1234u16;
    let q = query(id, &labels);
    let fast = response(id, &labels, [198, 51, 100, 1]);
    let slow = response(id, &labels, [203, 0, 113, 2]);

    // 两条交换用同一份查询字节、同一事务 ID，只有显式上游地址不同。
    let a = Upstream::bind().await;
    let b = Upstream::bind().await;
    let (addr_a, addr_b) = (a.addr, b.addr);
    let (seen_a, seen_b) = (Seen::of(&a), Seen::of(&b));
    // B 被刻意压晚一拍：它在 A 应答之后才发话，两条交换的收发窗口因此重叠。
    let (gate_tx, gate_rx) = oneshot::channel();
    let handles = vec![
        tokio::spawn(answer_when_gated(b, slow.clone(), gate_rx)),
        tokio::spawn(answer_once(a, fast.clone())),
        tokio::spawn(release_after(gate_tx, STAGGER)),
    ];

    let (first, second) = timeout(WAIT, {
        let (qa, qb) = (q.clone(), q.clone());
        async move {
            tokio::try_join!(
                upstream::exchange(&qa, addr_a, OPEN),
                upstream::exchange(&qb, addr_b, OPEN)
            )
        }
    })
    .await
    .expect("并发交换总超时")
    .expect("两条并发交换都应拿到各自上游的响应");

    assert_eq!(first, fast, "上游 A 的响应字节被串改");
    assert_eq!(second, slow, "上游 B 的响应字节被串改");
    assert_ne!(
        answer_of(&first),
        answer_of(&second),
        "同域名同事务 ID 却拿到同一个 IP：两条交换串了"
    );
    assert_eq!(answer_of(&first), Some([198, 51, 100, 1]));
    assert_eq!(answer_of(&second), Some([203, 0, 113, 2]));
    // 每条交换只碰自己那个上游，各自恰好收到一条查询。
    assert_eq!(seen_a.count(), 1, "上游 A 收包次数不是 1");
    assert_eq!(seen_b.count(), 1, "上游 B 收包次数不是 1");

    reap(handles).await;
}

/// 相同域名、相同事务 ID：**交错**时序下（第二条交换仍在等响应时，第一条已
/// 完成整个往返）两条响应都只回给自己的会话。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_name_and_id_two_upstreams_do_not_cross_when_interleaved() {
    let labels = ["isolated", "example"];
    let id = 0x1234u16;
    let q = query(id, &labels);
    let quick = response(id, &labels, [192, 0, 2, 1]);
    let late = response(id, &labels, [192, 0, 2, 2]);

    let quick_up = Upstream::bind().await;
    let late_up = Upstream::bind().await;
    let decoy = Upstream::bind().await; // 未授权出口替身，必须一条都收不到。
    let (quick_addr, late_addr) = (quick_up.addr, late_up.addr);
    let (seen_quick, seen_late, seen_decoy) =
        (Seen::of(&quick_up), Seen::of(&late_up), Seen::of(&decoy));
    let (gate_tx, gate_rx) = oneshot::channel();
    let handles = vec![
        tokio::spawn(answer_once(quick_up, quick.clone())),
        tokio::spawn(answer_when_gated(late_up, late.clone(), gate_rx)),
        tokio::spawn(only_count(decoy)),
    ];

    // 先让第二条交换上路：查询已发出，正等它自己的响应。
    let pending_second = tokio::spawn({
        let q = q.clone();
        async move { upstream::exchange(&q, late_addr, OPEN).await }
    });
    tokio::time::sleep(STAGGER).await;

    // 第一条交换在第二条仍在飞行时完成整个往返，随后才放行慢上游。
    let first = timeout(WAIT, upstream::exchange(&q, quick_addr, OPEN))
        .await
        .expect("第一次交换总超时")
        .expect("第一条交换应拿到自己的响应");
    let _ = gate_tx.send(());
    let second = timeout(WAIT, pending_second)
        .await
        .expect("第二次交换任务未结束")
        .expect("任务不应 panic")
        .expect("第二条交换应拿到自己的响应");

    assert_eq!(first, quick);
    assert_eq!(second, late);
    assert_ne!(
        answer_of(&first),
        answer_of(&second),
        "交错时序下两个上游给出同一个 IP：响应串了"
    );
    timeout(SETTLE, tokio::time::sleep(SETTLE)).await.ok();
    assert_eq!(seen_quick.count(), 1);
    assert_eq!(seen_late.count(), 1);
    assert_eq!(seen_decoy.count(), 0, "未授权出口收到了本不该到达的查询");

    reap(handles).await;
}

/// 问题区名字仅大小写不同（上游规范化为小写回显）：按 RFC 1035 2.3.1 视为同一
/// 名字，必须接受，不得因逐字节比较而超时。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn question_name_is_matched_case_insensitively() {
    let id = 0xABCDu16;
    let q = query(id, &["MixedCase", "Example"]);
    // 上游把回显名字规范化为小写是合法行为；其余字段逐字节都符合查询。
    let reply = response(id, &["mixedcase", "example"], [198, 51, 100, 9]);

    let up = Upstream::bind().await;
    let addr = up.addr;
    let seen_up = Seen::of(&up);
    let decoy = Upstream::bind().await;
    let seen_decoy = Seen::of(&decoy);
    let handles = vec![
        tokio::spawn(answer_once(up, reply.clone())),
        tokio::spawn(only_count(decoy)),
    ];

    let result = timeout(WAIT, upstream::exchange(&q, addr, OPEN))
        .await
        .expect("交换总超时");
    assert!(
        matches!(&result, Ok(bytes) if bytes == &reply),
        "大小写规范化回显应被接受，实际 {}",
        shape(&result)
    );
    assert_eq!(seen_up.count(), 1, "显式上游只应收到那一条查询");
    assert_eq!(seen_decoy.count(), 0, "合法名字匹配却不该碰任何其它出口");

    reap(handles).await;
}

/// 问题区 qtype 不符（A 查询遇到 AAAA 响应）：判为非预期 → 以期限错误结束，
/// 且绝不改发系统 DNS 替身或另一出口。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_question_zone_does_not_fall_back() {
    let labels = ["isolated", "example"];
    let id = 0x2222u16;
    let q = query(id, &labels);
    let mismatch = response_qtype_aaaa(id, &labels);

    let up = Upstream::bind().await;
    let addr = up.addr;
    let system = Upstream::bind().await; // 系统 DNS 替身。
    let other_egress = Upstream::bind().await; // 另一出口替身。
    let (seen_up, seen_system, seen_other) =
        (Seen::of(&up), Seen::of(&system), Seen::of(&other_egress));
    let handles = vec![
        tokio::spawn(answer_once(up, mismatch.clone())),
        tokio::spawn(only_count(system)),
        tokio::spawn(only_count(other_egress)),
    ];

    let result = timeout(WAIT, upstream::exchange(&q, addr, TIGHT))
        .await
        .expect("交换总超时");
    assert!(
        matches!(result, Err(Error::Timeout)),
        "问题区不符应只以期限错误结束，实际 {}",
        shape(&result)
    );
    timeout(SETTLE, tokio::time::sleep(SETTLE)).await.ok();
    assert_eq!(seen_up.count(), 1, "显式上游只应收到那一条查询");
    assert_eq!(seen_system.count(), 0, "失败后回退了系统 DNS 替身");
    assert_eq!(seen_other.count(), 0, "失败后回退了另一出口");

    reap(handles).await;
}

/// 非法载荷洪泛：丢弃计数触顶后以 `TooManyRejects` 收敛，不转向其它出口，
/// 也不把总期限拖长。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_flood_is_bounded_and_does_not_fall_back() {
    let labels = ["isolated", "example"];
    let id = 0x3333u16;
    let q = query(id, &labels);
    // 短于固定头部、结构上必然非法的载荷：每次都判为非预期。
    let junk = vec![0u8; 6];

    let up = Upstream::bind().await;
    let addr = up.addr;
    let system = Upstream::bind().await;
    let (seen_up, seen_system) = (Seen::of(&up), Seen::of(&system));
    let handles = vec![
        tokio::spawn(flood_invalid(up, junk, 64)),
        tokio::spawn(only_count(system)),
    ];

    let started = tokio::time::Instant::now();
    let result = timeout(WAIT, upstream::exchange(&q, addr, OPEN))
        .await
        .expect("交换总超时");
    assert!(
        matches!(result, Err(Error::TooManyRejects)),
        "洪泛应按丢弃上限收敛，实际 {}",
        shape(&result)
    );
    assert!(
        started.elapsed() < OPEN,
        "触顶后仍耗满整个期限，说明丢弃上限没有生效"
    );
    timeout(SETTLE, tokio::time::sleep(SETTLE)).await.ok();
    assert_eq!(seen_up.count(), 1);
    assert_eq!(seen_system.count(), 0, "非法洪泛之后回退了系统 DNS 替身");

    reap(handles).await;
}

/// 上游永不回应：以期限错误结束，系统 DNS 替身与另一出口都收不到任何查询。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_upstream_times_out_without_falling_back() {
    let labels = ["isolated", "example"];
    let q = query(0x4444, &labels);

    let up = Upstream::bind().await;
    let addr = up.addr;
    let system = Upstream::bind().await;
    let other_egress = Upstream::bind().await;
    let (seen_up, seen_system, seen_other) =
        (Seen::of(&up), Seen::of(&system), Seen::of(&other_egress));
    let handles = vec![
        tokio::spawn(only_count(up)),
        tokio::spawn(only_count(system)),
        tokio::spawn(only_count(other_egress)),
    ];

    let result = timeout(WAIT, upstream::exchange(&q, addr, TIGHT))
        .await
        .expect("交换总超时");
    assert!(
        matches!(result, Err(Error::Timeout)),
        "沉默上游应按期限失败，实际 {}",
        shape(&result)
    );
    timeout(SETTLE, tokio::time::sleep(SETTLE)).await.ok();
    assert_eq!(seen_up.count(), 1, "显式上游只应收到那一条查询");
    assert_eq!(seen_system.count(), 0, "超时后回退了系统 DNS 替身");
    assert_eq!(seen_other.count(), 0, "超时后回退了另一出口");

    reap(handles).await;
}

/// 查询本身非法：在发包之前拒绝，显式上游与系统 DNS 替身都收不到任何查询。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_query_reaches_no_upstream() {
    let short = vec![0u8, 1, 2];

    let up = Upstream::bind().await;
    let addr = up.addr;
    let system = Upstream::bind().await;
    let (seen_up, seen_system) = (Seen::of(&up), Seen::of(&system));
    let handles = vec![
        tokio::spawn(only_count(up)),
        tokio::spawn(only_count(system)),
    ];

    let result = timeout(WAIT, upstream::exchange(&short, addr, OPEN))
        .await
        .expect("交换总超时")
        .expect_err("非法查询必须被拒绝");
    assert!(matches!(result, Error::BadQuery(_)), "实际 {result:?}");
    // 错误只描述失败种类，不得带出域名或原始字节。
    assert!(
        !result.to_string().contains("example"),
        "错误文本泄漏了域名"
    );
    timeout(SETTLE, tokio::time::sleep(SETTLE)).await.ok();
    assert_eq!(seen_up.count(), 0, "非法查询却发往了显式上游");
    assert_eq!(seen_system.count(), 0, "非法查询却发往了系统 DNS 替身");

    reap(handles).await;
}

/// 零期限：直接拒绝，不绑定、不发送，任何替身都收不到查询。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_deadline_sends_nothing_anywhere() {
    let q = query(0x5555, &["isolated", "example"]);
    let system = Upstream::bind().await;
    let addr = system.addr;
    let seen_system = Seen::of(&system);
    let handles = vec![tokio::spawn(only_count(system))];

    let result = upstream::exchange(&q, addr, Duration::ZERO)
        .await
        .expect_err("零期限必须被拒绝");
    assert!(matches!(result, Error::InvalidDeadline), "实际 {result:?}");
    timeout(SETTLE, tokio::time::sleep(SETTLE)).await.ok();
    assert_eq!(seen_system.count(), 0, "零期限却发出了查询");

    reap(handles).await;
}
