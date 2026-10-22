//! A 组：**正常收尾后的回收**。
//!
//! 判据（A1）：一次完整往返（发请求 → 收响应 → 双方干净关闭）之后——
//!
//! 1. 上游目标必须观察到**对端 EOF**（`TargetEvent::PeerEof`）：中继在请求方向
//!    干净结束后对上游做了写半关闭（参考 `task.Close(link.Writer)`），并在回程
//!    方向结束后**关闭了整条上游连接** ⇒ 上游侧的会话资源被回收，不是泄漏。
//! 2. salt 记忆池的状态必须符合**实现的真实语义**：本仓的入站 salt 记忆池是
//!    **「时间窗内保留」**语义——salt 在 AEAD 认证通过时被记录，**连接收尾不删除**
//!    （`crate::salt_store` 的 `record` 只增不减，收尾只做「回写」）。因此
//!    正常收尾后，该连接的 salt **仍留在记忆池里**（= 不泄漏到别的连接，但
//!    **确实**仍被记住，直到时间窗过期或被容量逐出）。
//! 3. 收尾之后再开一条连接必须能正常往返 ⇒ 上一条的清理没有把共享状态搞坏。
//!
//! 判据（A2）：收尾后**再开一条连接必须能正常往返**（用**不同的 salt**；用同
//! 一个 salt 会被记忆池按设计判为重放，那是 B 组之外的另一格）。

use std::time::Duration;

use lengsuo_shadowsocks::TargetAddr;

use super::common::{
    fixed_salt_request, local_set, read_response, roundtrip, send_raw, start_relay, TempDir,
    OBSERVE, PASSWORD, SUITE, WAIT,
};
use super::probe::{
    drain_events, next_event, port_has_listener, read_raw_until_end, spawn_target,
    wait_pool_entries, Flavor, TargetEvent,
};
use super::proc::{
    assert_reclaimed, baseline, roundtrip_with_password, runtime_password, serial_guard,
    start_relay_with_password,
};

/// 记忆池的窗口取足够大（连接结束后仍能数到条目），时间窗取足够长
/// （本组只观察「连接收尾后条目是否仍在」，不观察过期逐出——那是 `salt_persist_runtime.rs`
/// 的既有覆盖）。
const POOL_CAPACITY: usize = 64;
const POOL_WINDOW: Duration = Duration::from_secs(600);

/// A1：完整往返后，上游会话被回收（上游看到 EOF），且 salt 记忆池状态符合真实语义。
#[test]
fn clean_roundtrip_reclaims_upstream_session_and_keeps_salt_pool_semantics() {
    let _guard = serial_guard();

    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let dir = TempDir::new("normal-a1");
        let state = dir.path().join("salt-state.bin");

        let mut upstream = spawn_target(Flavor::Echo).await;
        let target = TargetAddr::V4([127, 0, 0, 1], upstream.addr.port());
        let (relay, handle) = start_relay(Some((POOL_CAPACITY, POOL_WINDOW)), Some(&state)).await;

        // 固定 salt：这样才能在事后精确地问「这条连接的 salt 还在不在记忆池里」。
        let salt = [0x11u8; 32];
        let wire = fixed_salt_request(&salt, &target, b"clean-roundtrip-payload").await;
        let stream = send_raw(relay, &wire).await;
        let reply = read_response(stream).await;
        assert_eq!(
            reply,
            b"clean-roundtrip-payload".to_vec(),
            "回程应与载荷一致"
        );

        // ① 上游必须看到对端 EOF：中继在回程方向结束后**关闭了整条上游连接**
        //    ⇒ 上游侧的会话资源被回收（不是「连接还挂着没释放」）。
        assert_eq!(
            next_event(&mut upstream, WAIT).await,
            Some(TargetEvent::Accepted),
            "上游应先看到中继拨来的连接"
        );
        assert_eq!(
            next_event(&mut upstream, WAIT).await,
            Some(TargetEvent::Received(23)),
            "上游应收到请求载荷（只记长度，不记内容）"
        );
        assert_eq!(
            next_event(&mut upstream, WAIT).await,
            Some(TargetEvent::PeerEof),
            "上游必须看到对端 EOF：回程方向结束后中继应关闭整条上游连接（会话资源回收）"
        );

        // ② 记忆池状态：实现语义是「记录后按时间窗保留，连接收尾**不删除**」。
        //    因此正常收尾后，这条连接的 salt **仍**在窗口里（= 记忆池没有在收尾时
        //    误清；但也没有把 salt 泄漏成「全局已用」——同 salt 再次出现会被判重放，
        //    这正是记忆池的意义，见 B3）。
        let entries = wait_pool_entries(&state, 1, WAIT).await;
        assert_eq!(
            entries, 1,
            "正常收尾后记忆池应恰好保留本连接的 1 条 salt 记录（实现语义：按窗口保留，收尾不删）"
        );

        handle.shutdown().await.expect("中继应干净停止");
    });
}

/// A2：收尾后**再开一条连接**必须能正常往返 ⇒ 上一条的清理没把共享状态搞坏。
#[test]
fn new_connection_after_clean_close_roundtrips_normally() {
    let _guard = serial_guard();

    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let dir = TempDir::new("normal-a2");
        let state = dir.path().join("salt-state.bin");
        let mut upstream = spawn_target(Flavor::Echo).await;
        let target = TargetAddr::V4([127, 0, 0, 1], upstream.addr.port());
        let (relay, handle) = start_relay(Some((POOL_CAPACITY, POOL_WINDOW)), Some(&state)).await;

        // 第一条连接：完整往返后干净收尾。
        let first = roundtrip(relay, &target, b"first-connection").await;
        assert_eq!(first, b"first-connection".to_vec(), "第一条连接回程应一致");
        // 等上游看到 EOF（证明第一条已真正收尾，而不是还在跑）。
        let _ = next_event(&mut upstream, WAIT).await;
        let _ = next_event(&mut upstream, WAIT).await;
        assert_eq!(
            next_event(&mut upstream, WAIT).await,
            Some(TargetEvent::PeerEof),
            "第一条连接应被上游观察到 EOF"
        );

        // 第二条连接：**新的随机 salt**（本端 `TcpWriter` 每次生成新 salt）⇒
        // 不该被记忆池判重放，必须能正常往返。
        let second = roundtrip(relay, &target, b"second-connection").await;
        assert_eq!(
            second,
            b"second-connection".to_vec(),
            "第一条连接收尾后，第二条连接必须仍能正常往返"
        );

        // 记忆池此时应记着**两条** salt（两条连接各一条）——证明第二条没有被
        // 第一条的收尾误清，也没有被误当成同一条。
        let entries = wait_pool_entries(&state, 2, WAIT).await;
        assert_eq!(
            entries, 2,
            "两条连接各自记一条 salt：第一条的收尾不得把状态搞坏（也不得误清第二条）"
        );

        handle.shutdown().await.expect("中继应干净停止");
    });
}

/// A3：记忆池的**共享**语义在收尾后仍然有效——同 salt 再次出现必须被判重放
/// （=「已用」标记**确实**留在了正确的记忆池里，没有被连接收尾误清）。
#[test]
fn salt_pool_remembers_closed_connection_salt_for_replay_detection() {
    let _guard = serial_guard();

    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let dir = TempDir::new("normal-a3");
        let state = dir.path().join("salt-state.bin");
        let mut upstream = spawn_target(Flavor::Echo).await;
        let target = TargetAddr::V4([127, 0, 0, 1], upstream.addr.port());
        let (relay, handle) = start_relay(Some((POOL_CAPACITY, POOL_WINDOW)), Some(&state)).await;

        // 第一条连接用固定 salt，成功往返。
        let salt = [0x22u8; 32];
        let wire = fixed_salt_request(&salt, &target, b"first").await;
        let stream = send_raw(relay, &wire).await;
        let reply = read_response(stream).await;
        assert_eq!(reply, b"first".to_vec(), "第一条连接回程应一致");
        // 记下第一条连接在上游侧留下的全部事件。
        let first_events = drain_events(&mut upstream, OBSERVE, Duration::from_millis(200)).await;
        assert_eq!(
            first_events
                .iter()
                .filter(|event| **event == TargetEvent::Accepted)
                .count(),
            1,
            "第一条连接应在上游产生恰好一次 Accepted"
        );

        // 第二条连接用**同一个 salt** ⇒ 必须在**握手阶段**被拒（记忆池仍记得它）：
        // 上游**不会**看到第二次连接，且客户端拿不到任何回程字节。
        let wire = fixed_salt_request(&salt, &target, b"second").await;
        let stream = send_raw(relay, &wire).await;
        let got = read_raw_until_end(stream)
            .await
            .expect("重放连接应被干净关闭，而不是读出错");
        assert!(
            got.is_empty(),
            "同 salt 的重放连接不得拿到任何回程字节，实际 {got:?}"
        );
        // 上游侧：第二条连接**从未拨到上游**（没有新的 Accepted）。
        let second_events = drain_events(&mut upstream, OBSERVE, Duration::from_millis(200)).await;
        assert_eq!(
            second_events
                .iter()
                .filter(|event| **event == TargetEvent::Accepted)
                .count(),
            0,
            "重放连接必须在握手阶段被拒（不得拨号上游），实际事件：{second_events:?}"
        );

        handle.shutdown().await.expect("中继应干净停止");
    });
}

/// A4：正常收尾后，**端口**不得被 listener 占着（中继停止后端口可再 bind）。
#[test]
fn relay_stop_releases_listening_port() {
    let _guard = serial_guard();

    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let upstream = spawn_target(Flavor::Echo).await;
        let target = TargetAddr::V4([127, 0, 0, 1], upstream.addr.port());
        let (relay, handle) = start_relay(None, None).await;
        let port = relay.port();

        let reply = roundtrip(relay, &target, b"before-stop").await;
        assert_eq!(reply, b"before-stop".to_vec(), "停止前应能正常往返");

        handle.shutdown().await.expect("中继应干净停止");

        // 端口上不应再有 LISTEN 套接字（`/proc/net/tcp` 视角，仅 Linux）。
        if let Some(has_listener) = port_has_listener(port) {
            assert!(
                !has_listener,
                "中继停止后端口 {port} 上不应残留 LISTEN 套接字"
            );
        }
        // 同一端口可以重新 bind（这才是「端口没被占着」的直接证据）。
        let rebound = tokio::net::TcpListener::bind(("127.0.0.1", port)).await;
        assert!(
            rebound.is_ok(),
            "中继停止后端口 {port} 应可重新 bind：{:?}",
            rebound.err()
        );
        drop(rebound);
    });
}

/// A5：一条连接正常收尾**不能**把中继的其它能力搞坏：套件/口令不变的情况下，
/// 后续连接仍按同一套件工作（状态没有跨连接串味）。
#[test]
fn subsequent_connections_keep_same_suite_semantics() {
    let _guard = serial_guard();

    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let upstream = spawn_target(Flavor::Echo).await;
        let target = TargetAddr::V4([127, 0, 0, 1], upstream.addr.port());
        let (relay, handle) = start_relay(None, None).await;

        for index in 0..3u8 {
            let payload = format!("round-{index}").into_bytes();
            let reply = roundtrip(relay, &target, &payload).await;
            assert_eq!(reply, payload, "第 {index} 次往返应一致");
        }
        // 三次往返都成功 ⇒ 套件/口令/记忆池状态没有被前一次污染。
        assert_eq!(SUITE.salt_len(), 32, "本组固定套件的 salt 长度");
        assert!(!PASSWORD.is_empty(), "本组固定假口令非空");
        handle.shutdown().await.expect("中继应干净停止");
    });
}

/// A6：正常收尾后，客户端侧的**读任务**必须真的结束（读端拿到干净 EOF，
/// 而不是永远挂着）——这正是「不得留下未关闭的读任务」的直接断言。
#[test]
fn client_read_side_finishes_with_clean_eof_after_close() {
    let _guard = serial_guard();

    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let upstream = spawn_target(Flavor::Echo).await;
        let target = TargetAddr::V4([127, 0, 0, 1], upstream.addr.port());
        let (relay, handle) = start_relay(None, None).await;

        let reply = roundtrip(relay, &target, b"eof-check").await;
        assert_eq!(reply, b"eof-check".to_vec(), "回程应与载荷一致");
        // `read_response` 只有在 `TcpReader::recv` 返回 `Ok(None)`（干净 EOF）时
        // 才会结束；它带 `WAIT` 超时 ⇒ 读任务没挂死就是「读半确实结束了」。
        assert!(
            OBSERVE < WAIT,
            "读端超时必须显著大于观察窗口，否则「及时结束」判据没有意义"
        );
        handle.shutdown().await.expect("中继应干净停止");
    });
}

/// A7（**进程级资源回收**）：一次完整往返结束后，打开的 fd 数与线程数必须
/// **回落到基线**——这是「会话被回收」的**资源侧**证据（A1~A6 只证明了**逻辑
/// 层**的「连接结束了」，没证明「底层的 fd / 线程真的没了」）。
///
/// 判据：
///
/// 1. **基线**在「中继已启动、尚无本用例的连接」时取（`/proc/self/fd` 与
///    `/proc/self/task`）；此时基线里的 fd 就是「常驻的那些」。
/// 2. 完整往返（写请求 → 半关闭 → 读到干净 EOF）**之后**再取读数 ⇒ 差值 =
///    「这条连接残留了多少 fd / 线程」。
/// 3. fd 数 ≤ 基线（**不多于**基线 + 0），线程数 ≤ 基线（**不多于**基线 + 0）。
///    容忍度取 0 的论证见 `proc.rs` 的 [`FD_SLACK`] / [`THREAD_SLACK`]。
///
/// ⚠️ 断言在**同一进程内**、连接结束**之后**读数——不是「进程退出后当然没有
/// fd」那种无效断言。⚠️ 读数窗口由**独占锁**串行化（见本文件各用例开头的
/// `serial_guard()`），否则并行用例的 fd / 线程会污染读数 ⇒ 假红。
#[test]
fn clean_roundtrip_reclaims_process_level_file_descriptors_and_threads() {
    let _guard = serial_guard();

    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        // 运行时生成的**假口令**（与任何生产凭据无关）。
        let password = runtime_password();
        let upstream = spawn_target(Flavor::Echo).await;
        let target = TargetAddr::V4([127, 0, 0, 1], upstream.addr.port());
        let (relay, handle) = start_relay_with_password(&password).await;

        // ① 基线：中继已在跑、本用例还没建连接 ⇒ 基线里只有「常驻」的 fd。
        //    线程基线取「派发突发结束后的稳定值」（libtest 会为每个用例派发
        //    一个线程，那些线程随用例结束而退出 ⇒ 读数只减不增）。
        let base = baseline().await;

        // ② 一次完整往返：客户端读到干净 EOF ⇒ 中继的两个方向都结束 ⇒ 连接
        //    任务被 drop ⇒ socket 随之关闭。
        let reply = roundtrip_with_password(relay, &target, b"resource-probe", &password).await;
        assert_eq!(
            reply,
            b"resource-probe".to_vec(),
            "回程应与载荷一致（连接确实完整往返过）"
        );

        // ③ 连接已结束 ⇒ 资源必须回落。
        assert_reclaimed(base, "A7 正常收尾后").await;

        handle.shutdown().await.expect("中继应干净停止");
    });
}
