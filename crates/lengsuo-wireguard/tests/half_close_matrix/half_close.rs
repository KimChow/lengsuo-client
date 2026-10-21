//! 异常矩阵「半关闭」格：❌（只有半包拒绝）→ ✅（证明一个方向的会话结束后，
//! 另一方向仍按协议语义工作）。
//!
//! 采用的语义（**本仓实现的真实语义**，与 wireguard-go commit
//! `2631ce99a06f27120d581611cf125d68bc6aa565` 一致）：
//!
//! WireGuard 的 transport 层**没有**「方向关闭」这个概念。参考实现里
//! `device/receive.go` 的 `RoutineSequentialReceiver` 对每个数据报文只做三件事：
//! 重放窗口校验 → `ReceivedWithKeypair`（晋升 next→current）→ 投递给 TUN。
//! 数据报文走的是**同一个 keypair 的同一条 AEAD 上下文**，两个方向各用一把
//! 密钥（`t0`/`t1`），互不干扰。因此：
//!
//! - 「A 方向结束」在本仓的可观测语义 = **A 方向不再发送数据报文**（发送端
//!   停止产出报文），而**不是**「A 方向被协议层关闭」。
//! - 「B 方向是否仍可用」的判据 = B 方向的报文在 A 方向静默后**仍能通过认证
//!   解封并被投递**。
//! - 关闭方向后重放旧包 ⇒ **fail-closed**：重放窗口拒绝（`Replay`）或 AEAD
//!   认证失败，**绝不允许**被静默接受，也**绝不允许**被当作新会话。
//!
//! 换言之，本仓（与参考一致）实现的是 **「方向独立的密钥上下文 + 单向静默」**
//! 语义，**不是** TCP 式「半关闭后另一方向读到 EOF」语义。参考里唯一与
//! 「关闭」沾边的是 `peer.Stop()`：它终止收发循环并 `ZeroAndFlushAll()` 清空
//! **整个 peer** 的密钥——那是 peer 级关闭，不是方向级。
//!
//! 因此下面四条用例按上述真实语义书写，不套用 TCP 的 EOF 语义。

use super::fixture::{
    establish, open_fd_count, serial_guard, thread_count, SessionSpec, PAYLOAD_A, PAYLOAD_B,
};

/// A-1：单向结束后反向仍可用。
///
/// 步骤：建立会话 → A 方向发一条数据并被对端收到（证明会话是好的）→
/// A 方向「结束」（发送端停止产出报文，并显式进入 fail-closed 的停止态）→
/// 断言 B 方向仍能封装出合法报文、被 A 端成功认证解封并取出明文。
#[test]
fn half_close_one_direction_keeps_reverse_direction_working() {
    // 串行执行：本文件用进程级读数（线程数/fd 数）观测「无悬挂任务」，
    // 必须把并行执行的其它用例挡在观测窗外。
    let _guard = serial_guard();
    let (client, server) = establish(&SessionSpec::default());

    // 初始：A→B 方向通。
    let mut a_sender = client.sender();
    let mut b_receiver = server.receiver();
    let packet = a_sender.seal(PAYLOAD_A).expect("A 方向封装");
    let opened = b_receiver.open(&packet).expect("B 端必须能解封 A 的报文");
    assert_eq!(opened.plaintext.as_slice(), PAYLOAD_A);

    // 「A 方向结束」：发送端停止产出报文。
    //
    // 本仓 transport 层没有「方向关闭」API（参考亦然），所以「结束」的可观测
    // 定义是：**该方向的发送上下文被弃用，不再产出任何报文**。这里用
    // `Sender::poison()` 表达「该方向已停用」——它是公开的 fail-closed 入口。
    a_sender.poison();
    let stopped = a_sender.seal(PAYLOAD_A);
    assert!(stopped.is_err(), "已结束的方向不得再产出报文：{stopped:?}");

    // 判据：反方向（B→A）必须仍按协议语义工作。
    let mut b_sender = server.sender();
    let mut a_receiver = client.receiver();
    let reply = b_sender.seal(PAYLOAD_B).expect("反方向必须仍能封装");
    let opened = a_receiver.open(&reply).expect("A 端必须仍能解封 B 的报文");
    assert_eq!(
        opened.plaintext.as_slice(),
        PAYLOAD_B,
        "反方向的明文必须与发方一致"
    );
    assert_eq!(opened.counter, 0, "反方向计数器从 0 起独立推进");
}

/// A-1 的补充：方向独立性来自「两方向各用一把密钥」，不是共享上下文。
///
/// 断言 A 方向的报文**不能**用 B 方向的密钥解开——若两方向共用同一上下文，
/// 「关闭一个方向」就会连带污染另一个方向。
///
/// 判据要隔离「receiver 标识不匹配」这一结构原因：两个接收上下文都用**同一个**
/// `expected_receiver`（A 报文头里的 receiver 字段），只有密钥不同。
#[test]
fn half_close_directions_use_independent_key_contexts() {
    // 串行执行：本文件用进程级读数（线程数/fd 数）观测「无悬挂任务」，
    // 必须把并行执行的其它用例挡在观测窗外。
    let _guard = serial_guard();
    let (client, server) = establish(&SessionSpec::default());

    let mut a_sender = client.sender();
    let a_packet = a_sender.seal(PAYLOAD_A).expect("A 方向封装");
    // A 报文头的 receiver 字段 = 对端 index（B 方向的本地 index）。
    let expected_receiver = client.remote_index;

    // B 方向的**接收**密钥恰好等于 A 方向的**发送**密钥（参考
    // `BeginSymmetricSession` 的方向性 KDF2：(send, recv) vs (recv, send)），
    // 因此 B 能解开 A 的报文。
    assert_eq!(
        client.send_key, server.recv_key,
        "A 的发送密钥必须等于 B 的接收密钥"
    );
    assert_eq!(
        client.recv_key, server.send_key,
        "A 的接收密钥必须等于 B 的发送密钥"
    );
    assert_ne!(client.send_key, client.recv_key, "两方向必须用不同的密钥");

    // 用**反向**密钥（= A 的接收密钥 = B 的发送密钥）解 A 的报文 ⇒ 必须失败。
    let mut reversed = lengsuo_wireguard::transport::Receiver::new(
        lengsuo_wireguard::transport::TransportKey::new(&client.recv_key)
            .expect("接收密钥长度合法"),
        expected_receiver,
        u64::MAX,
    );
    let outcome = reversed.open(&a_packet);
    assert!(
        matches!(outcome, Err(lengsuo_wireguard::TransportError::AuthFailed)),
        "反向密钥解封 A 的报文必须认证失败（fail-closed）：{outcome:?}"
    );
    assert!(reversed.is_poisoned(), "反向密钥解封失败必须永久 poison");

    // 用**正向**密钥（B 的接收密钥）解 ⇒ 成功，且明文一致。
    let mut forward = lengsuo_wireguard::transport::Receiver::new(
        lengsuo_wireguard::transport::TransportKey::new(&server.recv_key)
            .expect("接收密钥长度合法"),
        expected_receiver,
        u64::MAX,
    );
    let opened = forward.open(&a_packet).expect("正向密钥解封必须成功");
    assert_eq!(opened.plaintext.as_slice(), PAYLOAD_A);
}

/// A-2：半关闭后旧包不得被接受为新会话。
///
/// 三种「旧包」都要 fail-closed：
/// 1. **完全重放**（同一计数器、同一密文）⇒ 重放窗口拒绝（`Replay`），不改变
///    窗口状态、不 poison；
/// 2. **篡改**（改密文末字节）⇒ AEAD 认证失败，永久 poison；
/// 3. **换会话重放**（新会话建立后拿旧会话的密文来用）⇒ 认证失败，因为会话
///    密钥已经重新协商。
#[test]
fn half_close_rejects_stale_packets_fail_closed() {
    // 串行执行：本文件用进程级读数（线程数/fd 数）观测「无悬挂任务」，
    // 必须把并行执行的其它用例挡在观测窗外。
    let _guard = serial_guard();
    let (client, server) = establish(&SessionSpec::default());

    let mut a_sender = client.sender();
    let mut b_receiver = server.receiver();
    let good = a_sender.seal(PAYLOAD_A).expect("A 方向封装");

    // 首次收：成功。
    let opened = b_receiver.open(&good).expect("首次收必须成功");
    assert_eq!(opened.plaintext.as_slice(), PAYLOAD_A);
    let highest_before = b_receiver.highest();

    // (1) 完全重放：重放窗口必须拒绝。
    let replay = b_receiver.open(&good);
    assert!(replay.is_err(), "重放旧包必须被拒绝：{replay:?}");
    assert!(
        matches!(replay, Err(lengsuo_wireguard::TransportError::Replay(_))),
        "重放必须是重放窗口拒绝（不是认证失败）：{replay:?}"
    );
    assert!(
        !b_receiver.is_poisoned(),
        "重放拒绝只丢包，不得 poison 接收端"
    );
    assert_eq!(
        b_receiver.highest(),
        highest_before,
        "重放拒绝不得改变重放窗口状态"
    );

    // (2) 篡改旧包：AEAD 认证失败并永久 poison。
    let mut tampered = good.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let mut strict = server.receiver();
    let outcome = strict.open(&tampered);
    assert!(
        matches!(outcome, Err(lengsuo_wireguard::TransportError::AuthFailed)),
        "篡改旧包必须报认证失败：{outcome:?}"
    );
    assert!(strict.is_poisoned(), "AEAD 失败必须永久 poison");
    // poison 后不得再产出明文。
    let after = strict.open(&good);
    assert!(after.is_err(), "poison 之后不得再解封任何报文：{after:?}");

    // (3) 换会话重放：旧会话的密文在新会话里不可用。
    let spec = SessionSpec {
        client_ephemeral: super::fixture::CLIENT_EPHEMERAL_ALT,
        ..SessionSpec::default()
    };
    let (client2, server2) = establish(&spec);
    assert_ne!(
        client2.send_key, client.send_key,
        "新会话必须重新协商出不同的发送密钥"
    );
    let mut new_receiver = server2.receiver();
    let outcome = new_receiver.open(&good);
    assert!(
        matches!(outcome, Err(lengsuo_wireguard::TransportError::AuthFailed)),
        "旧会话的密文在新会话里必须认证失败：{outcome:?}"
    );
    assert!(
        new_receiver.is_poisoned(),
        "换会话重放必须 poison，绝不静默接受"
    );
}

/// A-3：半关闭不产生悬挂任务。
///
/// 本仓 `lengsuo-wireguard` 的**已编译**源码里没有任何 `std::thread`、
/// `tokio::spawn` 或 `async fn`（`src/device.rs` 未被 `lib.rs` 挂载，不参与
/// 编译），所以「关闭后残留读循环」在实现上不可能发生。本用例用两个可观测点
/// 证明这一点，而不是凭空断言：
///
/// - **fd 数**（`/proc/self/fd`）：建立会话 + 半关闭前后**必须相等**——socket
///   与密钥材料都没有泄漏成常驻句柄。
/// - **线程数**（`/proc/self/task`）：本仓不创建线程，所以「建立会话」这一步
///   **不得**让线程数增加。注意不能用「前后绝对值相等」来判：Rust 测试
///   harness 自身按并行度创建 worker 线程，与本用例无关，且会让绝对值漂移。
///   正确判据是**自参照**——把「建立会话」当作基线，断言它没有增加线程数。
///
/// 若某平台没有这两个可观测点，断言退化为「跳过」而不是伪造通过。
#[test]
fn half_close_leaves_no_pending_tasks() {
    // 串行执行：本文件用进程级读数（线程数/fd 数）观测「无悬挂任务」，
    // 必须把并行执行的其它用例挡在观测窗外。
    let _guard = serial_guard();

    // 基线：本仓的任何会话建立动作都不得创建线程。
    let threads_baseline = thread_count();
    let fds_baseline = open_fd_count();

    let (client, server) = establish(&SessionSpec::default());
    let mut a_sender = client.sender();
    let mut b_receiver = server.receiver();
    let packet = a_sender.seal(PAYLOAD_A).expect("封装");
    b_receiver.open(&packet).expect("解封");

    // 半关闭：A 方向停止产出报文。
    a_sender.poison();
    assert!(
        a_sender.seal(PAYLOAD_A).is_err(),
        "已结束方向不得再产出报文"
    );

    // 建立会话 + 半关闭**不得**新增线程（自参照判据）。
    if let (Some(baseline), Some(after)) = (threads_baseline, thread_count()) {
        assert_eq!(
            baseline, after,
            "建立会话与半关闭不得创建任何线程（不得残留读循环/后台任务）"
        );
    } else {
        eprintln!("[half_close] 本平台无 /proc/self/task 观测点，线程数断言跳过");
    }

    // 会话材料析构后，fd 数必须回到基线。
    drop((client, server, b_receiver));
    match (fds_baseline, open_fd_count()) {
        (Some(baseline), Some(after)) => assert_eq!(
            baseline, after,
            "半关闭前后打开的 fd 数必须不变（socket 不得泄漏）"
        ),
        _ => {
            eprintln!("[half_close] 本平台无 /proc/self/fd 观测点，fd 数断言跳过");
        }
    }
}
