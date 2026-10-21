//! 「半关闭不产生悬挂任务」独立观测用例。
//!
//! ⛔ **为什么单独成一个测试二进制**：本用例断言的是**进程级**读数
//! （`/proc/self/task` 线程数、`/proc/self/fd` fd 数）。同一个测试二进制里
//! 并行跑多个用例时，libtest 会按 `--test-threads`（= CPU 核数）创建 worker
//! 线程池，同一二进制里其它用例的 `tokio` 阻塞池线程也会随时增减 ⇒ 观测窗内
//! 进程级读数随机漂移（实测在 8 / 9 / 10 / 12 / 14 之间跳），断言必然 flaky，
//! 还会让 `cargo test --workspace` 的合流门禁**随机变红**。
//!
//! 本文件**只含这一个用例** ⇒ 该二进制里 libtest 只有一个 worker 线程 ⇒
//! 观测窗内读数稳定 ⇒ 断言真正反映「本仓代码有没有留下悬挂线程/句柄」。
//!
//! 语义基线与其它异常矩阵格一致：WireGuard transport 层没有「方向关闭」概念，
//! 「A 方向结束」= A 方向不再发送数据报文（详见 `half_close_matrix/half_close.rs`
//! 的模块说明）。
#[path = "half_close_matrix/fixture.rs"]
mod fixture;

use fixture::{establish, open_fd_count, serial_guard, thread_count, SessionSpec, PAYLOAD_A};

/// 半关闭不产生悬挂任务：建立会话 + 半关闭前后，进程级线程数与 fd 数不变。
///
/// - **fd 数**（`/proc/self/fd`）：建立会话 + 半关闭前后**必须相等**——socket
///   与密钥材料都没有泄漏成常驻句柄。
/// - **线程数**（`/proc/self/task`）：本仓不创建线程，所以「建立会话」这一步
///   **不得**让线程数增加。
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
