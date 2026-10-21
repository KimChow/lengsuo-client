//! 异常矩阵「**清理**」格的 REALITY 收尾**幂等**部分。
//!
//! 与 `cleanup/mod.rs` 同属「清理」格，但单独成文件（按职责拆分，控制在
//! 400 行软目标内）。本文件守的判据是**幂等**本身，不是「不崩就行」。
//!
//! ## 已修缺陷（本卡修掉的）
//!
//! 修前：`src/reality_link.rs` 的 `shutdown()` 对裸字段 `writer_task` 做
//! `(&mut self.writer_task).await`，而 `close()` 又先调 `shutdown()` ⇒
//! `writer_task` 被**二次** await，tokio 直接 panic：
//! `JoinHandle polled after completion`（tokio 1.53
//! `runtime/task/core.rs:427`）。⇒ `shutdown()` 与 `close()` **都不幂等**。
//!
//! 修法：写任务句柄改成 `Option<JoinHandle<()>>`，`take()` 之后即「已收走」
//! ⇒ 重复调用不再 await 同一个句柄。**幂等靠状态（`Option::take`），不靠
//! 吞 panic**（没有 `catch_unwind`）。
//!
//! ## 幂等判据（**显式断言**，不是「不崩就行」）
//!
//! 用 [`RealityStream::pending_tasks`] 观测「尚未收走的后台任务数」：
//! 新建 = `2`（写 + 读）；第一次 `shutdown()` 后 = `1`（写已收走，**读仍在**）；
//! 第一次 `close()` 后 = `0`。**重复调用不得再改变该计数**——这正是
//! 「不再重复等待同一个任务」的可观测证据。

use std::time::Duration;

use tokio::time::timeout;

use super::super::{reality_fixture, DEADLINE};

/// 单次收尾操作的观察上限（挂住即失败，不被内部超时掩盖）。
const JOIN_LIMIT: Duration = Duration::from_secs(8);

/// **1. 重复 `shutdown()` 幂等。**
///
/// 断言点：
/// - 第一次 `shutdown()` 返回 `Ok`；
/// - 第一次之后 `pending_tasks() == 1`（写任务已收走，读任务**仍在**——
///   `shutdown()` 只关写方向，不收读任务）；
/// - 第二次及以后的 `shutdown()` **不 panic**、**在有限时间内**返回、
///   `pending_tasks()` **保持 1 不变**（⇒ 没有重复等待写任务）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_shutdown_is_idempotent() {
    timeout(DEADLINE, async {
        let server = reality_fixture::start_server().await;
        let config = reality_fixture::client_config();
        let mut client = reality_fixture::connect(&format!("127.0.0.1:{}", server.port), &config)
            .await
            .expect("REALITY 建流");

        // 新建流：写任务 + 读任务都待收。
        assert_eq!(
            client.pending_tasks(),
            2,
            "新建流必须有两个待收的后台任务（写 + 读）"
        );

        // 第一次 shutdown：正常关闭写方向并等写任务收尾。
        timeout(JOIN_LIMIT, client.shutdown())
            .await
            .expect("第一次 shutdown 挂住")
            .expect("第一次 shutdown 应当成功");
        assert_eq!(
            client.pending_tasks(),
            1,
            "第一次 shutdown 后只剩读任务待收（写任务必须已被收走）"
        );

        // 重复 shutdown：不得 panic、不得挂住、不得再收走任何任务。
        for round in 2..=3 {
            let outcome = timeout(JOIN_LIMIT, client.shutdown())
                .await
                .unwrap_or_else(|_| panic!("第 {round} 次 shutdown 挂住"));
            assert!(
                outcome.is_ok(),
                "第 {round} 次 shutdown 必须返回 Ok（幂等），实际：{outcome:?}"
            );
            assert_eq!(
                client.pending_tasks(),
                1,
                "第 {round} 次 shutdown 不得再收走任何任务（幂等）"
            );
        }
    })
    .await
    .expect("用例总超时");
}

/// **2. 重复 `close()` 幂等。**
///
/// 断言点：
/// - 第一次 `close()` 在有限时间内返回；
/// - 第一次之后 `pending_tasks() == 0`（写、读任务都被收走）；
/// - 第二次及以后的 `close()` **不 panic**、**立即返回**、
///   `pending_tasks()` **保持 0**（⇒ 没有重复等待读任务）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_close_is_idempotent() {
    timeout(DEADLINE, async {
        let server = reality_fixture::start_server().await;
        let config = reality_fixture::client_config();
        let mut client = reality_fixture::connect(&format!("127.0.0.1:{}", server.port), &config)
            .await
            .expect("REALITY 建流");

        assert_eq!(client.pending_tasks(), 2, "新建流必须有两个待收的后台任务");

        // 第一次 close：正常收尾。
        timeout(JOIN_LIMIT, client.close())
            .await
            .expect("第一次 close 挂住");
        assert_eq!(
            client.pending_tasks(),
            0,
            "第一次 close 后不得有任何待收任务（写 + 读都被收走）"
        );

        // 重复 close：不得 panic、不得挂住、不得改变计数。
        for round in 2..=3 {
            timeout(JOIN_LIMIT, client.close())
                .await
                .unwrap_or_else(|_| panic!("第 {round} 次 close 挂住"));
            assert_eq!(
                client.pending_tasks(),
                0,
                "第 {round} 次 close 不得再收走任何任务（幂等）"
            );
        }
    })
    .await
    .expect("用例总超时");
}

/// **3. `shutdown()` 之后再 `close()`：不 panic，且 `close()` 仍收完读任务。**
///
/// 这是修掉的缺陷的**直接复现路径**（修前：二次 await 同一个 `JoinHandle`
/// ⇒ tokio panic `JoinHandle polled after completion`）。用例名沿用原
/// 「已知缺陷取证」用例的判据（`shutdown()` → `close()`），只把**断言方向**
/// 从「实况是 panic」翻成「幂等、不 panic」。
///
/// 断言点：
/// - `shutdown()` 之后 `pending_tasks() == 1`（读任务**仍在**）；
/// - 随后的 `close()` **不 panic**、在有限时间内返回；
/// - `close()` 之后 `pending_tasks() == 0` ⇒ **`close()` 仍把 `reader_task`
///   收完了**（不是被 `shutdown()` 顺带收走的，也不是被跳过的）。
///
/// 收尾动作放进**独立任务**里观测：万一实现回归成 panic，panic 只杀掉那个
/// 任务（表现为 `JoinError`），不会把整个用例二进制带崩；`JoinError` 本身
/// 即「幂等被破坏」的失败信号。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reality_stream_shutdown_then_close_is_idempotent() {
    timeout(DEADLINE, async {
        let server = reality_fixture::start_server().await;
        let config = reality_fixture::client_config();
        let mut client = reality_fixture::connect(&format!("127.0.0.1:{}", server.port), &config)
            .await
            .expect("REALITY 建流");

        // 后续收尾（shutdown → close → close）放到**独立任务**里观测：万一
        // 实现回归成 panic，panic 只杀掉那个任务（表现为 `JoinError`），不会
        // 把整个用例二进制带崩；`JoinError` 本身即「幂等被破坏」的失败信号。
        // 断言顺序：**先**判「不 panic」（本卡的主判据），**再**判计数。
        let outcome = tokio::spawn(async move {
            // 第一次收尾：只关写方向（读任务仍在）。
            client.shutdown().await.expect("第一次 shutdown");
            let after_shutdown = client.pending_tasks();
            // 第二次收尾：close()。修前此处 panic（tokio: JoinHandle polled
            // after completion）。
            client.close().await;
            let after_first_close = client.pending_tasks();
            // 第三次：再 close 一次也不得 panic。
            client.close().await;
            (after_shutdown, after_first_close, client.pending_tasks())
        })
        .await;
        let (after_shutdown, after_first_close, after_second_close) = outcome.expect(
            "shutdown 之后 close 不得 panic（修前是 tokio: JoinHandle polled after completion）",
        );
        assert_eq!(
            after_shutdown, 1,
            "shutdown 之后读任务必须仍在（关写方向不收读任务）"
        );
        assert_eq!(
            after_first_close, 0,
            "close 之后读任务必须已被收走（pending_tasks 归零）"
        );
        assert_eq!(after_second_close, 0, "重复 close 后计数保持 0（幂等）");
    })
    .await
    .expect("用例总超时");
}
