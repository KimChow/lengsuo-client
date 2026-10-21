// 用例组 B：半关闭（逐外层）与半关闭的逐外层判定辅助。
//
// 本文件由 `tests/transport_matrix/xray_matrix.rs` 以 `include!` 拼入该模块。

/// 半关闭（raw / tcp 档）：关写端后仍能收完 64 KiB 回程。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_tcp_half_close() {
    timeout(TOTAL, async {
        assert_half_close(Outer::Tcp).await;
    })
    .await
    .unwrap();
}

/// 半关闭（ws 档）。
///
/// 参考端的 WS 外层在收到客户端的 `Close` 帧后**拆除整个会话**（不是半关闭），
/// 故断言回程**收不到任何字节**，且业务目标仍被抵达过一次（请求已穿过外层）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_ws_half_close() {
    timeout(TOTAL, async {
        assert_half_close(Outer::Ws).await;
    })
    .await
    .unwrap();
}

/// 半关闭（httpupgrade 档）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_httpupgrade_half_close() {
    timeout(TOTAL, async {
        assert_half_close(Outer::HttpUpgrade).await;
    })
    .await
    .unwrap();
}

/// 半关闭的**逐外层**判定。
///
/// 编排：
///
/// 1. 业务目标读满请求载荷后**立刻**回写 64 KiB；
/// 2. 客户端写完头部与载荷后**关写端**（WS 发 `Close` 帧，TCP / HTTPUpgrade 发 FIN）；
/// 3. 客户端读回程。
///
/// 结论唯一确定（实测基线 v26.3.27 / commit `d2758a0`）：
///
/// - 参考端保半关闭（`tcp` / `httpupgrade`）⇒ 会话存活，回程**收满** 64 KiB；
/// - 参考端拆会话（`ws`）⇒ 会话被拆除，回程**收不满**。
///
/// 注意：业务目标**不能**用“等对端 EOF 才回写”的编排。实测（基线 v26.3.27 /
/// commit `d2758a0`）：参考端**确实**把 EOF 传播给目标连接（目标观察到 EOF），
/// 但此后**回程再也送不到客户端**——目标在观察到 EOF 后**成功写出**了全部
/// 64 KiB（`write` → `Ok(65536)`），客户端却只收到 0 字节；数据丢在参考端的
/// 转发环节，不在目标的写侧。三档外层在该编排下**都是 0 字节**，因此这种编排
/// **无法区分** `tcp`/`httpupgrade` 与 `ws`。
///
/// 因此本用例必须用“读满载荷**立刻**回写”的编排：只有回程**已经在途**时，
/// “保半关闭”（`tcp`/`httpupgrade` ⇒ 收满）与“拆会话”（`ws` ⇒ 收不到）才是
/// 可判别的。实测三档分别为 65536 / 0 / 65536 字节。
/// 本仓服务端与之不同（`server/relay.rs` 的 `copy_until_eof` 只对目标写侧
/// `shutdown`，**不**拆回程方向），该差异记在 `docs/trojan-transport.md` 的
/// 偏离清单里。
async fn assert_half_close(outer: Outer) {
    let bulk = vec![0xA5u8; REPLY_BULK_LEN];
    let identity = Identity::new();
    let target = Target::bind(bulk.clone()).await;
    let port = free_port();
    let reference = launch(server_config(port, &identity, outer), port).await;
    let outcome = run_client(&identity, port, outer, Action::HalfClose, target.port()).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let accepted = target.accepted();
    drop(reference);
    target.stop().await;

    match HalfClose::of(outer) {
        HalfClose::Preserved => {
            assert_eq!(
                outcome.reply.len(),
                REPLY_BULK_LEN,
                "{} 档参考端保半关闭：关写端后必须收满 {REPLY_BULK_LEN} 字节回程",
                outer.name()
            );
            assert!(
                outcome.reply.iter().all(|byte| *byte == 0xA5),
                "{} 档半关闭后的回程内容必须逐字节一致",
                outer.name()
            );
            assert_eq!(
                accepted,
                1,
                "{} 档半关闭必须恰好抵达业务目标一次",
                outer.name()
            );
        }
        HalfClose::SessionTornDown => {
            assert!(
                outcome.reply.len() < REPLY_BULK_LEN,
                "{} 档参考端拆会话：关写端后回程必须被截断（实收 {} 字节），\
                 若收满说明参考端在该外层上保半关闭——与实测基线不符",
                outer.name(),
                outcome.reply.len()
            );
            assert_eq!(
                accepted,
                1,
                "{} 档：请求必须已穿过外层抵达业务目标一次（会话是被关写端拆掉的，\
                 不是被拒绝的）",
                outer.name()
            );
        }
    }
}
