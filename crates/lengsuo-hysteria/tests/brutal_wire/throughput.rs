// 实跑吞吐取证（`#[ignore]`）：协商速率对上传吞吐的限速效果与 CUBIC 对照。
/// 实跑 1：协商 256 KiB/s，客户端上传吞吐被 Brutal 限住；同场景 CUBIC
/// 对照必须突破上界（证明限速来自注入的 Brutal，而非装置本身）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "实跑吞吐取证，需 --ignored"]
async fn brutal_limits_client_upload() {
    const NEGOTIATED: u64 = 256 * 1024;
    let brutal = measure("brutal-up", NEGOTIATED, "brutal").await;
    assert_eq!(brutal.got, RESPONSE_BYTES, "回程未收齐，测量无效");
    in_band("brutal", upload_rate(&brutal), NEGOTIATED as f64);

    let cubic = measure("cubic-up", NEGOTIATED, "").await;
    assert_eq!(cubic.got, RESPONSE_BYTES, "回程未收齐，测量无效");
    let cubic_rate = upload_rate(&cubic);
    assert!(
        cubic_rate > 3.0 * NEGOTIATED as f64,
        "CUBIC 对照未被限速（{cubic_rate:.0} B/s ≤ 3x 协商值），无法证明 Brutal 生效"
    );
    eprintln!("[对照 cubic] 实测 {cubic_rate:.0} B/s（未注入 Brutal）");
}

/// 实跑 2：协商 2 MiB/s，验证限速随协商值缩放（而非固定常量）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "实跑吞吐取证，需 --ignored"]
async fn brutal_rate_follows_negotiation() {
    const NEGOTIATED: u64 = 2 * 1024 * 1024;
    let run = measure("brutal-2m", NEGOTIATED, "brutal").await;
    assert_eq!(run.got, RESPONSE_BYTES, "回程未收齐，测量无效");
    in_band("brutal-2m", upload_rate(&run), NEGOTIATED as f64);
}
