// 承接自孤儿用例 `crates/ss-cli/tests/setup.rs`。
//
// 孤儿版里除 `smoke_bind_release` 外还有 `Fixture`/`tempdir`/`tmp`/`bind_ephemeral`
// 三个夹具 helper —— 它们**只**被 30 个配置用例使用，而那 30 例因无实现可承接已整体删除；
// 留着会触发 `dead_code` 告警（`cargo clippy --all-targets -- -D warnings` 会炸），
// 故此处只承接仍有用例与其 helper。

/// 等端口真正被释放（内核回收监听套接字）。
async fn wait_for_port_release(addr: std::net::SocketAddr) {
    for _ in 0..1000 {
        if std::net::TcpListener::bind(addr).is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("port {:?} still occupied after 5s", addr);
}

/// 孤儿用例逐字承接（用例名与断言完全一致）。
///
/// 偏离 D2：孤儿版带 `#[serial]`（来自 `serial_test` 依赖）。本仓 `Cargo.lock` 里**没有**
/// `serial_test` 条目，加 dev-dependency 会改动 `Cargo.lock`（本卡禁改的共享区）⇒ 去属性。
/// 本用例只绑回环临时端口（`127.0.0.1:0`），不与其它用例争端口，串行化非必需。
#[tokio::test]
async fn smoke_bind_release() {
    let l1 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l1.local_addr().unwrap();
    drop(l1);
    wait_for_port_release(addr).await;
}
