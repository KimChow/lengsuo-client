//! salt 持久化的**子进程 worker**：扮演跨进程语义的独立实例（进程 A / 进程 B）。
//!
//! 结果一律用**退出码**承载（不靠 stdout 解析）；`LENGSUO_SALT_WORKER` 未设置时
//! 执行一次真实的写→读往返自检（避免零用例空跑）。

use std::time::Duration;

use lengsuo_shadowsocks::{
    RelayConfig, RelayConfigParts, RelayService, SaltStore, SaltStoreConfig, TargetAddr,
};

use super::{
    ctx_from_env, exchange, fixed_salt_stream, local_set, relay_config, spawn_echo, TempDir,
    FIXED_SALT, PASSWORD, SUITE,
};

/// 子进程 worker。未设 `LENGSUO_SALT_WORKER` 时做一次写→读往返自检。
#[test]
fn salt_persist_worker() {
    let Ok(mode) = std::env::var("LENGSUO_SALT_WORKER") else {
        let dir = TempDir::new("worker-selfcheck");
        let path = dir.path().join("self.bin");
        let config = SaltStoreConfig::new(&path, 8, Duration::from_secs(60));
        let store = SaltStore::open(&config, SUITE, PASSWORD.as_bytes()).expect("自检开库");
        store
            .record(
                &FIXED_SALT,
                lengsuo_shadowsocks::ReplayFilter::system_now_millis(),
            )
            .expect("自检记录");
        store.flush().expect("自检回写");
        drop(store);
        let reopened = SaltStore::open(&config, SUITE, PASSWORD.as_bytes()).expect("自检重开");
        assert_eq!(reopened.len(), 1, "自检往返应记住一个 salt");
        return;
    };

    let ctx = ctx_from_env();
    match mode.as_str() {
        // 进程 A：用**旧口令**写状态文件（供密钥轮换用例的前置）。
        "store_write_previous" => {
            let key_password = ctx.previous.expect("缺少上一代口令");
            let config = SaltStoreConfig::new(&ctx.path, 64, Duration::from_millis(ctx.window_ms));
            let store =
                SaltStore::open(&config, SUITE, key_password.as_bytes()).expect("旧口令开库");
            store
                .record(
                    &ctx.salt,
                    lengsuo_shadowsocks::ReplayFilter::system_now_millis(),
                )
                .expect("记录 salt");
            store.flush().expect("回写状态");
            std::process::exit(0);
        }
        // 进程 B（轮换）：新口令 + 旧口令读 ⇒ 加载成功、salt 仍在窗内、
        // 且文件已被**升级重写**为新口令的 MAC（旧口令此后不再可用）。
        "store_rotate" => {
            let previous = ctx.previous.expect("缺少上一代口令");
            let config = SaltStoreConfig::new(&ctx.path, 64, Duration::from_millis(ctx.window_ms))
                .with_previous_password(previous.as_bytes().to_vec());
            let store = SaltStore::open(&config, SUITE, ctx.password.as_bytes()).expect("轮换开库");
            assert_eq!(store.len(), 1, "轮换加载后应记住旧文件里的 salt");
            let err = store
                .record(
                    &ctx.salt,
                    lengsuo_shadowsocks::ReplayFilter::system_now_millis(),
                )
                .expect_err("轮换后同 salt 必须仍被判重放");
            assert!(err.to_string().contains("重放"), "应报重放，实际 {err}");
            drop(store);

            // 升级重写已生效：新口令能打开，旧口令打不开（MAC 不符）。
            let fresh = SaltStoreConfig::new(&ctx.path, 64, Duration::from_millis(ctx.window_ms));
            let reopened =
                SaltStore::open(&fresh, SUITE, ctx.password.as_bytes()).expect("新口令应能打开");
            assert_eq!(reopened.len(), 1, "升级重写后 salt 应仍在");
            let stale = SaltStoreConfig::new(&ctx.path, 64, Duration::from_millis(ctx.window_ms));
            let err = SaltStore::open(&stale, SUITE, previous.as_bytes())
                .expect_err("升级重写后旧口令必须失效");
            assert!(
                err.to_string().contains("标签校验失败"),
                "旧口令应报 MAC 校验失败，实际 {err}"
            );
            std::process::exit(0);
        }
        // 用当前口令写状态文件。
        "store_write" => {
            let config = SaltStoreConfig::new(&ctx.path, 64, Duration::from_millis(ctx.window_ms));
            let store = SaltStore::open(&config, SUITE, ctx.password.as_bytes()).expect("开库");
            store
                .record(
                    &ctx.salt,
                    lengsuo_shadowsocks::ReplayFilter::system_now_millis(),
                )
                .expect("记录 salt");
            store.flush().expect("回写状态");
            std::process::exit(0);
        }
        // 进程 A：中继建立连接（固定 salt）并让服务回写状态文件。
        "relay_write" => {
            let runtime = local_set();
            let local = tokio::task::LocalSet::new();
            local.block_on(&runtime, async {
                let echo = spawn_echo().await;
                let target = TargetAddr::V4([127, 0, 0, 1], echo.port());
                let service = RelayService::bind(
                    std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)),
                    relay_config(&ctx.path, ctx.window_ms),
                )
                .await
                .expect("中继绑定");
                let addr = service.local_addr().expect("中继地址");
                let handle = service.start().await.expect("中继启动");
                let wire = fixed_salt_stream(&ctx.salt, &target, b"first-process-payload").await;
                let got = exchange(addr, &wire).await;
                assert!(got.is_ok(), "进程 1 的连接应成功：{got:?}");
                handle.shutdown().await.expect("中继停止");
                assert!(ctx.path.exists(), "进程 1 必须写出状态文件");
            });
            std::process::exit(0);
        }
        // 进程 B：同一状态文件 + 同一 salt ⇒ 必须被判重放并拒绝；
        // **不同 salt** 必须照常放行（负控制组）。
        "relay_check" => {
            let runtime = local_set();
            let local = tokio::task::LocalSet::new();
            local.block_on(&runtime, async {
                let echo = spawn_echo().await;
                let target = TargetAddr::V4([127, 0, 0, 1], echo.port());
                let service = RelayService::bind(
                    std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)),
                    relay_config(&ctx.path, ctx.window_ms),
                )
                .await
                .expect("中继绑定");
                let addr = service.local_addr().expect("中继地址");
                let handle = service.start().await.expect("中继启动");
                let wire = fixed_salt_stream(&ctx.salt, &target, b"replayed-payload").await;
                let got = exchange(addr, &wire).await;
                assert!(
                    got.is_err(),
                    "进程 2 用同一 salt 必须被拒（实际交付了字节：{got:?}）"
                );
                // 负控制组：**不同 salt** 必须照常放行 —— 证明拒绝是针对这个 salt
                // 的记忆，不是「服务整体坏了」。
                let fresh_salt = [0x3Cu8; 32];
                let fresh = fixed_salt_stream(&fresh_salt, &target, b"fresh-payload").await;
                let got = exchange(addr, &fresh).await;
                assert!(got.is_ok(), "不同 salt 必须放行（负控制组），实际 {got:?}");
                handle.shutdown().await.expect("中继停止");
            });
            std::process::exit(0);
        }
        // 状态文件损坏 ⇒ 中继**启动**必须失败。
        "relay_start_expect_fail" => {
            let runtime = local_set();
            let local = tokio::task::LocalSet::new();
            local.block_on(&runtime, async {
                let service = RelayService::bind(
                    std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)),
                    relay_config(&ctx.path, ctx.window_ms),
                )
                .await
                .expect("中继绑定");
                let err = service
                    .start()
                    .await
                    .err()
                    .expect("状态文件损坏时启动必须失败");
                assert!(
                    err.to_string().contains("salt 记忆池持久化失败"),
                    "应报 salt 记忆池持久化失败，实际 {err}"
                );
            });
            std::process::exit(0);
        }
        // 无状态文件 ⇒ 中继启动必须成功。
        "relay_start_expect_ok" => {
            let runtime = local_set();
            let local = tokio::task::LocalSet::new();
            local.block_on(&runtime, async {
                let service = RelayService::bind(
                    std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)),
                    relay_config(&ctx.path, ctx.window_ms),
                )
                .await
                .expect("中继绑定");
                let handle = service.start().await.expect("无状态文件时启动必须成功");
                handle.shutdown().await.expect("中继停止");
            });
            std::process::exit(0);
        }
        // 不配置路径 ⇒ 内存行为与现状一致（同一 salt 第二次仍被拒，且不落盘）。
        "relay_no_state" => {
            let runtime = local_set();
            let local = tokio::task::LocalSet::new();
            local.block_on(&runtime, async {
                let echo = spawn_echo().await;
                let target = TargetAddr::V4([127, 0, 0, 1], echo.port());
                let config = RelayConfig::new(
                    RelayConfigParts {
                        suite: SUITE,
                        idle_timeout: Duration::from_secs(5),
                        replay: Some((64, Duration::from_millis(ctx.window_ms))),
                    },
                    ctx.password.as_bytes(),
                );
                let service = RelayService::bind(
                    std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)),
                    config,
                )
                .await
                .expect("中继绑定");
                let addr = service.local_addr().expect("中继地址");
                let handle = service.start().await.expect("中继启动");
                let wire = fixed_salt_stream(&ctx.salt, &target, b"memory-only-payload").await;
                assert!(exchange(addr, &wire).await.is_ok(), "首次连接应成功");
                let again = fixed_salt_stream(&ctx.salt, &target, b"memory-only-payload").await;
                assert!(
                    exchange(addr, &again).await.is_err(),
                    "内存重放窗口照常拒绝同 salt 的第二次连接"
                );
                handle.shutdown().await.expect("中继停止");
            });
            std::process::exit(0);
        }
        other => {
            eprintln!("未知 worker 模式 {other}");
            std::process::exit(1);
        }
    }
}
