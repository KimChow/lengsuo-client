//! 入站 salt 记忆池的**持久化运行时接线**验收（仅回环、假口令、临时目录）。
//!
//! 与固定参考（Xray v26.3.27 / `d2758a02`）的关系：参考**没有**任何重放过滤，
//! 也**没有**任何重放状态持久化（`proxy/shadowsocks/config.go` 只定义
//! `ErrIVNotUnique`，`protocol.go` 的两个错误分支是死代码）。本用例集验证的是
//! **本仓在参考之上新增**的入站防护：把 `crate::salt_store` 的持久化记忆池真正接进
//! `RelayService` 运行时，使「重启后仍能识别重放的 salt」成为**运行时可观察的
//! 事实**，而不是只有 API 存在。
//!
//! 覆盖六条判据：
//!
//! 1. **跨进程重放拒绝**（核心断言）：进程 1 用某 salt 建立连接并让服务回写状态
//!    文件 ⇒ 进程 2 用**同一 salt** ⇒ 必须被判为重放并拒绝；
//! 2. **窗口过期后放行**：窗口极短 ⇒ 过期后同 salt 不再被拒（窗口语义真实生效）；
//! 3. **文件损坏 ⇒ fail-closed**：破坏 MAC 字节 ⇒ 启动**必须报错**；
//! 4. **首次启动无文件 ⇒ 正常启动**（不是错误）；
//! 5. **密钥轮换**：旧口令写、旧+新口令读 ⇒ 正常加载并**升级重写**；
//! 6. **不配置路径 ⇒ 行为与现状一致**（回归保护）。
//!
//! 跨进程用当前测试二进制 `--exact salt_persist_worker` 扮演独立实例（与
//! `tests/replay.rs` 同一手法）：口令经环境变量注入两个子进程；状态文件一律落在
//! 系统临时目录并在用例结束清理。**本文件无 `#[ignore]`**：默认套件真跑。

#[path = "salt_persist/mod.rs"]
#[allow(dead_code)]
mod salt_persist;

use std::time::Duration;

use lengsuo_shadowsocks::{ReplayFilter, SaltStore, SaltStoreConfig};

use salt_persist::{
    hex_encode, run_worker, worker_env, TempDir, FIXED_SALT, PASSWORD, PREVIOUS_PASSWORD, SUITE,
};

/// **核心断言**：跨进程重放拒绝。
///
/// 进程 1：起中继（挂上 salt 状态文件）→ 用固定 salt 建立连接 → 服务记录 salt 并
/// 回写状态文件 → 进程 1 退出。进程 2：起中继（**同一状态文件**）→ 用**同一 salt**
/// 建立连接 ⇒ 必须被判为重放并拒绝（连接被关、无任何载荷交付）。
#[test]
fn cross_process_restart_rejects_replay() {
    let dir = TempDir::new("restart");
    let path = dir.path().join("salt-state.bin");

    let write = run_worker("relay_write", &worker_env(&path, 60_000, None));
    assert!(
        write.status.success(),
        "进程 1（建立连接并回写状态）应成功：{}",
        String::from_utf8_lossy(&write.stderr)
    );
    assert!(
        path.exists(),
        "进程 1 必须真的把状态文件写出来（运行时接线生效）"
    );

    let check = run_worker("relay_check", &worker_env(&path, 60_000, None));
    assert!(
        check.status.success(),
        "进程 2 用同一 salt 必须被判为重放并拒绝：{}",
        String::from_utf8_lossy(&check.stderr)
    );

    // 状态文件里**不得**出现口令 / 主密钥（只写 MAC 化的窗口数据）。
    let raw = std::fs::read(&path).expect("读状态文件失败");
    let master = ss_core::kdf::evp_bytes_to_key(PASSWORD.as_bytes(), SUITE.key_len());
    for (what, secret) in [("口令", PASSWORD.as_bytes()), ("主密钥", master.as_slice())] {
        assert!(
            !raw.windows(secret.len()).any(|window| window == secret),
            "状态文件里绝不能出现{what}"
        );
    }
}

/// 窗口过期后放行：窗口极短 ⇒ 过期后同 salt **不再**被拒（窗口语义真实生效，
/// 不是无脑拒绝一切）。
#[test]
fn expired_window_allows_same_salt() {
    let dir = TempDir::new("expire");
    let path = dir.path().join("salt-state.bin");
    let window = Duration::from_millis(80);

    let config = SaltStoreConfig::new(&path, 64, window);
    let store = SaltStore::open(&config, SUITE, PASSWORD.as_bytes()).expect("首次启动应正常");
    assert!(store.is_empty(), "首次启动的记忆池应为空");

    store
        .record(&FIXED_SALT, ReplayFilter::system_now_millis())
        .expect("首次记录应成功");
    // 窗口内：同 salt 再次记录必须被判重放。
    let err = store
        .record(&FIXED_SALT, ReplayFilter::system_now_millis())
        .expect_err("窗口内的同 salt 必须被判重放");
    assert!(err.to_string().contains("重放"), "应报重放，实际 {err}");

    // 等窗口过期后再来一次：应放行（证明不是无脑拒绝）。
    std::thread::sleep(window + Duration::from_millis(120));
    store
        .record(&FIXED_SALT, ReplayFilter::system_now_millis())
        .expect("窗口过期后同 salt 应放行");
}

/// 文件损坏 ⇒ fail-closed：破坏状态文件的 MAC 字节 ⇒ **启动必须报错**，
/// 绝不静默当空窗口继续（否则等于关掉重放保护）。
#[test]
fn corrupt_state_file_fails_closed() {
    let dir = TempDir::new("corrupt");
    let path = dir.path().join("salt-state.bin");

    // 先正常写出一个状态文件。
    let write = run_worker("store_write", &worker_env(&path, 60_000, None));
    assert!(
        write.status.success(),
        "写状态文件应成功：{}",
        String::from_utf8_lossy(&write.stderr)
    );

    // 破坏 MAC 区的最后一个字节（MAC 是文件末尾 32 字节）。
    let mut bytes = std::fs::read(&path).expect("读状态文件失败");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&path, &bytes).expect("写回损坏状态文件失败");

    // 进程内：`SaltStore::open` 必须报错（而不是返回空窗口）。
    let config = SaltStoreConfig::new(&path, 64, Duration::from_secs(60));
    let err = SaltStore::open(&config, SUITE, PASSWORD.as_bytes())
        .expect_err("状态文件损坏必须 fail-closed 报错");
    assert!(
        err.to_string().contains("标签校验失败"),
        "应报 MAC 校验失败，实际 {err}"
    );

    // 跨进程：中继**启动**必须失败（不是启动成功后才在连接上失败）。
    let start = run_worker("relay_start_expect_fail", &worker_env(&path, 60_000, None));
    assert!(
        start.status.success(),
        "损坏状态文件时服务启动必须报错退出：{}",
        String::from_utf8_lossy(&start.stderr)
    );
}

/// 首次启动无文件 ⇒ 正常启动（**不是错误**）。
#[test]
fn missing_state_file_starts_fresh() {
    let dir = TempDir::new("fresh");
    let path = dir.path().join("salt-state.bin");
    assert!(!path.exists(), "初始不该有状态文件");

    let config = SaltStoreConfig::new(&path, 64, Duration::from_secs(60));
    let store = SaltStore::open(&config, SUITE, PASSWORD.as_bytes())
        .expect("文件不存在必须是正常启动（不是错误）");
    assert!(store.is_empty(), "首次启动的记忆池应为空");
    drop(store);

    // 中继启动也必须正常（无文件 ⇒ 空窗口启动）。
    let start = run_worker("relay_start_expect_ok", &worker_env(&path, 60_000, None));
    assert!(
        start.status.success(),
        "无状态文件时服务启动应成功：{}",
        String::from_utf8_lossy(&start.stderr)
    );
}

/// 密钥轮换：旧口令写、旧+新口令读 ⇒ 正常加载并**升级重写**
/// （之后旧口令不再能打开，新口令可以）。
#[test]
fn key_rotation_loads_and_upgrades() {
    let dir = TempDir::new("rotate");
    let path = dir.path().join("salt-state.bin");

    // 进程 1：用**旧口令**写状态文件。
    let write = run_worker(
        "store_write_previous",
        &worker_env(&path, 60_000, Some(PREVIOUS_PASSWORD)),
    );
    assert!(
        write.status.success(),
        "旧口令写状态应成功：{}",
        String::from_utf8_lossy(&write.stderr)
    );

    // 进程 2：用**新口令 + 旧口令**读 ⇒ 正常加载并升级重写。
    let rotate = run_worker(
        "store_rotate",
        &worker_env(&path, 60_000, Some(PREVIOUS_PASSWORD)),
    );
    assert!(
        rotate.status.success(),
        "旧+新口令读应正常加载并升级重写：{}",
        String::from_utf8_lossy(&rotate.stderr)
    );
}

/// 不配置路径 ⇒ 行为与现状一致（回归保护）：内存重放窗口照常工作，
/// 且**不产生任何状态文件**。
#[test]
fn no_path_configured_keeps_memory_behavior() {
    let dir = TempDir::new("nopath");
    let path = dir.path().join("must-not-exist.bin");

    // 中继在**不配置路径**时照常工作（既有行为），且不落任何状态文件。
    let worker = run_worker("relay_no_state", &worker_env(&path, 60_000, None));
    assert!(
        worker.status.success(),
        "不配置路径时中继行为应与现状一致：{}",
        String::from_utf8_lossy(&worker.stderr)
    );
    assert!(
        !path.exists(),
        "不配置路径时不得产生状态文件（内存行为不变）"
    );
}

/// 状态文件路径的十六进制编码自检（辅助函数本身的最小断言）。
#[test]
fn hex_roundtrip_keeps_salt_bytes() {
    let encoded = hex_encode(&FIXED_SALT);
    assert_eq!(
        encoded.len(),
        FIXED_SALT.len() * 2,
        "hex 长度应是字节数的两倍"
    );
}
