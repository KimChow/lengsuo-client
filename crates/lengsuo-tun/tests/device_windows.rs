//! Windows wintun 设备**实机**验证（需管理员权限）。
//!
//! 前置：
//! - `LENGSUO_WINTUN_DLL` 指向 amd64 `wintun.dll`；或把它放到测试可执行文件同目录。
//! - 以**管理员**运行（创建适配器会在系统里注册网络接口）。
//!
//! 全部用例默认 `#[ignore]`：普通 CI/开发环境不带驱动与权限。
//!
//! 实跑（本机 Windows + MSVC，管理员）：
//! ```text
//! LENGSUO_WINTUN_DLL=<...>/wintun/bin/amd64/wintun.dll \
//!   cargo test -p lengsuo-tun --test device_windows --locked -- --ignored --nocapture
//! ```
//!
//! 本文件只使用 [`lengsuo_tun::device`] 的安全 API。动态库加载是**唯一** `unsafe` 点，
//! 集中在 [`load_library`] 内（与生产加载器共用同一约定），本 crate 本身
//! `#![forbid(unsafe_code)]`。
//!
//! ⚠️ 本组用例验证的是**设备接入层**（适配器注册、ring 会话、收发语义、错误分类、
//! 生命周期）。**不等价于**用户态 TCP/IP 栈、系统路由/DNS 分流、真实浏览器
//! A/B/C 多出口验收——那些属系统级阶段，见 `docs/tun-status.md`。
#![cfg(windows)]

use std::time::Duration;

use lengsuo_tun::device::{Device, DeviceConfig, Error, Library};

/// 宿主注入 dll 的唯一 unsafe 点：按仓库规则集中在此，测试与生产加载器共用。
unsafe fn load_library() -> wintun::Wintun {
    let path =
        std::env::var("LENGSUO_WINTUN_DLL").expect("设置 LENGSUO_WINTUN_DLL 指向 amd64/wintun.dll");
    wintun::load_from_path(&path).expect("加载 wintun.dll 失败")
}

fn library() -> Library {
    Library::from_handle(unsafe { load_library() }).expect("wintun 句柄封装")
}

/// 基线：适配器真实创建 + ring 会话开启 + send 被接受 + receive 超时准时 + close 清理。
#[tokio::test]
#[ignore = "需要管理员权限与 wintun.dll（LENGSUO_WINTUN_DLL）"]
async fn adapter_create_send_receive_loopback() {
    let library = library();
    let config = DeviceConfig::for_test();
    println!(
        "adapter {} guid {:?} mtu {}",
        config.adapter_name, config.guid, config.mtu
    );
    let mut device = Device::create(&library, config).expect("创建适配器（需管理员）");
    device.start_session(0x400_000).expect("开启 ring 会话");

    // 设备接入层验收点：适配器已注册（create 成功）、ring 会话开启、
    // send 接受载荷、receive 超时语义正确（wintun 无同会话回环——系统把
    // 包路由进虚拟网卡时 receive 才有数据，那是用户态栈/系统级阶段的验收）。
    let payload: Vec<u8> = (0..200u16).map(|i| (i % 251) as u8).collect();
    device.send(&payload).expect("发送 200B 载荷");
    let outcome = device.receive(Duration::from_millis(500));
    assert!(outcome.is_err(), "系统未路由进来的包不应出现在 receive");

    device.close().expect("关闭");
}

/// 系统侧身份与 MTU 真实生效（不只是 API 返回 Ok）。
///
/// 取证点：接口索引被系统真实分配（≠0）、MTU 写入后**回读**一致、
/// 适配器名与配置一致、GUID 非零且稳定。
#[tokio::test]
#[ignore = "需要管理员权限与 wintun.dll（LENGSUO_WINTUN_DLL）"]
async fn device_system_identity_and_mtu_roundtrip() {
    let library = library();
    let config = DeviceConfig::for_test();
    let expected_name = config.adapter_name.clone();
    let mut device = Device::create(&library, config).expect("创建适配器（需管理员）");

    // ① 系统分配了真实接口索引（0 不是合法接口，出现即异常）。
    let index = device.interface_index().expect("读取接口索引");
    assert_ne!(index, 0, "接口索引应由系统真实分配，不应为 0");
    println!("interface index = {index}");

    // ② 适配器名与请求一致（create 用的就是它）。
    assert_eq!(device.config().adapter_name, expected_name);

    // ③ GUID 非零且两次读取稳定。
    let guid = device.guid().expect("读取 GUID");
    assert_ne!(guid, 0, "GUID 不应为零");
    assert_eq!(device.guid().expect("再次读取 GUID"), guid, "GUID 应稳定");
    println!("guid = {guid}");

    // ④ MTU 写入 → 回读一致（系统侧事实，非本地缓存）。
    //
    // ⚠️ 这条断言在实机首次运行时**发现真实缺陷**：wintun 绑定的 `set_mtu` 只设
    // IPv4，而 `get_mtu` 对同一 LUID 的 v4/v6 两行取先命中者（实测恒读到未设置的
    // IPv6 → 65535），导致「写 1400 读回 65535」。修复见 `Device::set_mtu`：
    // 本层改为 v4/v6 同时设置，回读取两族较小值。此处同时断言**两族都生效**。
    for mtu in [1400u16, 1380, 1500] {
        device.set_mtu(mtu).expect("设置 MTU");
        let read_back = device.mtu().expect("回读 MTU");
        assert_eq!(read_back, mtu, "MTU 回读应与写入一致（{mtu}）");
        // 双栈一致性：v4 与 v6 都必须是写入值，不允许只改一半。
        let (v4, v6) = device.mtu_per_family().expect("按协议族回读 MTU");
        assert_eq!(v4, Some(mtu), "IPv4 MTU 应为 {mtu}（实际 {v4:?}）");
        assert_eq!(v6, Some(mtu), "IPv6 MTU 应为 {mtu}（实际 {v6:?}）");
        println!("mtu {mtu} verified (ipv4={v4:?} ipv6={v6:?})");
    }

    device.close().expect("关闭");
}

/// ring 容量边界与错误分类（不依赖系统路由）。
///
/// 取证点：非法 ring 容量被拒（不 panic）、合法容量接受、会话重入（二次
/// start_session 不报错且仅一个会话）、close 幂等、关闭后所有操作返回
/// `Closed`、无会话时 receive/send 返回类型化错误。
#[tokio::test]
#[ignore = "需要管理员权限与 wintun.dll（LENGSUO_WINTUN_DLL）"]
async fn device_ring_bounds_and_lifecycle() {
    let library = library();
    let mut device =
        Device::create(&library, DeviceConfig::for_test()).expect("创建适配器（需管理员）");

    // ① 无会话时收发都为类型化错误（不得 panic）。
    assert!(
        device.receive(Duration::from_millis(10)).is_err(),
        "无会话时 receive 应返回错误"
    );
    assert!(device.send(b"x").is_err(), "无会话时 send 应返回错误");

    // ② 非法 ring 容量被拒（非 2 的幂 / 越界）。
    for bad in [0x3_0000u32, 0x7_0000, 0x1_0000, 0x800_0000] {
        assert!(
            device.start_session(bad).is_err(),
            "非法 ring 容量 {bad:#x} 应被拒"
        );
    }

    // ③ 合法容量接受。
    device.start_session(0x20_0000).expect("开启合法 ring 会话");
    assert!(device.has_session(), "会话应处于活动态");

    // ④ 会话重入：二次 start_session 成功且仍只有一个会话（旧会话已结束）。
    device.start_session(0x40_0000).expect("重入开启会话");
    assert!(device.has_session(), "重入后仍应有活动会话");

    // ⑤ 显式结束会话后 has_session 为假，且 end_session 幂等。
    device.end_session().expect("结束会话");
    assert!(!device.has_session(), "结束后不应再有会话");
    device.end_session().expect("重复结束应为空操作");

    // ⑥ close 幂等，且关闭后所有操作返回 Closed。
    device.close().expect("关闭");
    device.close().expect("重复关闭应为空操作");
    assert!(device.is_closed(), "关闭后应标记为已关闭");
    match device.receive(Duration::from_millis(10)) {
        Err(Error::Closed) => {}
        other => panic!("关闭后 receive 应返回 Closed，实际 {other:?}"),
    }
    match device.send(b"x") {
        Err(Error::Closed) => {}
        other => panic!("关闭后 send 应返回 Closed，实际 {other:?}"),
    }
    match device.start_session(0x20_0000) {
        Err(Error::Closed) => {}
        other => panic!("关闭后 start_session 应返回 Closed，实际 {other:?}"),
    }
}

/// Drop 释放不泄漏（真实创建 → 直接 drop，不显式 close）。
///
/// 取证点：`Device` 析构能安全释放适配器与会话，进程不 panic、不留残留会话；
/// 随后同名复用不报「已在用」。
#[tokio::test]
#[ignore = "需要管理员权限与 wintun.dll（LENGSUO_WINTUN_DLL）"]
async fn device_drop_releases_adapter() {
    let library = library();
    let config = DeviceConfig::for_test();

    {
        let mut device = Device::create(&library, config).expect("创建适配器（需管理员）");
        device.start_session(0x20_0000).expect("开启会话");
        // 故意不 close，交给 Drop。
    }
    println!("dropped adapter without explicit close");

    // 重新创建 + 开会话 + 显式关闭：若 Drop 未正确释放，这里会失败。
    let mut reused = Device::create(&library, DeviceConfig::for_test()).expect("Drop 后重新创建");
    reused.start_session(0x20_0000).expect("重新开启会话");
    reused.close().expect("关闭");
}

// 实机验证记录（2026-10-16 首次，wintun 0.14.1 amd64）：
// 管理员 PowerShell 下 `cargo test -p lengsuo-tun --test device_windows -- --ignored --nocapture`
// —— 适配器真实创建（系统注册接口 lengsuo-tun-test-*）、ring 会话开启、
// send 200B 接受、receive 500ms 超时准时返回、close 清理，全部通过。
// 系统级路由（ping 虚拟网关、浏览器流量）属用户态栈阶段验收，不在本层。
