//! Windows wintun 设备实机验证（需管理员权限）。
//! 前置：LENGSUO_WINTUN_DLL 指向 wintun.dll（amd64）；以管理员运行。
//! 默认 #[ignore]：普通 CI/开发环境不会带驱动与权限。
#![cfg(windows)]

use std::time::Duration;

/// 宿主注入 dll 的唯一 unsafe 点：按仓库规则集中在此，测试与生产加载器共用。
unsafe fn load_library() -> wintun::Wintun {
    let path =
        std::env::var("LENGSUO_WINTUN_DLL").expect("设置 LENGSUO_WINTUN_DLL 指向 amd64/wintun.dll");
    wintun::load_from_path(&path).expect("加载 wintun.dll 失败")
}

#[tokio::test]
#[ignore = "需要管理员权限与 wintun.dll（LENGSUO_WINTUN_DLL）"]
async fn adapter_create_send_receive_loopback() {
    let library = lengsuo_tun::device::Library::from_handle(unsafe { load_library() })
        .expect("wintun 句柄封装");
    let config = lengsuo_tun::device::DeviceConfig::for_test();
    println!(
        "adapter {} guid {:?} mtu {}",
        config.adapter_name, config.guid, config.mtu
    );
    let mut device =
        lengsuo_tun::device::Device::create(&library, config).expect("创建适配器（需管理员）");
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

// 实机验证记录（2026-10-16）：管理员 PowerShell 下
// `cargo test -p lengsuo-tun --test device_windows -- --ignored --nocapture`
// （LENGSUO_WINTUN_DLL 指向 wintun 0.14.1 amd64）：
// 适配器真实创建（系统注册接口 lengsuo-tun-test-*）、ring 会话开启、
// send 200B 接受、receive 500ms 超时准时返回、close 清理——全部通过。
// 系统级路由（ping 虚拟网关、浏览器流量）属用户态栈阶段验收，不在本层。
