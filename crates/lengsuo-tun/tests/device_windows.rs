//! Windows wintun 设备实机验证（需管理员权限）。
//! 前置：LENGSUO_WINTUN_DLL 指向 wintun.dll（amd64）；以管理员运行。
//! 默认 #[ignore]：普通 CI/开发环境不会带驱动与权限。
#![cfg(windows)]

use std::time::Duration;

/// 宿主注入 dll 的唯一 unsafe 点：按仓库规则集中在此，测试与生产加载器共用。
unsafe fn load_library() -> wintun::Wintun {
    let path = std::env::var("LENGSUO_WINTUN_DLL")
        .expect("设置 LENGSUO_WINTUN_DLL 指向 amd64/wintun.dll");
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
    let mut device = lengsuo_tun::device::Device::create(&library, config)
        .expect("创建适配器（需管理员）");
    device
        .start_session(0x400_000)
        .expect("开启 ring 会话");

    // 回环：同一会话自发自收（wintun ring 语义）。
    let payload: Vec<u8> = (0..200u16).map(|i| (i % 251) as u8).collect();
    device.send(&payload).expect("发送");
    let received = device
        .receive(Duration::from_secs(5))
        .expect("接收");
    assert_eq!(received, payload, "回环字节必须一致");

    // 超时路径：无新包时 receive 必须在期限内报错而不是挂住。
    let outcome = device.receive(Duration::from_millis(200));
    assert!(outcome.is_err(), "空闲会话不应读到数据");

    device.close().expect("关闭");
}
