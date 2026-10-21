//! 设备层的用例：平台不支持必须**显式**报错，绝不静默 no-op。
//!
//! 「平台不支持必须显式报错」这条契约在**所有平台**都编译，因此任意平台的 CI
//! 都能验证它不会静默假装成功。

use std::time::Duration;

use lengsuo_tun::ingress::PacketSource;

use crate::runtime_entry::{open_device, DeviceError, TunDevice, UnsupportedDevice};

use crate::support::config;

/// 非 Linux 平台的设备桩：收发都显式报「平台不支持」，**不静默 no-op**。
#[test]
fn unsupported_platform_reports_explicitly_instead_of_silently_doing_nothing() {
    let mut device = UnsupportedDevice::new("lstest0");
    let error = device
        .receive(Duration::from_millis(1))
        .expect_err("桩设备不得假装收到包");
    assert!(
        matches!(error, DeviceError::Unsupported { .. }),
        "期望平台不支持，实际 {error:?}"
    );
    assert!(error.to_string().contains("平台不支持"));

    let error = device.send(&[0u8; 20]).expect_err("桩设备不得假装写回成功");
    assert!(matches!(error, DeviceError::Unsupported { .. }));
}

/// 设备桩的名字被如实保留，便于日志定位。
#[test]
fn unsupported_device_keeps_its_name() {
    assert_eq!(UnsupportedDevice::new("lstest0").name(), "lstest0");
}

/// 在**非 Linux** 平台上，`open_device` 显式报不支持；Linux 上则真去开设备
/// （无权限时也必须显式报错，不是静默返回空设备）。
#[test]
fn open_device_never_silently_returns_an_empty_device() {
    let config = config();
    match open_device(&config) {
        Ok(device) => {
            // Linux 且有权限：设备是真设备，不是空壳。
            assert!(!device.name().is_empty());
            // 真实设备必须报告生效的 MTU。
            assert_eq!(device.mtu(), Some(config.mtu));
        }
        Err(error) => {
            // 无权限 / 非 Linux：显式错误。
            assert!(
                matches!(
                    error,
                    DeviceError::Unsupported { .. } | DeviceError::Syscall { .. }
                ),
                "期望显式错误，实际 {error:?}"
            );
        }
    }
}
