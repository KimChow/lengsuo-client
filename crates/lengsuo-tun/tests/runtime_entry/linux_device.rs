//! **真实 TUN 设备**的端到端用例（`#[ignore]`）。
//!
//! # 为什么要 `#[ignore]`
//!
//! 打开 `/dev/net/tun` 需要 `CAP_NET_ADMIN`（或 root）。CI 的普通容器 runner
//! 通常没有这个能力，因此本组用例默认跳过，用 `--ignored` 实跑。
//!
//! # 本组用例证明什么
//!
//! 与 `support.rs` 里的内存替身不同，本组用例**真的**去 `/dev/net/tun` 挂载接口，
//! 验证：
//! 1. `TUNSETIFF` 挂载成功，且内核回写的设备名可用；
//! 2. 设置的 MTU 真的生效——**从内核读回**（`SIOCGIFMTU`），不是复述本地字段；
//! 3. 接口真的被置 UP——**从内核读回**（`SIOCGIFFLAGS`）；
//! 4. 写路径真的把一个 IP 报文注入了内核（写成功后内核会据此回一个 ICMP 或
//!    ARP 之类的报文出来，读得到就说明写确实到了内核）。
//!
//! # TUN 的收发方向（**不要**写成「写什么就读回什么」）
//!
//! TUN 设备是**单向对**的：
//! - `write` ＝ 把报文**注入**内核的接收路径（当作「从链路收到的包」）；
//! - `read` ＝ 取出内核**要发出去**的包（当作「内核交给链路的包」）。
//!
//! 所以写进去的字节**不会**原样读回来。读回来的必然是内核因为该报文而产生的
//! 其它报文（例如目的地址不可达时的 ICMP）。
//!
//! # 不证明什么
//!
//! 本组用例**不**与任何外部实现互通（没有对端、没有出口协议），因此**不是**
//! 「TUN 已实机可用」的完整证据，只证明设备层这一段真的跑通了。

use std::time::Duration;

use lengsuo_tun::ingress::{PacketSource, Receipt};

use crate::runtime_entry::{open_device, DeviceError, TunDevice};

/// 真实设备用例：挂载 → 设 MTU → 置 UP → 写入注入内核 → 读回内核产物。
///
/// 需要 `CAP_NET_ADMIN`。跑法：
/// `cargo test -p lengsuo-tun --test runtime_entry -- --ignored`
#[test]
#[ignore = "需要 CAP_NET_ADMIN：打开 /dev/net/tun"]
fn real_tun_device_is_configured_and_writes_reach_the_kernel() {
    let config = crate::support::config();
    let mut device = match open_device(&config) {
        Ok(device) => device,
        Err(error) => {
            // 没有权限不是「通过」，是「没跑成」——必须显式失败。
            panic!("真实 TUN 设备应可打开，实际失败：{error}");
        }
    };

    // ① 设备名被内核接受，且非空。
    assert!(!device.name().is_empty(), "设备名不得为空");
    // ② MTU 生效：本地记录的 MTU 与配置一致。
    assert_eq!(
        device.mtu(),
        Some(config.mtu),
        "本地记录的 MTU 必须与配置一致"
    );

    // ③ 从内核读回状态：MTU 认账、接口已 UP。
    //    这是「生效」的唯一可信证据——复述本地字段不算数。
    let state = device.query_state().expect("从内核读回接口状态应成功");
    assert_eq!(state.mtu, config.mtu, "内核认账的 MTU 必须与配置一致");
    assert!(state.up, "接口必须已置 UP");

    // ④ 写路径：写一个目的地址不可达的 IPv4 报文，内核会因此产生一个 ICMP
    //    差错报文，读得到就说明写确实到了内核。
    let mut packet =
        crate::support::tcp_packet(1000, 0, lengsuo_tun::tcp::segment::Flags::SYN, &[]);
    // 目的地址改成一个内核不会路由的地址，制造可观测的内核反应。
    packet[16..20].copy_from_slice(&[192, 0, 2, 123]);
    device.send(&packet).expect("写回报文应成功");

    let mut saw_kernel_packet = false;
    for _ in 0..50 {
        match device
            .receive(Duration::from_millis(100))
            .expect("收包不应报错")
        {
            Receipt::Packet(bytes) => {
                // 内核产出的报文是一份 IP 报文：首字节高 4 位是版本号。
                // ⚠️ 不能用 `packet::inspect` 校验它——那个解析器**只**接受 TCP/UDP，
                // 而内核这里回的是 ICMP（`UnsupportedProtocol` 是**正确**行为）。
                // 因此这里只断言「是 IP 报文」，传输层类型交由上层决定。
                let version = bytes.first().map(|byte| byte >> 4).unwrap_or(0);
                assert!(
                    version == 4 || version == 6,
                    "内核产出的应是 IPv4/IPv6 报文，实际首字节 {bytes:?}"
                );
                saw_kernel_packet = true;
                break;
            }
            Receipt::Timeout => continue,
        }
    }
    assert!(
        saw_kernel_packet,
        "写入的报文应让内核产生响应（读不到说明写没到内核）"
    );

    // ⑤ 关闭设备：`Drop` 负责关闭描述符，这里只验证不再 panic。
    drop(device);
}

/// 真实设备用例：设备层的失败必须是**显式**的，不是空设备。
#[test]
#[ignore = "需要 CAP_NET_ADMIN：打开 /dev/net/tun"]
fn real_tun_device_reports_errors_explicitly() {
    // 设备名超长 ⇒ 显式报错（不是静默截断）。
    let mut config = crate::support::config();
    config.device_name = "x".repeat(64);
    let error = open_device(&config).expect_err("超长设备名必须报错");
    assert!(
        matches!(error, DeviceError::Io { .. } | DeviceError::Syscall { .. }),
        "期望显式错误，实际 {error:?}"
    );
}
