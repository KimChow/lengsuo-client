//! Linux 真实 TUN 设备的**无特权真机证据**：设备探测 + 能力查询 + 失败分类。
//!
//! # 为什么要有这组用例
//!
//! 真实 TUN 设备的端到端用例（`runtime_entry` 里的 `linux_device`）需要
//! `CAP_NET_ADMIN`，因此标了 `#[ignore]`，**进不了基线轮**（基线轮不带
//! `--ignored`）。于是「Linux 真机上 TUN 到底能不能用」这件事在自动门禁里
//! 是**空白**——只有研究机上一次手工实跑能作证。
//!
//! 本组补的正是这块空白，而且**不需要任何特权**：
//! 1. **设备探测**：真的去 `stat` 并打开 `/dev/net/tun`，确认它是什么、能不能开；
//! 2. **能力查询**：读 `/proc/self/status` 的 `CapEff`，判断本进程是否持有
//!    `CAP_NET_ADMIN`；
//! 3. **失败分类**：真的去 `open_device`，把结果分成「成功挂载 / 无权限 /
//!    设备缺失 / 真失败」四类，并**如实断言**实际结果与能力查询的预测一致。
//!
//! # 关键性质：如实区分「没权限」与「真失败」
//!
//! 「没有 `CAP_NET_ADMIN`」是**环境事实**，不是代码缺陷；「挂载报了个说不清的
//! errno」才是真失败。本组把这两者分开：权限不足时断言的是「错误**显式**且
//! **分类正确**」，而**不是**断言「设备应当可用」——后者在 CI 上必然假红。
//! 真正挂上时（研究机上有特权），本组顺带把内核读回也做一遍。
//!
//! # 与 `#[ignore]` 那组的关系
//!
//! 两组**不重复**：被忽略的那组证明「有特权时内核认账」（MTU/UP 从内核读回、
//! 写注入内核）；本组证明「**任何特权状态下**探测/能力查询/分类这条链都通」。
//!
//! # 平台
//!
//! 本组是 **Linux 专属**：它验的是 `/dev/net/tun` 这条 Linux 路径。文件级
//! `#![cfg(target_os = "linux")]`（与 `device_windows.rs` 的 `#![cfg(windows)]`
//! 同一范式）保证在 Windows 上整个目标不产生用例，而不是产生「必然红」的用例。
//!
//! # 边界
//!
//! - 本组**不**与任何外部实现互通（没有对端、没有出口协议）。
//! - 本组只在有特权时挂载一个接口，描述符一关接口即销毁，不改系统路由。
//! - 断言与错误输出**不打印**任何报文原始字节或凭据。
#![cfg(target_os = "linux")]

// The included file is a bin crate root: it has its own `main` behind
// `#[cfg(not(test))]`, so the test harness entry point stays unique.
#[path = "../src/bin/lengsuo-tun-runtime.rs"]
#[allow(dead_code, unused_imports)]
mod runtime_entry;

use crate::runtime_entry::{open_device, DeviceError, RawConfig, RuntimeConfig};

/// 设备节点路径（Linux 的 TUN 字符设备）。
const TUN_NODE: &str = "/dev/net/tun";
/// 能力查询用的进程状态文件。
const PROC_SELF_STATUS: &str = "/proc/self/status";
/// `CAP_NET_ADMIN` 的位号（Linux `capability.h`）。
const CAP_NET_ADMIN_BIT: u64 = 12;

/// 挂载分类用的设备名（≤ `IFNAMSIZ-1` = 15 字符，且与真实适配器区分得开）。
const PROBE_NAME: &str = "lspprobe0";
/// 第二个挂载分类用的设备名：与 `PROBE_NAME` 分开，避免并行用例抢同一个接口。
const PROBE_NAME_ALT: &str = "lspprobe1";
/// 挂载用的 MTU。
const PROBE_MTU: u16 = 1500;

/// `EPERM`：内核因缺少能力而拒绝。
const EPERM: i32 = 1;
/// `ENOENT`：设备节点不存在。
const ENOENT: i32 = 2;
/// `EACCES`：设备节点权限不足。
const EACCES: i32 = 13;

/// 挂载结果的分类。
///
/// 这是本组用例的**核心语义**：把「环境不给权限」和「代码/环境真失败」分开，
/// 前者不是缺陷，后者必须暴露。
#[derive(Debug, Clone, PartialEq, Eq)]
enum AttachOutcome {
    /// 真的挂上了：设备名与生效 MTU。
    Attached {
        /// 内核认账的设备名。
        name: String,
        /// 内核认账的 MTU。
        mtu: u16,
    },
    /// 无权限：`EPERM` / `EACCES`。
    PermissionDenied {
        /// errno。
        errno: i32,
    },
    /// 设备节点不存在：`ENOENT`。
    DeviceAbsent {
        /// errno。
        errno: i32,
    },
    /// **真失败**：errno 说不清，或错误类型不对。
    Unexpected {
        /// errno（错误不是系统调用失败时为 `None`）。
        errno: Option<i32>,
        /// 失败细节（不含任何凭据）。
        detail: String,
    },
}

/// 把 `open_device` 的错误分类。
///
/// 分类口径**只认 errno**：内核明确说「没权限」或「没设备」就是环境事实；
/// 其余一律算真失败。
fn classify(error: &DeviceError) -> AttachOutcome {
    match error {
        DeviceError::Syscall { code, .. } => match *code {
            EPERM | EACCES => AttachOutcome::PermissionDenied { errno: *code },
            ENOENT => AttachOutcome::DeviceAbsent { errno: *code },
            _ => AttachOutcome::Unexpected {
                errno: Some(*code),
                detail: format!("系统调用失败，errno {code}"),
            },
        },
        DeviceError::Io { detail } => AttachOutcome::Unexpected {
            errno: None,
            detail: detail.clone(),
        },
        DeviceError::Unsupported { platform } => AttachOutcome::Unexpected {
            errno: None,
            detail: format!("平台不支持：{platform}"),
        },
        DeviceError::Closed => AttachOutcome::Unexpected {
            errno: None,
            detail: "设备已关闭".to_string(),
        },
    }
}

/// 构造一份合法配置（只填设备名与 MTU，其余取默认值）。
fn config_with(name: &str) -> RuntimeConfig {
    RawConfig {
        device_name: Some(name.to_string()),
        mtu: Some(PROBE_MTU),
        ..RawConfig::default()
    }
    .into_config()
    .expect("配置应合法")
}

/// 本进程的有效能力集（`CapEff`）。读不到时返回 `None`。
fn effective_capabilities() -> Option<u64> {
    let text = std::fs::read_to_string(PROC_SELF_STATUS).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:") {
            return u64::from_str_radix(rest.trim(), 16).ok();
        }
    }
    None
}

/// 本进程是否持有 `CAP_NET_ADMIN`。读不到能力集时返回 `None`。
fn has_net_admin() -> Option<bool> {
    effective_capabilities().map(|caps| caps & (1u64 << CAP_NET_ADMIN_BIT) != 0)
}

/// 设备探测：节点在位且是字符设备，还是显式缺失。
///
/// 断言口径是**如实**：节点在位就必须是字符设备（不是普通文件/目录），缺失就
/// 必须是 `NotFound`——两种都是环境事实，但都不许被悄悄糊过去。
#[test]
fn device_node_probe_distinguishes_character_device_from_absence() {
    use std::os::unix::fs::FileTypeExt;

    match std::fs::metadata(TUN_NODE) {
        Ok(metadata) => {
            assert!(
                metadata.file_type().is_char_device(),
                "{TUN_NODE} 必须是字符设备，实际 {:?}",
                metadata.file_type()
            );
            // 第二项能力查询：节点能否以读写方式打开。
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(TUN_NODE)
            {
                Ok(file) => {
                    let opened = file
                        .metadata()
                        .expect("打开后应仍能取到节点元数据")
                        .file_type();
                    assert!(
                        opened.is_char_device(),
                        "打开的 {TUN_NODE} 仍须是字符设备，实际 {opened:?}"
                    );
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
                    ) =>
                {
                    // 节点在位但打不开（权限/已被移除）——环境事实，如实记下。
                    eprintln!("TUN 探测：节点在位但打不开（{error}）——环境事实，非代码缺陷");
                }
                Err(error) => panic!("打开 {TUN_NODE} 失败且不是权限/缺失问题：{error}"),
            }
        }
        Err(error) => {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::NotFound,
                "节点缺失必须是 NotFound，实际 {error}"
            );
            eprintln!("TUN 探测：设备节点不存在——环境事实，非代码缺陷");
        }
    }
}

/// 挂载结果必须**可分类**：真失败一律暴露，权限不足不算缺陷。
///
/// 这是本组最关键的一条：它把「没权限」与「真失败」分开。
#[test]
fn attach_failure_is_classified_as_permission_not_a_real_failure() {
    let config = config_with(PROBE_NAME);
    let outcome = match open_device(&config) {
        Ok(device) => AttachOutcome::Attached {
            name: device.name().to_string(),
            mtu: device.mtu().unwrap_or(0),
        },
        Err(error) => classify(&error),
    };

    match &outcome {
        AttachOutcome::Attached { name, mtu } => {
            assert!(!name.is_empty(), "挂上了就必须有设备名");
            assert_eq!(*mtu, PROBE_MTU, "挂上了就必须报告生效的 MTU");
            eprintln!("TUN 探测：已挂载，设备名 {name}，MTU {mtu}");
            // 挂上了 ⇒ 本进程必然持有 CAP_NET_ADMIN。能力查询若说「没有」，
            // 说明能力查询本身读错了，两边不一致 ⇒ 门禁必须红。
            if has_net_admin() == Some(false) {
                panic!("内核允许挂载 TUN，但能力查询显示本进程没有 CAP_NET_ADMIN：两者不一致");
            }
        }
        AttachOutcome::PermissionDenied { errno } => {
            eprintln!("TUN 探测：无权限（errno {errno}）——环境事实，非代码缺陷");
            // 权限不足是**环境事实**：errno 必须是内核明确说的那两种之一。
            assert!(
                *errno == EPERM || *errno == EACCES,
                "权限分类的 errno 必须是 EPERM/EACCES，实际 {errno}"
            );
            // 权限不足 ⇒ 本进程**不**持有 CAP_NET_ADMIN；能力查询若说「有」，
            // 说明内核拒绝的理由不是能力，两边不一致 ⇒ 门禁必须红。
            if has_net_admin() == Some(true) {
                panic!(
                    "能力查询显示本进程持有 CAP_NET_ADMIN，但内核仍以权限不足拒绝挂载：两者不一致"
                );
            }
        }
        AttachOutcome::DeviceAbsent { errno } => {
            eprintln!("TUN 探测：设备节点不存在（errno {errno}）——环境事实，非代码缺陷");
            assert_eq!(*errno, ENOENT, "设备缺失的 errno 必须是 ENOENT");
        }
        AttachOutcome::Unexpected { errno, detail } => {
            // 真失败：既不是权限也不是缺失 ⇒ 门禁必须红。
            panic!("TUN 挂载真失败（errno {errno:?}）：{detail}");
        }
    }
}

/// 有特权时：**从内核读回**接口状态，而不是复述本地字段。
///
/// 没特权时退化为「失败必须显式且分类正确」——不是「设备应当可用」。
#[test]
fn privileged_attach_is_confirmed_by_reading_the_kernel_state() {
    let config = config_with(PROBE_NAME_ALT);
    match open_device(&config) {
        Ok(device) => {
            assert!(!device.name().is_empty(), "设备名不得为空");
            assert_eq!(
                device.mtu(),
                Some(PROBE_MTU),
                "本地记录的 MTU 必须与配置一致"
            );
            // 只有内核认账的值才算「生效」。
            let state = device.query_state().expect("从内核读回接口状态应成功");
            assert_eq!(state.mtu, PROBE_MTU, "内核认账的 MTU 必须与配置一致");
            assert!(state.up, "接口必须已置 UP");
        }
        Err(error) => {
            let outcome = classify(&error);
            assert!(
                matches!(
                    outcome,
                    AttachOutcome::PermissionDenied { .. } | AttachOutcome::DeviceAbsent { .. }
                ),
                "无特权时的失败必须是权限/设备缺失分类，实际 {outcome:?}"
            );
            // 失败必须**显式**：错误信息指明是设备层失败，而不是静默成功。
            assert!(
                error.to_string().contains("设备"),
                "错误信息应指明是设备层失败，实际 {error}"
            );
        }
    }
}

/// 设备名长度非法 ⇒ **在碰平台之前**就报错。
///
/// 这条不需要任何特权：长度检查发生在打开 `/dev/net/tun` 之前，所以错误类型
/// 必须是 `Io`（参数层），一旦是 `Syscall` 就说明已经去动过平台了。
#[test]
fn device_name_is_rejected_before_any_privileged_operation() {
    // 绕过 `RawConfig::into_config`（它自己也会拒），直接构造已校验形态的配置，
    // 目的是单独考察**设备层**的守门。
    let config = RuntimeConfig {
        device_name: "x".repeat(64),
        mtu: PROBE_MTU,
        routes: Vec::new(),
        read_timeout_ms: 10,
        session_capacity: 1024,
        session_ttl_ms: 60_000,
        max_packets: 0,
        max_steps: 0,
        environment: 1,
        device_id: 1,
        epoch: 1,
    };
    let error = open_device(&config).expect_err("超长设备名必须报错");
    assert!(
        matches!(error, DeviceError::Io { .. }),
        "期望参数层错误（未碰平台），实际 {error:?}"
    );
}

/// 分类表本身：权限、缺失、真失败三者**互不混淆**。
///
/// 这是纯逻辑断言，不发任何系统调用，因此不会因环境而变。
#[test]
fn classification_table_distinguishes_permission_absence_and_real_failure() {
    let cases = [
        (EPERM, AttachOutcome::PermissionDenied { errno: EPERM }),
        (EACCES, AttachOutcome::PermissionDenied { errno: EACCES }),
        (ENOENT, AttachOutcome::DeviceAbsent { errno: ENOENT }),
    ];
    for (errno, expected) in cases {
        let error = DeviceError::Syscall {
            op: "挂载 TUN 接口",
            code: errno,
        };
        assert_eq!(classify(&error), expected, "errno {errno} 的分类不对");
    }

    // 其余 errno 一律是真失败——不得被当成「没权限」而放过。
    for errno in [16, 19, 22, 5, 11] {
        let error = DeviceError::Syscall {
            op: "挂载 TUN 接口",
            code: errno,
        };
        assert!(
            matches!(classify(&error), AttachOutcome::Unexpected { .. }),
            "errno {errno} 必须归为真失败"
        );
    }

    // 非系统调用类错误同样是真失败。
    assert!(matches!(
        classify(&DeviceError::Io {
            detail: "boom".to_string()
        }),
        AttachOutcome::Unexpected { .. }
    ));
}
