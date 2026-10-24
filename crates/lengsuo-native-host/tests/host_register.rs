//! 注册层：Windows 计划的 `reg` 命令行**逐字符**断言（且绝不出现 HKLM / 真浏览器品牌键）、
//! POSIX 实写临时目录 + 读回逐字节相同 + 幂等、`deregister` 只删自己那一项。
//!
//! # 反向锚点（本卡报告里贴「改什么 ⇒ 哪几条红」）
//!
//! - 把渲染改回两字段 / 把 `type` 改错 ⇒ `tests/host_manifest.rs` 的
//!   `rendered_bytes_equal_the_hand_written_literal`、`rendered_json_has_exactly_five_fields_in_fixed_order`、
//!   `type_is_exactly_stdio` 变红；
//! - 把 Windows 值名从默认值改成显式名字（`/ve` → `/v lengsuo.credential`）⇒
//!   本文件的 `windows_add_command_is_char_exact` 变红。

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

// 仅 POSIX 实 IO 夹具消费；Windows 上那些用例被 `#[cfg(unix)]` 门掉 ⇒ 随之门控。
#[cfg(unix)]
use lengsuo_native_host::manifest::{render_host_manifest, Platform};
use lengsuo_native_host::register::{
    deregister, plan_posix, plan_windows, register, CommandRunner, PosixPlan, RegisterError,
    RegistrationPlan, POSIX_USER_SUBDIR, REGISTRY_ROOT,
};

/// 记录收到的命令行（测试专用的注入执行器；生产实现属 Windows 侧，本卡不写）。
#[derive(Default)]
struct RecordingRunner {
    commands: Mutex<Vec<String>>,
}

impl CommandRunner for RecordingRunner {
    fn run(&self, command_line: &str) -> Result<(), String> {
        self.commands
            .lock()
            .expect("锁不该中毒")
            .push(command_line.to_owned());
        Ok(())
    }
}

/// 只要被调用就失败的执行器：钉住「POSIX 分支不碰 runner」。
/// 消费方全是 `#[cfg(unix)]` 的 POSIX 实 IO 用例 ⇒ 随之门控。
#[cfg(unix)]
struct RefusingRunner;

impl CommandRunner for RefusingRunner {
    fn run(&self, command_line: &str) -> Result<(), String> {
        Err(format!(
            "POSIX 分支不该执行任何命令，却收到：{command_line}"
        ))
    }
}

/// 仓内惯例：零新依赖 ⇒ `std::env::temp_dir()` + 进程号 + 原子计数。
fn unique_temp_dir(tag: &str) -> PathBuf {
    static NEXT: OnceLock<std::sync::atomic::AtomicUsize> = OnceLock::new();
    let n = NEXT
        .get_or_init(Default::default)
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "lengsuo-native-host-register-{tag}-{}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("建临时目录失败");
    dir
}

#[cfg(unix)]
const SYNTHETIC_MANIFEST: &str = "/opt/lengsuo/lengsuo-native-host";
/// 合成的 Windows 绝对路径（命令行逐字断言用；不指向真实文件也没关系 —— 本卡不真跑）。
const SYNTHETIC_MANIFEST_WIN: &str = r"C:\lengsuo\lengsuo-native-host.exe";
const SYNTHETIC_JSON: &str = r#"{"name":"lengsuo.credential","description":"d","type":"stdio","path":"/opt/lengsuo/lengsuo-native-host","allowed_origins":["chrome-extension://ejlmmjamfpkoopjachjhcbdjlddknhok/"]}"#;

// ------------------------------------------------------------- Windows 计划

#[test]
fn windows_plan_targets_hkcu_chromium_key_with_default_value_name() {
    let plan = plan_windows(r"C:\Program Files\lengsuo\lengsuo-native-host.exe")
        .expect("合法 Windows 绝对路径 ⇒ 必须成功");
    assert_eq!(
        plan.key_path,
        r"HKCU\SOFTWARE\Chromium\NativeMessagingHosts\lengsuo.credential"
    );
    assert!(plan.key_path.starts_with(&format!("{REGISTRY_ROOT}\\")));
    // 值名 = **默认值**（`ReadValue(nullptr, …)` 读的那一项）。
    assert_eq!(plan.value_name, None);
    assert_eq!(
        plan.value_data,
        r"C:\Program Files\lengsuo\lengsuo-native-host.exe"
    );
}

#[test]
fn windows_add_command_is_char_exact() {
    let plan = plan_windows(SYNTHETIC_MANIFEST_WIN).expect("必须成功");
    let expected = concat!(
        r#"reg.exe add "HKCU\SOFTWARE\Chromium\NativeMessagingHosts\lengsuo.credential""#,
        r#" /ve /t REG_SZ /d "C:\lengsuo\lengsuo-native-host.exe" /f"#
    );
    assert_eq!(plan.add_command, expected);
}

#[test]
fn windows_delete_command_is_char_exact_and_value_only() {
    let plan = plan_windows(SYNTHETIC_MANIFEST_WIN).expect("必须成功");
    let expected =
        r#"reg.exe delete "HKCU\SOFTWARE\Chromium\NativeMessagingHosts\lengsuo.credential" /ve /f"#;
    assert_eq!(plan.delete_command, expected);
    // 只删默认值：不删整个键（`/va` 才是删全部值）。
    assert!(plan.delete_command.ends_with(" /ve /f"));
}

#[test]
fn windows_commands_never_touch_hklm_or_the_other_brands_key() {
    let plan = plan_windows(r"D:\x\lengsuo-native-host.exe").expect("必须成功");
    let produced = [
        plan.key_path.as_str(),
        plan.value_data.as_str(),
        plan.add_command.as_str(),
        plan.delete_command.as_str(),
    ];
    for s in produced {
        assert!(!s.contains("HKLM"), "不得出现 HKLM：{s}");
        assert!(!s.contains("HKEY_LOCAL_MACHINE"), "不得出现 HKLM：{s}");
        // 真浏览器品牌键是别人的落点，写它会污染别人的浏览器。
        assert!(
            !s.contains(r"SOFTWARE\Google\Chrome"),
            "不得写真浏览器品牌键：{s}"
        );
        assert!(
            !s.contains(r"SOFTWARE\Wow6432Node"),
            "不得写 Wow6432Node 视图：{s}"
        );
    }
    // 键落在用户级 HKCU（`launch_context_win.cc:192` 先查它）。
    assert!(plan.key_path.starts_with(&format!("{REGISTRY_ROOT}\\")));
}

#[test]
fn windows_plan_rejects_relative_and_unsafe_paths() {
    for path in [
        "lengsuo-native-host.exe",
        r"lengsuo\x.exe",
        "/opt/lengsuo/x",
    ] {
        let err = plan_windows(path).expect_err("相对/异形路径必须被拒");
        assert!(
            matches!(err, RegisterError::ManifestPathNotAbsolute { .. }),
            "{path:?} ⇒ 期望 ManifestPathNotAbsolute，得到 {err:?}"
        );
    }
    let err = plan_windows(r#"C:\we"ird\x.exe"#).expect_err("含引号必须被拒");
    assert!(matches!(
        err,
        RegisterError::ManifestPathNotCommandSafe { .. }
    ));
    // 引号被拒 ⇒ 命令行恒可安全加引号。
    let ok = plan_windows(r"C:\lengsuo\x.exe").expect("无引号路径必须成功");
    assert!(ok.add_command.starts_with("reg.exe add \""));
}

// --------------------------------------------------------------- POSIX 计划

#[test]
fn posix_plan_writes_into_user_native_messaging_hosts() {
    let plan = plan_posix(Path::new("/home/u/.lengsuo-profile"), SYNTHETIC_JSON)
        .expect("绝对 user_data_dir ⇒ 必须成功");
    let expected = Path::new("/home/u/.lengsuo-profile")
        .join(POSIX_USER_SUBDIR)
        .join("lengsuo.credential.json");
    assert_eq!(plan.manifest_file, expected);
    assert_eq!(plan.contents, SYNTHETIC_JSON);
    assert_eq!(
        plan.manifest_file.file_name().and_then(|n| n.to_str()),
        Some("lengsuo.credential.json")
    );
}

#[test]
fn posix_plan_rejects_relative_dir_and_empty_manifest() {
    let err =
        plan_posix(Path::new("relative-profile"), SYNTHETIC_JSON).expect_err("相对目录必须被拒");
    assert!(matches!(err, RegisterError::UserDataDirNotAbsolute { .. }));
    let err = plan_posix(Path::new(""), SYNTHETIC_JSON).expect_err("空目录必须被拒");
    assert!(matches!(err, RegisterError::UserDataDirNotAbsolute { .. }));
    let err = plan_posix(Path::new("/abs"), "").expect_err("空 manifest 必须被拒");
    assert!(matches!(err, RegisterError::EmptyManifest));
    // Windows 形状的目录不是 POSIX 绝对路径。
    let err = plan_posix(Path::new(r"C:\profile"), SYNTHETIC_JSON).expect_err("必须被拒");
    assert!(matches!(err, RegisterError::UserDataDirNotAbsolute { .. }));
}

/// Windows 对等夹具（上轮 Windows 实机复验观察到的事实，钉成绿用例防回退）：
/// Windows 的 `unique_temp_dir()` 产出盘符形状目录 ⇒ `plan_posix` 必须 fail-closed 拒绝。
#[cfg(windows)]
#[test]
fn windows_shaped_temp_dir_is_rejected_by_posix_plan() {
    let dir = unique_temp_dir("win-posix-reject");
    let err = plan_posix(&dir, SYNTHETIC_JSON).expect_err("盘符形状目录必须被拒");
    assert!(
        matches!(err, RegisterError::UserDataDirNotAbsolute { .. }),
        "期望 UserDataDirNotAbsolute，得到 {err:?}"
    );
}

// ----------------------------------------------------------- 注册（含 IO）

// 以下 4 个是 POSIX 文件系统语义的实 IO 夹具：`unique_temp_dir()` 在 Windows 产出盘符
// 形状目录，`plan_posix` 会按 POSIX 绝对路径判据**正确拒绝**（fail-closed，非产品缺陷）
// ⇒ 门控到 Unix；Windows 侧对等钉住见 `windows_shaped_temp_dir_is_rejected_by_posix_plan`。
#[cfg(unix)]
#[test]
fn posix_register_writes_file_read_back_identical_and_is_idempotent() {
    let dir = unique_temp_dir("posix-register");
    let plan = plan_posix(&dir, SYNTHETIC_JSON).expect("必须成功");
    let wrapped = RegistrationPlan::Posix(plan.clone());

    register(&wrapped, &RefusingRunner).expect("POSIX 注册不该碰 runner，也不该失败");

    let written = std::fs::read(&plan.manifest_file).expect("文件必须存在");
    assert_eq!(written, SYNTHETIC_JSON.as_bytes(), "读回必须逐字节相同");
    assert_eq!(
        std::fs::read_to_string(&plan.manifest_file).unwrap(),
        SYNTHETIC_JSON
    );

    // 幂等：重复注册内容不变。
    register(&wrapped, &RefusingRunner).expect("第二次注册必须成功");
    let again = std::fs::read(&plan.manifest_file).expect("文件必须仍在");
    assert_eq!(again, SYNTHETIC_JSON.as_bytes());
}

#[cfg(unix)]
#[test]
fn posix_register_creates_missing_native_messaging_hosts_dir() {
    let dir = unique_temp_dir("posix-mkdir");
    let plan = plan_posix(&dir, SYNTHETIC_JSON).expect("必须成功");
    assert!(!plan.manifest_file.parent().unwrap().exists());
    register(&RegistrationPlan::Posix(plan.clone()), &RefusingRunner).expect("必须成功");
    assert!(plan.manifest_file.is_file());
}

#[test]
fn windows_register_and_deregister_only_produce_commands_via_injected_runner() {
    let plan = plan_windows(r"C:\lengsuo\lengsuo-native-host.exe").expect("必须成功");
    let wrapped = RegistrationPlan::Windows(plan);
    let runner = RecordingRunner::default();

    register(&wrapped, &runner).expect("注册必须成功");
    deregister(&wrapped, &runner).expect("撤销必须成功");

    let commands = runner.commands.into_inner().expect("锁不该中毒");
    assert_eq!(commands.len(), 2, "恰好两条命令：add + delete");
    assert!(commands[0].starts_with("reg.exe add "));
    assert!(commands[1].starts_with("reg.exe delete "));
    for c in &commands {
        assert!(!c.contains("HKLM") && !c.contains(r"SOFTWARE\Google\Chrome"));
    }
}

#[test]
fn runner_failure_is_named_error() {
    struct Failing;
    impl CommandRunner for Failing {
        fn run(&self, _: &str) -> Result<(), String> {
            Err("boom: exit 1".to_owned())
        }
    }
    let plan = plan_windows(r"C:\x\host.exe").expect("必须成功");
    let err = register(&RegistrationPlan::Windows(plan), &Failing).unwrap_err();
    assert!(matches!(err, RegisterError::RunnerFailed(ref m) if m.contains("boom")));
}

// ----------------------------------------------------------- 撤销注册（IO）

#[cfg(unix)]
#[test]
fn posix_deregister_removes_only_our_file_and_is_idempotent() {
    let dir = unique_temp_dir("posix-deregister");
    let plan = plan_posix(&dir, SYNTHETIC_JSON).expect("必须成功");
    register(&RegistrationPlan::Posix(plan.clone()), &RefusingRunner).expect("必须成功");

    // 同目录里**别人的**文件必须活着。
    let hosts_dir = dir.join(POSIX_USER_SUBDIR);
    let other_host = hosts_dir.join("someone.else.json");
    let ours_only = hosts_dir.join("keep.txt");
    std::fs::write(&other_host, b"{}").unwrap();
    std::fs::write(&ours_only, b"keep").unwrap();

    deregister(&RegistrationPlan::Posix(plan.clone()), &RefusingRunner).expect("撤销必须成功");
    assert!(!plan.manifest_file.exists(), "自己的 manifest 必须被删");
    assert!(other_host.is_file(), "⛔ 不得删别人的 host");
    assert!(ours_only.is_file(), "⛔ 不得删别人的文件");
    assert!(hosts_dir.is_dir(), "⛔ 不得删目录本身");

    // 幂等：再撤一次也是成功。
    deregister(&RegistrationPlan::Posix(plan), &RefusingRunner).expect("二次撤销必须幂等成功");
}

#[test]
fn deregister_refuses_relative_manifest_path() {
    // 手工构造的坏计划（正常路径都来自 plan_*，这里钉住防线本身）。
    let plan = RegistrationPlan::Posix(PosixPlan {
        manifest_file: PathBuf::from("relative.json"),
        contents: SYNTHETIC_JSON.to_owned(),
    });
    let err = deregister(&plan, &RefusingRunner).expect_err("相对路径必须被拒");
    assert!(matches!(err, RegisterError::ManifestFileNotAbsolute { .. }));
}

// ------------------------------------------------------------ 一致性联测

// POSIX 实 IO（落盘到 `unique_temp_dir`），同上门控；Windows 对等见
// `windows_shaped_temp_dir_is_rejected_by_posix_plan`。
#[cfg(unix)]
#[test]
fn rendered_manifest_round_trips_through_posix_register() {
    // 渲染 → 计划 → 落盘 → 读回 == 渲染（跨模块的粘合层不吞字节）。
    let dir = unique_temp_dir("roundtrip");
    let rendered = render_host_manifest(
        SYNTHETIC_MANIFEST,
        "Lengsuo credential vault host",
        Platform::Posix,
    )
    .expect("必须成功");
    let plan = plan_posix(&dir, &rendered).expect("必须成功");
    register(&RegistrationPlan::Posix(plan.clone()), &RefusingRunner).expect("必须成功");
    let back = std::fs::read_to_string(&plan.manifest_file).unwrap();
    assert_eq!(back, rendered);
    let parsed: serde_json::Value = serde_json::from_str(&back).unwrap();
    assert_eq!(parsed["path"].as_str(), Some(SYNTHETIC_MANIFEST));
}
