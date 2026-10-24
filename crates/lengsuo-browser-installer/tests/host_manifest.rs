//! `plan_host_install` / `install_host_manifest` 的规划与 fail-closed 安装测试。
//!
//! 全部夹具合成（宿主二进制写空文件），不依赖 W3b-2d 的真实二进制；
//! 期望值手写（不把被测实现当 oracle）。

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use lengsuo_browser_installer::host_manifest::{
    install_host_manifest, plan_host_install, HostInstallError, HostInstallRequest,
};
use lengsuo_native_host::register::{CommandRunner, RegistrationPlan, POSIX_USER_SUBDIR};
use lengsuo_native_host::Platform;

/// 测试专用注入执行器：记录收到的命令行。
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

/// 只要被调用就失败：钉住「POSIX 分支不碰 runner」。消费方是
/// `#[cfg(unix)]` 的 POSIX 端到端用例 ⇒ 随之门控（Windows 侧用 RecordingRunner 钉零调用）。
#[cfg(unix)]
struct RefusingRunner;

#[cfg(unix)]
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
        "lengsuo-browser-installer-{tag}-{}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("建临时目录失败");
    dir
}

/// 手写的 POSIX 清单期望（host_binary 无 JSON 特殊字符，可直接插值）。
fn expected_posix_manifest(host_binary: &str) -> String {
    format!(
        "{{\"name\":\"lengsuo.credential\",\"description\":\"Lengsuo credential native messaging host\",\"type\":\"stdio\",\"path\":\"{host_binary}\",\"allowed_origins\":[\"chrome-extension://ejlmmjamfpkoopjachjhcbdjlddknhok/\"]}}"
    )
}

// ------------------------------------------------------------- Windows 计划（纯函数）

#[test]
fn windows_plan_host_binary_manifest_file_and_reg_command() {
    let req = HostInstallRequest {
        install_root: PathBuf::from(r"C:\Program Files\Lengsuo"),
        platform: Platform::Windows,
        user_data_dir: None,
    };
    let plan = plan_host_install(&req).expect("合法 Windows 根 ⇒ 必须成功");

    assert_eq!(
        plan.host_binary,
        r"C:\Program Files\Lengsuo\lengsuo-native-host.exe"
    );
    assert_eq!(
        plan.manifest_file,
        r"C:\Program Files\Lengsuo\lengsuo.credential.json"
    );

    // 五字段顺序固定、无空白、无尾换行；Windows 反斜杠按 JSON 规则转义成 `\\`。
    let expected = r#"{"name":"lengsuo.credential","description":"Lengsuo credential native messaging host","type":"stdio","path":"C:\\Program Files\\Lengsuo\\lengsuo-native-host.exe","allowed_origins":["chrome-extension://ejlmmjamfpkoopjachjhcbdjlddknhok/"]}"#;
    assert_eq!(plan.manifest_json, expected);
    // 结构性空白：字段之间不带分隔空格（值内部的空格属于路径/描述内容）。
    assert!(!plan.manifest_json.contains("\": "));
    assert!(!plan.manifest_json.contains("\", "));
    assert!(!plan.manifest_json.ends_with('\n'));

    let name_pos = plan.manifest_json.find("\"name\"").unwrap();
    let desc_pos = plan.manifest_json.find("\"description\"").unwrap();
    let type_pos = plan.manifest_json.find("\"type\"").unwrap();
    let path_pos = plan.manifest_json.find("\"path\"").unwrap();
    let origins_pos = plan.manifest_json.find("\"allowed_origins\"").unwrap();
    assert!(name_pos < desc_pos && desc_pos < type_pos && type_pos < path_pos);
    assert!(path_pos < origins_pos);
    assert!(plan.manifest_json.contains("\"type\":\"stdio\""));
    assert!(plan
        .manifest_json
        .contains("chrome-extension://ejlmmjamfpkoopjachjhcbdjlddknhok/"));
    assert!(!plan.manifest_json.contains("chrome-extension://*"));

    match &plan.registration {
        RegistrationPlan::Windows(wp) => {
            assert_eq!(
                wp.add_command,
                concat!(
                    r#"reg.exe add "HKCU\SOFTWARE\Chromium\NativeMessagingHosts\lengsuo.credential""#,
                    r#" /ve /t REG_SZ /d "C:\Program Files\Lengsuo\lengsuo.credential.json" /f"#
                )
            );
            for s in [
                wp.key_path.as_str(),
                wp.value_data.as_str(),
                wp.add_command.as_str(),
                wp.delete_command.as_str(),
            ] {
                assert!(!s.contains("HKLM"), "不得出现 HKLM：{s}");
                assert!(!s.contains("HKEY_LOCAL_MACHINE"), "不得出现 HKLM：{s}");
                assert!(
                    !s.contains(r"SOFTWARE\Google\Chrome"),
                    "不得写真浏览器品牌键：{s}"
                );
            }
        }
        RegistrationPlan::Posix(_) => panic!("Windows 请求必须产出 Windows 注册计划"),
    }
}

// ------------------------------------------------------------- POSIX 计划（纯函数）

#[test]
fn posix_plan_manifest_file_and_registration() {
    let req = HostInstallRequest {
        install_root: PathBuf::from("/opt/lengsuo"),
        platform: Platform::Posix,
        user_data_dir: Some(PathBuf::from("/home/u/.lengsuo-profile")),
    };
    let plan = plan_host_install(&req).expect("必须成功");

    assert_eq!(plan.host_binary, "/opt/lengsuo/lengsuo-native-host");
    // 落点期望用 Path 拼接构造（⛔ 不硬编码 `/` 分隔符：Windows 上 `PathBuf` 拼出来是 `\`）。
    let expected_manifest_file = Path::new("/home/u/.lengsuo-profile")
        .join(POSIX_USER_SUBDIR)
        .join("lengsuo.credential.json");
    assert_eq!(Path::new(&plan.manifest_file), expected_manifest_file);
    assert_eq!(
        plan.manifest_json,
        expected_posix_manifest("/opt/lengsuo/lengsuo-native-host")
    );

    match &plan.registration {
        RegistrationPlan::Posix(pp) => {
            assert_eq!(pp.contents, plan.manifest_json);
            assert_eq!(pp.manifest_file, expected_manifest_file);
        }
        RegistrationPlan::Windows(_) => panic!("POSIX 请求必须产出 POSIX 注册计划"),
    }
}

// ------------------------------------------------------------- POSIX 端到端（含 IO）

// POSIX 文件系统语义的实 IO 夹具：`unique_temp_dir()` 在 Windows 产出盘符形状目录，
// `plan_host_install` 会按 POSIX 绝对路径判据**正确拒绝**（fail-closed，非产品缺陷）
// ⇒ 门控到 Unix；Windows 侧对等钉住见下方 `windows_binary_missing_fail_closed_zero_side_effects`。
#[cfg(unix)]
#[test]
fn posix_install_round_trip_read_back_identical_and_idempotent() {
    let install_root = unique_temp_dir("install-root");
    let host_bin = install_root.join("lengsuo-native-host");
    std::fs::write(&host_bin, b"").expect("写合成空文件作为宿主二进制夹具");
    let user_data_dir = unique_temp_dir("user-data");
    let req = HostInstallRequest {
        install_root: install_root.clone(),
        platform: Platform::Posix,
        user_data_dir: Some(user_data_dir.clone()),
    };

    let outcome = install_host_manifest(&req, &RefusingRunner).expect("安装必须成功");
    let manifest_file = Path::new(&outcome.manifest_file);
    assert!(manifest_file.is_file());

    let expected = expected_posix_manifest(&host_bin.to_string_lossy());
    let written = std::fs::read_to_string(manifest_file).expect("读回清单");
    assert_eq!(written, expected, "读回必须与手写期望逐字节相同");

    // 幂等：重复安装内容不变。
    install_host_manifest(&req, &RefusingRunner).expect("第二次安装必须成功");
    let again = std::fs::read_to_string(manifest_file).expect("清单必须仍在");
    assert_eq!(again, expected);
}

// ------------------------------------------------------------- Fail-closed

#[test]
fn install_root_must_be_absolute_on_both_platforms() {
    for (root, platform) in [
        (PathBuf::from("relative/root"), Platform::Posix),
        (PathBuf::from(r"relative\root"), Platform::Windows),
        (PathBuf::from(""), Platform::Posix),
    ] {
        let req = HostInstallRequest {
            install_root: root,
            platform,
            user_data_dir: Some(PathBuf::from("/abs")),
        };
        let err = plan_host_install(&req).expect_err("非绝对根必须被拒");
        assert!(
            matches!(err, HostInstallError::InstallRootNotAbsolute),
            "期望 InstallRootNotAbsolute，得到 {err:?}"
        );
    }
}

#[test]
fn posix_missing_user_data_dir_is_named_error() {
    let req = HostInstallRequest {
        install_root: PathBuf::from("/opt/lengsuo"),
        platform: Platform::Posix,
        user_data_dir: None,
    };
    let err = plan_host_install(&req).expect_err("缺 user_data_dir 必须被拒");
    assert!(matches!(err, HostInstallError::MissingUserDataDir));
}

#[cfg(unix)]
#[test]
fn host_binary_missing_fail_closed_zero_side_effects() {
    let install_root = unique_temp_dir("no-bin");
    let user_data_dir = unique_temp_dir("no-bin-udd");
    let req = HostInstallRequest {
        install_root,
        platform: Platform::Posix,
        user_data_dir: Some(user_data_dir.clone()),
    };
    let runner = RecordingRunner::default();

    let err = install_host_manifest(&req, &runner).expect_err("宿主二进制缺失必须失败");
    assert!(
        matches!(err, HostInstallError::HostBinaryMissing { .. }),
        "期望 HostBinaryMissing，得到 {err:?}"
    );
    // 零副作用：清单目录未产生，runner 未被调用。
    assert!(!user_data_dir.join(POSIX_USER_SUBDIR).exists());
    assert!(
        runner.commands.lock().unwrap().is_empty(),
        "runner 不得被调用"
    );
}

/// Windows 对等夹具（`#[cfg(windows)]`）：Windows 的 `unique_temp_dir()` 是盘符形状
/// ⇒ `Platform::Windows` 计划能走完整 fail-closed 路径：宿主二进制缺失 ⇒ `HostBinaryMissing`
/// 且 runner 零调用（Windows 的清单落点在注册表、经 runner 写入 ⇒ runner 未被调用即零副作用）。
/// 真正执行 `reg.exe` 落库属实机验证，测试不跑（见状态报告）。
#[cfg(windows)]
#[test]
fn windows_binary_missing_fail_closed_zero_side_effects() {
    let install_root = unique_temp_dir("no-bin-win");
    let req = HostInstallRequest {
        install_root,
        platform: Platform::Windows,
        user_data_dir: None,
    };
    let runner = RecordingRunner::default();

    let err = install_host_manifest(&req, &runner).expect_err("宿主二进制缺失必须失败");
    assert!(
        matches!(err, HostInstallError::HostBinaryMissing { .. }),
        "期望 HostBinaryMissing，得到 {err:?}"
    );
    assert!(
        runner.commands.lock().unwrap().is_empty(),
        "runner 不得被调用"
    );
}
