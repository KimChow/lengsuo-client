//! host manifest 渲染：逐字节等于向量里的手写字面量；五个字段、顺序固定、无空白/尾换行；
//! `allowed_origins` 只含本扩展；必填项缺失/非绝对路径 fail-closed。
//!
//! ⛔ 期望值是向量文件里**独立手写**的 JSON 文本，不是把渲染结果反过来当期望；
//! 直接按**逐字节相等**比（不折叠空白），因此实现换字段顺序或加空格都会被抓到。
//!
//! ⚠️ 本文件在 W3（本卡）**改了断言形状**：旧断言是「恰好两个字段」
//! （`name` + `allowed_origins`），而 Chromium 的解析器要求
//! `description`（`:85`）/ `type=="stdio"`（`:92-94`）/ `path`（`:100`）
//! ⇒ 旧形状**必被拒**。这是**缺陷修复**，不是为了让测试变绿而改测试：
//! 反向锚点见 `tests/host_register.rs` 顶部说明与本卡报告。

use lengsuo_native_host::manifest::{
    is_absolute_path, render_host_manifest, ManifestError, Platform, HOST_NAME, HOST_TYPE_STDIO,
};

fn vector() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/native-host-io-v1.json");
    serde_json::from_str(&std::fs::read_to_string(&path).expect("读不到向量文件"))
        .expect("向量文件必须是合法 JSON")
}

/// 向量里钉住的 `path` 是**合成** POSIX 绝对路径（见 `rendered_note`）。
const VECTORS_PLATFORM: Platform = Platform::Posix;

fn render_vector() -> String {
    let v = vector();
    render_host_manifest(
        v["host_manifest"]["path"].as_str().unwrap(),
        v["host_manifest"]["description"].as_str().unwrap(),
        VECTORS_PLATFORM,
    )
    .expect("向量里的合成 path 是 POSIX 绝对路径 ⇒ 必须渲染成功")
}

#[test]
fn rendered_bytes_equal_the_hand_written_literal() {
    let v = vector();
    let expected = v["host_manifest"]["rendered"].as_str().unwrap();
    assert_eq!(render_vector(), expected);
    // 无尾换行、无首尾空白。
    let text = render_vector();
    assert_eq!(text.trim(), text);
}

#[test]
fn rendered_json_has_exactly_five_fields_in_fixed_order() {
    let text = render_vector();
    // 逐字节比的字面量已钉住顺序，这里再按「出现位置递增」独立验一遍。
    let order = [
        "\"name\":",
        "\"description\":",
        "\"type\":",
        "\"path\":",
        "\"allowed_origins\":",
    ];
    let mut last = 0;
    for key in order {
        let at = text.find(key).unwrap_or_else(|| panic!("缺字段 {key}"));
        assert!(at >= last, "{key} 的位置跑到了前一个字段之前");
        last = at;
    }

    let rendered: serde_json::Value = serde_json::from_str(&text).unwrap();
    let object = rendered.as_object().unwrap();
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["allowed_origins", "description", "name", "path", "type"]
    );
    assert_eq!(object["name"].as_str(), Some(HOST_NAME));
    assert_eq!(object["name"].as_str(), Some("lengsuo.credential"));
    assert_eq!(
        object["name"].as_str(),
        vector()["host_manifest"]["name"].as_str()
    );
    assert_eq!(
        object["description"].as_str(),
        Some("Lengsuo credential vault host")
    );
    assert_eq!(
        object["path"].as_str(),
        Some("/opt/lengsuo/lengsuo-native-host")
    );
    // ⛔ host manifest 没有 `key` 字段（公钥属于扩展清单）。
    assert!(object.get("key").is_none(), "host manifest 不得带 key");
}

#[test]
fn type_is_exactly_stdio() {
    let rendered: serde_json::Value = serde_json::from_str(&render_vector()).unwrap();
    assert_eq!(rendered["type"].as_str(), Some("stdio"));
    assert_eq!(HOST_TYPE_STDIO, "stdio");
    // Chromium 只认这一个类型字面量（`:93-94`）。
    assert!(render_vector().contains("\"type\":\"stdio\""));
}

#[test]
fn allowed_origins_is_exactly_our_origin() {
    let rendered: serde_json::Value = serde_json::from_str(&render_vector()).unwrap();
    let origins = rendered["allowed_origins"].as_array().unwrap();
    assert_eq!(origins.len(), 1, "allowed_origins 只允许一项");
    assert_eq!(
        origins[0].as_str(),
        Some("chrome-extension://ejlmmjamfpkoopjachjhcbdjlddknhok/")
    );
    // 逐字节（含引号）也在渲染文本里。
    assert!(render_vector().contains(
        "\"allowed_origins\":[\"chrome-extension://ejlmmjamfpkoopjachjhcbdjlddknhok/\"]"
    ));
}

#[test]
fn no_wildcard_and_trailing_slash_kept() {
    let text = render_vector();
    assert!(!text.contains('*'), "⛔ 不得通配");
    assert!(!text.contains("all_urls"));
    // 每个 origin 都以 `/` 结尾。
    let rendered: serde_json::Value = serde_json::from_str(&text).unwrap();
    for origin in rendered["allowed_origins"].as_array().unwrap() {
        let origin = origin.as_str().unwrap();
        assert!(origin.ends_with('/'), "{origin} 必须带尾斜杠");
        assert!(origin.starts_with("chrome-extension://"));
    }
}

#[test]
fn no_token_whitespace_and_no_trailing_newline() {
    let text = render_vector();
    // 字符串**值内部**的空格是必需的（description 是自然语言）；这里禁的是
    // 字段之间的排版空白。
    assert!(!text.contains(": "), "字段值前不得有空格");
    assert!(!text.contains(", "), "字段之间不得有空格");
    assert!(!text.contains(",\n"));
    assert!(!text.ends_with('\n'), "不得有尾换行");
    assert!(!text.contains('\n') && !text.contains('\t'));
}

// ---------------------------------------------------------------- fail-closed

#[test]
fn empty_path_is_named_error() {
    let err = render_host_manifest("", "desc", Platform::Posix).unwrap_err();
    assert_eq!(err, ManifestError::EmptyPath);
    assert!(render_host_manifest("", "desc", Platform::Windows).is_err());
    // 错误文本可读且带具名变体（不是笼统字符串）。
    assert!(format!("{err}").contains("为空"));
}

#[test]
fn relative_path_is_rejected_on_both_platforms() {
    let cases = [
        ("opt/lengsuo/lengsuo-native-host", Platform::Posix),
        ("lengsuo-native-host", Platform::Windows),
        // Windows 上的 POSIX 绝对路径**不是** Windows 绝对路径。
        ("/opt/lengsuo/lengsuo-native-host", Platform::Windows),
        // POSIX 上的盘符路径**不是** POSIX 绝对路径。
        (r"C:\lengsuo\lengsuo-native-host.exe", Platform::Posix),
        // ⛔ 单个前导分隔符（无盘符）不是 Windows 绝对路径（`IsPathAbsolute` 同样拒）。
        (r"\lengsuo\lengsuo-native-host.exe", Platform::Windows),
        // 盘符不完整 / 缺分隔符（`IsPathAbsolute` 的盘符分支同样要求分隔符紧跟）。
        ("C:", Platform::Windows),
        ("C:x", Platform::Windows),
    ];
    for (path, platform) in cases {
        let err = render_host_manifest(path, "desc", platform).unwrap_err();
        match err {
            ManifestError::NotAbsolutePath {
                path: got,
                platform: got_p,
            } => {
                assert_eq!(got, path);
                assert_eq!(got_p, platform);
            }
            other => panic!("{path:?} / {platform:?} 期望 NotAbsolutePath，得到 {other:?}"),
        }
    }
}

#[test]
fn empty_description_is_named_error() {
    let err =
        render_host_manifest("/opt/lengsuo/lengsuo-native-host", "", Platform::Posix).unwrap_err();
    assert_eq!(err, ManifestError::EmptyDescription);
}

#[test]
fn absolute_path_predicate_covers_both_platform_families() {
    let posix_ok = [
        "/",
        "/opt/lengsuo/lengsuo-native-host",
        "/opt/a b/lengsuo native host",
        "/weird/./absolute",
    ];
    for p in posix_ok {
        assert!(
            is_absolute_path(p, Platform::Posix),
            "{p:?} 应判 POSIX 绝对"
        );
    }
    // `IsPathAbsolute`（Windows）真值表：盘符 + 紧跟分隔符，或**一对**前导分隔符
    // （分隔符 `\/` 都认）。
    let windows_ok = [
        r"C:\lengsuo\lengsuo-native-host.exe",
        "C:/lengsuo/lengsuo-native-host.exe",
        r"c:\x.exe",
        r"\\server\share\lengsuo-native-host.exe",
        r"\\?\C:\lengsuo\lengsuo-native-host.exe",
        "//weird/but/absolute",
        r"/\mixed/separators",
    ];
    for p in windows_ok {
        assert!(
            is_absolute_path(p, Platform::Windows),
            "{p:?} 应判 Windows 绝对"
        );
    }
    // 交叉：盘符 / UNC 形状在 POSIX **不**成立。
    for p in [
        r"C:\lengsuo\lengsuo-native-host.exe",
        "C:/lengsuo/lengsuo-native-host.exe",
        r"c:\x.exe",
        r"\\?\C:\lengsuo\lengsuo-native-host.exe",
    ] {
        assert!(
            !is_absolute_path(p, Platform::Posix),
            "{p:?} 不是 POSIX 绝对"
        );
    }
    // 交叉：POSIX 首字符 `/` 的普通形状在 Windows 不成立（未构成双前导分隔符）。
    for p in posix_ok {
        assert!(
            !is_absolute_path(p, Platform::Windows),
            "{p:?} 不是 Windows 绝对"
        );
    }
    for p in posix_ok {
        assert!(
            !is_absolute_path(p, Platform::Windows),
            "{p:?} 不是 Windows 绝对"
        );
    }
    // 边界：盘符不完整 / 缺分隔符 / 空 / 单前导分隔符。
    for p in ["C:", "C:x", "C", "", "1:\\x", r"\x", r"\"] {
        assert!(!is_absolute_path(p, Platform::Windows), "{p:?} 不该判绝对");
    }
    for p in ["", "x", "./x", "../x", "~/x"] {
        assert!(!is_absolute_path(p, Platform::Posix), "{p:?} 不该判绝对");
    }
}

// ------------------------------------------------------------------- 转义

#[test]
fn json_special_chars_are_escaped_not_rejected() {
    // 描述里的引号 / 反斜杠 / 控制字符 ⇒ 转义后仍是合法 JSON，解析回来逐字节相等。
    let desc = "say \"hi\" \\ back\\slash\nline\ttab\u{1}ctrl";
    let text = render_host_manifest("/opt/lengsuo/lengsuo-native-host", desc, Platform::Posix)
        .expect("转义（而不是拒绝）⇒ 必须成功");
    assert!(!text.contains('\n'), "控制字符必须已转义");
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("转义后必须是合法 JSON");
    assert_eq!(parsed["description"].as_str(), Some(desc));
    assert!(text.contains("\\u000a"), "换行应转成 \\u000a");
    assert!(text.contains("\\u0001"), "C0 控制字符应转成 \\u00XX");
}

#[test]
fn windows_backslash_path_survives_escaping() {
    // 选转义而非拒绝的**理由**：Windows 绝对路径天然含 `\`。
    let path = r"C:\Program Files\lengsuo\lengsuo-native-host.exe";
    let text =
        render_host_manifest(path, "desc", Platform::Windows).expect("Windows 路径必须可渲染");
    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed["path"].as_str(), Some(path), "转义后必须解析回原文");
    assert!(
        text.contains(r"C:\\Program Files"),
        "`\\` 应转成 `\\\\`（JSON 里写 `\\\\`）"
    );
}

#[test]
fn render_is_stable_across_calls() {
    assert_eq!(render_vector(), render_vector());
    assert_eq!(
        render_host_manifest("/opt/x", "d", Platform::Posix),
        render_host_manifest("/opt/x", "d", Platform::Posix)
    );
}
