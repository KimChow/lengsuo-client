//! `ss_client::config` 的激活验收用例。
//!
//! 覆盖 `docs/ss-client-config-activate.md` 要求的表：
//! 默认值与必填项缺失、规则动作集合、端口区间、带宽上限、
//! `load_config` 文件缺失 / 格式错、规则可命中与无匹配时的默认动作。
//!
//! **凭据纪律**：本文件只出现**测试专用假值** —— 口令是
//! `TESTONLY-PASSWORD-DO-NOT-ECHO`，地址是 RFC 5737 文档保留段
//! `203.0.113.0/24` / `192.0.2.0/24` / `198.51.100.0/24`，无真实服务器与真实口令。

// 集成测试的 crate root 在 `tests/` 下，`mod` 的相对路径基准是 `tests/`，
// 故用 `#[path]` 指到子目录（rustfmt 会照常格式化 `#[path]` 文件）。
#[path = "ss_client_config/matching.rs"]
mod matching;

use ss_client::config::{load_config, load_config_str, Action, PortRange};
use ss_client::error::{ConfigError, Error};

/// 假出口：`203.0.113.7` 是 RFC 5737 TEST-NET-3，口令是显式假值。
const FAKE_SS_URL: &str = "ss://aes-256-gcm:TESTONLY-PASSWORD-DO-NOT-ECHO@203.0.113.7:8388";
/// 假口令的独立片段，用于断言「错误消息不回显口令」。
const FAKE_SECRET: &str = "TESTONLY-PASSWORD-DO-NOT-ECHO";

/// 拼一份配置文本。
///
/// `extra` 放在**最前**：TOML 语义下「表头之后的裸键属于该表」，
/// 所以顶层键（`fallback` / `rules`）必须写在任何表头之前。
pub(crate) fn config_with(extra: &str) -> String {
    format!("{extra}\n[outbound]\nss_url = \"{FAKE_SS_URL}\"\n")
}

// ---------------------------------------------------------------- 默认值 / 必填项

#[test]
fn minimal_config_uses_documented_defaults() {
    let config = load_config_str(&config_with("")).expect("minimal config must load");
    assert!(!config.outbound.udp, "udp defaults to false");
    assert!(!config.outbound.mux.enabled, "mux defaults to disabled");
    assert_eq!(config.outbound.mux.max_connections, 8);
    assert_eq!(config.outbound.connect_timeout_ms, 5_000);
    assert!(
        config.dns.direct_use_system,
        "dns.direct_use_system defaults to true"
    );
    assert!(config.dns.direct.is_empty());
    assert!(config.rules.is_empty());
    assert_eq!(config.fallback, Action::Proxy, "fallback defaults to proxy");
    assert!(config.direct_allow_private);
    assert!(config.geoip_dir.is_none());
    assert!(config.geosite_dir.is_none());
}

#[test]
fn missing_outbound_is_err_not_default_fallback() {
    let err = load_config_str("[dns]\ndirect = [\"192.0.2.1\"]\n").unwrap_err();
    assert!(matches!(
        err,
        Error::Config(ConfigError::Missing("outbound"))
    ));
}

#[test]
fn missing_ss_url_is_err_not_default_fallback() {
    let err = load_config_str("[outbound]\nudp = true\n").unwrap_err();
    assert!(matches!(
        err,
        Error::Config(ConfigError::Missing("outbound.ss_url"))
    ));
}

#[test]
fn empty_ss_url_is_err() {
    let err = load_config_str("[outbound]\nss_url = \"\"\n").unwrap_err();
    assert!(matches!(err, Error::Config(ConfigError::Invalid { .. })));
}

#[test]
fn missing_rule_name_or_action_is_err() {
    let err = load_config_str(&config_with(
        "[[rules]]\naction = \"proxy\"\nmatch = { port = [\"443\"] }\n",
    ))
    .unwrap_err();
    assert!(matches!(
        err,
        Error::Config(ConfigError::Missing("rules.name"))
    ));

    let err = load_config_str(&config_with(
        "[[rules]]\nname = \"x\"\nmatch = { port = [\"443\"] }\n",
    ))
    .unwrap_err();
    assert!(matches!(
        err,
        Error::Config(ConfigError::Missing("rules.action"))
    ));
}

// ---------------------------------------------------------------- 动作集合

#[test]
fn rule_action_allows_only_direct_or_proxy() {
    for bad in ["block", "reject", "bypass", "DIRECT", "Proxy", ""] {
        let err = load_config_str(&config_with(&format!(
            "[[rules]]\nname = \"x\"\naction = \"{bad}\"\nmatch = {{ port = [\"443\"] }}\n"
        )))
        .unwrap_err();
        assert!(
            matches!(err, Error::Config(ConfigError::UnsupportedAction { .. })),
            "action `{bad}` must be rejected, got {err:?}"
        );
    }
}

#[test]
fn fallback_action_allows_only_direct_or_proxy() {
    for bad in ["block", "reject", ""] {
        let err = load_config_str(&config_with(&format!("fallback = \"{bad}\"\n"))).unwrap_err();
        assert!(
            matches!(err, Error::Config(ConfigError::UnsupportedAction { .. })),
            "fallback `{bad}` must be rejected, got {err:?}"
        );
    }
}

#[test]
fn direct_rule_without_any_resolver_is_rejected() {
    let err = load_config_str(&config_with(
        "[[rules]]\nname = \"x\"\naction = \"direct\"\nmatch = { port = [\"443\"] }\n\
         [dns]\ndirect_use_system = false\n",
    ))
    .unwrap_err();
    assert!(matches!(err, Error::Config(ConfigError::Invalid { .. })));
}

// ---------------------------------------------------------------- 端口区间

#[test]
fn port_matcher_rejects_zero_overflow_and_reversed_range() {
    for bad in ["0", "65536", "99999", "9000-8000", "-0", "0-0"] {
        let err = load_config_str(&config_with(&format!(
            "[[rules]]\nname = \"x\"\naction = \"proxy\"\nmatch = {{ port = [\"{bad}\"] }}\n"
        )))
        .unwrap_err();
        assert!(
            matches!(err, Error::Config(ConfigError::Invalid { .. })),
            "port `{bad}` must be rejected, got {err:?}"
        );
    }
}

#[test]
fn port_matcher_accepts_single_and_range() {
    let config = load_config_str(&config_with(
        "[[rules]]\nname = \"x\"\naction = \"proxy\"\nmatch = { port = [\"443\", \"8000-9000\"] }\n",
    ))
    .expect("valid ports must load");
    assert_eq!(
        config.rules[0].match_.port,
        vec![
            PortRange {
                start: 443,
                end: 443
            },
            PortRange {
                start: 8_000,
                end: 9_000
            },
        ]
    );
}

// ---------------------------------------------------------------- 带宽上限

#[test]
fn bandwidth_limits_have_explicit_boundary_behaviour() {
    // 0 = 不限制；类型上限原样接受（不静默截断）。
    let config = load_config_str(&config_with(
        "[[rules]]\nname = \"x\"\naction = \"proxy\"\nmatch = { port = [\"443\"] }\n\
         max_download_kbps = 0\nper_conn_download_kbps = 4294967295\nmax_concurrent = 0\n",
    ))
    .expect("boundary bandwidth must load");
    assert_eq!(config.rules[0].max_download_kbps, 0);
    assert_eq!(config.rules[0].per_conn_download_kbps, u32::MAX);
    assert_eq!(config.rules[0].max_concurrent, 0);

    // 越界即拒绝。
    let err = load_config_str(&config_with(
        "[[rules]]\nname = \"x\"\naction = \"proxy\"\nmatch = { port = [\"443\"] }\n\
         max_download_kbps = 4294967296\n",
    ))
    .unwrap_err();
    assert!(matches!(err, Error::Config(ConfigError::Invalid { .. })));
}

// ---------------------------------------------------------------- load_config

#[test]
fn load_config_missing_file_returns_typed_error() {
    let err = load_config("/nonexistent/ss-client-config-activate/missing.toml").unwrap_err();
    assert!(
        matches!(err, Error::Config(ConfigError::Read { .. })),
        "missing file must be a typed read error, got {err:?}"
    );
}

#[test]
fn load_config_empty_path_is_rejected() {
    let err = load_config("   ").unwrap_err();
    assert!(matches!(err, Error::Config(ConfigError::Invalid { .. })));
}

#[test]
fn load_config_malformed_file_returns_typed_error_without_echoing_password() {
    let path = write_temp(
        "malformed",
        "[outbound]\nss_url = \"ss://aes-256-gcm:SECRET\n",
    );
    let err = load_config(path.to_str().unwrap()).unwrap_err();
    assert!(
        matches!(err, Error::Config(ConfigError::ParseFile { .. })),
        "malformed file must be a typed parse error, got {err:?}"
    );
    let message = err.to_string();
    assert!(
        !message.contains("SECRET"),
        "parse error must not echo the credential: {message}"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn load_config_str_malformed_returns_typed_error() {
    let err = load_config_str("[outbound\nss_url = 1\n").unwrap_err();
    assert!(
        matches!(err, Error::Config(ConfigError::Parse { .. })),
        "malformed text must be a typed parse error, got {err:?}"
    );
}

#[test]
fn load_config_reads_a_real_file() {
    let path = write_temp("ok", &config_with(""));
    let config = load_config(path.to_str().unwrap()).expect("valid file must load");
    assert_eq!(config.outbound.ss_url, FAKE_SS_URL);
    assert_eq!(config.fallback, Action::Proxy);
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------- 凭据不泄漏

#[test]
fn error_messages_never_echo_the_password() {
    // URL 形状不对（缺端口）。
    let err = load_config_str(
        "[outbound]\nss_url = \"ss://aes-256-gcm:TESTONLY-PASSWORD-DO-NOT-ECHO@203.0.113.7\"\n",
    )
    .unwrap_err();
    assert!(!err.to_string().contains(FAKE_SECRET));

    // 加密名不支持。
    let err = load_config_str(
        "[outbound]\nss_url = \"ss://rc4-md5:TESTONLY-PASSWORD-DO-NOT-ECHO@203.0.113.7:8388\"\n",
    )
    .unwrap_err();
    assert!(!err.to_string().contains(FAKE_SECRET));

    // 口令为空。
    let err = load_config_str("[outbound]\nss_url = \"ss://aes-256-gcm:@203.0.113.7:8388\"\n")
        .unwrap_err();
    assert!(!err.to_string().contains(FAKE_SECRET));
}

#[test]
fn debug_output_redacts_the_password() {
    let config = load_config_str(&config_with("")).unwrap();
    let dump = format!("{config:?}");
    assert!(
        !dump.contains(FAKE_SECRET),
        "Debug must not leak the password: {dump}"
    );
    assert!(
        dump.contains("***"),
        "Debug must show a redaction marker: {dump}"
    );

    let outbound = format!("{:?}", config.outbound);
    assert!(!outbound.contains(FAKE_SECRET));
    assert!(outbound.contains("ss://aes-256-gcm:***@203.0.113.7:8388"));
}

// ---------------------------------------------------------------- 其它拒绝项

#[test]
fn unknown_match_field_is_rejected() {
    let err = load_config_str(&config_with(
        "[[rules]]\nname = \"x\"\naction = \"proxy\"\nmatch = { domainz = [\"a.test\"] }\n",
    ))
    .unwrap_err();
    assert!(matches!(err, Error::Config(ConfigError::Invalid { .. })));
}

#[test]
fn duplicate_rule_name_is_rejected() {
    let err = load_config_str(&config_with(
        "[[rules]]\nname = \"dup\"\naction = \"proxy\"\nmatch = { port = [\"443\"] }\n\
         [[rules]]\nname = \"dup\"\naction = \"proxy\"\nmatch = { port = [\"8443\"] }\n",
    ))
    .unwrap_err();
    assert!(matches!(err, Error::Config(ConfigError::DuplicateRule(_))));
}

#[test]
fn cidr_with_host_bits_set_is_rejected() {
    let err = load_config_str(&config_with(
        "[[rules]]\nname = \"x\"\naction = \"proxy\"\nmatch = { ip = [\"192.168.1.5/16\"] }\n",
    ))
    .unwrap_err();
    assert!(matches!(err, Error::Config(ConfigError::Invalid { .. })));
}

#[test]
fn bad_domain_mode_is_rejected() {
    let err = load_config_str(&config_with(
        "[[rules]]\nname = \"x\"\naction = \"proxy\"\n\
         match = { domain_mode = \"suffix\", domain = [\"a.test\"] }\n",
    ))
    .unwrap_err();
    assert!(matches!(err, Error::Config(ConfigError::Invalid { .. })));
}

#[test]
fn unsupported_cipher_is_rejected_at_load_time() {
    let err = load_config_str(
        "[outbound]\nss_url = \"ss://aes-192-gcm:TESTONLY-PASSWORD-DO-NOT-ECHO@203.0.113.7:8388\"\n",
    )
    .unwrap_err();
    assert!(matches!(err, Error::Config(ConfigError::Invalid { .. })));
}

// ---------------------------------------------------------------- TOML 两种规则写法

#[test]
fn rules_accept_both_array_of_tables_and_inline_array() {
    let aot = load_config_str(&config_with(
        "[[rules]]\nname = \"x\"\naction = \"proxy\"\nmatch = { port = [\"443\"] }\n",
    ))
    .unwrap();
    let inline = load_config_str(&config_with(
        "rules = [{ name = \"x\", action = \"proxy\", match = { port = [\"443\"] } }]\n",
    ))
    .unwrap();
    assert_eq!(aot.rules.len(), 1);
    assert_eq!(inline.rules.len(), 1);
    assert_eq!(aot.rules[0].name, inline.rules[0].name);
    assert_eq!(aot.rules[0].match_.port, inline.rules[0].match_.port);
}

// ---------------------------------------------------------------- 夹具

/// 写一个临时配置文件（假值），返回路径。
pub(crate) fn write_temp(name: &str, contents: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "ss-client-config-activate-{}-{name}.toml",
        std::process::id()
    ));
    std::fs::write(&path, contents).expect("temp config must be writable");
    path
}
