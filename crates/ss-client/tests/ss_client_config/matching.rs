//! 规则匹配与域名模式语义（`ss_client::config` 的匹配面）。

use ss_client::config::{load_config_str, Action, Match, MatchOutcome, Target};

use super::{config_with, FAKE_SS_URL};

/// 两条规则：域名命中 → direct；私网段 → proxy。
fn matching_config() -> ss_client::config::ClientConfig {
    load_config_str(&format!(
        "[outbound]\nss_url = \"{FAKE_SS_URL}\"\n\
         [dns]\ndirect = [\"192.0.2.1\"]\n\
         [[rules]]\nname = \"direct-example\"\naction = \"direct\"\n\
         match = {{ domain_mode = \"plain\", domain = [\"example.com\"] }}\n\
         [[rules]]\nname = \"proxy-lan\"\naction = \"proxy\"\n\
         match = {{ ip = [\"192.168.0.0/16\"] }}\n"
    ))
    .expect("matching config must load")
}

#[test]
fn rule_hit_selects_the_rule_action() {
    let config = matching_config();
    let target = Target {
        domain: Some("example.com"),
        ip: None,
        port: 443,
        network: Some("tcp"),
        process: None,
        protocol: None,
    };
    let decision = config.decide(&target);
    assert_eq!(decision.action, Action::Direct);
    assert_eq!(decision.rule.as_deref(), Some("direct-example"));
    assert!(!decision.needs_resolution);
}

#[test]
fn no_match_uses_the_explicit_fallback_action() {
    let config = matching_config();
    // 域名不命中；第二条规则依赖 IP 而目标未解析 ⇒ 无法判定 ⇒ 走 fallback。
    let target = Target {
        domain: Some("other.test"),
        ip: None,
        port: 443,
        network: Some("tcp"),
        process: None,
        protocol: None,
    };
    let decision = config.decide(&target);
    assert_eq!(decision.action, Action::Proxy, "fallback must be proxy");
    assert!(decision.rule.is_none(), "fallback must not name a rule");
    assert!(
        decision.needs_resolution,
        "an address-dependent rule with an unresolved target must ask for resolution"
    );
}

#[test]
fn address_dependent_rule_hits_once_the_address_is_known() {
    let config = matching_config();
    let target = Target {
        domain: Some("other.test"),
        ip: Some("192.168.1.5".parse().unwrap()),
        port: 443,
        network: Some("tcp"),
        process: None,
        protocol: None,
    };
    let decision = config.decide(&target);
    assert_eq!(decision.action, Action::Proxy);
    assert_eq!(decision.rule.as_deref(), Some("proxy-lan"));
    assert!(!decision.needs_resolution);
}

#[test]
fn first_matching_rule_wins() {
    let config = load_config_str(&format!(
        "[outbound]\nss_url = \"{FAKE_SS_URL}\"\n\
         [dns]\ndirect = [\"192.0.2.1\"]\n\
         [[rules]]\nname = \"first\"\naction = \"direct\"\n\
         match = {{ domain_mode = \"plain\", domain = [\"example.com\"] }}\n\
         [[rules]]\nname = \"second\"\naction = \"proxy\"\n\
         match = {{ domain_mode = \"plain\", domain = [\"example.com\"] }}\n"
    ))
    .unwrap();
    let target = Target {
        domain: Some("example.com"),
        ..Target::default()
    };
    assert_eq!(config.decide(&target).rule.as_deref(), Some("first"));
}

// ---------------------------------------------------------------- 域名模式语义

/// 对 `sub.example.com` 用给定模式与模式串做一次域名维度判定。
fn domain_match(mode: Option<&str>, pattern: &str) -> MatchOutcome {
    Match {
        domain_mode: mode.map(str::to_owned),
        domain: vec![pattern.to_owned()],
        ..Match::default()
    }
    .matches(&Target {
        domain: Some("sub.example.com"),
        ..Target::default()
    })
}

#[test]
fn domain_mode_semantics_are_distinct() {
    // plain = 整串相等：子域不命中。
    assert_eq!(
        domain_match(Some("plain"), "example.com"),
        MatchOutcome::NotMatched
    );
    assert_eq!(
        Match {
            domain_mode: Some("plain".to_owned()),
            domain: vec!["example.com".to_owned()],
            ..Match::default()
        }
        .matches(&Target {
            domain: Some("example.com"),
            ..Target::default()
        }),
        MatchOutcome::Matched
    );
    // keyword = 子串包含。
    assert_eq!(
        domain_match(Some("keyword"), "example.com"),
        MatchOutcome::Matched
    );
    // mapping = 后缀（域名本身或其子域）。
    assert_eq!(
        domain_match(Some("mapping"), "example.com"),
        MatchOutcome::Matched
    );
    // any = 该维度不限制。
    assert_eq!(
        domain_match(Some("any"), "example.com"),
        MatchOutcome::Matched
    );
    // 未给模式时按 plain 处理（不是「忽略域名列表」）。
    assert_eq!(domain_match(None, "example.com"), MatchOutcome::NotMatched);
}

#[test]
fn geo_prefixed_domains_are_undecided_not_guessed() {
    assert_eq!(
        domain_match(Some("mapping"), "geosite:youtube"),
        MatchOutcome::Undecided
    );
}

// ---------------------------------------------------------------- 端口维度

#[test]
fn port_dimension_selects_by_range() {
    let config = load_config_str(&config_with(
        "[[rules]]\nname = \"web\"\naction = \"proxy\"\nmatch = { port = [\"8000-9000\"] }\n",
    ))
    .unwrap();
    let hit = config.decide(&Target {
        port: 8443,
        ..Target::default()
    });
    assert_eq!(hit.rule.as_deref(), Some("web"));
    let miss = config.decide(&Target {
        port: 443,
        ..Target::default()
    });
    assert!(miss.rule.is_none());
}
