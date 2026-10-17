//! 规格 §1 数据模型的 serde 契约测试：字段名、枚举数值、缺省值与 fail-closed 拒绝分支。

use policy_engine::model::{
    Action, Actions, ActiveRange, EmptyStrategyDefault, PolicyMode, PolicySpec, RuleItem, Targets,
};

const MODE_ALL: u8 = 1;
const MODE_SOME_BLACK: u8 = 2;
const MODE_SOME_WHITE: u8 = 3;
const MODE_SPECIAL_CASE: u8 = 4;

/// 最小可用策略 JSON：只有必填字段。
const MINIMAL_POLICY_JSON: &str = r#"{
    "policy_id": "p-1",
    "name": "全放行",
    "mode": 1,
    "targets": { "user_ids": [], "role_ids": [], "dept_ids": [], "account_ids": [] },
    "rules": []
}"#;

/// 完整策略 JSON：用于验证每个字段的线格式。
const FULL_POLICY_JSON: &str = r##"{
    "policy_id": "p-9",
    "name": "特殊案例",
    "mode": 4,
    "strategy_empty_default": 1,
    "targets": {
        "user_ids": ["u-1"],
        "role_ids": ["r-2"],
        "dept_ids": ["d-3"],
        "account_ids": ["a-4"]
    },
    "rules": [
        {
            "url_pattern": "*.example.com/*",
            "is_accessible": false,
            "is_log": true,
            "actions": {
                "access": true,
                "clipboard": false,
                "file_upload": false,
                "file_download": false,
                "print": false,
                "console": false,
                "click_dom": true
            },
            "dom_selectors": ["#download-btn"]
        }
    ],
    "active_range": { "start_ms": 1000, "end_ms": 2000 }
}"##;

#[test]
fn policy_mode_wire_values_are_frozen_numbers() {
    let cases = [
        (PolicyMode::All, MODE_ALL),
        (PolicyMode::SomeBlack, MODE_SOME_BLACK),
        (PolicyMode::SomeWhite, MODE_SOME_WHITE),
        (PolicyMode::SpecialCase, MODE_SPECIAL_CASE),
    ];
    for (mode, number) in cases {
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, number.to_string(), "{mode:?} 必须序列化为冻结数值");
        let back: PolicyMode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, mode);
    }
}

#[test]
fn policy_mode_rejects_unknown_numbers_fail_closed() {
    for json in ["0", "5", "255", "-1", r#""ALL""#, "null"] {
        let parsed: Result<PolicyMode, _> = serde_json::from_str(json);
        assert!(parsed.is_err(), "未知 mode {json} 必须拒绝，不得回退默认值");
    }
}

#[test]
fn empty_strategy_default_is_black_and_only_variant() {
    let parsed: EmptyStrategyDefault = serde_json::from_str("1").unwrap();
    assert_eq!(parsed, EmptyStrategyDefault::Black);
    let json = serde_json::to_string(&EmptyStrategyDefault::Black).unwrap();
    assert_eq!(json, "1");
    // 0（缺省哨兵）、2（White 未实现）以及字符串都必须拒绝。
    for bad in ["0", "2", r#""White""#] {
        assert!(
            serde_json::from_str::<EmptyStrategyDefault>(bad).is_err(),
            "未知 empty-strategy 默认值 {bad} 必须拒绝"
        );
    }
}

#[test]
fn targets_field_names_are_frozen_on_the_wire() {
    let targets: Targets = serde_json::from_str(
        r#"{ "user_ids": ["u"], "role_ids": ["r"], "dept_ids": ["d"], "account_ids": ["a"] }"#,
    )
    .unwrap();
    assert_eq!(targets.user_ids, vec!["u".to_string()]);
    assert_eq!(targets.role_ids, vec!["r".to_string()]);
    assert_eq!(targets.dept_ids, vec!["d".to_string()]);
    assert_eq!(targets.account_ids, vec!["a".to_string()]);

    let json = serde_json::to_string(&targets).unwrap();
    for key in ["user_ids", "role_ids", "dept_ids", "account_ids"] {
        assert!(json.contains(key), "序列化必须使用冻结字段名 {key}: {json}");
    }
    assert!(!json.contains("userId"), "不得出现驼峰变体: {json}");
}

#[test]
fn minimal_policy_applies_blacklist_empty_default_and_no_window() {
    let policy: PolicySpec = serde_json::from_str(MINIMAL_POLICY_JSON).unwrap();
    assert_eq!(policy.policy_id, "p-1");
    assert_eq!(policy.name, "全放行");
    assert_eq!(policy.mode, PolicyMode::All);
    assert_eq!(policy.rules.len(), 0);
    assert_eq!(policy.active_range, None);
    // 规格 §1：strategy 为空 ⇒ 默认黑名单模式（实证），缺省值即 Black。
    assert_eq!(policy.strategy_empty_default, EmptyStrategyDefault::Black);
    assert!(policy.targets.is_empty());

    let back = serde_json::to_string(&policy).unwrap();
    let round: PolicySpec = serde_json::from_str(&back).unwrap();
    assert_eq!(round, policy);
}

#[test]
fn full_policy_roundtrips_every_spec_field() {
    let policy: PolicySpec = serde_json::from_str(FULL_POLICY_JSON).unwrap();
    assert_eq!(policy.mode, PolicyMode::SpecialCase);
    assert_eq!(
        policy.active_range,
        Some(ActiveRange::checked_new(1000, 2000).unwrap())
    );
    assert_eq!(policy.rules.len(), 1);

    let rule: &RuleItem = &policy.rules[0];
    assert_eq!(rule.url_pattern, "*.example.com/*");
    assert!(!rule.is_accessible);
    assert!(rule.is_log);
    assert_eq!(rule.dom_selectors, vec!["#download-btn".to_string()]);
    assert!(rule.actions.access);
    assert!(rule.actions.click_dom);
    assert!(!rule.actions.clipboard);
    assert!(!rule.actions.file_upload);
    assert!(!rule.actions.file_download);
    assert!(!rule.actions.print);
    assert!(!rule.actions.console);

    let json = serde_json::to_string(&policy).unwrap();
    assert_eq!(serde_json::from_str::<PolicySpec>(&json).unwrap(), policy);
    for key in [
        "policy_id",
        "name",
        "mode",
        "strategy_empty_default",
        "targets",
        "rules",
        "active_range",
        "url_pattern",
        "is_accessible",
        "is_log",
        "actions",
        "dom_selectors",
        "start_ms",
        "end_ms",
    ] {
        assert!(json.contains(key), "序列化缺少规格字段 {key}: {json}");
    }
}

#[test]
fn actions_default_to_all_denied_and_are_never_implicitly_granted() {
    let actions: Actions = serde_json::from_str("{}").unwrap();
    assert_eq!(
        actions,
        Actions::none(),
        "actions 缺省必须全 false（deny-by-default）"
    );
    assert!(!actions.access);
    assert!(!actions.clipboard);
    assert!(!actions.file_upload);
    assert!(!actions.file_download);
    assert!(!actions.print);
    assert!(!actions.console);
    assert!(!actions.click_dom);

    let all = Actions::all();
    assert!(all.access && all.print && all.console && all.click_dom);
}

#[test]
fn mandatory_rule_fields_without_defaults_are_rejected() {
    // url_pattern 与 is_accessible 没有安全缺省，缺失即拒绝（fail-closed）。
    for bad in [
        r#"{ "is_accessible": true }"#,
        r#"{ "url_pattern": "*.a.com/*" }"#,
        r#"{ "url_pattern": "*.a.com/*", "is_accessible": "true" }"#,
    ] {
        assert!(
            serde_json::from_str::<RuleItem>(bad).is_err(),
            "必填字段缺失或类型错误必须拒绝: {bad}"
        );
    }
}

#[test]
fn active_range_requires_ordered_bounds() {
    assert!(serde_json::from_str::<ActiveRange>(r#"{ "start_ms": 5, "end_ms": 9 }"#).is_ok());
    assert!(serde_json::from_str::<ActiveRange>(r#"{ "start_ms": 9, "end_ms": 9 }"#).is_ok());
    // 反向区间是配置错误，构造期拒绝，不静默当作“永不生效”或“总是生效”。
    assert!(serde_json::from_str::<ActiveRange>(r#"{ "start_ms": 9, "end_ms": 5 }"#).is_err());
    assert!(serde_json::from_str::<ActiveRange>(r#"{ "start_ms": -1, "end_ms": 5 }"#).is_err());
}

#[test]
fn policy_level_active_range_absent_defaults_to_no_window() {
    let policy: PolicySpec = serde_json::from_str(MINIMAL_POLICY_JSON).unwrap();
    let json = serde_json::to_string(&policy).unwrap();
    // None 序列化为显式 null，便于线格式审查；审查者不需要猜缺省语义。
    assert!(
        json.contains(r#""active_range":null"#),
        "缺省窗口必须显式写出: {json}"
    );

    // 字段整体省略与显式 null 都必须解析为「无时间窗」。
    let without_field: PolicySpec = serde_json::from_str(
        r#"{ "policy_id": "p", "name": "n", "mode": 2, "targets": {
                "user_ids": [], "role_ids": [], "dept_ids": [], "account_ids": [] },
             "rules": [] }"#,
    )
    .unwrap();
    assert_eq!(without_field.active_range, None);
    assert_eq!(without_field.mode, PolicyMode::SomeBlack);
}

#[test]
fn unknown_fields_are_rejected_instead_of_being_ignored() {
    // 契约冻结：拼错或夹带的未知字段必须报错，不能静默忽略后按缺省值执行。
    let with_extra = MINIMAL_POLICY_JSON.replace(
        "\"name\": \"全放行\",",
        "\"name\": \"全放行\", \"whitelist_all\": true,",
    );
    assert!(serde_json::from_str::<PolicySpec>(&with_extra).is_err());

    let rule = r#"{ "url_pattern": "*.a.com/*", "is_accessible": true }"#;
    assert!(serde_json::from_str::<RuleItem>(&rule.replace(
        r#""is_accessible": true"#,
        r#""is_accessible": true, "allow_all_actions": true"#
    ))
    .is_err());
    assert!(serde_json::from_str::<Actions>(r#"{ "access": true, "xxx": 1 }"#).is_err());
    assert!(
        serde_json::from_str::<Targets>(r#"{ "user_ids": [], "role_ids": [], "dept_ids": [] }"#)
            .is_err(),
        "四个生效对象字段必须齐备（缺一个即配置错误）"
    );
}

#[test]
fn action_wire_names_match_actions_object_keys() {
    for (action, key) in [
        (Action::Access, "access"),
        (Action::Clipboard, "clipboard"),
        (Action::FileUpload, "file_upload"),
        (Action::FileDownload, "file_download"),
        (Action::Print, "print"),
        (Action::Console, "console"),
        (Action::ClickDom, "click_dom"),
    ] {
        assert_eq!(
            action.as_str(),
            key,
            "操作名必须与 RuleActions 的键一一对应"
        );
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, format!(r#""{key}""#));
        assert_eq!(serde_json::from_str::<Action>(&json).unwrap(), action);
        assert_eq!(Action::parse(key).unwrap(), action);
    }
    assert!(Action::parse("read_file").is_none(), "未知操作名必须拒绝");
}
