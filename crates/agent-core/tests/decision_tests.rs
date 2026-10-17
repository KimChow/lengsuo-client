//! decision 模块测试（trait 语义/置信门/规则桩/结构校验）。

use agent_core::decision::{
    DecisionAnswer, DecisionProvider, DecisionQuestion, RuleBasedDecider, DEFAULT_CONFIDENCE_GATE,
    NONE_LABEL,
};

fn provider() -> RuleBasedDecider {
    RuleBasedDecider::default()
}

#[test]
fn choice_probabilities_sum_to_one_and_include_none() {
    let a = provider()
        .decide(&DecisionQuestion::Choice {
            state: "write the error log into the report".into(),
            options: vec!["fs.write".into(), "web.fetch".into()],
        })
        .expect("decide");
    assert_eq!(a.labels.len(), 3);
    assert_eq!(a.labels[2], NONE_LABEL);
    let sum: f32 = a.probabilities.iter().sum();
    assert!((sum - 1.0).abs() < 1e-4, "sum={sum}");
}

#[test]
fn keyword_hit_promotes_option() {
    let a = provider()
        .decide(&DecisionQuestion::Choice {
            state: "search the repo for files containing TODO".into(),
            options: vec!["fs.read".into(), "fs.search".into(), "web.fetch".into()],
        })
        .expect("decide");
    let (i, _) = a.top().expect("top");
    assert_eq!(a.labels[i], "fs.search", "关键词命中应提升搜索工具");
    assert!(a.confident, "命中且分布集中应过默认置信门 0.6");
}

#[test]
fn no_hit_defers_to_none() {
    let a = provider()
        .decide(&DecisionQuestion::Choice {
            state: "帮我写一首诗".into(),
            options: vec!["fs.write".into(), "exec.run".into()],
        })
        .expect("decide");
    assert_eq!(
        a.probability_of(NONE_LABEL),
        a.top().map(|(_, p)| p),
        "无命中 ⇒ NONE 应为最高"
    );
}

#[test]
fn noul_is_conservative_by_default() {
    let a = provider()
        .decide(&DecisionQuestion::Noul {
            state: "环境 A".into(),
            question: "放行该写操作".into(),
        })
        .expect("decide");
    let no = a.probability_of("no").expect("no label");
    let yes = a.probability_of("yes").expect("yes label");
    assert!(no >= yes, "保守缺省应偏 no");
    // 自信时必须自信在 no 上（自信地说 yes 才是危险方向）
    assert!(
        !a.confident || a.top().map(|(i, _)| a.labels[i].as_str()) == Some("no"),
        "保守桩不得自信地偏向 yes"
    );
}

#[test]
fn noul_affirmative_flips() {
    let a = provider()
        .decide(&DecisionQuestion::Noul {
            state: "该工具在白名单".into(),
            question: "已授权的动作".into(),
        })
        .expect("decide");
    assert!(a.probability_of("yes").expect("yes") > a.probability_of("no").expect("no"));
}

#[test]
fn score_is_uniform() {
    let a = provider()
        .decide(&DecisionQuestion::Score {
            state: "x".into(),
            levels: vec!["低".into(), "中".into(), "高".into()],
        })
        .expect("decide");
    for p in &a.probabilities {
        assert!((p - 1.0 / 3.0).abs() < 1e-4);
    }
    assert!(!a.confident, "均匀分布不过 0.6 门");
}

#[test]
fn confidence_gate_flags_low_top() {
    let a = DecisionAnswer::normalized(
        vec!["a".into(), "b".into()],
        vec![0.5, 0.5],
        DEFAULT_CONFIDENCE_GATE,
        "t",
    )
    .expect("answer");
    assert!(!a.confident, "top=0.5 < 0.6 ⇒ 需深思");
}

#[test]
fn validate_rejects_bad_answers() {
    let mut bad =
        DecisionAnswer::normalized(vec!["a".into(), "b".into()], vec![0.6, 0.4], 0.6, "t")
            .expect("answer");
    bad.probabilities = vec![0.6];
    assert!(bad.validate().is_err(), "标签/概率数量不一致");
    bad.probabilities = vec![0.5, 0.2];
    assert!(bad.validate().is_err(), "总和偏离 1");
}

#[test]
fn trait_object_dispatch() {
    let provider: Box<dyn DecisionProvider> = Box::new(RuleBasedDecider::default());
    let a = provider
        .decide(&DecisionQuestion::Choice {
            state: "read the file content".into(),
            options: vec!["fs.read".into(), "fs.write".into()],
        })
        .expect("decide");
    let (i, _) = a.top().expect("top");
    assert_eq!(a.labels[i], "fs.read");
}

#[test]
fn empty_options_rejected() {
    let err = provider().decide(&DecisionQuestion::Choice {
        state: "s".into(),
        options: vec![],
    });
    assert!(err.is_err());
}
