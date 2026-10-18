//! §5.1 compose：三层记忆 + 身份 + 当日日志的组装语义。

use std::fs;

use agent_memory::{append_daily, Identity, MemoryError};

use crate::{days_before, default_identity, today, TempDir};

#[test]
fn compose_on_empty_dir_returns_default_identity_and_no_layers() {
    // 目录完全不存在（既无身份文件也无记忆文件）：缺失 = 空内容，不是错误（规格 §1）。
    let dir = TempDir::new("empty");
    let bundle = dir.engine(true).compose().expect("空目录不得报错");

    assert_eq!(
        bundle.identity,
        default_identity(),
        "身份缺省名未按规格填充"
    );
    assert_eq!(bundle.user_memory, None);
    assert_eq!(bundle.project_memory, None);
    assert_eq!(bundle.daily_tail, None);
}

#[test]
fn compose_with_all_layers_present_fills_every_field() {
    let dir = TempDir::new("all-layers");
    let paths = dir.paths();
    let day = today();

    dir.put(
        &dir.identity_dir().join("SOUL.md"),
        "冷静、克制、先复现再动手",
    );
    dir.put(&dir.identity_dir().join("USER.md"), "  阿澜 \n"); // 读取时 trim
    dir.put(&dir.identity_dir().join("AI_NAME"), "小索");
    dir.put(&dir.user_memory(), "偏好：中文回复；不碰危险命令。\n");
    dir.put(&dir.project_memory(), "本仓 Rust 网络面；无 unsafe。\n");
    append_daily(&paths, day, "完成分层实现").expect("当日日志写入");

    let bundle = dir.engine(true).compose().expect("compose 失败");

    assert_eq!(
        bundle.identity,
        Identity {
            ai_name: "小索".into(),
            user_name: "阿澜".into(),
            soul: "冷静、克制、先复现再动手".into(),
        },
        "身份层未从文件填充（或 trim 语义不符）"
    );
    assert_eq!(
        bundle.user_memory.as_deref(),
        Some("偏好：中文回复；不碰危险命令。\n")
    );
    assert_eq!(
        bundle.project_memory.as_deref(),
        Some("本仓 Rust 网络面；无 unsafe。\n")
    );
    assert_eq!(bundle.daily_tail.as_deref(), Some("完成分层实现"));
}

#[test]
fn compose_does_not_inject_a_non_today_daily_file() {
    // 规格 §3：daily_tail 只取当日文件；昨日日志存在也必须是 None。
    let dir = TempDir::new("not-today");
    let paths = dir.paths();
    let stale = days_before(today(), 1);
    append_daily(&paths, stale, "昨天的日志").expect("昨日日志写入");

    let bundle = dir.engine(true).compose().expect("compose 失败");
    assert_eq!(bundle.daily_tail, None, "非当日日志被注入");
}

#[test]
fn compose_distinguishes_missing_layer_from_empty_layer() {
    // 缺失 ⇒ None（不注入）；存在但为空 ⇒ Some("")（这一层确实在，只是正文为空）。
    let dir = TempDir::new("missing-vs-empty");
    let engine = dir.engine(true);
    assert_eq!(engine.compose().unwrap().user_memory, None);

    dir.put(&dir.user_memory(), "");
    let bundle = engine.compose().expect("compose 失败");
    assert_eq!(bundle.user_memory.as_deref(), Some(""));
    assert_eq!(bundle.project_memory, None);
}

#[test]
fn compose_fails_closed_when_a_layer_is_unreadable() {
    // fail-closed：单层 IO 失败 ⇒ 整体 Err 上抛，不 panic、不静默降级成 None（规格 §3）。
    let dir = TempDir::new("unreadable-layer");
    let engine = dir.engine(true);
    // 把用户记忆路径占成目录：read_to_string 必失败（Is a directory）。
    fs::create_dir_all(dir.user_memory()).unwrap();

    let err = engine.compose().expect_err("目录占位必须上抛 IO 错误");
    match err {
        MemoryError::Io { path, .. } => assert_eq!(path, dir.user_memory()),
        other => panic!("期望 Io 变体，实际 {other:?}"),
    }
}
