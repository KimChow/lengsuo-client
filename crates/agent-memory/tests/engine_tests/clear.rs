//! §2 删除能力：清空后 compose 变回 None，且不受开关限制。

use crate::TempDir;

#[test]
fn clearing_memory_layers_makes_compose_return_none_again() {
    // 规格 §2：提供查看与删除能力；删除后对应层在 compose 中变回 None。
    let dir = TempDir::new("clear");
    let engine = dir.engine(true);
    engine.set_user_memory("用户记忆正文").unwrap();
    engine.set_project_memory("项目记忆正文").unwrap();
    assert!(engine.compose().unwrap().user_memory.is_some());
    assert!(engine.compose().unwrap().project_memory.is_some());

    engine.clear_user_memory().unwrap();
    engine.clear_project_memory().unwrap();
    let bundle = engine.compose().unwrap();
    assert_eq!(bundle.user_memory, None);
    assert_eq!(bundle.project_memory, None);
    assert!(!dir.exists(&dir.user_memory()));
    assert!(!dir.exists(&dir.project_memory()));

    // 幂等：再删一次仍是 Ok（不存在视为已清空）。
    engine.clear_user_memory().unwrap();
    engine.clear_project_memory().unwrap();
}

#[test]
fn clearing_works_even_when_memory_is_disabled() {
    // 隐私优先于开关字面语义：跨会话记忆关掉之后，历史残留仍必须能删。
    let dir = TempDir::new("clear-disabled");
    dir.engine(true).set_user_memory("待清除").unwrap();

    let off = dir.engine(false);
    off.clear_user_memory().unwrap();
    assert!(!dir.exists(&dir.user_memory()));
    assert_eq!(off.compose().unwrap().user_memory, None);
}
