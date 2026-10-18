//! §5.2 开关：`enabled=false` 压制三层记忆读写，但不影响身份层。

use agent_memory::{append_daily, Identity, MemoryBundle};

use crate::{assert_disabled, default_identity, today, TempDir};

#[test]
fn disabled_engine_composes_identity_only() {
    // enabled=false：三层文件都在盘上也一律不注入（规格 §2 隐私默认）。
    let dir = TempDir::new("disabled-compose");
    let paths = dir.paths();
    dir.put(&dir.user_memory(), "不该出现的用户记忆");
    dir.put(&dir.project_memory(), "不该出现的项目记忆");
    append_daily(&paths, today(), "不该出现的日志").unwrap();

    let bundle: MemoryBundle = dir
        .engine(false)
        .compose()
        .expect("disabled compose 不得报错");
    assert_eq!(bundle.identity, default_identity());
    assert_eq!(bundle.user_memory, None);
    assert_eq!(bundle.project_memory, None);
    assert_eq!(bundle.daily_tail, None);
    assert!(!dir.engine(false).enabled(), "enabled() 与实际开关不符");
}

#[test]
fn disabled_engine_rejects_memory_writes_without_touching_disk() {
    let dir = TempDir::new("disabled-write");
    let engine = dir.engine(false);

    let user = engine.set_user_memory("任意正文");
    let project = engine.set_project_memory("任意正文");
    assert_disabled(user, "set_user_memory");
    assert_disabled(project, "set_project_memory");
    // 闸门先于落盘：既不建文件，也不建父目录。
    assert!(!dir.exists(&dir.user_memory()), "关闭时用户记忆文件被创建");
    assert!(
        !dir.exists(&dir.paths().home.join("memory")),
        "关闭时用户记忆目录被创建"
    );
    assert!(
        !dir.exists(&dir.project_memory()),
        "关闭时项目记忆文件被创建"
    );
}

#[test]
fn identity_reads_and_writes_ignore_the_memory_switch() {
    // 规格 §2：身份层是产品人格，不受跨会话记忆开关限制。
    let dir = TempDir::new("identity-unaffected");
    let engine = dir.engine(false);

    engine.set_soul("先复现，再动手；不猜。").unwrap();
    engine.set_ai_name("小索").unwrap();
    engine.set_user_name("阿澜").unwrap();

    assert_eq!(
        engine.read_identity().unwrap(),
        Identity {
            ai_name: "小索".into(),
            user_name: "阿澜".into(),
            soul: "先复现，再动手；不猜。".into(),
        },
        "disabled 状态下身份读写不一致"
    );
    // compose 的身份层同样填充（开关只压制记忆三层）。
    let bundle = engine.compose().unwrap();
    assert_eq!(bundle.identity.ai_name, "小索");
    assert_eq!(bundle.identity.soul, "先复现，再动手；不猜。");
}
