use super::*;

#[test]
fn rejects_zero_stream_capacity() {
    assert!(
        matches!(ServerState::new(0), Err(StateError::InvalidConfig)),
        "活跃流上限为零时状态机不可构造"
    );
    assert!(ServerState::new(1).is_ok());
}

#[test]
fn only_waste_is_tolerated_before_settings() {
    let mut st = ServerState::new(4).unwrap();
    assert_eq!(
        st.accept(&frame(Command::Waste, 7, vec![0xff; 16])),
        Ok(Event::Padding),
        "Waste 可带任意数据与任意流编号且无状态影响"
    );
    assert_eq!(
        st.accept(&frame(Command::Waste, 0, Vec::new())),
        Ok(Event::Padding)
    );
    assert!(!st.is_poisoned());
    for command in [
        Command::Syn,
        Command::Push,
        Command::Fin,
        Command::HeartRequest,
        Command::HeartResponse,
    ] {
        reject(
            Vec::new(),
            4,
            frame(command, 1, Vec::new()),
            StateError::SettingsExpected,
            &format!("{command:?} 在 Settings 之前"),
        );
    }
}

#[test]
fn settings_accepted_once_with_zero_stream_id() {
    let st = started(4, 2);
    assert_eq!(st.peer_version(), Some(2), "Settings 后暴露协商版本");
    reject(
        vec![valid(2)],
        4,
        valid(1),
        StateError::InvalidSettings("只接收一次"),
        "重复 Settings",
    );
    reject(
        Vec::new(),
        4,
        settings("v=2 \nclient=x\npadding-md5=0"),
        StateError::InvalidSettings("版本非 1 或 2"),
        "版本值带空格亦拒绝",
    );
    reject(
        Vec::new(),
        4,
        frame(Command::Settings, 1, GOOD.as_bytes().to_vec()),
        StateError::InvalidSettings("stream id 非零"),
        "Settings 的流编号必须为零",
    );
    let mut st = ServerState::new(4).unwrap();
    assert_eq!(st.peer_version(), None, "未收到 Settings 时无版本");
    assert_eq!(st.accept(&valid(1)), Ok(Event::Settings { version: 1 }));
    assert_eq!(st.peer_version(), Some(1), "版本 1 客户端同样协商成功");
}

#[test]
fn settings_rejects_bad_text() {
    let cases: Vec<(&str, &str, StateError)> = vec![
        (
            "行缺少等号",
            "v=2\nclient\npadding-md5=0",
            StateError::InvalidSettings("行缺少等号"),
        ),
        ("空文本", "", StateError::InvalidSettings("行缺少等号")),
        (
            "尾部换行",
            "v=2\nclient=x\npadding-md5=0123456789abcdef0123456789abcdef\n",
            StateError::InvalidSettings("行缺少等号"),
        ),
        (
            "键为空",
            "=2\nclient=x\npadding-md5=0",
            StateError::InvalidSettings("键为空"),
        ),
        (
            "重复键",
            "v=2\nv=1\nclient=x\npadding-md5=0",
            StateError::InvalidSettings("键重复"),
        ),
        (
            "版本非 1 或 2",
            "v=3\nclient=x\npadding-md5=0",
            StateError::InvalidSettings("版本非 1 或 2"),
        ),
        (
            "版本为空",
            "v=\nclient=x\npadding-md5=0",
            StateError::InvalidSettings("版本非 1 或 2"),
        ),
        (
            "缺少版本",
            "client=x\npadding-md5=0123456789abcdef0123456789abcdef",
            StateError::InvalidSettings("缺少 v"),
        ),
        (
            "client 为空",
            "v=2\nclient=\npadding-md5=0",
            StateError::InvalidSettings("client 为空"),
        ),
        (
            "缺少 client",
            "v=2\npadding-md5=0123456789abcdef0123456789abcdef",
            StateError::InvalidSettings("缺少 client"),
        ),
        (
            "md5 大写",
            "v=2\nclient=x\npadding-md5=0123456789ABCDEF0123456789ABCDEF",
            StateError::InvalidSettings("padding-md5 非法"),
        ),
        (
            "md5 长度不足",
            "v=2\nclient=x\npadding-md5=deadbeef",
            StateError::InvalidSettings("padding-md5 非法"),
        ),
        (
            "md5 非十六进制",
            "v=2\nclient=x\npadding-md5=zzz3456789abcdef0123456789abcdef",
            StateError::InvalidSettings("padding-md5 非法"),
        ),
        (
            "缺少 padding-md5",
            "v=2\nclient=x",
            StateError::InvalidSettings("缺少 padding-md5"),
        ),
    ];
    for (name, text, expected) in cases {
        reject(Vec::new(), 4, settings(text), expected, name);
    }
    reject(
        Vec::new(),
        4,
        frame(Command::Settings, 0, vec![0xff, 0xfe]),
        StateError::InvalidSettings("非 UTF-8"),
        "非 UTF-8",
    );
    let over = format!("v=2\nclient=x\npadding-md5={MD5}\npad={}", "y".repeat(4096));
    reject(
        Vec::new(),
        4,
        settings(&over),
        StateError::InvalidSettings("文本超出上限"),
        "文本超上限",
    );
}

#[test]
fn settings_allows_unknown_key_within_limit() {
    let mut st = ServerState::new(4).unwrap();
    let text = format!("v=2\nclient=lengsuo/0.1\npadding-md5={MD5}\nfuture=1");
    assert!(
        text.len() <= 4096 && text.len() > 40,
        "未知键用例须在上限内"
    );
    assert_eq!(
        st.accept(&settings(&text)),
        Ok(Event::Settings { version: 2 })
    );
    assert_eq!(
        st.accept(&push(1)),
        Err(StateError::InvalidStream("引用不存在的流")),
        "扩展键不降低后续流校验强度"
    );
}
