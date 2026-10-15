use super::*;

#[test]
fn client_direction_frames_from_server_poison_the_session() {
    for command in [Command::Syn, Command::Settings] {
        reject(
            v2(4),
            frame(command, 0, Vec::new()),
            ClientError::ClientToServer(command),
            &format!("{command:?} 是客户端方向帧"),
        );
        reject(
            v1(4),
            frame(command, 1, b"x".to_vec()),
            ClientError::ClientToServer(command),
            &format!("{command:?} 携带数据时同样按方向违规拒绝"),
        );
    }
}

#[test]
fn client_direction_frames_before_settings_report_the_gate_first() {
    // 未发出客户端 Settings 时，所有非 Waste 帧都先落在同一道门禁上，
    // 与帧方向无关，结果同样 poison，不存在静默容忍。
    for command in [Command::Syn, Command::Settings] {
        let mut st = ClientState::new(4).unwrap();
        assert_eq!(
            st.accept(&frame(command, 2, b"x".to_vec())),
            Err(ClientError::RemoteBeforeSettings(command)),
            "{command:?} 在 Settings 门禁前按违规帧拒绝"
        );
        assert!(st.is_poisoned(), "{command:?}：违规后必须失效");
    }
}

#[test]
fn direction_violation_poisons_every_later_accept_and_open() {
    let mut st = v2(4);
    let id = open_ready(&mut st, 1);
    assert_eq!(st.accept(&push(id, vec![1])), Ok(Event::Data(id)));
    assert_eq!(
        st.accept(&frame(Command::Syn, 2, Vec::new())),
        Err(ClientError::ClientToServer(Command::Syn))
    );
    assert!(st.is_poisoned());
    for later in [
        frame(Command::Waste, 0, vec![0]),
        heart(Command::HeartRequest, 0),
        fin(id),
    ] {
        assert_eq!(
            st.accept(&later),
            Err(ClientError::Poisoned),
            "失效后一律拒绝"
        );
    }
    assert_eq!(st.open_stream(), Err(ClientError::Poisoned));
    assert_eq!(st.close_stream(id), Err(ClientError::Poisoned));
    assert_eq!(
        st.mark_settings_sent(),
        Err(ClientError::Poisoned),
        "失效后连本地 API 也不再接受"
    );
    assert_eq!(st.peer_version(), 2, "失效不改写已协商版本");
}

#[test]
fn update_padding_is_allowed_in_both_versions_with_zero_id() {
    let scheme = b"stop=8\n0=30-30\n1=100-400";
    for mut st in [v1(4), v2(4)] {
        assert_eq!(
            st.accept(&frame(Command::UpdatePadding, 0, scheme.to_vec())),
            Ok(Event::PaddingUpdate),
            "版本 1 与 2 都接受 padding 更新，方案解析交由上层"
        );
        assert_eq!(
            st.accept(&frame(Command::UpdatePadding, 0, Vec::new())),
            Ok(Event::PaddingUpdate),
            "空方案文本仍是更新事件，不在本模块判定合法性"
        );
        assert!(!st.is_poisoned());
    }
    let st = v2(4);
    reject(
        st,
        frame(Command::UpdatePadding, 3, scheme.to_vec()),
        ClientError::InvalidStream("padding 更新流编号非零"),
        "padding 更新必须使用零流编号",
    );
}

#[test]
fn heartbeat_requires_version_two_and_keeps_correlation_id() {
    for command in [Command::HeartRequest, Command::HeartResponse] {
        let what = match command {
            Command::HeartRequest => "心跳请求",
            _ => "心跳回复",
        };
        reject(
            v1(4),
            heart(command, 0),
            ClientError::InvalidVersion(what),
            "版本 1 禁用心跳",
        );
        reject(
            v2(4),
            frame(command, 0, vec![1]),
            ClientError::InvalidVersion("心跳携带数据"),
            "心跳不得携带数据",
        );
    }
    let mut st = v2(4);
    let id = open_ready(&mut st, 1);
    // 任意非零关联值都必须原样保留，它不是本端流编号。
    assert_eq!(
        st.accept(&heart(Command::HeartRequest, 37)),
        Ok(Event::Heartbeat(37)),
        "心跳请求把关联值交上层回包"
    );
    assert_eq!(
        st.accept(&heart(Command::HeartRequest, 0)),
        Ok(Event::Heartbeat(0)),
        "关联值可为零"
    );
    assert_eq!(
        st.accept(&heart(Command::HeartRequest, u32::MAX)),
        Ok(Event::Heartbeat(u32::MAX))
    );
    assert_eq!(
        st.accept(&heart(Command::HeartResponse, id)),
        Ok(Event::Ignore),
        "心跳回复只是丢弃，不构成完整健康验证"
    );
    assert_eq!(
        st.accept(&heart(Command::HeartResponse, 4000000000)),
        Ok(Event::Ignore)
    );
    assert!(st.is_active(id) && st.is_ready(id), "心跳不影响流状态");
    assert_eq!(st.accept(&push(id, vec![1])), Ok(Event::Data(id)));
    assert!(!st.is_poisoned());
}

#[test]
fn heartbeat_never_maps_stream_ids_to_environments() {
    let mut st = v2(4);
    let a = open_ready(&mut st, 1);
    let b = open_ready(&mut st, 2);
    // 关联值恰好等于某个活跃流编号时也只作心跳处理，不改流状态。
    assert_eq!(
        st.accept(&heart(Command::HeartRequest, a)),
        Ok(Event::Heartbeat(a))
    );
    assert_eq!(
        st.accept(&heart(Command::HeartResponse, b)),
        Ok(Event::Ignore)
    );
    assert_eq!(st.accept(&fin(b)), Ok(Event::Closed(b)));
    assert_eq!(
        st.accept(&heart(Command::HeartRequest, b)),
        Ok(Event::Heartbeat(b)),
        "已关闭流的编号作为心跳关联值仍合法"
    );
    assert!(st.is_ready(a));
    assert!(!st.is_poisoned());
}

#[test]
fn waste_is_ignored_in_every_state() {
    let mut st = v2(4);
    let id = open_ready(&mut st, 1);
    for waste in [
        frame(Command::Waste, 0, Vec::new()),
        frame(Command::Waste, id, vec![0; 200]),
        frame(Command::Waste, u32::MAX, vec![7]),
    ] {
        assert_eq!(st.accept(&waste), Ok(Event::Ignore), "Waste 只看命令字");
    }
    assert!(st.is_ready(id), "Waste 不改流状态");
    // Settings 发送前的唯一例外也是 Waste。
    let mut st = ClientState::new(4).unwrap();
    assert_eq!(
        st.accept(&frame(Command::Waste, 5, vec![1])),
        Ok(Event::Ignore)
    );
    assert!(!st.is_poisoned() && !st.settings_sent());
}

#[test]
fn empty_push_on_ready_stream_is_ignored() {
    let mut st = v2(4);
    let id = open_ready(&mut st, 1);
    assert_eq!(
        st.accept(&push(id, Vec::new())),
        Ok(Event::Ignore),
        "空数据不产生事件"
    );
    assert!(st.is_ready(id), "空数据不改就绪状态");
}

#[test]
fn server_settings_can_upgrade_a_session_that_already_opened_streams() {
    // 版本 1 下已开流并收发数据，随后收到 v=2 才进入 ACK 要求。
    let mut st = v1(4);
    let old = st.open_stream().unwrap();
    assert_eq!(st.accept(&push(old, vec![1])), Ok(Event::Data(old)));
    assert_eq!(
        st.accept(&server_settings("v=2")),
        Ok(Event::Settings { version: 2 })
    );
    assert!(!st.is_ready(old), "升级后旧流需重新等待 SYNACK");
    let new = st.open_stream().unwrap();
    assert_eq!(st.accept(&syn_ack(old, Vec::new())), Ok(Event::Ready(old)));
    assert_eq!(st.accept(&syn_ack(new, Vec::new())), Ok(Event::Ready(new)));
    assert!(st.is_ready(old) && st.is_ready(new));
    assert_eq!(
        st.accept(&server_settings("v=2")),
        Err(ClientError::InvalidSettings("只接收一次"))
    );
    assert_eq!(st.peer_version(), 2, "拒绝重复设置不改写已协商版本");
}

#[test]
fn version_one_server_settings_keeps_session_at_version_one() {
    let mut st = v1(4);
    assert_eq!(
        st.accept(&server_settings("v=1")),
        Ok(Event::Settings { version: 1 }),
        "v=1 显式协商为版本 1"
    );
    assert_eq!(st.peer_version(), 1);
    let id = st.open_stream().unwrap();
    assert!(st.is_ready(id), "版本 1 活跃即就绪");
    assert_eq!(
        st.accept(&heart(Command::HeartRequest, 1)),
        Err(ClientError::InvalidVersion("心跳请求")),
        "协商为 1 后仍禁用心跳"
    );
}
