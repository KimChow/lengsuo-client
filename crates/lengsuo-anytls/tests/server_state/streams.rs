use super::*;

#[test]
fn syn_requires_no_data_and_strictly_increasing_nonzero_id() {
    reject(
        vec![valid(2)],
        4,
        syn(0),
        StateError::InvalidStream("SYN 流编号为零"),
        "SYN 流编号不可为零",
    );
    reject(
        vec![valid(2)],
        4,
        frame(Command::Syn, 5, vec![1]),
        StateError::InvalidStream("SYN 携带数据"),
        "SYN 不得携带数据",
    );
    reject(
        vec![valid(2), syn(5)],
        4,
        syn(5),
        StateError::InvalidStream("SYN 流编号未严格递增"),
        "重复 id 必须拒绝",
    );
    reject(
        vec![valid(2), syn(5)],
        4,
        syn(4),
        StateError::InvalidStream("SYN 流编号未严格递增"),
        "回退 id 必须拒绝",
    );
}

#[test]
fn capacity_rejects_new_syn_at_limit() {
    reject(
        vec![valid(2), syn(1)],
        1,
        syn(2),
        StateError::InvalidStream("活跃流已达上限"),
        "上限 1 时第二条 SYN 拒绝",
    );
    reject(
        vec![valid(2), syn(1), syn(2)],
        2,
        syn(3),
        StateError::InvalidStream("活跃流已达上限"),
        "上限 2 时第三条 SYN 拒绝",
    );
}

#[test]
fn capacity_counts_active_streams_not_history() {
    let mut st = started(1, 2);
    assert_eq!(st.accept(&syn(1)), Ok(Event::Open(1)));
    assert_eq!(st.accept(&fin(1)), Ok(Event::Close(1)));
    assert_eq!(
        st.accept(&syn(2)),
        Ok(Event::Open(2)),
        "关闭后释放容量，更大的新 id 可打开"
    );
    assert!(!st.is_poisoned());
}

#[test]
fn push_and_fin_require_active_stream() {
    reject(
        vec![valid(2)],
        4,
        push(3),
        StateError::InvalidStream("引用不存在的流"),
        "未打开的流不可推送",
    );
    reject(
        vec![valid(2)],
        4,
        fin(3),
        StateError::InvalidStream("引用不存在的流"),
        "未打开的流不可 FIN",
    );
    reject(
        vec![valid(2), syn(3)],
        4,
        frame(Command::Fin, 3, vec![1]),
        StateError::InvalidStream("FIN 携带数据"),
        "FIN 不得携带数据",
    );
    // Frame 不实现 Clone，每例重建前缀帧。
    let closed = || vec![valid(2), syn(3), fin(3)];
    reject(
        closed(),
        4,
        push(3),
        StateError::InvalidStream("引用不存在的流"),
        "关闭后不可再推送",
    );
    reject(
        closed(),
        4,
        fin(3),
        StateError::InvalidStream("引用不存在的流"),
        "关闭后不可重复 FIN",
    );
    reject(
        closed(),
        4,
        syn(3),
        StateError::InvalidStream("SYN 流编号未严格递增"),
        "已关闭 id 不得复用",
    );
}

#[test]
fn heartbeat_requires_version_two_and_no_data() {
    reject(
        vec![valid(1)],
        4,
        frame(Command::HeartRequest, 0, Vec::new()),
        StateError::InvalidVersion("心跳请求"),
        "版本 1 禁心跳请求",
    );
    reject(
        vec![valid(1)],
        4,
        frame(Command::HeartResponse, 0, Vec::new()),
        StateError::InvalidVersion("心跳回复"),
        "版本 1 禁心跳回复",
    );
    reject(
        vec![valid(2)],
        4,
        frame(Command::HeartResponse, 0, vec![1]),
        StateError::InvalidVersion("心跳携带数据"),
        "心跳回复不得携带数据",
    );
    let mut st = started(4, 2);
    assert_eq!(
        st.accept(&frame(Command::HeartRequest, 0, Vec::new())),
        Ok(Event::Heartbeat(0)),
        "心跳请求交由上层回复"
    );
    assert_eq!(
        st.accept(&frame(Command::HeartResponse, 37, Vec::new())),
        Ok(Event::Padding),
        "客户端心跳回复保留任意关联值，静默丢弃"
    );
    assert_eq!(
        st.accept(&frame(Command::Waste, 3, vec![0])),
        Ok(Event::Padding)
    );
    assert_eq!(
        st.accept(&frame(Command::HeartRequest, 0, Vec::new())),
        Ok(Event::Heartbeat(0)),
        "心跳可重复发生"
    );
    assert!(!st.is_poisoned());
}

#[test]
fn server_direction_frames_are_rejected_from_client() {
    for command in [
        Command::Alert,
        Command::UpdatePadding,
        Command::SynAck,
        Command::ServerSettings,
    ] {
        reject(
            vec![valid(2)],
            4,
            frame(command, 0, Vec::new()),
            StateError::ServerToClient(command),
            &format!("{command:?} 是服务端方向帧"),
        );
        let mut st = ServerState::new(4).unwrap();
        assert_eq!(
            st.accept(&frame(command, 0, b"v=2".to_vec())),
            Err(StateError::ServerToClient(command)),
            "{command:?} 在 Settings 之前同样按方向违规拒绝"
        );
    }
}

#[test]
fn first_bad_frame_poisons_every_later_accept() {
    let mut st = started(4, 2);
    assert_eq!(st.accept(&syn(1)), Ok(Event::Open(1)));
    assert_eq!(
        st.accept(&push(9)),
        Err(StateError::InvalidStream("引用不存在的流"))
    );
    for bad in [
        frame(Command::Waste, 0, vec![0]),
        valid(2),
        syn(2),
        frame(Command::HeartRequest, 0, Vec::new()),
    ] {
        assert_eq!(st.accept(&bad), Err(StateError::Poisoned), "失效后一律拒绝");
    }
}

#[test]
fn two_streams_do_not_leak_into_each_other() {
    let mut st = started(4, 2);
    st.accept(&syn(1)).unwrap();
    st.accept(&syn(2)).unwrap();
    assert_eq!(
        st.accept(&frame(Command::Push, 1, vec![1, 1])),
        Ok(Event::Data(1))
    );
    assert_eq!(
        st.accept(&frame(Command::Push, 2, vec![2])),
        Ok(Event::Data(2))
    );
    assert_eq!(st.accept(&fin(1)), Ok(Event::Close(1)));
    assert_eq!(
        st.accept(&frame(Command::Push, 2, vec![3])),
        Ok(Event::Data(2)),
        "流 1 关闭不影响流 2"
    );
    assert_eq!(
        st.accept(&frame(Command::HeartRequest, 0, Vec::new())),
        Ok(Event::Heartbeat(0))
    );
    assert_eq!(st.accept(&fin(2)), Ok(Event::Close(2)));
    assert!(!st.is_poisoned(), "全程合法序列不应失效");
    assert_eq!(st.peer_version(), Some(2), "版本状态不受流事件影响");
}

#[test]
fn events_never_copy_payload() {
    let mut st = started(4, 2);
    st.accept(&syn(1)).unwrap();
    let owned = frame(Command::Push, 1, vec![9, 8, 7]);
    assert_eq!(st.accept(&owned), Ok(Event::Data(1)), "事件只报告流编号");
    assert_eq!(owned.data, vec![9, 8, 7], "载荷仍在调用方持有的原帧中");
    let bytes = owned.encode().unwrap();
    let (decoded, used) = Frame::decode(&bytes).unwrap();
    assert_eq!(used, bytes.len());
    assert!(decoded == owned, "帧可原样编解码，状态机不消耗它");
}

#[test]
fn heartbeat_preserves_reference_correlation_id() {
    let mut state = started(4, 2);
    assert_eq!(
        state.accept(&frame(Command::HeartRequest, 37, vec![])),
        Ok(Event::Heartbeat(37))
    );
}
