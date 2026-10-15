use super::*;

/// 与 `client_state` 内部私有上限一致的取值，仅用于构造边界用例。
const SETTINGS_LIMIT: usize = 4096;

fn settings_at(len: usize) -> String {
    // "v=2\nk=" 共 6 字节，其余用 x 填充到目标长度。
    format!("v=2\nk={}", "x".repeat(len - 6))
}

#[test]
fn zero_capacity_is_rejected_at_construction() {
    assert!(
        matches!(ClientState::new(0), Err(ClientError::InvalidConfig),),
        "活跃流上限为零时状态机不可构造"
    );
    assert!(ClientState::new(1).is_ok());
}

#[test]
fn only_waste_is_allowed_before_settings_is_sent() {
    let mut st = ClientState::new(4).unwrap();
    assert!(!st.settings_sent());
    assert_eq!(
        st.accept(&frame(Command::Waste, 7, vec![0xff; 16])),
        Ok(Event::Ignore),
        "Settings 发送前 Waste 可带任意数据与任意流编号"
    );
    assert_eq!(
        st.open_stream(),
        Err(ClientError::SettingsNotSent),
        "Settings 未发送时不可开流"
    );
    assert!(!st.is_poisoned(), "本地 API 错误不破坏会话");
    for command in [
        Command::ServerSettings,
        Command::SynAck,
        Command::Push,
        Command::Fin,
        Command::UpdatePadding,
        Command::HeartRequest,
        Command::HeartResponse,
        Command::Alert,
    ] {
        let mut st = ClientState::new(4).unwrap();
        assert_eq!(
            st.accept(&frame(command, 1, Vec::new())),
            Err(ClientError::RemoteBeforeSettings(command)),
            "{command:?} 在客户端 Settings 发送前必须拒绝"
        );
        assert!(st.is_poisoned(), "{command:?}：远端违规使会话失效");
    }
}

#[test]
fn mark_settings_sent_only_once_and_local_errors_are_harmless() {
    let mut st = ClientState::new(4).unwrap();
    st.mark_settings_sent().unwrap();
    assert!(st.settings_sent());
    assert_eq!(
        st.mark_settings_sent(),
        Err(ClientError::SettingsAlreadySent),
        "重复标记是本地错误"
    );
    let id = st.open_stream().expect("开流");
    assert_eq!(
        st.close_stream(id + 3),
        Err(ClientError::InvalidStream("引用从未创建的流")),
        "本地参数错误只返回错误"
    );
    assert!(!st.is_poisoned(), "本地错误不使会话失效");
    assert!(st.is_active(id), "本地错误不得影响既有流");
    assert_eq!(st.peer_version(), 1, "未收到 ServerSettings 时默认版本 1");
}

#[test]
fn server_settings_requires_zero_id_and_single_occurrence() {
    let mut st = v1(4);
    assert_eq!(
        st.accept(&server_settings("v=2")),
        Ok(Event::Settings { version: 2 }),
        "收到 ServerSettings 后升级到版本 2"
    );
    assert_eq!(st.peer_version(), 2);
    reject(
        st,
        server_settings("v=2"),
        ClientError::InvalidSettings("只接收一次"),
        "重复 ServerSettings",
    );
    reject(
        v1(4),
        frame(Command::ServerSettings, 1, b"v=2".to_vec()),
        ClientError::InvalidSettings("stream id 非零"),
        "ServerSettings 必须使用流编号零",
    );
    let mut st = v1(4);
    assert_eq!(
        st.accept(&server_settings("v=1\nunknown=ok")),
        Ok(Event::Settings { version: 1 }),
        "未知键允许并忽略"
    );
    assert_eq!(st.peer_version(), 1);
}

#[test]
fn server_settings_text_is_utf8_distinct_and_within_limit() {
    assert_eq!(
        v1(4).accept(&server_settings(&settings_at(SETTINGS_LIMIT))),
        Ok(Event::Settings { version: 2 }),
        "恰好等于上限可接受"
    );
    for (data, reason) in [
        (b"v=3".to_vec(), "版本非 1 或 2"),
        (b"client=x".to_vec(), "缺少 v"),
        (vec![0xff, 0xfe], "非 UTF-8"),
        (b"v=2\nv=2".to_vec(), "键重复"),
        (b"v=2\n=x".to_vec(), "键为空"),
        (b"v=2\nplain".to_vec(), "行缺少等号"),
    ] {
        reject(
            v1(4),
            frame(Command::ServerSettings, 0, data),
            ClientError::InvalidSettings(reason),
            "非法 ServerSettings",
        );
    }
    reject(
        v1(4),
        server_settings(&settings_at(SETTINGS_LIMIT + 1)),
        ClientError::InvalidSettings("文本超出上限"),
        "超出上限即拒绝；该上限是本实现自设，非参考实现限制",
    );
}

#[test]
fn alert_terminates_session_without_poisoning_it() {
    let mut st = v2(4);
    let id = open_ready(&mut st, 1);
    let alert = frame(Command::Alert, 0, b"password mismatch".to_vec());
    assert_eq!(st.accept(&alert), Ok(Event::Alert));
    assert_eq!(alert.data, b"password mismatch", "错误文本仍在调用方原帧中");
    assert!(st.is_terminated(), "Alert 后会话终止");
    assert!(!st.is_poisoned(), "Alert 是合法协议事件，不是协议违规");
    assert_eq!(st.accept(&fin(id)), Err(ClientError::Terminated));
    assert_eq!(st.open_stream(), Err(ClientError::Terminated));
    assert_eq!(st.close_stream(id), Err(ClientError::Terminated));
    assert_eq!(
        st.accept(&frame(Command::Waste, 0, vec![0])),
        Err(ClientError::Terminated),
        "终止后连 Waste 也不再处理"
    );
}

#[test]
fn alert_without_text_still_terminates() {
    let mut st = v1(4);
    assert_eq!(
        st.accept(&frame(Command::Alert, 0, Vec::new())),
        Ok(Event::Alert)
    );
    assert!(st.is_terminated());
}
