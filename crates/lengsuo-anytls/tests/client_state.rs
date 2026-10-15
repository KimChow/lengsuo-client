//! AnyTLS v2 客户端会话状态机测试：纯内存、单线程、确定性。
//! 只验证帧方向、ID 生命周期与 SYNACK/心跳/Alert 语义，
//! 不证明 TLS、认证、padding 方案、心跳计时、复用池或参考互通。
use lengsuo_anytls::{
    client_state::{ClientError, ClientState, Event},
    frame::{Command, Frame},
};

fn frame(command: Command, stream_id: u32, data: Vec<u8>) -> Frame {
    Frame {
        command,
        stream_id,
        data,
    }
}
fn server_settings(text: &str) -> Frame {
    frame(Command::ServerSettings, 0, text.as_bytes().to_vec())
}
fn push(id: u32, data: Vec<u8>) -> Frame {
    frame(Command::Push, id, data)
}
fn fin(id: u32) -> Frame {
    frame(Command::Fin, id, Vec::new())
}
fn syn_ack(id: u32, data: Vec<u8>) -> Frame {
    frame(Command::SynAck, id, data)
}
fn heart(command: Command, id: u32) -> Frame {
    frame(command, id, Vec::new())
}

/// 前置：客户端 Settings 已发出；未采纳 ServerSettings 时对端版本默认 1。
fn fresh(max_streams: usize) -> ClientState {
    let mut st = ClientState::new(max_streams).expect("状态机可构造");
    st.mark_settings_sent().expect("前置：标记 Settings 已发送");
    assert_eq!(st.peer_version(), 1, "未协商时默认按版本 1 运行");
    st
}
/// 版本 1 会话：服务器不发 ServerSettings，客户端停留在 v1。
fn v1(max_streams: usize) -> ClientState {
    fresh(max_streams)
}
/// 版本 2 会话：已采纳 ServerSettings v=2。
fn v2(max_streams: usize) -> ClientState {
    let mut st = fresh(max_streams);
    assert_eq!(
        st.accept(&server_settings("v=2")),
        Ok(Event::Settings { version: 2 }),
        "用例前置：ServerSettings 必须先被采纳"
    );
    st
}
/// 打开一条流并按当前版本推进到就绪状态，供数据用例复用。
fn open_ready(st: &mut ClientState, expect_id: u32) -> u32 {
    let id = st.open_stream().expect("开流");
    assert_eq!(id, expect_id, "流编号必须严格连续");
    if st.peer_version() == 2 {
        assert_eq!(st.accept(&syn_ack(id, Vec::new())), Ok(Event::Ready(id)));
    }
    id
}

/// 远端违规必带失效：断言错误值、poisoned 标记，以及失效后连合法帧与新流都拒绝。
fn reject(mut st: ClientState, bad: Frame, expected: ClientError, note: &str) {
    assert_eq!(st.accept(&bad), Err(expected), "应拒绝：{note}");
    assert!(st.is_poisoned(), "{note}：拒绝后会话必须失效");
    assert_eq!(
        st.accept(&frame(Command::Waste, 0, Vec::new())),
        Err(ClientError::Poisoned),
        "{note}：失效后连合法 Waste 也拒绝"
    );
    assert_eq!(
        st.open_stream(),
        Err(ClientError::Poisoned),
        "{note}：失效后不可再开流"
    );
    assert_eq!(
        st.close_stream(1),
        Err(ClientError::Poisoned),
        "{note}：失效后不可再关流"
    );
}

#[path = "client_state/frames.rs"]
mod frame_tests;
#[path = "client_state/settings.rs"]
mod settings_tests;
#[path = "client_state/streams.rs"]
mod stream_tests;
