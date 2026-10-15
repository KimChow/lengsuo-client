//! AnyTLS v2 服务端入站状态机测试：纯内存、单线程、确定性。
//! 只验证帧顺序与流表语义，不证明 TLS、认证、padding 更新或参考互通。
use lengsuo_anytls::{
    frame::{Command, Frame},
    server_state::{Event, ServerState, StateError},
};

const MD5: &str = "0123456789abcdef0123456789abcdef";
const GOOD: &str = "v=2\nclient=anytls/0.0.1\npadding-md5=0123456789abcdef0123456789abcdef";

fn frame(command: Command, stream_id: u32, data: Vec<u8>) -> Frame {
    Frame {
        command,
        stream_id,
        data,
    }
}
fn settings(text: &str) -> Frame {
    frame(Command::Settings, 0, text.as_bytes().to_vec())
}
fn valid(v: u8) -> Frame {
    settings(&format!("v={v}\nclient=anytls/0.0.1\npadding-md5={MD5}"))
}
fn syn(id: u32) -> Frame {
    frame(Command::Syn, id, Vec::new())
}
fn fin(id: u32) -> Frame {
    frame(Command::Fin, id, Vec::new())
}
fn push(id: u32) -> Frame {
    frame(Command::Push, id, vec![0x5a])
}

fn started(max_streams: usize, version: u8) -> ServerState {
    let mut st = ServerState::new(max_streams).unwrap();
    assert_eq!(
        st.accept(&valid(version)),
        Ok(Event::Settings { version }),
        "用例前置：Settings 必须先被接受"
    );
    st
}

/// 拒绝必带失效：每次单独构造状态，验证错误值、poisoned 标记及失效后 fail-closed。
fn reject(prefix: Vec<Frame>, max_streams: usize, bad: Frame, expected: StateError, note: &str) {
    let mut st = ServerState::new(max_streams).unwrap();
    for f in &prefix {
        st.accept(f).unwrap();
    }
    assert_eq!(st.accept(&bad), Err(expected), "应拒绝：{note}");
    assert!(st.is_poisoned(), "{note}：拒绝后状态必须失效");
    assert_eq!(
        st.accept(&frame(Command::Waste, 0, Vec::new())),
        Err(StateError::Poisoned),
        "{note}：失效后连合法 Waste 也拒绝"
    );
}

#[path = "server_state/settings.rs"]
mod settings_tests;
#[path = "server_state/streams.rs"]
mod stream_tests;
