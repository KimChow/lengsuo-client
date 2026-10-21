use super::*;
use crate::mux::frame::{
    decode_address_port, read_data, FrameMetadata, SessionStatus, TargetNetwork,
};
use ss_core::target::TargetAddr;
use std::io::Cursor;

fn tcp(host: &str, port: u16) -> (TargetAddr, TargetNetwork) {
    (
        TargetAddr::Domain(host.to_string(), port),
        TargetNetwork::Tcp,
    )
}

fn drain_frame(wire: &[u8]) -> (FrameMetadata, Result<Vec<u8>, FrameError>) {
    let mut reader = Cursor::new(wire);
    let meta = FrameMetadata::decode_from(&mut reader, false).expect("帧头可解码");
    let data = if meta.has_data() {
        read_data(&mut reader, meta.status != SessionStatus::New)
    } else {
        Err(FrameError::MetaTooLong)
    };
    (meta, data)
}

#[test]
fn session_manager_enforces_strategy_and_idle_close() {
    let strategy = Strategy {
        max_concurrency: 2,
        max_connection: 3,
    };
    let mut manager = SessionManager::new();
    let a = manager.allocate(&strategy).expect("第一次分配");
    assert_eq!(a, 1, "ID 从 1 起");
    assert!(manager.add(
        a,
        SessionState {
            target: tcp("a", 1)
        }
    ));
    let b = manager.allocate(&strategy).expect("第二次分配");
    assert!(manager.add(
        b,
        SessionState {
            target: tcp("b", 1)
        }
    ));
    assert_eq!(manager.size(), 2);
    assert_eq!(
        manager.allocate(&strategy),
        Err(AllocateError::ConcurrencyLimit)
    );
    // 释放一条后仍可分配（活跃数 vs 累计数不同口径）。
    manager.remove(a);
    let c = manager.allocate(&strategy).expect("释放后可分配");
    assert!(manager.add(
        c,
        SessionState {
            target: tcp("c", 1)
        }
    ));
    assert_eq!(manager.size(), 2);
    assert_eq!(manager.count(), 3);
    manager.remove(b);
    manager.remove(c);
    assert_eq!(
        manager.allocate(&strategy),
        Err(AllocateError::ConnectionLimit)
    );

    // `CloseIfNoSessionAndIdle`：`count` 未变且无活跃会话时才关闭。
    let mut idle = SessionManager::new();
    let id = idle.allocate(&Strategy::default()).expect("可分配");
    idle.add(
        id,
        SessionState {
            target: tcp("a", 1),
        },
    );
    assert!(!idle.close_if_no_session_and_idle(1, 1), "仍有活跃会话");
    idle.remove(id);
    assert!(
        !idle.close_if_no_session_and_idle(1, 1),
        "活跃数快照与当前不符（参考 checkSize 语义）"
    );
    assert!(!idle.close_if_no_session_and_idle(0, 99), "count 已变");
    assert!(idle.close_if_no_session_and_idle(0, 1));
    assert!(idle.closed());
    assert_eq!(
        idle.allocate(&Strategy::default()),
        Err(AllocateError::Closed)
    );
}

#[test]
fn close_with_error_sets_option_error_and_address_codec_covers_all_families() {
    let mut writer = SessionWriter::response(4, TargetNetwork::Udp);
    writer.has_error = true;
    let mut out = Vec::new();
    writer.close(&mut out).expect("可写");
    let (meta, _) = drain_frame(&out);
    assert!(meta.has_error(), "hasError 时置 OptionError");

    for (addr, kind) in [
        (TargetAddr::V4([127, 0, 0, 1], 53), 1u8),
        (TargetAddr::Domain("test.invalid".into(), 53), 2),
        (
            TargetAddr::V6([0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 53),
            3,
        ),
    ] {
        let mut wire = Vec::new();
        crate::mux::frame::encode_address_port(&mut wire, &addr).expect("可编码");
        assert_eq!(wire[2], kind);
        assert_eq!(
            decode_address_port(&wire).expect("可解码"),
            (addr, wire.len())
        );
    }
    // 未知地址类型与截断均 fail-closed。
    assert!(decode_address_port(&[0, 1, 9, 0]).is_err());
    assert!(decode_address_port(&[0, 1]).is_err());
    assert!(decode_address_port(&[0, 1, 2, 0]).is_err(), "空域名");
}
