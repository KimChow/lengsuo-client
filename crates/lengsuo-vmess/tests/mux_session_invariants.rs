//! Mux 会话级原语的回归锁（非 ignore，不依赖 Xray）。
//!
//! 背景（2026-10-24 W4 核验卡判定）：`muxframe`/`muxsession` 目前是**库层孤岛**
//! （`crates/lengsuo-egress/src/outbound_vmess.rs` 对 mux 零引用），且出口接线
//! 被库层「按设计拒绝 Mux 命令」阻塞（`request` 模块无 Mux 变体）。本文件锁住
//! **未来接线所依赖的会话级不变量**——这些行为若被改动，出口接线的判定与
//! `tests/xray_mux.rs` 的参考互通结论都要重新取证：
//!
//! - 会话分配：id 从 1 递增、策略上限、被拒分配不递增 count；
//! - 帧语义：元数据帧 `option = 0`（Xray `unknown status: 108` 的实跑根因）、
//!   Stream 8KiB 分片（首片 New、其余 Keep）、Packet 一报一帧、End 的错误标志；
//! - 生命周期：End 移除表项、未知会话 Keep 不致命且**库层不自动回 End**
//!   （编排职责在调用方）、sink 故障关闭会话。
//!
//! 帧级（字节层）编解码由 `src/muxframe/tests.rs` 单测覆盖；与 Xray 的线级
//! 互通由 `tests/xray_mux.rs`（`#[ignore]`）覆盖，此处不重复。

use std::io::Cursor;

use lengsuo_vmess::muxframe::{
    FrameMetadata, SessionStatus, TargetNetwork, OPTION_DATA, OPTION_ERROR, SESSION_CHUNK_SIZE,
};
use lengsuo_vmess::muxsession::{
    encode_frame_with_payload, ClientSession, FrameReader, SessionStrategy, SessionTable,
    StreamSender, StreamSink,
};
use ss_core::target::TargetAddr;

/// 回环测试目标（只用回环地址 + 固定端口常量，不发起连接）。
fn target() -> TargetAddr {
    TargetAddr::V4([127, 0, 0, 1], 443)
}

/// 解出字节流里的全部帧（EOF 停止）。
fn all_frames(bytes: Vec<u8>) -> Vec<(FrameMetadata, Option<Vec<u8>>)> {
    let mut reader = FrameReader::new(Cursor::new(bytes), false);
    let mut frames = Vec::new();
    while let Ok(frame) = reader.next_frame() {
        frames.push(frame);
    }
    frames
}

#[test]
fn session_allocation_is_sequential_and_enforces_strategy() {
    // 无策略：id 从 1 开始连续分配（`m.count++` 后取 `ID = count`）。
    let mut table = SessionTable::new(SessionStrategy::default());
    let first = table
        .allocate(TargetNetwork::Tcp, target())
        .expect("首个会话应分配成功");
    let second = table
        .allocate(TargetNetwork::Udp, target())
        .expect("第二个会话应分配成功");
    assert_eq!((first.id, second.id), (1, 2));
    assert_eq!(
        (first.network, second.network),
        (TargetNetwork::Tcp, TargetNetwork::Udp)
    );
    assert_eq!(table.size(), 2);
    assert_eq!(table.count(), 2);
    assert_eq!(table.ids(), vec![1, 2]);

    // max_concurrency：活跃会话数触顶即拒；被拒分配不递增 count；释放后可再分配。
    let mut table = SessionTable::new(SessionStrategy {
        max_concurrency: 1,
        max_connection: 0,
    });
    assert!(table.allocate(TargetNetwork::Tcp, target()).is_some());
    assert!(table.allocate(TargetNetwork::Tcp, target()).is_none());
    assert_eq!(table.count(), 1, "被拒分配不得递增 count");
    table.remove(1);
    let reallocated = table
        .allocate(TargetNetwork::Tcp, target())
        .expect("释放活跃槽后应可再分配");
    assert_eq!(reallocated.id, 2, "id 只增不复用");

    // max_connection：累计触顶即拒——释放活跃槽也不能再分配。
    let mut table = SessionTable::new(SessionStrategy {
        max_concurrency: 0,
        max_connection: 2,
    });
    assert!(table.allocate(TargetNetwork::Tcp, target()).is_some());
    assert!(table.allocate(TargetNetwork::Tcp, target()).is_some());
    table.remove(1);
    table.remove(2);
    assert!(
        table.allocate(TargetNetwork::Tcp, target()).is_none(),
        "累计上限触顶后，释放活跃槽也不得再分配"
    );
    assert_eq!(table.count(), 2);
}

#[test]
fn meta_only_new_frame_carries_option_zero() {
    let mut sender = StreamSender::new(7, TargetNetwork::Tcp, target());
    let mut out = Vec::new();
    sender
        .send_new(&mut out, None)
        .expect("元数据帧应可编码（100ms 无首包路径）");
    let frames = all_frames(out);
    assert_eq!(frames.len(), 1, "元数据帧之后不得跟随任何帧");
    let (meta, payload) = &frames[0];
    assert_eq!(meta.session_id, 7);
    assert_eq!(meta.status, SessionStatus::New);
    assert_eq!(
        meta.target.as_ref().map(|(_, net)| *net),
        Some(TargetNetwork::Tcp)
    );
    // 参考 `writeMetaOnly`（writer.go:62-69）的 Option 为 0：带 OptionData 会被
    // 对端当作本帧数据长度读走（实跑证据：Xray `unknown status: 108`）。
    assert_eq!(meta.option, 0, "元数据帧不得带 OptionData");
    assert!(payload.is_none());
    assert!(sender.new_sent, "发出 New 后应置 new_sent");
}

#[test]
fn large_stream_payload_splits_per_chunk_first_new_rest_keep() {
    let payload = vec![0xA5u8; SESSION_CHUNK_SIZE * 2 + 100];
    let mut sender = StreamSender::new(1, TargetNetwork::Tcp, target());
    let mut out = Vec::new();
    sender.send_new(&mut out, Some(&payload)).expect("应可编码");

    let frames = all_frames(out);
    assert_eq!(
        frames.len(),
        3,
        "8KiB×2+100 应切成 3 帧（首片 New、其余 Keep）"
    );
    let (first_meta, first_data) = &frames[0];
    assert_eq!(first_meta.status, SessionStatus::New);
    assert_eq!(
        first_meta.option, OPTION_DATA,
        "带数据段的帧必须置 OptionData"
    );
    assert!(first_meta.target.is_some(), "New 帧必须带目标地址段");
    assert_eq!(
        first_data.as_deref().map(<[u8]>::len),
        Some(SESSION_CHUNK_SIZE)
    );
    for (index, expected_len) in [(1, SESSION_CHUNK_SIZE), (2, 100)] {
        let (meta, data) = &frames[index];
        assert_eq!(meta.status, SessionStatus::Keep);
        assert_eq!(meta.option, OPTION_DATA);
        assert!(meta.target.is_none(), "Keep 帧不带地址段");
        assert_eq!(data.as_deref().map(<[u8]>::len), Some(expected_len));
    }
    let reassembled: Vec<u8> = frames
        .iter()
        .flat_map(|(_, data)| data.as_deref().unwrap_or(&[]))
        .copied()
        .collect();
    assert_eq!(reassembled, payload, "分片重组后必须逐字节一致");
}

#[test]
fn keep_before_new_upgrades_to_new_frame() {
    let mut sender = StreamSender::new(3, TargetNetwork::Tcp, target());
    let mut out = Vec::new();
    sender
        .send_keep(&mut out, b"first-write")
        .expect("未发 New 时的 Keep 应升级为 New");
    let frames = all_frames(out);
    let (meta, data) = &frames[0];
    assert_eq!(meta.status, SessionStatus::New, "首写必须是 New 帧");
    assert_eq!(data.as_deref(), Some(&b"first-write"[..]));
    assert!(sender.new_sent);
}

#[test]
fn udp_session_sends_one_datagram_per_frame() {
    // 数据段上限 = buf.Size(8192)（`read_data` 拒超限），取上限内的尺寸。
    let datagram = vec![7u8; 6000];
    let mut sender = StreamSender::new(5, TargetNetwork::Udp, target());
    let mut out = Vec::new();
    sender
        .send_new(&mut out, Some(&datagram))
        .expect("应可编码");

    // Packet 模式（参考 SplitFirst）：一次调用 = 一个数据报 = 一帧，整报文承载。
    let frames = all_frames(out);
    assert_eq!(frames.len(), 1, "UDP 数据报必须单帧完整承载");
    let (meta, data) = &frames[0];
    assert_eq!(meta.status, SessionStatus::New);
    assert_eq!(
        meta.target.as_ref().map(|(_, net)| *net),
        Some(TargetNetwork::Udp)
    );
    assert_eq!(data.as_deref(), Some(&datagram[..]));
}

#[test]
fn end_frame_option_reflects_error_flag() {
    let mut sender = StreamSender::new(9, TargetNetwork::Tcp, target());
    let mut clean = Vec::new();
    sender.send_end(&mut clean, false).expect("应可编码");
    let frames = all_frames(clean);
    let (meta, data) = &frames[0];
    assert_eq!(meta.session_id, 9);
    assert_eq!(meta.status, SessionStatus::End);
    assert_eq!(meta.option, 0, "正常关闭的 End 帧不带错误标志");
    assert!(data.is_none(), "End 帧不携带数据段");

    let mut faulty = Vec::new();
    sender.send_end(&mut faulty, true).expect("应可编码");
    let (meta, _) = &all_frames(faulty)[0];
    assert_eq!(meta.option, OPTION_ERROR, "出错的 End 帧必须带 OptionError");
}

#[test]
fn remote_end_removes_session_and_close_local_emits_end_frame() {
    let mut client = ClientSession::new(SessionStrategy::default());
    let state = client.open(TargetNetwork::Tcp, target()).expect("分配成功");
    // 对端 End ⇒ 本端表项移除（参考 handleStatusEnd）。
    let remote_end = encode_frame_with_payload(state.id, SessionStatus::End, 0, None, None)
        .expect("End 帧应可编码");
    let (meta, _) = &all_frames(remote_end)[0];
    client.handle_frame(meta, None).expect("End 帧处理应成功");
    assert!(
        client.table().get(state.id).is_none(),
        "对端 End 后表项应移除"
    );

    // 本端关闭 ⇒ End 帧（带错误标志）+ 表项移除（参考 Writer.Close）。
    let state = client.open(TargetNetwork::Tcp, target()).expect("再分配");
    let frame = client.close_local(state.id, true);
    let (meta, _) = &all_frames(frame)[0];
    assert_eq!(
        (meta.session_id, meta.status, meta.option),
        (state.id, SessionStatus::End, OPTION_ERROR)
    );
    assert!(
        client.table().get(state.id).is_none(),
        "本端关闭后表项应移除"
    );
}

#[test]
fn unknown_session_keep_is_ignored_and_caller_sends_closing_end() {
    let mut client = ClientSession::new(SessionStrategy::default());
    let ghost = FrameMetadata {
        session_id: 0xFFFF,
        status: SessionStatus::Keep,
        option: OPTION_DATA,
        target: None,
        source: None,
        local: None,
    };
    client
        .handle_frame(&ghost, Some(b"ghost-payload"))
        .expect("未知会话的 Keep 不得致命");
    assert!(client.table().get(0xFFFF).is_none());
    assert_eq!(client.table().count(), 0, "未知会话不得进入本地表");
    assert!(
        !client.table().is_closed(),
        "未知会话 Keep 不得关闭整条承载"
    );
    // 编排契约：库层不自动回 End；由调用方用 `closing_end_frame` 生成并写出
    // （参考 handleStatusKeep 未命中 ⇒ NewResponseWriter(...).Close()，option=0）。
    let end = ClientSession::closing_end_frame(0xFFFF);
    let (meta, data) = &all_frames(end)[0];
    assert_eq!(
        (meta.session_id, meta.status, meta.option),
        (0xFFFF, SessionStatus::End, 0)
    );
    assert!(data.is_none());
}

/// 记录关闭回调的 sink：写侧可注入故障。
#[derive(Default)]
struct FailingSink {
    fail_writes: bool,
    remote_closed: bool,
}

impl StreamSink for FailingSink {
    fn write(&mut self, _payload: &[u8]) -> Result<(), String> {
        if self.fail_writes {
            return Err("sink 写入故障".to_owned());
        }
        Ok(())
    }
    fn close_remote(&mut self) -> Result<(), String> {
        self.remote_closed = true;
        Ok(())
    }
    fn close_local(&mut self) -> Result<(), String> {
        Ok(())
    }
}

#[test]
fn keep_data_reaches_attached_sink_and_sink_error_closes_session() {
    fn keep_meta(session_id: u16) -> FrameMetadata {
        FrameMetadata {
            session_id,
            status: SessionStatus::Keep,
            option: OPTION_DATA,
            target: None,
            source: None,
            local: None,
        }
    }
    // 正常路径：Keep+data 投递给已登记 sink，会话保持存活。
    let mut client = ClientSession::new(SessionStrategy::default());
    let state = client.open(TargetNetwork::Tcp, target()).expect("分配成功");
    client.attach(state.id, Box::<FailingSink>::default());
    client
        .handle_frame(&keep_meta(state.id), Some(b"downstream"))
        .expect("投递应成功");
    assert!(
        client.table().get(state.id).is_some(),
        "sink 正常时会话必须保持存活"
    );

    // sink 写失败 ⇒ 会话被移除（fail-closed，参考 fetchOutput 的 hasError 路径）。
    let state = client.open(TargetNetwork::Tcp, target()).expect("再分配");
    client.attach(
        state.id,
        Box::new(FailingSink {
            fail_writes: true,
            remote_closed: false,
        }),
    );
    client
        .handle_frame(&keep_meta(state.id), Some(b"downstream"))
        .expect("sink 故障由库层消化，不向读循环传播错误");
    assert!(
        client.table().get(state.id).is_none(),
        "sink 写失败后必须关闭该会话"
    );
}
