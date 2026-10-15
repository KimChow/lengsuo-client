use super::*;

#[test]
fn stream_ids_start_at_one_and_increase_strictly() {
    let mut st = v1(4);
    for expect in 1..=4u32 {
        assert_eq!(st.open_stream(), Ok(expect), "流编号从 1 严格连续");
    }
    assert_eq!(
        st.open_stream(),
        Err(ClientError::StreamLimitReached),
        "活跃流达上限时拒绝开流"
    );
    assert_eq!(st.close_stream(1), Ok(()));
    assert_eq!(st.close_stream(2), Ok(()));
    assert_eq!(
        st.open_stream(),
        Ok(5),
        "释放容量后新编号继续递增，不复用已关闭编号",
    );
}

#[test]
fn capacity_rejection_does_not_consume_an_id() {
    let mut st = v1(1);
    assert_eq!(st.open_stream(), Ok(1));
    for _ in 0..3 {
        assert_eq!(st.open_stream(), Err(ClientError::StreamLimitReached));
    }
    assert_eq!(st.close_stream(1), Ok(()));
    assert_eq!(st.open_stream(), Ok(2), "被容量拒绝的调用不得消耗流编号");
}

#[test]
fn closed_ids_are_never_reused_and_close_is_local_only() {
    let mut st = v1(4);
    let first = st.open_stream().unwrap();
    assert_eq!(st.close_stream(first), Ok(()));
    assert!(!st.is_active(first), "关闭后不再是活跃流");
    assert_eq!(
        st.close_stream(first),
        Err(ClientError::InvalidStream("流已关闭")),
        "重复关闭是本地错误"
    );
    assert_eq!(
        st.close_stream(0),
        Err(ClientError::InvalidStream("流编号为零")),
        "零不是合法流编号"
    );
    assert_eq!(
        st.close_stream(9),
        Err(ClientError::InvalidStream("引用从未创建的流")),
        "从未创建的流不可关闭"
    );
    assert_eq!(st.open_stream(), Ok(2), "已关闭编号不会被再次分配");
    assert!(!st.is_poisoned(), "以上都是本地错误，不破坏会话");
    assert!(!st.is_terminated());
}

#[test]
fn readiness_depends_on_version_and_synack() {
    // 版本 1：活跃即就绪，无需 SYNACK。
    let mut st = v1(4);
    let id = st.open_stream().unwrap();
    assert!(st.is_ready(id), "版本 1 活跃流直接就绪");
    assert!(!st.is_ready(9), "不存在的流永不就绪");
    // 版本 2：必须收到成功 SYNACK 才就绪。
    let mut st = v2(4);
    let id = st.open_stream().unwrap();
    assert!(!st.is_ready(id), "版本 2 未 ACK 时不就绪");
    assert_eq!(st.accept(&syn_ack(id, Vec::new())), Ok(Event::Ready(id)));
    assert!(st.is_ready(id), "成功 SYNACK 后就绪");
    assert_eq!(
        st.accept(&syn_ack(id, Vec::new())),
        Ok(Event::Ignore),
        "重复成功 SYNACK 不改变状态"
    );
    assert!(st.is_ready(id), "重复 ACK 后仍就绪");
    assert!(!st.is_poisoned(), "以上都不应失效会话");
}

#[test]
fn error_synack_rejects_only_that_stream() {
    let mut st = v2(4);
    let a = open_ready(&mut st, 1);
    let b = st.open_stream().unwrap();
    let bad = syn_ack(b, b"dial tcp failed".to_vec());
    assert_eq!(st.accept(&bad), Ok(Event::Rejected(b)));
    assert_eq!(
        bad.data, b"dial tcp failed",
        "错误文本仍在调用方持有的原帧中"
    );
    assert!(!st.is_active(b), "被拒流已由状态机移除");
    assert!(!st.is_poisoned(), "单流错误不毒化会话");
    assert!(st.is_active(a) && st.is_ready(a), "另一条流不受影响");
    assert_eq!(st.accept(&push(a, vec![7])), Ok(Event::Data(a)));
    assert_eq!(
        st.close_stream(b),
        Err(ClientError::InvalidStream("流已关闭")),
        "被拒流无需再次关闭"
    );
    assert_eq!(st.open_stream(), Ok(3), "被拒编号不会被复用");
}

#[test]
fn late_frames_after_close_are_ignored_not_poisoning() {
    let mut st = v2(4);
    let live = open_ready(&mut st, 1);
    let closed = st.open_stream().unwrap();
    assert_eq!(
        st.accept(&syn_ack(closed, Vec::new())),
        Ok(Event::Ready(closed))
    );
    assert_eq!(st.close_stream(closed), Ok(()));
    // 迟到帧指向本端已关闭的流：静默忽略，且不得影响其他活跃流。
    for late in [
        push(closed, vec![1, 2, 3]),
        fin(closed),
        syn_ack(closed, Vec::new()),
        syn_ack(closed, b"late error".to_vec()),
    ] {
        assert_eq!(
            st.accept(&late),
            Ok(Event::Ignore),
            "{:?} 类迟到帧应忽略",
            late.command
        );
        assert!(!st.is_poisoned(), "迟到帧不得毒化会话");
    }
    assert!(st.is_active(live), "活跃流不受影响");
    assert!(st.is_ready(live));
    assert_eq!(st.accept(&push(live, vec![9])), Ok(Event::Data(live)));
    assert_eq!(st.accept(&fin(live)), Ok(Event::Closed(live)));
    assert_eq!(st.open_stream(), Ok(3), "关闭后编号仍不复用");
}

#[test]
fn never_created_stream_ids_are_rejected() {
    // 超出已分配上限的编号是真正的协议违规，不能与迟到帧混为一谈。
    for bad in [
        push(6, vec![0]),
        fin(6),
        syn_ack(6, Vec::new()),
        syn_ack(6, b"err".to_vec()),
    ] {
        let mut st = v2(4);
        open_ready(&mut st, 1);
        reject(
            st,
            bad,
            ClientError::InvalidStream("引用从未创建的流"),
            "从未创建的流不得被远端引用",
        );
    }
}

#[test]
fn zero_stream_id_frames_are_rejected() {
    for bad in [syn_ack(0, Vec::new()), push(0, vec![1]), fin(0)] {
        let mut st = v2(4);
        open_ready(&mut st, 1);
        reject(
            st,
            bad,
            ClientError::InvalidStream("流编号为零"),
            "零流编号的数据/ACK/FIN 必须拒绝",
        );
    }
}

#[test]
fn synack_is_version_two_only() {
    reject(
        v1(4),
        syn_ack(1, Vec::new()),
        ClientError::InvalidVersion("SYNACK"),
        "版本 1 不使用 SYNACK",
    );
    reject(
        v1(4),
        syn_ack(1, b"err".to_vec()),
        ClientError::InvalidVersion("SYNACK"),
        "版本 1 不使用带错误文本的 SYNACK",
    );
}

#[test]
fn data_before_synack_is_violation_in_version_two() {
    let mut st = v2(4);
    let id = st.open_stream().unwrap();
    reject(
        st,
        push(id, vec![1]),
        ClientError::InvalidStream("数据早于 SYNACK"),
        "版本 2 未 ACK 即收到数据",
    );
    // 版本 1 同一序列合法，说明差异只来自协商出的版本。
    let mut st = v1(4);
    let id = st.open_stream().unwrap();
    assert_eq!(st.accept(&push(id, vec![1])), Ok(Event::Data(id)));
    assert_eq!(
        st.accept(&push(id, Vec::new())),
        Ok(Event::Ignore),
        "空数据帧不产生事件，也不改变流状态"
    );
    assert!(st.is_active(id));
}

#[test]
fn fin_with_data_is_rejected() {
    let mut st = v2(4);
    let id = open_ready(&mut st, 1);
    reject(
        st,
        frame(Command::Fin, id, vec![1]),
        ClientError::InvalidStream("FIN 携带数据"),
        "FIN 不得携带数据",
    );
}

#[test]
fn events_never_copy_payload() {
    let mut st = v2(4);
    let id = open_ready(&mut st, 1);
    let owned = push(id, vec![9, 8, 7]);
    assert_eq!(st.accept(&owned), Ok(Event::Data(id)), "事件只报告流编号");
    assert_eq!(owned.data, vec![9, 8, 7], "载荷仍在调用方持有的原帧中");
    let bytes = owned.encode().unwrap();
    let (decoded, used) = Frame::decode(&bytes).unwrap();
    assert_eq!(used, bytes.len());
    assert!(decoded == owned, "帧可原样编解码，状态机不消耗它");
}

#[test]
fn two_streams_do_not_leak_into_each_other() {
    let mut st = v2(4);
    let a = open_ready(&mut st, 1);
    let b = open_ready(&mut st, 2);
    assert_eq!(st.accept(&push(a, vec![1, 1])), Ok(Event::Data(a)));
    assert_eq!(st.accept(&push(b, vec![2])), Ok(Event::Data(b)));
    assert_eq!(st.accept(&fin(a)), Ok(Event::Closed(a)));
    assert_eq!(
        st.accept(&push(b, vec![3])),
        Ok(Event::Data(b)),
        "流 1 关闭不影响流 2 的数据"
    );
    assert_eq!(st.accept(&syn_ack(b, vec![4])), Ok(Event::Rejected(b)));
    assert_eq!(
        st.accept(&push(b, vec![5])),
        Ok(Event::Ignore),
        "被拒流之后的数据按迟到处理"
    );
    assert!(!st.is_poisoned(), "全程合法序列不应失效");
    assert_eq!(st.peer_version(), 2, "版本状态不受流事件影响");
    assert_eq!(st.open_stream(), Ok(3));
}
