//! B 组（续）：**多 chunk** 传输下的异常收尾。
//!
//! 这一组补的是「**同一个连接里连发多个 chunk**」这条路径的清理判据。其余
//! 单 chunk 场景见同目录的 `abnormal.rs`。
//!
//! 为什么单独成组：本仓的请求方向（`src/relay.rs` 的 `copy_request`）有**两条**
//! 不同的转发路径——
//!
//! - `head_payload`：与目标地址**同 chunk** 到达的载荷（握手时解出地址后剩余的
//!   字节）——这是**单 chunk**请求走的路径。
//! - **后续 chunk**：`reader.recv()` 循环里读到的每一个 chunk——**只有一条连接
//!   上连发多个 chunk** 才会走到。
//!
//! 只用单 chunk 请求写用例，**覆盖不到**第二条路径。`docs/shadowsocks-lifecycle.md`
//! §5 的变异记录证实了这一点：把「不转发后续 chunk」这个变异打进生产代码，
//! 当时的 16 条用例**一条都没抓到**。
//!
//! 与固定参考（Xray `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）的对应关系：
//!
//! - 参考 `proxy/shadowsocks/protocol.go:116` 的 `addrParser.ReadAddressPort(buffer, br)`
//!   把目标地址从缓冲流里**消费掉**，只有 `bodyReader` 会被拷给上游
//!   （`server.go` 的 `requestDone` ⇒ `buf.Copy(bodyReader, link.Writer, ...)`）。
//!   ⇒ **地址字节不得转交给上游**，本组按此写断言。
//! - 参考 `server.go:275-283` 的 `requestDone` 靠底层 EOF 收尾，**不伪造终止帧**；
//!   截断时 `buf.Copy` 返回错误 ⇒ `task.Run` 返回错误 ⇒ `common.Interrupt` 收掉
//!   连接（`server.go:286-289`）。⇒ 半截数据**不得**被当成成功转交，本组按此
//!   写 fail-closed 断言。

use std::time::Duration;

use lengsuo_shadowsocks::TargetAddr;

use super::common::{
    abort, local_set, read_response_exact, roundtrip, send_request_chunks, start_relay,
    write_request_chunks, OBSERVE, WAIT,
};
use super::probe::{
    drain_events, received_bytes, spawn_target, wait_received_delta, Flavor, TargetEvent,
};

/// B8：同一个连接里**连发多个 chunk**，随后客户端 RST ⇒ 中继必须把**每一个**
/// chunk 都转发给上游（不能只转发第一个），且异常结束后会话被回收。
///
/// 判据：
/// 1. 上游在异常结束前**已收到全部** chunk 的载荷字节数——少一个字节就说明中继
///    吞了某个 chunk。三个 chunk 的载荷长度**互不相同**（5 / 7 / 11），这样
///    「漏掉任意一个」都会让总字节数对不上，不会被其它 chunk 的长度掩盖。
/// 2. **地址不转发**：上游收到的字节数**恰好**等于载荷总和，不含地址字节。
/// 3. 异常结束后上游**不再**收到任何新字节（会话确实被收掉）。
#[test]
fn multi_chunk_request_is_fully_forwarded_before_abnormal_end() {
    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let mut upstream = spawn_target(Flavor::Echo).await;
        let target = TargetAddr::V4([127, 0, 0, 1], upstream.addr.port());
        let (relay, handle) = start_relay(None, None).await;

        // 三个 chunk：第一个带地址头，后两个只有载荷。长度互不相同 ⇒ 漏一个就能看出来。
        let first = b"aaaaa";
        let second = b"bbbbbb";
        let third = b"ccccccccccc";
        // 上游应收到的字节数 = 三个 chunk 的**载荷**总和（**不含**地址字节）。
        let expected_bytes = first.len() + second.len() + third.len();

        // 建立连接并连发三个 chunk（**不半关闭**，保持连接打开）。
        let mut stream = tokio::net::TcpStream::connect(relay)
            .await
            .expect("连接中继");
        write_request_chunks(
            &mut stream,
            &target,
            &[first.as_slice(), second.as_slice(), third.as_slice()],
        )
        .await;

        // 同步点：等上游确认已收到**全部** chunk 的载荷（否则 RST 与转发并发 ⇒ 竞态）。
        let got = wait_received_delta(&mut upstream, expected_bytes, WAIT).await;
        assert_eq!(
            got, expected_bytes,
            "中继必须把**每一个** chunk 都转发给上游（不能只转发第一个，也不能把地址一起转过去）"
        );

        // 现在制造异常结束：客户端 RST（不发 EOF）。
        abort(stream);

        // 会话被回收：上游看到 EOF 或错误，且**此后不再收到任何字节**。
        let events = drain_events(&mut upstream, OBSERVE, Duration::from_millis(200)).await;
        assert!(
            events.contains(&TargetEvent::PeerEof) || events.contains(&TargetEvent::Failed),
            "RST 之后本仓侧应在 {OBSERVE:?} 内感知断开并关闭上游连接，实际事件：{events:?}"
        );
        let teardown_at = events
            .iter()
            .position(|event| matches!(event, TargetEvent::PeerEof | TargetEvent::Failed))
            .expect("上游必须观察到收尾事件");
        let after: usize = events[teardown_at..]
            .iter()
            .filter_map(|event| match event {
                TargetEvent::Received(len) => Some(*len),
                _ => None,
            })
            .sum();
        assert_eq!(
            after, 0,
            "会话收尾后不得再向上游投递载荷，实际事件：{events:?}"
        );

        handle.shutdown().await.expect("中继应干净停止");
    });
}

/// B9：多 chunk 传输**中途**第二个 chunk 被截断 ⇒ 前面已完整收到的 chunk 必须
/// 已转发（不回滚），而**截断的那个 chunk 不得**被当成成功转交上游（fail-closed）。
///
/// 判据（与参考 `server.go:275-283` 的 `requestDone` 对齐：请求方向靠底层 EOF
/// 收尾，**不伪造终止帧**）：
/// 1. 上游收到的字节数 = 第一个 chunk 的完整载荷（**不含**地址字节）——**恰好**，
///    不多不少：第二个 chunk 的截断部分一个字节都不能进上游。
/// 2. 会话被回收：上游看到 EOF 或错误。
/// 3. 之后的新连接仍可用（异常结束没污染共享状态）。
///
/// 截断点特意落在**第二个 chunk 的载荷密文内部**（不是 size 段）：载荷密文被
/// 截断时，若中继 fail-open（把半截密文当明文转交），上游就会收到**部分明文**
/// ——这是最危险的形态。size 段被截断时中继连长度都不知道，本来就无从转交。
#[test]
fn truncated_second_chunk_never_reaches_upstream() {
    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let mut upstream = spawn_target(Flavor::Echo).await;
        let target = TargetAddr::V4([127, 0, 0, 1], upstream.addr.port());
        let (relay, handle) = start_relay(None, None).await;

        // 用**固定 salt** 手工拼两个 chunk 的线上字节：第一个 chunk 完整（地址 +
        // 载荷），第二个 chunk 完整写出 size 段后，载荷密文**只给一半**。
        let salt = [0x81u8; 32];
        let first_payload = b"complete-first";
        let second_payload = b"never-delivered";
        let wire = fixed_salt_two_chunks(&salt, &target, first_payload, second_payload).await;

        // 第一个 chunk 的线上长度 = salt + size 段 + 载荷密文（含 tag）。
        let first_chunk_len = salt.len()
            + ss_core::chunk::SIZE_WIRE_LEN
            + first_payload.len()
            + ss_core::crypto::TAG_LEN;
        // 截断点：第二个 chunk 的 size 段写全，载荷密文只给**一半**（不含 tag）。
        let cut = first_chunk_len
            + ss_core::chunk::SIZE_WIRE_LEN
            + (second_payload.len() + ss_core::crypto::TAG_LEN) / 2;
        assert!(
            cut < wire.len(),
            "截断点必须落在第二个 chunk 的载荷密文内部（wire {} 字节，截断点 {cut}）",
            wire.len()
        );
        assert!(
            cut > first_chunk_len + ss_core::chunk::SIZE_WIRE_LEN,
            "截断点必须落在第二个 chunk 的**载荷**段（不能只截 size 段）"
        );

        // 写前半截，然后**不发 EOF**直接 RST ⇒ 中继读到的是「chunk 内截断」。
        let mut stream = tokio::net::TcpStream::connect(relay)
            .await
            .expect("连接中继");
        tokio::io::AsyncWriteExt::write_all(&mut stream, &wire[..cut])
            .await
            .expect("写中继");
        abort(stream);

        // ① fail-closed：上游**只**收到第一个 chunk 的载荷（**不含**地址字节），
        //    第二个 chunk 的任何一个字节都不得进上游。
        let events = drain_events(&mut upstream, OBSERVE, Duration::from_millis(200)).await;
        let received = received_bytes(&events);
        assert_eq!(
            received,
            first_payload.len(),
            "第二个 chunk 被截断 ⇒ 它不得被当作成功转交上游（上游应恰好收到第一个 chunk 的载荷，不含地址），实际收到 {received} 字节，事件：{events:?}"
        );

        // ② 会话被回收。
        assert!(
            events.contains(&TargetEvent::PeerEof) || events.contains(&TargetEvent::Failed),
            "截断后本仓侧应在 {OBSERVE:?} 内关闭上游连接（会话被回收），实际事件：{events:?}"
        );

        // ③ 之后的新连接仍可用 ⇒ 异常结束没污染共享状态。
        let reply = roundtrip(relay, &target, b"after-truncated-second").await;
        assert_eq!(
            reply,
            b"after-truncated-second".to_vec(),
            "截断后新连接必须仍能正常往返"
        );

        handle.shutdown().await.expect("中继应干净停止");
    });
}

/// B10：多 chunk 传输**正常收尾**时，回程方向必须把上游的**全部**数据回写给
/// 客户端，且**按 chunk 边界**（不是一个 chunk 都不发、或把两段粘成别的形态）。
///
/// 这一条覆盖 B8/B9 之外的另一半：请求方向连发多个 chunk、上游回声多段 ⇒
///
/// - **回程方向**（`src/relay.rs` 的 `copy_response`）必须把每一段都写出去；
/// - 客户端的写端半关闭（`task.Close(link.Writer)` 的对侧）之后，回程方向读到
///   干净 EOF ⇒ 客户端读到**干净 EOF**（不是挂死、不是错误）。
///
/// 与参考对齐：`server.go:245-273` 的 `responseDone` 用**新 salt + 新 nonce
/// 序列**写回（回程方向是独立的一条 AEAD 会话），`buf.Copy(link.Reader,
/// responseWriter, ...)` 把上游的字节**逐段**转交。
#[test]
fn multi_chunk_roundtrip_delivers_every_response_chunk_then_clean_eof() {
    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let mut upstream = spawn_target(Flavor::Segmented).await;
        let target = TargetAddr::V4([127, 0, 0, 1], upstream.addr.port());
        let (relay, handle) = start_relay(None, None).await;

        // 三段载荷，长度互不相同 ⇒ 回程少一段就能看出来。
        let first = b"resp-a";
        let second = b"resp-bb";
        let third = b"resp-ccc";
        let expected_bytes = first.len() + second.len() + third.len();

        // 客户端连发三个 chunk，然后**半关闭写端**（请求方向干净结束）。
        let mut stream = tokio::net::TcpStream::connect(relay)
            .await
            .expect("连接中继");
        send_request_chunks(
            &mut stream,
            &target,
            &[first.as_slice(), second.as_slice(), third.as_slice()],
        )
        .await;

        // 回程：客户端必须收到**全部**三段（回程方向是独立 AEAD 会话，
        // 逐 chunk 解帧）。
        let got = read_response_exact(stream, expected_bytes).await;
        assert_eq!(
            got.len(),
            expected_bytes,
            "回程方向必须把上游的每一段都回写（收到 {} 字节，应为 {expected_bytes}）",
            got.len()
        );
        // 逐段核对（上游是回声目标，回程内容 = 请求载荷，顺序不变）。
        let mut want = Vec::new();
        want.extend_from_slice(first);
        want.extend_from_slice(second);
        want.extend_from_slice(third);
        assert_eq!(got, want, "回程内容必须与请求载荷一致（顺序不变）");

        // 上游侧：请求方向干净结束 ⇒ 中继对上游写半关闭 ⇒ 上游看到 EOF。
        let events = drain_events(&mut upstream, OBSERVE, Duration::from_millis(200)).await;
        assert!(
            events.contains(&TargetEvent::PeerEof),
            "请求方向干净结束后中继应对上游写半关闭（上游看到 EOF），实际事件：{events:?}"
        );

        handle.shutdown().await.expect("中继应干净停止");
    });
}

/// 用**固定 salt** 构造**两个** chunk 的线上字节（salt + chunk1 + chunk2）。
///
/// 两个 chunk 共用**同一个** AEAD 会话（nonce 序列连续，size 段与载荷段各消耗
/// 一个 nonce）——与客户端 `TcpWriter` 在一条连接上连发多个 chunk 的线上格式
/// 完全一致。第一个 chunk 的明文 = 目标地址 + `first_payload`；第二个 chunk 的
/// 明文 = `second_payload`（地址不重复）。
async fn fixed_salt_two_chunks(
    salt: &[u8],
    target: &TargetAddr,
    first_payload: &[u8],
    second_payload: &[u8],
) -> Vec<u8> {
    let suite = super::common::SUITE;
    assert_eq!(salt.len(), suite.salt_len(), "salt 长度必须与套件一致");
    let master =
        ss_core::kdf::evp_bytes_to_key(super::common::PASSWORD.as_bytes(), suite.key_len());
    let subkey = ss_core::kdf::hkdf_sha1_subkey(&master, salt, suite.key_len());
    let mut aead = ss_core::crypto::SessionAead::new(suite, subkey);
    let mut first = Vec::new();
    target.encode_checked(&mut first).expect("回环目标可编码");
    first.extend_from_slice(first_payload);
    let mut wire = Vec::new();
    wire.extend_from_slice(salt);
    ss_core::chunk::write_chunk(&mut wire, &mut aead, &first)
        .await
        .expect("第一个 chunk 应可构造");
    ss_core::chunk::write_chunk(&mut wire, &mut aead, second_payload)
        .await
        .expect("第二个 chunk 应可构造");
    wire
}
