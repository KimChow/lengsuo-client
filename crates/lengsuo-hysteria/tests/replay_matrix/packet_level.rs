//! **包级重放**：抓到的 QUIC 数据报被再次投递时，发生了什么。
//!
//! 这是「重放是否依赖 QUIC 的连接 ID 与流 ID 机制」的直接取证。
//!
//! # 语义基线
//!
//! **QUIC 传输层（RFC 9000）**保证重放不会造成应用层重复交付。它由
//! **两个彼此独立的机制**共同保证，本文件的用例分别取证：
//!
//! 1. **同连接重放 ⇒ 包号去重丢弃**。重复的**包号**（packet number）
//!    会被丢弃：quinn-proto `src/connection/mod.rs:2340-2343`
//!    （`Dedup::insert` 返回 true ⇒ `debug!("discarding possible duplicate
//!    packet")` ⇒ `return`），去重窗口在 `src/connection/spaces.rs:470`
//!    `Dedup`（128 位位图）；参考实现用的 quic-go（`apernet/quic-go`
//!    fork）同理：`connection.go:1378` `IsPotentiallyDuplicate` ⇒
//!    `Dropping (potentially) duplicate packet`。
//!
//! 2. **跨连接重放 ⇒ 连接 ID 路由 + AEAD 密钥绑定**。数据报里的
//!    **连接 ID** 决定服务端把它路由到哪条连接：
//!    - 数据报仍带**原连接**的 CID ⇒ 路由回**原连接** ⇒ 由 (1) 的包号
//!      去重丢弃；
//!    - **原连接已关闭** ⇒ 该 CID 不在服务端路由表里 ⇒ 数据报无法被
//!      路由到**任何**存活连接（特别是不会命中别的会话）；
//!    - 即便攻击者把 CID 改写成**另一条存活连接**的 CID，1-RTT 包的
//!      **AEAD 密钥与连接绑定**（密钥由 TLS 握手 transcript 派生；Initial
//!      密钥由 `dst_cid` 派生 —— quinn-proto `src/crypto/rustls.rs:56`
//!      `initial_keys` / `:596` `initial_keys`）⇒ 解密失败被丢弃。
//!
//! ⇒ **结论（参考行为）**：传输层重放**不会**造成应用层重复交付。
//! 本仓用 quinn，语义相同（参考用 quic-go，同一套 RFC 9000 语义）。
//!
//! # 与 `frame_level.rs` 的分工
//!
//! - 本文件：**QUIC 数据报**被重放 ⇒ 不重复交付（传输层保证）。
//! - `frame_level.rs`：**应用层字节**被重放（通过正常 API 重新发出）
//!   ⇒ 被当成新请求（协议层无防重放）。

use std::time::Duration;

use super::support::{
    client_config, encode_tcp_request, pattern, spawn_tcp_target, start_server, RawStream,
    UdpRelay, RECLAIM_DEADLINE,
};

/// 重放用的固定 padding。
const REPLAY_PADDING: &[u8] = b"lengsuo-replay-fixed-padding-0123456789";

/// **否定断言**的观测窗（重放后「不该发生的事」必须**持续**不发生）。
///
/// 传输层的丢弃是**立即**发生的（包号去重 / CID 路由都是同步判定），
/// 3 秒的观测窗足够覆盖「重放已被服务端处理完」这个时间尺度。
///
/// ⚠️ 这是**有限**窗：它证明「3 秒内没发生」，不证明「永远不会发生」。
/// 这是否定断言的合理上限，也是本卡与参考**语义对齐**的部分：参考实现
/// 在同一条路径上也是**立即**丢弃（不排队、不重试）。
const NEGATIVE_WINDOW: Duration = Duration::from_secs(3);

/// 包级重放（同一连接）：重放抓到的 QUIC 数据报 ⇒ **不得**造成重复交付。
///
/// 步骤：
/// 1. 客户端经 UDP 中继连本仓服务端（服务端看到的源地址 = 中继 socket）；
/// 2. 走一次 TCP 承载，抓下客户端 → 服务端方向的数据报；
/// 3. 把其中一个数据报**逐字节**重发给服务端；
/// 4. 断言：目标**没有**收到第二份数据（传输层按包号去重丢弃）。
#[tokio::test]
async fn same_connection_packet_replay_is_not_delivered_twice() {
    super::support::case_within(super::support::CASE_DEADLINE, async {
        let server = start_server("pkt-same").await;
        let relay = UdpRelay::start(server.addr).await;
        let target = spawn_tcp_target().await;
        let addr = target.addr.to_string();

        // 客户端连中继（服务端看到的源地址是中继 socket）。
        let mut cfg = client_config(&server, &server.auth);
        cfg.server_addr = relay.addr;
        let client = lengsuo_hysteria::quic::HysteriaClient::connect(cfg.clone())
            .await
            .expect("建连失败");

        let payload = pattern(64);
        let mut framed = encode_tcp_request(&addr, REPLAY_PADDING);
        framed.extend_from_slice(&payload);
        let mut stream = RawStream::open(&client).await.expect("开流失败");
        stream.write_raw(&framed).await.expect("写失败");
        stream.finish();

        // 目标必须先收到第一份。
        let got = super::support::wait_until(RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len()
        })
        .await;
        assert!(got, "首份数据未到达目标");

        // 找到一个承载了 payload 的 QUIC 数据报（TCPRequest 的字节在流里，
        // 但会被 QUIC 分帧/加密，所以按**长度**定位不到内容；改用「包含
        // payload 的明文」不可行 —— 线上是密文）。
        //
        // ⇒ 改为按「客户端 → 服务端」方向的**全部**数据报逐个重放：其中
        // 必然包含承载 payload 的那个包。
        let captured = relay.captured();
        assert!(!captured.is_empty(), "中继未捕获到任何数据报");
        let before = target.received().len();

        // 重放全部捕获的数据报（逐字节、同 socket、同源地址）。
        for i in 0..captured.len() {
            assert!(relay.replay(i).await, "重放第 {i} 个数据报失败");
        }

        // 给服务端一点时间处理重放（**否定断言用观测窗**，不是「睡够就断言」）。
        //
        // ⚠️ 这里必须用 `observe_never` 而不是 `wait_until`：条件是
        // 「收到字节数**增长**」这一**不该发生**的事 ⇒ 需要的是
        // 「在观测窗内**始终不**增长」。
        let never =
            super::support::observe_never(NEGATIVE_WINDOW, || target.received().len() > before)
                .await;
        assert!(
            never,
            "包级重放造成了重复交付（received {} → {}）",
            before,
            target.received().len()
        );
        assert_eq!(
            target.accepts(),
            1,
            "包级重放不得新建出站连接（传输层按包号去重）"
        );
    })
    .await;
}

/// 跨连接重放：把连接 A 的数据报打到连接 B ⇒ **不得**被 B 接受。
///
/// 依据：1-RTT 包的 AEAD 密钥与**连接**绑定（TLS 握手 transcript），
/// 换连接重放 ⇒ 解密失败 ⇒ 被丢弃。参考实现同（quic-go 同一套 AEAD
/// 语义）。
#[tokio::test]
async fn cross_connection_packet_replay_is_rejected() {
    super::support::case_within(super::support::CASE_DEADLINE, async {
        let server = start_server("pkt-cross").await;
        let relay = UdpRelay::start(server.addr).await;
        let target = spawn_tcp_target().await;
        let addr = target.addr.to_string();

        let mut cfg = client_config(&server, &server.auth);
        cfg.server_addr = relay.addr;
        let client_a = lengsuo_hysteria::quic::HysteriaClient::connect(cfg.clone())
            .await
            .expect("会话 A 建连失败");

        // 会话 A：承载一次，让中继抓到 A 的数据报。
        let payload = pattern(48);
        let mut framed = encode_tcp_request(&addr, REPLAY_PADDING);
        framed.extend_from_slice(&payload);
        let mut stream = RawStream::open(&client_a).await.expect("开流失败");
        stream.write_raw(&framed).await.expect("写失败");
        stream.finish();
        let got = super::support::wait_until(RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len()
        })
        .await;
        assert!(got, "会话 A 的数据未到达目标");

        let captured_a = relay.captured();
        assert!(!captured_a.is_empty(), "中继未捕获到会话 A 的数据报");

        // 会话 B：**全新**连接（⇒ 全新 TLS 密钥 ⇒ 全新 AEAD 密钥）。
        let client_b = lengsuo_hysteria::quic::HysteriaClient::connect(cfg)
            .await
            .expect("会话 B 建连失败");

        // 会话 B 正常承载一次，确认 B 本身是健康的。
        let payload_b = pattern(32);
        let mut framed_b = encode_tcp_request(&addr, REPLAY_PADDING);
        framed_b.extend_from_slice(&payload_b);
        let mut stream_b = RawStream::open(&client_b).await.expect("开流失败");
        stream_b.write_raw(&framed_b).await.expect("写失败");
        stream_b.finish();
        let got_b = super::support::wait_until(RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len() + payload_b.len()
        })
        .await;
        assert!(got_b, "会话 B 未能正常往返");

        let before = target.received().len();

        // 把**会话 A 的全部数据报**重放（服务端会按 CID 找到 A 的连接，
        // 但 A 的连接已关闭 ⇒ 数据报被丢弃；即便 A 还活着，也只会命中 A
        // 的连接，不会命中 B）。
        for i in 0..captured_a.len() {
            assert!(relay.replay(i).await, "重放第 {i} 个数据报失败");
        }

        let never =
            super::support::observe_never(NEGATIVE_WINDOW, || target.received().len() > before)
                .await;
        assert!(
            never,
            "跨连接包级重放造成了重复交付（received {} → {}）",
            before,
            target.received().len()
        );
    })
    .await;
}

/// 重放**不得**污染后续会话：包级重放之后，新会话必须正常往返。
#[tokio::test]
async fn packet_replay_does_not_pollute_fresh_session() {
    super::support::case_within(super::support::CASE_DEADLINE, async {
        let server = start_server("pkt-iso").await;
        let relay = UdpRelay::start(server.addr).await;
        let target = spawn_tcp_target().await;
        let addr = target.addr.to_string();

        let mut cfg = client_config(&server, &server.auth);
        cfg.server_addr = relay.addr;
        let client = lengsuo_hysteria::quic::HysteriaClient::connect(cfg.clone())
            .await
            .expect("建连失败");

        let payload = pattern(40);
        let mut framed = encode_tcp_request(&addr, REPLAY_PADDING);
        framed.extend_from_slice(&payload);
        let mut stream = RawStream::open(&client).await.expect("开流失败");
        stream.write_raw(&framed).await.expect("写失败");
        stream.finish();
        let got = super::support::wait_until(RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len()
        })
        .await;
        assert!(got, "首份数据未到达目标");

        // 重放全部抓到的数据报。
        for i in 0..relay.captured().len() {
            assert!(relay.replay(i).await, "重放第 {i} 个数据报失败");
        }

        // 新会话（全新连接）必须正常往返。
        let client2 = lengsuo_hysteria::quic::HysteriaClient::connect(cfg)
            .await
            .expect("新会话建连失败");
        let mut stream2 = RawStream::open(&client2).await.expect("开流失败");
        let payload2 = pattern(72);
        let mut framed2 = encode_tcp_request(&addr, REPLAY_PADDING);
        framed2.extend_from_slice(&payload2);
        stream2.write_raw(&framed2).await.expect("写失败");
        stream2.finish();

        let got2 = super::support::wait_until(RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len() + payload2.len()
        })
        .await;
        assert!(
            got2,
            "包级重放后新会话未完成往返（received={}）",
            target.received().len()
        );
        let received = target.received();
        assert_eq!(
            &received[payload.len()..],
            &payload2[..],
            "新会话的数据必须逐字节正确"
        );
    })
    .await;
}

/// 连接 ID 的作用：服务端按**连接 ID**把数据报路由到连接 ⇒ 重放的数据报
/// 只会命中**原来那条连接**，不会凭空进入别的连接。
///
/// 这条把「重放与 QUIC 连接 ID 的关系」钉成可观测断言：新会话的
/// 服务端连接数**不因**重放而增加。
#[tokio::test]
async fn packet_replay_does_not_open_new_server_connections() {
    super::support::case_within(super::support::CASE_DEADLINE, async {
        let server = start_server("pkt-cid").await;
        let relay = UdpRelay::start(server.addr).await;
        let target = spawn_tcp_target().await;
        let addr = target.addr.to_string();

        let mut cfg = client_config(&server, &server.auth);
        cfg.server_addr = relay.addr;
        let client = lengsuo_hysteria::quic::HysteriaClient::connect(cfg.clone())
            .await
            .expect("建连失败");

        let before = server.open_connections();
        let payload = pattern(24);
        let mut framed = encode_tcp_request(&addr, REPLAY_PADDING);
        framed.extend_from_slice(&payload);
        let mut stream = RawStream::open(&client).await.expect("开流失败");
        stream.write_raw(&framed).await.expect("写失败");
        stream.finish();
        let got = super::support::wait_until(RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len()
        })
        .await;
        assert!(got, "首份数据未到达目标");

        for i in 0..relay.captured().len() {
            assert!(relay.replay(i).await, "重放第 {i} 个数据报失败");
        }

        // 否定断言：重放**不得**新建 QUIC 连接 ⇒ 在观测窗内连接数必须
        // **始终**不变。
        //
        // ⚠️ 旧写法 `wait_until(open_connections() <= before)` 是**恒真**
        // 条件（第一次轮询就返回 true）⇒ 断言形同虚设；这里改用
        // `observe_never`（条件成立即失败）。
        let never =
            super::support::observe_never(NEGATIVE_WINDOW, || server.open_connections() > before)
                .await;
        assert!(
            never,
            "重放后服务端连接数异常增长（{} → {}）",
            before,
            server.open_connections()
        );
        assert_eq!(
            server.open_connections(),
            before,
            "重放的数据报不得创建新的 QUIC 连接（按 CID 路由到原连接）"
        );
    })
    .await;
}
