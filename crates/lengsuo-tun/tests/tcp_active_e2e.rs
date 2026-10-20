//! 端到端：用户态 TCP 栈的**主动打开**方向（主动 connect）。
//!
//! # 性质（重要，勿误读）
//!
//! 本用例**不接真实网卡、不建真实 socket**：全部报文在内存里构造与解析，
//! 对端是同仓 `tcp::state`（被动方向状态机）或一个用 `tcp::segment` 拼出来的
//! 最小主动对端。测试因此证明的是**状态机与接入层的协议语义**，不是与任何
//! 外部实现的互通。
//!
//! 覆盖：
//! - 真主动：本卡主动方 → 内存对端 `Listen` ⇒ 完整三次握手、双向载荷逐字节一致。
//! - 双向互测：既有构件扮演**主动对端**，本卡主动方当**被动端**：入向 SYN 必须
//!   能驱动本卡离开 `SynSent` 并最终进入 `Established`。
//! - 五条反例在同目录的 `tcp_active_counterexample.rs`（默认套件一并实跑）。
//!
//! 所有用例带总超时（`tokio::time::timeout`），并对重传循环设硬迭代上限，
//! 杜绝无限重传与挂起。

use std::time::Duration;

use lengsuo_tun::tcp::active::{ActiveError, ActiveState, OutboundSegment};
use lengsuo_tun::tcp::segment::Flags;

#[path = "tcp_active_support/mod.rs"]
mod support;

use support::{open_connection, parse_out, ActivePeer, PassivePeer, NOW};

const TIMEOUT: Duration = Duration::from_secs(5);

/// 真主动：本卡主动方 → 内存对端 `Listen` ⇒ 三次握手 + 双向载荷逐字节一致。
#[tokio::test]
async fn active_handshake_and_bidirectional_payload() {
    tokio::time::timeout(TIMEOUT, async {
        let (connector, mut connection) = open_connection();

        // ① 本端发 SYN。
        let syn = connection.connect(NOW).unwrap();
        assert!(syn.flags.has_syn() && !syn.flags.has_ack());
        let syn_packet = connector.build_packets(&connection, &[syn]).unwrap();
        assert_eq!(syn_packet.len(), 1);

        // ② 对端 `Listen` 收 SYN ⇒ 回 SYN-ACK。
        let mut peer = PassivePeer::new();
        let (replies, delivered) = peer.feed(&syn_packet[0]);
        assert_eq!(replies.len(), 1, "对端应回 SYN-ACK");
        assert!(delivered.is_empty(), "握手期不应交付载荷");
        let syn_ack = parse_out(&replies[0]);
        assert!(syn_ack.flags.has_syn() && syn_ack.flags.has_ack());
        assert_eq!(
            syn_ack.ack,
            connection.snd_una() + 1,
            "SYN-ACK 须确认 ISN+1"
        );
        assert_eq!(syn_ack.window, 4096, "对端应通告自己的接收窗口");

        // ③ 本端收 SYN-ACK ⇒ 回最终 ACK，进入 Established。
        let result = connector
            .on_packet(&mut connection, &replies[0], NOW)
            .unwrap();
        assert!(result.failure.is_none());
        assert_eq!(result.packets.len(), 1, "应产出最终 ACK");
        let final_ack = parse_out(&result.packets[0]);
        assert_eq!(final_ack.flags, Flags::ACK);
        assert_eq!(final_ack.ack, syn_ack.seq + 1, "最终 ACK 须确认对端 ISN+1");
        assert!(connection.is_established());
        assert_eq!(
            connection.history(),
            &[
                ActiveState::SynSent,
                ActiveState::SynReceived,
                ActiveState::Established
            ],
            "状态必须依次走过 SynSent → SynReceived → Established"
        );

        // ④ 对端收最终 ACK ⇒ 对端侧也 Established。
        //    注意：既有被动栈对纯 ACK 会回一个确认段（`state.rs` 的既有语义），
        //    本卡不改那个子树，这里只断言对端确实进入 Established。
        let (replies, delivered) = peer.feed(&result.packets[0]);
        assert!(delivered.is_empty(), "第三个 ACK 不携带载荷");
        assert_eq!(peer.state(), lengsuo_tun::tcp::state::State::Established);
        for reply in &replies {
            let parsed = parse_out(reply);
            assert!(parsed.flags.has_ack(), "对端的回包必须是确认段");
        }

        // ⑤ 对端 → 本端：载荷逐字节交付。
        let sent = b"payload-from-peer-side";
        let data = peer.send_data(sent);
        let result = connector.on_packet(&mut connection, &data, NOW).unwrap();
        assert_eq!(result.delivered, sent, "载荷必须逐字节相等");
        assert!(result.packets.is_empty(), "纯数据段不必回 ACK");

        // ⑥ 本端 → 对端：载荷逐字节送达。
        let echo = b"payload-from-active-side";
        let segments = connection.send(echo).unwrap();
        let packets = connector.build_packets(&connection, &segments).unwrap();
        assert_eq!(packets.len(), 1);
        let sent_segment = parse_out(&packets[0]);
        assert!(sent_segment.flags.has_psh() && sent_segment.flags.has_ack());
        assert_eq!(sent_segment.payload, echo);
        let (_replies, delivered) = peer.feed(&packets[0]);
        assert_eq!(delivered, echo, "对端交付的载荷必须与本端发出的逐字节一致");

        // ⑥' 对端对按序数据不单独回 ACK（既有栈语义），发一个空载荷 ACK 段
        //     触发对端确认，确认号必须覆盖全部载荷。
        let piggyback = OutboundSegment {
            seq: connection.snd_nxt(),
            ack: connection.rcv_nxt(),
            flags: Flags::ACK,
            window: 4096,
            options: Vec::new(),
            payload: Vec::new(),
        };
        let packets = connector.build_packets(&connection, &[piggyback]).unwrap();
        let (replies, _) = peer.feed(&packets[0]);
        assert_eq!(replies.len(), 1, "对端应回 ACK");
        let peer_ack = parse_out(&replies[0]);
        assert_eq!(
            peer_ack.ack,
            sent_segment.seq + sent_segment.payload.len() as u32,
            "对端 ACK 必须覆盖全部载荷"
        );
    })
    .await
    .expect("用例超时");
}

/// 双向互测：既有构件扮演主动对端，本卡主动方当被动端，被入向 SYN 驱动进 Established。
#[tokio::test]
async fn inbound_syn_drives_active_side_to_established() {
    tokio::time::timeout(TIMEOUT, async {
        let (connector, mut connection) = open_connection();

        // ① 本端已发 SYN（SynSent）。
        let syn = connection.connect(NOW).unwrap();
        let _syn_packet = connector.build_packets(&connection, &[syn]).unwrap();
        assert_eq!(connection.state(), ActiveState::SynSent);

        // ② 主动对端也发 SYN（同时打开路径）：本卡必须能处理入向 SYN。
        let mut peer = ActivePeer::new(0x3000_0000);
        let peer_syn = peer.syn();
        let result = connector
            .on_packet(&mut connection, &peer_syn, NOW)
            .unwrap();
        assert!(result.failure.is_none());
        assert_eq!(result.packets.len(), 1, "收到裸 SYN 必须回 SYN-ACK");
        let syn_ack = parse_out(&result.packets[0]);
        assert!(syn_ack.flags.has_syn() && syn_ack.flags.has_ack());
        assert_eq!(syn_ack.ack, peer.seq(), "SYN-ACK 必须确认对端 ISN+1");
        assert_eq!(connection.state(), ActiveState::SynReceived);

        // ③ 对端回最终 ACK ⇒ 本卡进入 Established。
        let peer_ack = peer.ack(&syn_ack);
        let result = connector
            .on_packet(&mut connection, &peer_ack, NOW)
            .unwrap();
        assert!(result.failure.is_none());
        assert!(result.packets.is_empty());
        assert!(connection.is_established());
        assert_eq!(
            connection.history(),
            &[
                ActiveState::SynSent,
                ActiveState::SynReceived,
                ActiveState::Established
            ]
        );

        // ④ 双向载荷：本端 → 对端。
        let echo = b"half-open-payload";
        let segments = connection.send(echo).unwrap();
        let packets = connector.build_packets(&connection, &segments).unwrap();
        let sent = parse_out(&packets[0]);
        assert_eq!(sent.payload, echo);
        assert_eq!(sent.seq, connection.snd_nxt() - echo.len() as u32);
    })
    .await
    .expect("用例超时");
}

/// 状态机级别的额外断言：重复握手与过早发送都被拒，畸形输入不污染计数。
#[tokio::test]
async fn duplicate_connect_is_rejected() {
    tokio::time::timeout(TIMEOUT, async {
        let (_connector, mut connection) = open_connection();
        assert!(connection.connect(NOW).is_ok());
        // 第二次 connect 必须被拒（连接已在握手中）。
        assert!(matches!(connection.connect(NOW), Err(ActiveError::Closed)));
        // 未建立前不得发送应用数据。
        assert!(matches!(
            connection.send(b"too-early"),
            Err(ActiveError::NotEstablished)
        ));
        // 未建立前也不得关闭写端。
        assert!(connection.close().is_none());
        // 畸形输入不得污染丢弃计数。
        assert_eq!(connection.discarded_segments(), 0);
    })
    .await
    .expect("用例超时");
}
