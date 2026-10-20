//! 主动打开方向的**五条反例**：每条都必须 fail-closed，绝不 panic、绝不挂起。
//!
//! ① SYN-ACK 的确认号错误 ⇒ 回 RST + 报错 + 释放连接；
//! ② 收到 RST ⇒ 立即失败并释放；
//! ③ 连续丢 SYN-ACK ⇒ 重传达上限 ⇒ 报错并释放（**不无限重传**）；
//! ④ SYN 里超本端 MTU 的 MSS ⇒ 按 `src/mtu.rs` 的 clamp 处理；
//! ⑤ 截断的 TCP 段（头部截断 / 选项区截断）⇒ 解析失败而非 panic。
//!
//! 全部纯内存：不接真实网卡、不建真实 socket。所有用例带总超时，重传循环另有
//! 硬迭代上限。

use std::time::Duration;

use lengsuo_tun::tcp::active::{ActiveError, ActiveState};
use lengsuo_tun::tcp::connector::{Connector, RouteTable};
use lengsuo_tun::tcp::segment::Flags;

#[path = "tcp_active_support/mod.rs"]
mod support;

use support::{
    active_config, build_packet, open_connection, parse_out, PassivePeer, LOCAL_IP, LOCAL_PORT,
    MAX_RETRIES, NOW, REMOTE_IP, REMOTE_PORT,
};

const TIMEOUT: Duration = Duration::from_secs(5);
/// 重传上限用例里的循环硬上限：超出即判定「无限重传」失败。
const RETRANSMIT_LOOP_CAP: usize = 64;

/// 反例 1：SYN-ACK 的确认号错误 ⇒ 拒绝并 fail-closed（回 RST + 报错 + 释放）。
#[tokio::test]
async fn syn_ack_with_wrong_ack_number_is_rejected() {
    tokio::time::timeout(TIMEOUT, async {
        let (connector, mut connection) = open_connection();
        let syn = connection.connect(NOW).unwrap();
        let _syn_packet = connector.build_packets(&connection, &[syn]).unwrap();
        let expected = connection.snd_una() + 1;

        // 对端回 SYN-ACK，但确认号不是 ISN+1。
        let bad = build_packet(
            REMOTE_IP.into(),
            LOCAL_IP.into(),
            REMOTE_PORT,
            LOCAL_PORT,
            0x4000_0000,
            expected.wrapping_add(7),
            Flags::SYN | Flags::ACK,
            4096,
            &[],
            &[],
        );
        let result = connector.on_packet(&mut connection, &bad, NOW).unwrap();
        assert!(
            matches!(
                result.failure,
                Some(ActiveError::AckMismatch {
                    expected: e,
                    got
                }) if e == expected && got == expected.wrapping_add(7)
            ),
            "确认号不符必须报 AckMismatch，实得 {:?}",
            result.failure
        );
        assert_eq!(result.packets.len(), 1, "fail-closed 路径必须回一个 RST");
        let rst = parse_out(&result.packets[0]);
        assert_eq!(rst.flags, Flags::RST);
        assert_eq!(
            rst.seq,
            expected.wrapping_add(7),
            "RST 的 seq 取对端的确认号"
        );
        assert_eq!(
            connection.state(),
            ActiveState::Closed,
            "失败后必须释放连接"
        );
        assert!(!connection.is_established());
    })
    .await
    .expect("用例超时");
}

/// 反例 2：收到 RST ⇒ 立即失败并释放。
#[tokio::test]
async fn reset_fails_connection_immediately() {
    tokio::time::timeout(TIMEOUT, async {
        let (connector, mut connection) = open_connection();
        let syn = connection.connect(NOW).unwrap();
        let _syn_packet = connector.build_packets(&connection, &[syn]).unwrap();

        let rst = build_packet(
            REMOTE_IP.into(),
            LOCAL_IP.into(),
            REMOTE_PORT,
            LOCAL_PORT,
            0x5000_0000,
            0,
            Flags::RST,
            0,
            &[],
            &[],
        );
        let result = connector.on_packet(&mut connection, &rst, NOW).unwrap();
        assert_eq!(result.failure, Some(ActiveError::ConnectionRefused));
        assert!(result.packets.is_empty(), "RST 不应产生回包");
        assert_eq!(connection.state(), ActiveState::Closed);
    })
    .await
    .expect("用例超时");
}

/// 反例 3：连续丢 SYN-ACK ⇒ 重传到上限 ⇒ 报错并释放（绝不无限重传）。
#[tokio::test]
async fn lost_syn_acks_stop_at_retry_limit() {
    tokio::time::timeout(TIMEOUT, async {
        let (connector, mut connection) = open_connection();
        let syn = connection.connect(NOW).unwrap();
        let first = connector.build_packets(&connection, &[syn]).unwrap();
        assert_eq!(first.len(), 1);

        // 一直收不到 SYN-ACK：只准按 RTO 重传，达到上限即失败。
        let mut now = NOW;
        let mut transmissions = 1usize;
        let mut failure = None;
        for _ in 0..RETRANSMIT_LOOP_CAP {
            now += 1_000;
            match connection.on_timeout(now) {
                Ok(Some(retransmit)) => {
                    assert!(retransmit.flags.has_syn(), "重传的必须是 SYN");
                    let packets = connector.build_packets(&connection, &[retransmit]).unwrap();
                    assert_eq!(packets.len(), 1);
                    transmissions += 1;
                }
                Ok(None) => {}
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
        assert!(
            matches!(failure, Some(ActiveError::ConnectTimeout { .. })),
            "重传达上限必须报 ConnectTimeout，实得 {failure:?}"
        );
        assert!(
            transmissions <= 1 + MAX_RETRIES as usize,
            "重传次数必须有上限，实得 {transmissions}"
        );
        assert_eq!(connection.retries(), MAX_RETRIES);
        assert_eq!(
            connection.state(),
            ActiveState::Closed,
            "失败后必须释放连接"
        );
        // 释放后再计时也不得再产出任何报文。
        assert_eq!(connection.on_timeout(now + 10_000).unwrap(), None);
    })
    .await
    .expect("用例超时");
}

/// 反例 4：SYN 里超本端 MTU 的 MSS ⇒ 按 `src/mtu.rs` 的 clamp 处理。
#[tokio::test]
async fn syn_mss_is_clamped_by_local_mtu() {
    tokio::time::timeout(TIMEOUT, async {
        let mut config = active_config();
        // 配置里的 MSS（8960）远超接口 MTU（1500）能承载的值。
        config.mss = 8960;
        let mut routes = RouteTable::new();
        routes
            .insert_host(REMOTE_IP.into(), 3, LOCAL_IP.into())
            .unwrap();
        let connector = Connector::new(routes);
        let mut connection = connector.open(config).unwrap();
        assert_eq!(connection.local_mss(), 1460, "MSS 必须按 MTU 夹紧");

        let syn = connection.connect(NOW).unwrap();
        let packets = connector.build_packets(&connection, &[syn]).unwrap();
        let parsed = parse_out(&packets[0]);
        assert_eq!(parsed.options.len(), 4, "SYN 必须带 4 字节 MSS 选项");
        assert_eq!(parsed.options[0], 2, "MSS 选项 kind");
        assert_eq!(parsed.options[1], 4, "MSS 选项 length");
        let advertised = u16::from_be_bytes([parsed.options[2], parsed.options[3]]);
        assert_eq!(advertised, 1460, "通告的 MSS 必须是夹紧后的值");

        // 对端通告更小的 MSS 时，本端发送段长取两者较小值。
        let mut peer = PassivePeer::new();
        let (replies, _) = peer.feed(&packets[0]);
        assert_eq!(replies.len(), 1);
        let syn_ack = build_packet(
            REMOTE_IP.into(),
            LOCAL_IP.into(),
            REMOTE_PORT,
            LOCAL_PORT,
            0x6000_0000,
            connection.snd_una() + 1,
            Flags::SYN | Flags::ACK,
            4096,
            &[2, 4, 0x02, 0x00],
            &[],
        );
        let result = connector.on_packet(&mut connection, &syn_ack, NOW).unwrap();
        assert!(result.failure.is_none());
        assert_eq!(connection.peer_mss(), Some(512));
        assert_eq!(
            connection.effective_mss(),
            512,
            "生效 MSS 取本端与对端的较小值"
        );
    })
    .await
    .expect("用例超时");
}

/// 反例 5：截断的 TCP 段（头部截断 / 选项区截断 / 非法偏移）⇒ 解析失败而非 panic。
#[tokio::test]
async fn truncated_segments_fail_closed_without_panic() {
    tokio::time::timeout(TIMEOUT, async {
        let (connector, mut connection) = open_connection();
        let syn = connection.connect(NOW).unwrap();
        let syn_packet = connector.build_packets(&connection, &[syn]).unwrap();

        // ① 头部截断：TCP 段只有 12 字节。
        let short = support::wrap_ipv4(REMOTE_IP, LOCAL_IP, vec![0u8; 12]);
        assert!(
            connector.on_packet(&mut connection, &short, NOW).is_err(),
            "头部截断必须被拒"
        );

        // ② 选项区截断：数据偏移声明 24 字节头部，实际只给 20 字节。
        let mut truncated_options = vec![0u8; 20];
        truncated_options[12] = 0x60; // 数据偏移 = 6 → 24 字节头部
        truncated_options[13] = Flags::SYN.bits();
        let packet = support::wrap_ipv4(REMOTE_IP, LOCAL_IP, truncated_options);
        assert!(
            connector.on_packet(&mut connection, &packet, NOW).is_err(),
            "选项区截断必须被拒"
        );

        // ③ 数据偏移非法（< 5）与保留位非零。
        for bad_offset in [0x00u8, 0x40u8, 0x51u8] {
            let mut bytes = vec![0u8; 20];
            bytes[12] = bad_offset;
            bytes[13] = Flags::SYN.bits();
            let packet = support::wrap_ipv4(REMOTE_IP, LOCAL_IP, bytes);
            assert!(
                connector.on_packet(&mut connection, &packet, NOW).is_err(),
                "数据偏移 {bad_offset:#x} 必须被拒"
            );
        }

        // ④ 全部畸形输入之后连接仍可用（没有被畸形输入带崩）。
        assert_eq!(connection.state(), ActiveState::SynSent);
        let mut peer = PassivePeer::new();
        let (replies, _) = peer.feed(&syn_packet[0]);
        assert_eq!(replies.len(), 1, "畸形输入不得影响正常握手");

        // ⑤ 四元组不匹配的报文（串话）一律拒绝，不改连接状态。
        let stranger = build_packet(
            REMOTE_IP.into(),
            LOCAL_IP.into(),
            REMOTE_PORT,
            9999,
            0x7000_0000,
            0,
            Flags::SYN,
            4096,
            &[],
            &[],
        );
        assert!(
            connector
                .on_packet(&mut connection, &stranger, NOW)
                .is_err(),
            "端口不匹配的报文必须被拒"
        );
        assert_eq!(connection.state(), ActiveState::SynSent);

        // ⑥ 地址族不一致（IPv6 源）的报文必须被拒。
        let v6 = build_packet(
            "::1".parse().unwrap(),
            LOCAL_IP.into(),
            REMOTE_PORT,
            LOCAL_PORT,
            0x7000_0000,
            0,
            Flags::SYN,
            4096,
            &[],
            &[],
        );
        assert!(
            connector.on_packet(&mut connection, &v6, NOW).is_err(),
            "地址族不一致的报文必须被拒"
        );
    })
    .await
    .expect("用例超时");
}
