//! PLPMTUD 纯逻辑层测试：状态机迁移、DF 探测报文与确定性。
//!
//! 全部纯内存与注入时钟（`Instant + Duration`）：不建 socket、不打开设备、不需要
//! root、没有真实链路。报文用例只检查 IP 头部字段与校验和，校验和由测试侧独立
//! 实现 RFC 1071 折叠和核对，不复用被测代码。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use lengsuo_tun::mtu::{
    probe_packet_v4, probe_packet_v6, IpVersion, MtuError, PlpmtudSearch, PlpmtudState,
    BASE_PLPMTU, MAX_MTU, MAX_PROBES, PMTU_RAISE_TIMER,
};

const TARGET_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
const TARGET_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

/// 测试侧独立实现的 RFC 1071 一补码和（与被测代码不共享实现）。
fn ones_complement_sum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (chunks, tail) = bytes.as_chunks::<2>();
    for chunk in chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&byte) = tail.first() {
        sum += u32::from(byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

#[test]
fn base_plpmtud_is_1200_and_ceiling_below_base_is_rejected() {
    assert_eq!(BASE_PLPMTU, 1200);
    assert_eq!(MAX_PROBES, 3);
    assert_eq!(PMTU_RAISE_TIMER, Duration::from_secs(600));

    for ceiling in [0u16, 1, 576, 1199] {
        assert_eq!(
            PlpmtudSearch::new(TARGET_V4, ceiling),
            Err(MtuError::MtuOutOfRange {
                value: ceiling,
                min: BASE_PLPMTU,
                max: MAX_MTU,
            }),
            "ceiling {ceiling} 低于 base 必须拒绝"
        );
    }
    for ceiling in [BASE_PLPMTU, 1500, MAX_MTU] {
        let search = PlpmtudSearch::new(TARGET_V4, ceiling).unwrap();
        assert_eq!(search.state(), PlpmtudState::Base);
        assert_eq!(search.confirmed_pmtu(), BASE_PLPMTU);
        assert_eq!(search.target(), TARGET_V4);
    }
}

#[test]
fn probe_sequence_binary_searches_between_confirmed_and_ceiling() {
    let now = Instant::now();
    let mut search = PlpmtudSearch::new(TARGET_V6, 1500).unwrap();
    let mut probes = Vec::new();
    while let Some(size) = search.next_probe(now) {
        probes.push(size);
        search.on_ack(size, now).unwrap();
    }
    assert_eq!(probes.first(), Some(&1350));
    assert!(probes.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(probes
        .iter()
        .all(|&probe| probe > BASE_PLPMTU && probe <= 1500));
    assert_eq!(probes.last(), Some(&1500));
    assert_eq!(search.state(), PlpmtudState::SearchComplete);
    assert_eq!(search.confirmed_pmtu(), 1500);
}

#[test]
fn three_losses_at_same_size_roll_back_to_last_confirmed() {
    let now = Instant::now();
    let mut search = PlpmtudSearch::new(TARGET_V4, 1500).unwrap();
    let first = search.next_probe(now).unwrap();
    search.on_ack(first, now).unwrap();
    let second = search.next_probe(now).unwrap();
    assert_eq!(search.confirmed_pmtu(), first);

    for _ in 0..2 {
        search.on_loss(second, now).unwrap();
        assert_eq!(search.state(), PlpmtudState::Searching);
        assert_eq!(search.confirmed_pmtu(), first);
        assert_eq!(search.next_probe(now), Some(second));
    }
    search.on_loss(second, now).unwrap();
    assert_eq!(search.state(), PlpmtudState::SearchComplete);
    assert_eq!(search.confirmed_pmtu(), first);
    assert_eq!(search.next_probe(now), None);
}

#[test]
fn one_loss_does_not_blackhole_the_size_while_probes_remain() {
    let now = Instant::now();
    let mut search = PlpmtudSearch::new(TARGET_V4, 1500).unwrap();
    let size = search.next_probe(now).unwrap();
    search.on_loss(size, now).unwrap();
    assert_eq!(search.state(), PlpmtudState::Searching);
    assert_eq!(search.confirmed_pmtu(), BASE_PLPMTU);
    assert_eq!(search.next_probe(now), Some(size));
    search.on_ack(size, now).unwrap();
    assert_eq!(search.confirmed_pmtu(), size);
}

#[test]
fn ack_confirms_size_and_never_lowers_confirmed() {
    let now = Instant::now();
    let mut search = PlpmtudSearch::new(TARGET_V4, 1500).unwrap();
    let first = search.next_probe(now).unwrap();
    search.on_ack(first, now).unwrap();
    assert_eq!(search.confirmed_pmtu(), first);
    // 同一尺寸重复 ack（已不在飞）被拒绝，confirmed 不得回退。
    assert!(search.on_ack(first, now).is_err());
    assert_eq!(search.confirmed_pmtu(), first);
    let second = search.next_probe(now).unwrap();
    assert!(second > first);
    search.on_ack(second, now).unwrap();
    assert_eq!(search.confirmed_pmtu(), second);
}

#[test]
fn raise_timer_after_complete_restarts_search_from_confirmed() {
    let now = Instant::now();
    let mut search = PlpmtudSearch::new(TARGET_V4, 1500).unwrap();
    let first = search.next_probe(now).unwrap();
    search.on_ack(first, now).unwrap();
    let second = search.next_probe(now).unwrap();
    for _ in 0..MAX_PROBES {
        search.on_loss(second, now).unwrap();
        if search.state() == PlpmtudState::Searching {
            assert_eq!(search.next_probe(now), Some(second));
        }
    }
    assert_eq!(search.state(), PlpmtudState::SearchComplete);
    assert_eq!(search.confirmed_pmtu(), first);

    let early = now + PMTU_RAISE_TIMER - Duration::from_secs(1);
    assert_eq!(search.next_probe(early), None);
    search.on_raise_timer(now + PMTU_RAISE_TIMER);
    assert_eq!(search.state(), PlpmtudState::Searching);
    let resumed = search.next_probe(now + PMTU_RAISE_TIMER).unwrap();
    assert!(resumed > first && resumed <= 1500);
}

#[test]
fn probes_never_exceed_ceiling_nor_drop_below_base() {
    let now = Instant::now();
    let mut search = PlpmtudSearch::new(TARGET_V4, 1400).unwrap();
    for step in 0..50 {
        let Some(probe) = search.next_probe(now) else {
            break;
        };
        assert!(probe > search.confirmed_pmtu());
        assert!(probe <= 1400);
        assert!(probe >= BASE_PLPMTU);
        if step % 2 == 0 {
            search.on_ack(probe, now).unwrap();
        } else {
            search.on_loss(probe, now).unwrap();
        }
    }
    // ceiling 等于 base 时没有可探测区间：直接进入 SearchComplete。
    let mut at_base = PlpmtudSearch::new(TARGET_V4, BASE_PLPMTU).unwrap();
    assert_eq!(at_base.next_probe(now), None);
    assert_eq!(at_base.state(), PlpmtudState::SearchComplete);
    assert_eq!(at_base.confirmed_pmtu(), BASE_PLPMTU);
}

#[test]
fn disabled_state_never_emits_a_probe() {
    let now = Instant::now();
    let mut search = PlpmtudSearch::new(TARGET_V4, 1500).unwrap();
    search.disable();
    assert_eq!(search.state(), PlpmtudState::Disabled);
    assert_eq!(search.confirmed_pmtu(), BASE_PLPMTU);
    assert_eq!(search.next_probe(now), None);
    let later = now + PMTU_RAISE_TIMER * 10;
    assert_eq!(search.next_probe(later), None);
    search.on_raise_timer(later);
    assert_eq!(search.next_probe(later), None);
    assert_eq!(search.state(), PlpmtudState::Disabled);

    // 在飞时 disable 也必须清空：旧探测的 ack 不再改变 confirmed。
    let mut other = PlpmtudSearch::new(TARGET_V4, 1500).unwrap();
    let in_flight = other.next_probe(now).unwrap();
    other.disable();
    assert!(other.on_ack(in_flight, now).is_err());
    assert_eq!(other.confirmed_pmtu(), BASE_PLPMTU);
}

#[test]
fn mismatched_ack_or_loss_size_is_rejected_without_state_change() {
    let now = Instant::now();
    let mut search = PlpmtudSearch::new(TARGET_V4, 1500).unwrap();
    // 没有在飞探测时任何 ack 都是 Err，状态保持 Base。
    assert!(search.on_ack(1300, now).is_err());
    assert_eq!(search.state(), PlpmtudState::Base);
    assert_eq!(search.confirmed_pmtu(), BASE_PLPMTU);

    let probe = search.next_probe(now).unwrap();
    assert!(search.on_ack(probe + 1, now).is_err());
    assert_eq!(search.state(), PlpmtudState::Searching);
    assert_eq!(search.confirmed_pmtu(), BASE_PLPMTU);
    assert_eq!(search.next_probe(now), None, "在飞探测不得被错误 ack 清掉");

    assert!(search.on_loss(probe + 1, now).is_err());
    assert_eq!(search.state(), PlpmtudState::Searching);
    assert_eq!(search.confirmed_pmtu(), BASE_PLPMTU);
    assert_eq!(search.next_probe(now), None);

    search.on_ack(probe, now).unwrap();
    assert_eq!(search.confirmed_pmtu(), probe);
}

#[test]
fn ipv4_probe_sets_df_bit_and_header_checksum_verifies_to_zero() {
    let packet = probe_packet_v4(1500, 0x5a).unwrap();
    assert_eq!(packet.len(), 1500);
    assert_eq!(packet[0], 0x45);
    assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 1500);
    assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 0x4000);
    // 把校验和字段一并计入的折叠和必须为全 1（即写入值自校验为 0）。
    assert_eq!(ones_complement_sum(&packet[..20]), 0xffff);

    let mut zeroed = packet[..20].to_vec();
    zeroed[10] = 0;
    zeroed[11] = 0;
    let expected = !ones_complement_sum(&zeroed);
    assert_eq!(
        u16::from_be_bytes([packet[10], packet[11]]),
        expected,
        "首部校验和必须等于按 RFC 1071 重算的值"
    );
}

#[test]
fn ipv6_probe_has_no_df_field_and_payload_length_matches_total() {
    let packet = probe_packet_v6(1500, 0x33).unwrap();
    assert_eq!(packet.len(), 1500);
    assert_eq!(packet[0] >> 4, 6);
    assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 1500 - 40);
    assert_eq!(
        packet.len() - 40,
        usize::from(u16::from_be_bytes([packet[4], packet[5]]))
    );
    // IPv6 没有 DF/flags 字段：偏移 6 是下一头，且不是分片头(44)。
    assert_eq!(packet[6], 17);
    assert_ne!(packet[6], 44);
    assert_eq!(packet[7], 64);
}

#[test]
fn probe_request_out_of_range_is_rejected_for_both_families() {
    assert_eq!(
        probe_packet_v4(19, 0),
        Err(MtuError::Truncated {
            needed: 20,
            got: 19,
        })
    );
    assert_eq!(
        probe_packet_v6(39, 0),
        Err(MtuError::Truncated {
            needed: 40,
            got: 39,
        })
    );
    assert_eq!(
        probe_packet_v4(65536, 0),
        Err(MtuError::AdvertisedOutOfRange {
            family: IpVersion::V4,
            value: 65536,
            min: 20,
            max: 65535,
        })
    );
    assert_eq!(
        probe_packet_v6(65536, 0),
        Err(MtuError::AdvertisedOutOfRange {
            family: IpVersion::V6,
            value: 65536,
            min: 40,
            max: 65535,
        })
    );
    // 端点合法：恰好头部长度与 MAX_MTU 都接受。
    assert_eq!(probe_packet_v4(20, 0).unwrap().len(), 20);
    assert_eq!(probe_packet_v6(40, 0).unwrap().len(), 40);
    assert_eq!(probe_packet_v4(65535, 0).unwrap().len(), 65535);
    assert_eq!(probe_packet_v6(65535, 0).unwrap().len(), 65535);
}

#[test]
fn same_event_sequence_yields_byte_identical_probes() {
    fn run() -> Vec<Vec<u8>> {
        let now = Instant::now();
        let mut search = PlpmtudSearch::new(TARGET_V4, 1500).unwrap();
        let mut out = Vec::new();
        while let Some(size) = search.next_probe(now) {
            out.push(probe_packet_v4(usize::from(size), 0xa5).unwrap());
            search.on_ack(size, now).unwrap();
        }
        out
    }
    let first = run();
    let second = run();
    assert_eq!(first, second);
    assert!(first.len() > 1);
    assert_ne!(
        probe_packet_v4(1500, 1).unwrap(),
        probe_packet_v4(1500, 2).unwrap(),
        "不同 seed 必须产生不同载荷"
    );
}
