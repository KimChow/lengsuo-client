//! MTU 探测逻辑测试：MSS clamp、PMTUD 下调、反例与超 MTU 分段。
//!
//! 全部纯内存：不建设备、不发包、不需要 root。分段用例驱动既有用户态 TCP 栈的
//! 被动打开路径（复用 `tests/tcp_stack_e2e.rs` 的建连与报文构造手法），不重写栈。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use lengsuo_tun::mtu::{
    IpVersion, MssClamp, MtuError, PmtudState, IPV4_HEADER_BYTES, IPV6_HEADER_BYTES, MAX_MSS_V4,
    MAX_MSS_V6, MAX_MTU, MIN_MSS_V4, MIN_MSS_V6, MIN_MTU, RFC1191_PLATEAUS, TCP_HEADER_BYTES,
};

/// 超 MTU 分段用例放在子模块，避免单文件超过 400 行软目标。
#[path = "mtu_probe/stack.rs"]
mod stack;

const TARGET_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
const TARGET_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

// ---- MSS clamp ----

#[test]
fn mss_clamp_v4_boundaries() {
    for (mtu, mss) in [
        (1500u16, 1460u16),
        (1480, 1440),
        (1280, 1240),
        (576, 536),
        (u16::MAX, MAX_MSS_V4),
    ] {
        let clamp = MssClamp::new(mtu).unwrap();
        assert_eq!(clamp.mtu(), mtu);
        assert_eq!(clamp.mss_for_v4(), Ok(mss), "IPv4 MTU {mtu}");
    }
    assert_eq!(MssClamp::new(MIN_MTU).unwrap().mss_for_v4(), Ok(MIN_MSS_V4));
}

#[test]
fn mss_clamp_v6_boundaries() {
    for (mtu, mss) in [
        (1500u16, 1440u16),
        (1480, 1420),
        (1280, 1220),
        (u16::MAX, MAX_MSS_V6),
    ] {
        let clamp = MssClamp::new(mtu).unwrap();
        assert_eq!(clamp.mss_for_v6(), Ok(mss), "IPv6 MTU {mtu}");
    }
    assert_eq!(MssClamp::new(1280).unwrap().mss_for_v6(), Ok(MIN_MSS_V6));
    // 576 对 IPv4 合法，但对 IPv6 低于 1280 下限：fail-closed，不夹紧。
    assert_eq!(
        MssClamp::new(576).unwrap().mss_for_v6(),
        Err(MtuError::MtuOutOfRange {
            value: 576,
            min: 1280,
            max: MAX_MTU,
        })
    );
}

#[test]
fn mss_clamp_rejects_below_minimum() {
    for mtu in [0u16, 1, 68, 100, 575] {
        assert_eq!(
            MssClamp::new(mtu),
            Err(MtuError::MtuOutOfRange {
                value: mtu,
                min: MIN_MTU,
                max: MAX_MTU,
            }),
            "MTU {mtu} 必须被拒绝"
        );
    }
    // u16 结构上不可能超过上限；两端端点值都必须接受。
    assert!(MssClamp::new(MAX_MTU).is_ok());
}

#[test]
fn rfc1191_plateau_table_is_explicit() {
    assert_eq!(
        RFC1191_PLATEAUS,
        [65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68]
    );
}

#[test]
fn mss_overhead_constants_match_rfc_headers() {
    assert_eq!(MIN_MSS_V4, MIN_MTU - IPV4_HEADER_BYTES - TCP_HEADER_BYTES);
    assert_eq!(MIN_MSS_V6, 1280 - IPV6_HEADER_BYTES - TCP_HEADER_BYTES);
    assert_eq!(MAX_MSS_V4, MAX_MTU - IPV4_HEADER_BYTES - TCP_HEADER_BYTES);
    assert_eq!(MAX_MSS_V6, MAX_MTU - IPV6_HEADER_BYTES - TCP_HEADER_BYTES);
}

// ---- PMTUD 下调 ----

#[test]
fn icmpv4_frag_needed_with_next_hop_lowers_mss() {
    let mut state = PmtudState::new(TARGET_V4, 1500).unwrap();
    assert_eq!(state.target(), TARGET_V4);
    assert_eq!(state.family(), IpVersion::V4);
    assert_eq!(state.current_mtu(), 1500);
    assert_eq!(state.mss(), Ok(1460));
    // type=3 code=4，保留字节为 0，Next-Hop MTU=1400。
    assert_eq!(state.apply_icmp(&[3, 4, 0, 0, 0, 0, 0x05, 0x78]), Ok(1360));
    assert_eq!(state.current_mtu(), 1400);
    assert_eq!(state.mss(), Ok(1360));
    // 再收到 1300 的通告：继续下调。
    assert_eq!(state.apply_icmp(&[3, 4, 0, 0, 0, 0, 0x05, 0x14]), Ok(1260));
    assert_eq!(state.current_mtu(), 1300);
}

#[test]
fn icmpv4_without_next_hop_follows_plateaus_to_floor() {
    let mut state = PmtudState::new(TARGET_V4, 1500).unwrap();
    let zero = [3u8, 4, 0, 0, 0, 0, 0, 0];
    assert_eq!(state.apply_icmp(&zero), Ok(1452), "1500 → 1492");
    assert_eq!(state.current_mtu(), 1492);
    assert_eq!(state.apply_icmp(&zero), Ok(966), "1492 → 1006");
    assert_eq!(state.current_mtu(), 1006);
    // 表中 1006 之后是 508，低于 IPv4 下限，落在 576。
    assert_eq!(state.apply_icmp(&zero), Ok(536), "1006 → 576");
    assert_eq!(state.current_mtu(), 576);
    assert_eq!(
        state.apply_icmp(&zero),
        Err(MtuError::AtFloor {
            family: IpVersion::V4,
            floor: 576,
        })
    );
    assert_eq!(state.current_mtu(), 576, "失败不得改变状态");
}

#[test]
fn icmpv4_explicit_none_and_zero_share_plateau_path() {
    let mut state = PmtudState::new(TARGET_V4, 1500).unwrap();
    assert_eq!(state.on_frag_needed(None), Ok(1452));
    assert_eq!(state.on_frag_needed(Some(0)), Ok(966));
    assert_eq!(state.current_mtu(), 1006);
}

#[test]
fn icmpv6_packet_too_big_lowers_mss() {
    let mut state = PmtudState::new(TARGET_V6, 1500).unwrap();
    assert_eq!(state.family(), IpVersion::V6);
    assert_eq!(state.mss(), Ok(1440));
    // type=2 code=0，MTU=1280。
    assert_eq!(state.apply_icmp(&[2, 0, 0, 0, 0, 0, 0x05, 0x00]), Ok(1220));
    assert_eq!(state.current_mtu(), 1280);
    assert_eq!(state.mss(), Ok(1220));
    // 1200 低于 IPv6 下限：拒绝且不下调。
    assert_eq!(
        state.apply_icmp(&[2, 0, 0, 0, 0, 0, 0x04, 0xB0]),
        Err(MtuError::AdvertisedOutOfRange {
            family: IpVersion::V6,
            value: 1200,
            min: 1280,
            max: 65535,
        })
    );
    // MTU=0 不得被当作「未知」接受成 1280。
    assert_eq!(
        state.apply_icmp(&[2, 0, 0, 0, 0, 0, 0, 0]),
        Err(MtuError::AdvertisedOutOfRange {
            family: IpVersion::V6,
            value: 0,
            min: 1280,
            max: 65535,
        })
    );
    assert_eq!(state.current_mtu(), 1280, "失败不得改变状态");
}

// ---- 反例 ----

#[test]
fn advertisements_never_raise_the_estimate() {
    let mut v4 = PmtudState::new(TARGET_V4, 1500).unwrap();
    assert_eq!(
        v4.on_frag_needed(Some(1600)),
        Err(MtuError::NotSmaller {
            current: 1500,
            advertised: 1600,
        })
    );
    assert_eq!(
        v4.on_frag_needed(Some(1500)),
        Err(MtuError::NotSmaller {
            current: 1500,
            advertised: 1500,
        })
    );
    assert_eq!(v4.current_mtu(), 1500);

    let mut v6 = PmtudState::new(TARGET_V6, 1500).unwrap();
    assert_eq!(
        v6.on_packet_too_big(2000),
        Err(MtuError::NotSmaller {
            current: 1500,
            advertised: 2000,
        })
    );
    assert_eq!(v6.current_mtu(), 1500);
}

#[test]
fn out_of_range_advertisements_are_rejected() {
    let mut v4 = PmtudState::new(TARGET_V4, 1500).unwrap();
    // RFC 1191 要求 IPv4 Next-Hop MTU 的最高位为 0：0x8000 越界。
    assert_eq!(
        v4.on_frag_needed(Some(0x8000)),
        Err(MtuError::AdvertisedOutOfRange {
            family: IpVersion::V4,
            value: 32768,
            min: 576,
            max: 32767,
        })
    );
    assert_eq!(v4.current_mtu(), 1500);

    let mut v6 = PmtudState::new(TARGET_V6, 1500).unwrap();
    // 32 位字段超过本层 u16 表示上限。
    assert_eq!(
        v6.on_packet_too_big(65536),
        Err(MtuError::AdvertisedOutOfRange {
            family: IpVersion::V6,
            value: 65536,
            min: 1280,
            max: 65535,
        })
    );
    assert_eq!(v6.current_mtu(), 1500);
}

#[test]
fn non_pmtud_messages_are_rejected_without_state_change() {
    let mut v4 = PmtudState::new(TARGET_V4, 1500).unwrap();
    assert_eq!(
        v4.apply_icmp(&[3, 3, 0, 0, 0, 0, 0, 0]),
        Err(MtuError::NotPmtud {
            family: IpVersion::V4,
            kind: 3,
            code: 3,
        })
    );
    assert_eq!(
        v4.apply_icmp(&[11, 0, 0, 0, 0, 0, 0, 0]),
        Err(MtuError::NotPmtud {
            family: IpVersion::V4,
            kind: 11,
            code: 0,
        })
    );
    assert_eq!(v4.current_mtu(), 1500);

    let mut v6 = PmtudState::new(TARGET_V6, 1500).unwrap();
    assert_eq!(
        v6.apply_icmp(&[2, 1, 0, 0, 0, 0, 0x05, 0x00]),
        Err(MtuError::NotPmtud {
            family: IpVersion::V6,
            kind: 2,
            code: 1,
        })
    );
    assert_eq!(
        v6.apply_icmp(&[3, 4, 0, 0, 0, 0, 0, 0]),
        Err(MtuError::NotPmtud {
            family: IpVersion::V6,
            kind: 3,
            code: 4,
        })
    );
    assert_eq!(v6.current_mtu(), 1500);
}

#[test]
fn truncated_icmp_is_rejected_at_each_key_offset() {
    let full_v4 = [3u8, 4, 0, 0, 0, 0, 0x05, 0x78];
    let mut v4 = PmtudState::new(TARGET_V4, 1500).unwrap();
    for len in 0..full_v4.len() {
        assert_eq!(
            v4.apply_icmp(&full_v4[..len]),
            Err(MtuError::Truncated {
                needed: 8,
                got: len
            }),
            "IPv4 截断到 {len} 字节"
        );
    }
    assert_eq!(v4.current_mtu(), 1500);

    let full_v6 = [2u8, 0, 0, 0, 0, 0, 0x05, 0x00];
    let mut v6 = PmtudState::new(TARGET_V6, 1500).unwrap();
    for len in 0..full_v6.len() {
        assert_eq!(
            v6.apply_icmp(&full_v6[..len]),
            Err(MtuError::Truncated {
                needed: 8,
                got: len
            }),
            "IPv6 截断到 {len} 字节"
        );
    }
    assert_eq!(v6.current_mtu(), 1500);
}

#[test]
fn family_specific_handlers_reject_the_other_family() {
    let mut v6 = PmtudState::new(TARGET_V6, 1500).unwrap();
    assert_eq!(
        v6.on_frag_needed(None),
        Err(MtuError::FamilyMismatch {
            state: IpVersion::V6,
            message: IpVersion::V4,
        })
    );
    let mut v4 = PmtudState::new(TARGET_V4, 1500).unwrap();
    assert_eq!(
        v4.on_packet_too_big(1400),
        Err(MtuError::FamilyMismatch {
            state: IpVersion::V4,
            message: IpVersion::V6,
        })
    );
    assert_eq!(v4.current_mtu(), 1500);
    assert_eq!(v6.current_mtu(), 1500);
}

#[test]
fn pmtud_state_rejects_invalid_initial_mtu() {
    assert_eq!(
        PmtudState::new(TARGET_V6, 576),
        Err(MtuError::MtuOutOfRange {
            value: 576,
            min: 1280,
            max: MAX_MTU,
        })
    );
    assert_eq!(
        PmtudState::new(TARGET_V4, 575),
        Err(MtuError::MtuOutOfRange {
            value: 575,
            min: 576,
            max: MAX_MTU,
        })
    );
}
