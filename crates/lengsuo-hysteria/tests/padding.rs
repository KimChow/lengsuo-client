//! padding 长度策略测试。
//!
//! 覆盖 `padding.go` 的半开区间 `[Min, Max)` 语义与 `SegmentSize` 上下取整。
//! 本模块是纯函数，随机由调用方注入，因此这里用显式的抽样值断言确定性结果。
//! 填充字节内容不在本 crate 策略范围内（由调用方决定）。

use lengsuo_hysteria::padding::{
    floor_to_segment, padding_to_next_segment, sampled_within_total, Range,
};
use lengsuo_hysteria::Error;

#[test]
fn ranges_match_reference_intervals() {
    // padding.go：authRequest/authResponse = [256,2048)，tcpRequest = [64,512)，
    // tcpResponse = [128,1024)。
    assert_eq!(
        Range::AUTH_REQUEST,
        Range {
            min: 256,
            max: 2048
        }
    );
    assert_eq!(
        Range::AUTH_RESPONSE,
        Range {
            min: 256,
            max: 2048
        }
    );
    assert_eq!(Range::TCP_REQUEST, Range { min: 64, max: 512 });
    assert_eq!(
        Range::TCP_RESPONSE,
        Range {
            min: 128,
            max: 1024
        }
    );
    assert_eq!(Range::TCP_REQUEST.span(), 512 - 64);
    assert_eq!(Range::AUTH_REQUEST.span(), 2048 - 256);
}

#[test]
fn sample_endpoints_are_half_open() {
    let range = Range::TCP_REQUEST; // [64, 512)
    assert_eq!(range.sample(0).expect("Min 可取到"), 64);
    assert_eq!(range.sample(1).expect("1"), 65);
    assert_eq!(range.sample(range.span() - 1).expect("上界内"), 511);
    assert_eq!(
        range.sample(range.span()).expect_err("Max 取不到"),
        Error::PaddingRangeInvalid {
            min: 64,
            max: 512,
            sample: 448,
            span: 448
        }
    );
    assert_eq!(
        range.sample(range.span() + 1).expect_err("越界"),
        Error::PaddingRangeInvalid {
            min: 64,
            max: 512,
            sample: 449,
            span: 448
        }
    );
    // contains() 同样半开。
    assert!(range.contains(64) && range.contains(511));
    assert!(!range.contains(63) && !range.contains(512));
}

#[test]
fn degenerate_range_fails_closed() {
    // [n, n) 宽度为 0：参考实现里 rand.Intn(0) 会 panic，本仓必须报错而不是
    // 静默产出固定长度（那会把长度指纹暴露成常数）。
    let empty = Range { min: 100, max: 100 };
    assert_eq!(empty.span(), 0);
    assert_eq!(
        empty.sample(0).expect_err("空区间"),
        Error::PaddingRangeInvalid {
            min: 100,
            max: 100,
            sample: 0,
            span: 0
        }
    );
    assert_eq!(
        empty.clamp(50).expect_err("空区间无可返回值"),
        Error::PaddingRangeInvalid {
            min: 100,
            max: 100,
            sample: 50,
            span: 0
        }
    );
    // min > max 由构造函数拒绝。
    assert_eq!(Range::new(512, 64), None);
    assert_eq!(Range::new(100, 100), Some(empty));
    assert_eq!(Range::new(0, 1), Some(Range { min: 0, max: 1 }));
}

#[test]
fn zero_min_range_allows_zero_padding() {
    // 允许完全不加填充的区间（[0, 4096)）：抽样 0 得到 0 长度。
    let range = Range { min: 0, max: 4096 };
    assert_eq!(range.sample(0).expect("零填充合法"), 0);
    assert_eq!(range.sample(4095).expect("上界内"), 4095);
    assert!(range.span() == 4096);
}

#[test]
fn clamp_snaps_into_half_open_range() {
    let range = Range::TCP_RESPONSE; // [128, 1024)
    assert_eq!(range.clamp(0).expect("低于下界"), 128);
    assert_eq!(range.clamp(127).expect("低于下界"), 128);
    assert_eq!(range.clamp(128).expect("恰为下界"), 128);
    assert_eq!(range.clamp(500).expect("区间内不变"), 500);
    assert_eq!(range.clamp(1023).expect("上界内不变"), 1023);
    assert_eq!(range.clamp(1024).expect("恰为上界取最大可取值"), 1023);
    assert_eq!(range.clamp(999_999).expect("远超上界"), 1023);
    for len in 0..4096_usize {
        let clamped = range.clamp(len).expect("夹紧");
        assert!(
            range.contains(clamped),
            "{len} 夹紧后 {clamped} 应落在区间内"
        );
    }
}

#[test]
fn segment_rounding_up_and_down() {
    // 上取整：返回需要追加的 padding 字节数。
    assert_eq!(padding_to_next_segment(0, 100).expect("0 已对齐"), 0);
    assert_eq!(padding_to_next_segment(1, 100).expect("1"), 99);
    assert_eq!(padding_to_next_segment(100, 100).expect("已对齐"), 0);
    assert_eq!(padding_to_next_segment(101, 100).expect("余 1"), 99);
    assert_eq!(padding_to_next_segment(199, 100).expect("余 99"), 1);
    // 下取整：返回对齐后的长度。
    assert_eq!(floor_to_segment(0, 100).expect("0"), 0);
    assert_eq!(floor_to_segment(1, 100).expect("1"), 0);
    assert_eq!(floor_to_segment(99, 100).expect("99"), 0);
    assert_eq!(floor_to_segment(100, 100).expect("100"), 100);
    assert_eq!(floor_to_segment(299, 100).expect("299"), 200);
    // 上下取整互补：pad + 原长 - 余数 = 对齐长度。
    for len in 0..500_usize {
        for segment in [1_usize, 2, 7, 64, 1200, 1252] {
            let up = padding_to_next_segment(len, segment).expect("上取整");
            let down = floor_to_segment(len, segment).expect("下取整");
            assert_eq!(len + up, if up == 0 { len } else { down + segment });
            assert_eq!(len - down, len % segment);
            assert_eq!((len + up) % segment, 0, "{len}+{up} 应段对齐");
            assert_eq!(down % segment, 0, "{down} 应段对齐");
        }
    }
    // segment == 1 任何长度都已对齐；segment == 0 无法定义取整。
    assert_eq!(padding_to_next_segment(12345, 1).expect("段长 1"), 0);
    assert_eq!(floor_to_segment(12345, 1).expect("段长 1"), 12345);
    assert_eq!(
        padding_to_next_segment(10, 0).expect_err("段长 0"),
        Error::SegmentSizeInvalid { segment: 0 }
    );
    assert_eq!(
        floor_to_segment(10, 0).expect_err("段长 0"),
        Error::SegmentSizeInvalid { segment: 0 }
    );
}

#[test]
fn sampled_within_total_enforces_frame_cap() {
    // 上限恰好等于 header + padding 时可取；再多 1 字节即拒绝。
    let range = Range { min: 10, max: 20 };
    assert_eq!(
        sampled_within_total(range, 0, 100, 110).expect("恰好等于上限"),
        10
    );
    assert_eq!(
        sampled_within_total(range, 9, 100, 119).expect("上界内"),
        19
    );
    assert_eq!(
        sampled_within_total(range, 9, 100, 118).expect_err("超出总长上限"),
        Error::TooLong {
            field: "padded frame",
            len: 119,
            max: 118
        }
    );
    // 区间本身非法优先报区间错误。
    assert_eq!(
        sampled_within_total(Range { min: 5, max: 5 }, 0, 0, usize::MAX).expect_err("空区间"),
        Error::PaddingRangeInvalid {
            min: 5,
            max: 5,
            sample: 0,
            span: 0
        }
    );
    // header 长度极大时相加饱和，仍按超限失败而不是回绕。
    assert!(matches!(
        sampled_within_total(range, 0, usize::MAX, 100),
        Err(Error::TooLong { .. })
    ));
}

#[test]
fn connect_udp_padding_uses_strategy_and_stays_decodable() {
    // 端到端：策略给出 padding 长度，内容自字符表取值（测试用固定 'x'），
    // 帧必须能被自身解码且不吞掉后续载荷。
    use lengsuo_hysteria::connect_udp::ConnectUdpRequest;

    let range = Range::TCP_REQUEST;
    for sample in [0, 1, range.span() - 1] {
        let len = range.sample(sample).expect("策略长度");
        let req = ConnectUdpRequest {
            address: "target.invalid:443".to_string(),
            padding: vec![b'x'; len],
        };
        let bytes = req.encode().expect("编码");
        assert_eq!(bytes.len(), req.encoded_len().expect("长度"));
        let (decoded, used) = ConnectUdpRequest::decode(&bytes).expect("解码");
        assert_eq!(used, bytes.len());
        assert_eq!(decoded, req);
        assert_eq!(decoded.padding.len(), len);
        // 与 CONNECT-UDP 的定界解码接口一致。
        assert_eq!(
            ConnectUdpRequest::decode_exact(&bytes).expect("定界解码"),
            req
        );
    }
    // 参考实现的四个区间上界都落在帧 padding 上限 4096 之内，因此策略长度本身
    // 不会让 padding 超出协议上限（超出只可能来自调用方自己填入的更长填充）。
    for range in [
        Range::AUTH_REQUEST,
        Range::AUTH_RESPONSE,
        Range::TCP_REQUEST,
        Range::TCP_RESPONSE,
    ] {
        assert!(range.max <= 4096, "{range:?} 上界应在帧 padding 上限内");
        let longest = range.sample(range.span() - 1).expect("最大可取长度");
        assert!(range.contains(longest), "{longest} 应落在 {range:?} 内");
    }
    // 超过帧上限的显式填充必须被帧层拒绝（fail-closed，不静默截断）。
    let too_big = ConnectUdpRequest {
        address: "a:1".to_string(),
        padding: vec![b'x'; 4097],
    };
    assert!(too_big.encode().is_err());
}
