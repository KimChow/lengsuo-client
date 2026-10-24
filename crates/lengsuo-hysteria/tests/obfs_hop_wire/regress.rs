// 回归锁（非互通取证，无网络、无参考进程）：锁住「混淆/端口跳跃」原语与
// 线上包装层的**语义不变量**。既有覆盖的分工：
// - `tests/salamander.rs`：`Obfuscator` 布局/roundtrip（注入确定性哈希替身）；
// - `tests/xray_hysteria_obfs.rs`：参考生成的确定性向量逐字节对照（`#[ignore]`）；
// - 本文件：`WireMask` 级 roundtrip 与直通分支、`port_list` 解析/展开与
//   间隔规则、跳跃目标取值域、生产 `b2sum` 后端的 BLAKE2b-256 已知答案。

const REGRESS_PSK: &[u8] = b"lengsuo-regress-psk";

/// 固定盐流（`fill_bytes` 产出 0,1,2,…；做法同 `tests/salamander.rs`）。
struct RegressFixedSalt(Arc<Mutex<u8>>);

impl RegressFixedSalt {
    fn seq() -> Self {
        Self(Arc::new(Mutex::new(0)))
    }
}

impl TransportRng for RegressFixedSalt {
    fn gen_index(&self, bound: usize) -> usize {
        if bound <= 1 {
            0
        } else {
            self.gen_u64(bound as u64) as usize
        }
    }
    fn gen_u64(&self, bound: u64) -> u64 {
        if bound <= 1 {
            return 0;
        }
        let mut g = self.0.lock().expect("盐锁中毒");
        let v = u64::from(*g);
        *g = g.wrapping_add(1);
        v % bound
    }
    fn fill_bytes(&self, out: &mut [u8]) {
        let mut g = self.0.lock().expect("盐锁中毒");
        for b in out.iter_mut() {
            *b = *g;
            *g = g.wrapping_add(1);
        }
    }
}

/// `WireMask` 层（产品接线形态）混淆 → 解混淆 roundtrip，多长度。
#[test]
fn regress_wire_mask_roundtrip_multi_length() {
    let base: SocketAddr = "127.0.0.1:4433".parse().expect("固定地址");
    let mask =
        WireMask::new(base, Some(REGRESS_PSK.to_vec()), None, Arc::new(OsRng)).expect("口令合法");
    assert!(mask.obfuscated(), "带口令的 WireMask 必须处于混淆态");
    assert!(!mask.hopping());
    for len in [1usize, 2, 8, 31, 32, 33, 1200, 1500] {
        let plain: Vec<u8> = (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect();
        let mut enc = vec![0u8; len + SALT_LEN];
        let n = mask.obfuscate(&plain, &mut enc).expect("缓冲足够");
        assert_eq!(n, len + SALT_LEN, "线上长度 = 明文 + 8 字节盐");
        let got = mask.deobfuscate(&enc[..n]).expect("解混淆成功");
        assert_eq!(got, plain, "长度 {len} 的 WireMask roundtrip 不符");
    }
}

/// 未配置混淆/跳跃时的直通分支：字节零改写（`MaskedUdpSocket` 的
/// 「不包装」路径依赖它，对齐参考「未配置 finalmask」）。
#[test]
fn regress_wire_mask_passthrough_without_obfs() {
    let base: SocketAddr = "127.0.0.1:4433".parse().expect("固定地址");
    let mask = WireMask::new(base, None, None, Arc::new(OsRng)).expect("无混淆无跳跃");
    assert!(!mask.obfuscated());
    assert!(!mask.hopping());
    assert_eq!(
        mask.hop_interval(),
        Duration::from_secs(30),
        "未启用跳跃时报缺省 30s 间隔"
    );
    let payload = b"plain-payload";
    let mut buf = [0u8; 64];
    let n = mask.obfuscate(payload, &mut buf).expect("直通拷贝");
    assert_eq!(n, payload.len());
    assert_eq!(&buf[..n], &payload[..], "未启用混淆时不得改写字节");
    let got = mask.deobfuscate(&buf[..n]).expect("直通还原");
    assert_eq!(got, payload.to_vec());
}

/// `port_list` 解析/展开与跳跃间隔规则（对照参考 `PortList.UnmarshalJSON` /
/// `Ports()` 的闭区间展开与 `hop interval must be at least 5 seconds`）。
#[test]
fn regress_port_list_parse_expand_and_interval_rules() {
    // 单端口 + 闭区间：443 与 1000..=2000 共 1002 个，按声明顺序展开。
    let ranges = hop::parse_port_list("443,1000-2000").expect("合法 port_list");
    let ports = PortList { ranges }.ports();
    assert_eq!(ports.len(), 1002);
    assert_eq!(ports[0], 443);
    assert_eq!(ports[1], 1000);
    assert_eq!(ports[1001], 2000);
    // 空白容忍、空元素忽略、多段保持声明顺序。
    let ports = PortList {
        ranges: hop::parse_port_list(" 8443 , 1-3 ,, 5").expect("合法 port_list"),
    }
    .ports();
    assert_eq!(ports, vec![8443, 1, 2, 3, 5]);
    // fail-closed：端口 0 / 超过 u16 / 非数字 / 空端口列表。
    assert!(matches!(
        hop::parse_port_list("0"),
        Err(hop::HopError::InvalidPort { .. })
    ));
    assert!(matches!(
        hop::parse_port_list("65536"),
        Err(hop::HopError::InvalidPort { .. })
    ));
    assert!(matches!(
        hop::parse_port_list("abc"),
        Err(hop::HopError::InvalidPort { .. })
    ));
    assert!(matches!(
        HopSpec::new(vec![], 0, 0),
        Err(hop::HopError::NoPorts)
    ));
    // 起止颠倒：与参考 PortList 字符串路径一致，解析层不查 from > to；
    // 闭区间展开为空集 ⇒ 在 HopSpec 构造处 NoPorts fail-closed（不 panic、
    // 不静默放行空端口集）。
    let reversed = hop::parse_port_list("2000-1000").expect("解析层不查起止顺序");
    assert!(PortList { ranges: reversed }.ports().is_empty());
    assert!(matches!(
        HopSpec::from_port_list("2000-1000", 0, 0),
        Err(hop::HopError::NoPorts)
    ));
    // 间隔规则：0/0 → 缺省 30s；任一 < 5s 拒绝（报较小值）；5s 可用。
    let spec = HopSpec::from_port_list("443", 0, 0).expect("缺省间隔合法");
    assert_eq!(spec.interval_min, 30);
    assert_eq!(spec.interval_max, 30);
    assert!(matches!(
        HopSpec::new(vec![443], 4, 8),
        Err(hop::HopError::IntervalTooShort { got: 4 })
    ));
    let spec = HopSpec::new(vec![443, 8443], 5, 5).expect("5s 间隔合法");
    assert_eq!(spec.ports, vec![443, 8443]);
}

/// 跳跃目标取值域与地址改写规则：IP 恒不变、端口必取自端口集合、
/// `current_remote` 随跳更新（对照参考 `hop()`：全部端口均匀随机、允许自跳；
/// `UDPHopAddr` 保留同一 IP 只换端口）。
#[test]
fn regress_hop_destination_domain_and_current_tracking() {
    let base: SocketAddr = "127.0.0.1:443".parse().expect("固定地址");
    let spec = HopSpec::new(vec![443, 8443, 9443], 5, 5).expect("合法规格");
    let mask = WireMask::new(
        base,
        Some(REGRESS_PSK.to_vec()),
        Some(spec),
        Arc::new(OsRng),
    )
    .expect("掩码构造");
    assert!(mask.hopping());
    assert_eq!(mask.current_remote(), base, "起跳前目标必须是基址");
    for i in 0..64u32 {
        let dest = mask.next_hop().expect("未关闭前应能持续跳");
        assert_eq!(dest.ip(), base.ip(), "第 {i} 跳：IP 不得改变");
        assert!(
            matches!(dest.port(), 443 | 8443 | 9443),
            "第 {i} 跳：端口必须取自端口集合"
        );
        assert_eq!(
            mask.current_remote(),
            dest,
            "第 {i} 跳：current_remote 应随跳更新"
        );
    }
}

/// 生产哈希后端（`B2sumDeriver` → `b2sum -l 256`）与 RFC 7693 BLAKE2b-256
/// （参考 `golang.org/x/crypto/blake2b.Sum256`）的已知答案对照 + 整包已知
/// 答案（固定盐 = 0..8）：布局 = `[8B 盐][载荷 ^ key(i%32) 循环]`。
/// `#[ignore]`：b2sum 是外部进程（生产后端，见 docs 偏离清单），须
/// `--ignored` 实跑。
#[test]
#[ignore = "需要 GNU coreutils b2sum（生产 BLAKE2b 后端）"]
fn regress_b2sum_backend_blake2b256_known_answers() {
    let deriver = B2sumDeriver;
    assert_eq!(
        deriver.sum256(b"").expect("b2sum 可用"),
        [
            0x0e, 0x57, 0x51, 0xc0, 0x26, 0xe5, 0x43, 0xb2, 0xe8, 0xab, 0x2e, 0xb0, 0x60, 0x99,
            0xda, 0xa1, 0xd1, 0xe5, 0xdf, 0x47, 0x77, 0x8f, 0x77, 0x87, 0xfa, 0xab, 0x45, 0xcd,
            0xf1, 0x2f, 0xe3, 0xa8,
        ],
        "BLAKE2b-256(\"\") 已知答案"
    );
    assert_eq!(
        deriver.sum256(b"abc").expect("b2sum 可用"),
        [
            0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72, 0x31, 0x71, 0xef, 0x3f, 0xee, 0x98,
            0x57, 0x9b, 0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb, 0x3e, 0x42, 0x72, 0x62, 0xc8, 0xc0,
            0x68, 0xd5, 0x23, 0x19,
        ],
        "BLAKE2b-256(\"abc\") 已知答案"
    );

    // 整包已知答案：PSK = REGRESS_PSK、盐 = 0..8 ⇒
    // key = BLAKE2b256("lengsuo-regress-psk" || 00..07)
    //    = 215cc561a52ef8e932c0cfdfc4e493ea178e01c80b1edbf286c11aa427a6be05。
    let o = Obfuscator::with_deriver(
        REGRESS_PSK.to_vec(),
        Arc::new(RegressFixedSalt::seq()),
        Arc::new(B2sumDeriver),
    )
    .expect("口令合法");
    let plain: Vec<u8> = (0..40usize).map(|i| ((i * 31 + 7) % 251) as u8).collect();
    let mut out = vec![0u8; plain.len() + SALT_LEN];
    let n = o.obfuscate(&plain, &mut out).expect("b2sum 可用");
    assert_eq!(n, out.len());
    assert_eq!(
        out,
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x26, 0x7a, 0x80, 0x05, 0x26, 0x8c,
            0x39, 0x09, 0x36, 0xe3, 0x8d, 0xbe, 0x44, 0x7b, 0x2d, 0x37, 0x16, 0xae, 0x3e, 0x96,
            0x76, 0x82, 0x60, 0x28, 0x7f, 0xdc, 0x26, 0xff, 0x5d, 0x3f, 0x06, 0xd2, 0xd7, 0x46,
            0xfc, 0x39, 0xd2, 0xb8, 0x4d, 0x3d,
        ],
        "整包字节必须与参考格式逐字节一致"
    );
    let mut dec = vec![0u8; plain.len()];
    let m = o.deobfuscate(&out, &mut dec).expect("解混淆成功");
    assert_eq!(m, plain.len());
    assert_eq!(dec, plain);
}
