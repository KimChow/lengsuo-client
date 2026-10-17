//! VMess 请求头地址段线编码（对齐 Xray `proxy/vmess/encoding/encoding.go` 的
//! `addrParser` = `PortThenAddress()`，类型编号来自 `common/protocol/address.go`）。
//!
//! 线上布局（**与 SOCKS5 两处都不同**，这是本次修复的唯一偏差源）：
//! ```text
//! Port(BE16, 2B) | AddrType(1B) | ADDR
//! ```
//! - 顺序：VMess 端口在最前；ss-core `TargetAddr::encode_into`（SOCKS5/SIP022）
//!   是 `ATYP | ADDR | Port`，端口在最后。
//! - 类型编号：VMess IPv4=1 / Domain=2 / IPv6=3；SOCKS5 IPv4=1 / Domain=3 / IPv6=4。
//!
//! 地址**模型**仍复用 [`ss_core::target::TargetAddr`]：本模块只做线格式，
//! 不新增第二套地址类型，也不改 `ss-core` 的 SOCKS5 语义（其他协议依赖它）。

use ss_core::target::TargetAddr;

use crate::{Error, Result};

/// VMess 地址族字节：IPv4（`AddressType_IPv4`）。
const ADDR_TYPE_IPV4: u8 = 1;
/// VMess 地址族字节：域名（`AddressType_Domain`，非 SOCKS5 的 0x03）。
const ADDR_TYPE_DOMAIN: u8 = 2;
/// VMess 地址族字节：IPv6（`AddressType_IPv6`，非 SOCKS5 的 0x04）。
const ADDR_TYPE_IPV6: u8 = 3;
/// 域名段上限（1 字节长度前缀）。
const MAX_DOMAIN_LEN: usize = u8::MAX as usize;
/// 端口段字节数（BE16）。
const PORT_LEN: usize = 2;
/// 地址族字节数。
const ADDR_TYPE_LEN: usize = 1;
/// 域名长度前缀字节数。
const DOMAIN_LEN_PREFIX: usize = 1;

/// 地址段编码后的字节长度（预分配用）。
#[must_use]
pub fn encoded_addr_len(target: &TargetAddr) -> usize {
    let addr_len = match target {
        TargetAddr::V4(..) => 4,
        TargetAddr::V6(..) => 16,
        TargetAddr::Domain(host, _) => DOMAIN_LEN_PREFIX + host.len(),
    };
    PORT_LEN + ADDR_TYPE_LEN + addr_len
}

/// `PortThenAddress` 编码：先校验再写字节（校验失败不留下半截地址）。
///
/// 域名与 ss-core `encode_checked` 同规 fail-closed：空值、NUL、超过 255 字节
/// 一律拒绝，错误只携带字段名，不携带域名内容。
pub fn encode_target_addr(target: &TargetAddr, buf: &mut Vec<u8>) -> Result<()> {
    if let TargetAddr::Domain(host, _) = target {
        if host.is_empty() || host.len() > MAX_DOMAIN_LEN || host.contains('\0') {
            return Err(Error::InvalidField {
                field: "target.domain",
            });
        }
    }
    match target {
        TargetAddr::V4(ip, port) => {
            buf.extend_from_slice(&port.to_be_bytes());
            buf.push(ADDR_TYPE_IPV4);
            buf.extend_from_slice(ip);
        }
        TargetAddr::V6(ip, port) => {
            buf.extend_from_slice(&port.to_be_bytes());
            buf.push(ADDR_TYPE_IPV6);
            buf.extend_from_slice(ip);
        }
        TargetAddr::Domain(host, port) => {
            buf.extend_from_slice(&port.to_be_bytes());
            buf.push(ADDR_TYPE_DOMAIN);
            buf.push(host.len() as u8);
            buf.extend_from_slice(host.as_bytes());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(target: &TargetAddr) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_target_addr(target, &mut buf).expect("可编码");
        buf
    }

    #[test]
    fn ipv4_is_port_then_type1_then_addr() {
        let target = TargetAddr::V4([192, 0, 2, 1], 443);
        assert_eq!(
            encode(&target),
            vec![0x01, 0xBB, ADDR_TYPE_IPV4, 192, 0, 2, 1]
        );
        assert_eq!(encode(&target).len(), encoded_addr_len(&target));
    }

    #[test]
    fn ipv6_is_port_then_type3_then_addr() {
        let target = TargetAddr::V6([0x20; 16], 8080);
        let buf = encode(&target);
        assert_eq!(&buf[..2], &[0x1F, 0x90], "端口必须在前（BE16）");
        assert_eq!(buf[2], ADDR_TYPE_IPV6, "IPv6 必须是 3，不是 SOCKS5 的 0x04");
        assert_eq!(&buf[3..], &[0x20; 16][..]);
        assert_eq!(buf.len(), encoded_addr_len(&target));
    }

    #[test]
    fn domain_is_port_then_type2_len_addr() {
        let target = TargetAddr::Domain("example.invalid".into(), 8443);
        let buf = encode(&target);
        assert_eq!(
            &buf[..3],
            &[0x20, 0xFB, ADDR_TYPE_DOMAIN],
            "域名类型必须是 2"
        );
        assert_eq!(buf[3] as usize, 15);
        assert_eq!(&buf[4..], b"example.invalid");
        assert_eq!(buf.len(), encoded_addr_len(&target));
    }

    #[test]
    fn socks5_order_is_not_reused() {
        // 同一地址：VMess 端口在前，SOCKS5 端口在后 —— 锁死不可回退。
        let target = TargetAddr::V4([8, 8, 8, 8], 53);
        let vmess = encode(&target);
        let mut socks = Vec::new();
        target.encode_into(&mut socks);
        assert_eq!(vmess, vec![0x00, 0x35, ADDR_TYPE_IPV4, 8, 8, 8, 8]);
        assert_eq!(socks, vec![0x01, 8, 8, 8, 8, 0x00, 0x35]);
        assert_ne!(vmess, socks, "两种线格式不得相同");
    }

    #[test]
    fn invalid_domain_fails_closed_without_partial_write() {
        for host in [String::new(), "a\0b".into(), "x".repeat(MAX_DOMAIN_LEN + 1)] {
            let mut buf = vec![0xAAu8; 3];
            let error = encode_target_addr(&TargetAddr::Domain(host, 443), &mut buf)
                .expect_err("非法域名必须拒绝");
            assert!(matches!(
                error,
                Error::InvalidField {
                    field: "target.domain"
                }
            ));
            assert_eq!(&buf, &[0xAAu8; 3], "拒绝时不得写入半截地址");
            assert!(!error.to_string().contains("xxx"), "错误文本不得带域名");
        }
        // 上界本身合法。
        let target = TargetAddr::Domain("x".repeat(MAX_DOMAIN_LEN), 443);
        let mut buf = Vec::new();
        encode_target_addr(&target, &mut buf).expect("255 字节域名合法");
        assert_eq!(buf.len(), encoded_addr_len(&target));
    }
}
