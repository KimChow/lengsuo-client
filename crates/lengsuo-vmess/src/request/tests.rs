//! `request` 模块的单元测试（明文布局、FNV 尾部、字段约束）。

use super::*;
use crate::address::encoded_addr_len;
use crate::consts::SECURITY_AES_128_GCM;
use crate::Error;
use ss_core::target::TargetAddr;

fn planner() -> HeaderPlanner {
    let mut key_source = KeySource {
        body_key: [0x11u8; 16],
        body_iv: [0x22u8; 16],
        response_header: 0x33,
    };
    // KeySource 字段可变性仅测试用。
    let _ = &mut key_source;
    HeaderPlanner::new(key_source)
}

fn sample_header() -> RequestHeader {
    RequestHeader {
        target: Some(TargetAddr::Domain("example.invalid".into(), 443)),
        command: Command::Tcp,
        security: SecurityOption::Aes128Gcm,
        option: 0x05,
        padding_len: 4,
    }
}

#[test]
fn plan_layout_and_fnv_tail() {
    let header = sample_header();
    let padding = [0xAAu8; 4];
    let plain = planner().plan_with(&header, &padding).expect("可编码");
    // 1 + 16 + 16 + 1 + 1 + 3 + 地址(2+1+1+15) + 4 + 4
    assert_eq!(plain[0], VMESS_VERSION_BYTE);
    assert_eq!(&plain[1..17], &[0x22u8; 16]);
    assert_eq!(&plain[17..33], &[0x11u8; 16]);
    assert_eq!(plain[33], 0x33);
    assert_eq!(plain[34], 0x05);
    // security 字节 = padding<<4 | sec
    assert_eq!(plain[35], (4 << 4) | SECURITY_AES_128_GCM);
    assert_eq!(plain[36], 0x00);
    assert_eq!(plain[37], Command::Tcp.to_byte());
    // FNV 尾部自洽。
    let body = &plain[..plain.len() - 4];
    let tail = u32::from_be_bytes(plain[plain.len() - 4..].try_into().unwrap());
    assert_eq!(tail, fnv1a32(body));
    // 地址段是 PortThenAddress：端口在前、类型 2、再长度与域名。
    let addr = &plain[38..plain.len() - 4 - padding.len()];
    assert_eq!(
        addr,
        &[
            0x01, 0xBB, 0x02, 15, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'i', b'n', b'v',
            b'a', b'l', b'i', b'd'
        ]
    );
    assert_eq!(
        addr.len(),
        encoded_addr_len(&TargetAddr::Domain("example.invalid".into(), 443))
    );
    assert_eq!(38 + addr.len() + padding.len() + 4, plain.len());
}

#[test]
fn fnv1a32_known_vector() {
    // FNV-1a 32 标准空串与 "a" 向量（公共规范值，非 Go 特有）。
    assert_eq!(fnv1a32(b""), 0x811C_9DC5);
    assert_eq!(fnv1a32(b"a"), 0xE40C_292C);
}

#[test]
fn missing_target_rejected_and_mux_byte_unrepresentable() {
    // Mux（字节 3）不在 Command 枚举里（本层不支持）——枚举层面就无法构造。
    assert_eq!(Command::from_byte(CMD_MUX), None);
    // 缺地址必须拒绝（padding 与声明一致，确保真正走到 target 校验）。
    let mut header = sample_header();
    header.target = None;
    assert!(matches!(
        planner().plan_with(&header, &[0u8; 4]),
        Err(Error::InvalidField { field: "target" })
    ));
}

#[test]
fn padding_and_security_constraints() {
    let mut header = sample_header();
    header.padding_len = 16; // dice.Roll(16) 上界是 15
    assert!(matches!(
        planner().plan_with(&header, &[0u8; 16]),
        Err(Error::InvalidField {
            field: "padding_len"
        })
    ));
    let mut header = sample_header();
    header.security = SecurityOption::AutoCipher;
    assert!(matches!(
        planner().plan_with(&header, &[0u8; 4]),
        Err(Error::Unsupported { .. })
    ));
    // padding 长度与声明不符。
    let header = sample_header();
    assert!(matches!(
        planner().plan_with(&header, &[]),
        Err(Error::BadLength { .. })
    ));
}

#[test]
fn cipher_spec_key_lengths() {
    assert_eq!(
        CipherSpec {
            security: SecurityOption::None
        }
        .key_len(),
        0
    );
    assert_eq!(
        CipherSpec {
            security: SecurityOption::Aes128Gcm
        }
        .key_len(),
        16
    );
    assert_eq!(
        CipherSpec {
            security: SecurityOption::ChaCha20Poly1305
        }
        .key_len(),
        32
    );
}

#[test]
fn key_source_generate_is_random_and_debug_free() {
    let a = KeySource::generate().expect("可生成");
    let b = KeySource::generate().expect("可生成");
    assert_ne!(a.body_key, b.body_key, "CSPRNG 两次生成不得相同");
    assert_ne!(a.body_iv, b.body_iv);
    let _ = format!("{:?}", RequestHeader::is_mux(&sample_header()));
}
