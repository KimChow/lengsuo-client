//! 节点配置单元测试。

/// 测试专用：线上小写名（与 serde 重命名保持一致）。
impl Protocol {
    /// 线上小写名（测试与诊断用，与 serde 重命名保持一致）。
    #[must_use]
    pub fn to_string_value(self) -> &'static str {
        match self {
            Protocol::Trojan => "trojan",
            Protocol::AnyTls => "anytls",
            Protocol::Vless => "vless",
            Protocol::Vmess => "vmess",
            Protocol::Shadowsocks => "shadowsocks",
            Protocol::Ss2022 => "ss2022",
            Protocol::Hysteria => "hysteria",
            Protocol::Wireguard => "wireguard",
        }
    }
}

use super::*;

fn node_json(protocol: &str) -> String {
    format!(
        r#"[{{
                "name": "n1",
                "protocol": "{protocol}",
                "endpoint": {{ "host": "127.0.0.1", "port": 8443 }},
                "tls": {{ "insecure": true }},
                "auth": {{ "password": "pw" }}
            }}]"#
    )
}

#[test]
fn parse_all_eight_protocols() {
    for protocol in [
        "trojan",
        "anytls",
        "vless",
        "vmess",
        "shadowsocks",
        "ss2022",
        "hysteria",
        "wireguard",
    ] {
        let nodes: Vec<NodeConfig> =
            serde_json::from_str(&node_json(protocol)).unwrap_or_else(|e| {
                panic!("{protocol} 应可解析：{e}");
            });
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].protocol.to_string_value(), protocol);
    }
}

#[test]
fn unknown_protocol_rejected() {
    let raw = node_json("trojan-go");
    assert!(serde_json::from_str::<Vec<NodeConfig>>(&raw).is_err());
}

#[test]
fn debug_redacts_every_credential() {
    let raw = r#"[{
        "name": "n1",
        "protocol": "wireguard",
        "endpoint": { "host": "127.0.0.1", "port": 51820 },
        "auth": {
            "private_key": "cHJpdmF0ZS1rZXktbWF0ZXJpYWw=",
            "public_key": "cHVibGljLWtleS1tYXRlcmlhbA==",
            "secret_key": "shadowsocks-secret",
            "password": "vmess-uuid-text"
        },
        "method": "chacha20-poly1305"
    }]"#;
    let nodes: Vec<NodeConfig> = serde_json::from_str(raw).unwrap();
    let text = format!("{:?}", nodes[0]);
    for leak in [
        "cHJpdmF0ZS1rZXktbWF0ZXJpYWw=",
        "cHVibGljLWtleS1tYXRlcmlhbA==",
        "shadowsocks-secret",
        "vmess-uuid-text",
    ] {
        assert!(!text.contains(leak), "Debug 输出不得包含凭据：{text}");
    }
    assert!(text.contains("<redacted>"));
}

#[test]
fn validation_rejects_empty_and_zero_port() {
    let mut nodes: Vec<NodeConfig> = serde_json::from_str(&node_json("trojan")).unwrap();
    nodes[0].endpoint.port = 0;
    assert!(nodes[0].validate().is_err());

    let mut nodes: Vec<NodeConfig> = serde_json::from_str(&node_json("anytls")).unwrap();
    nodes[0].auth.password = String::new();
    assert!(nodes[0].validate().is_err());
}

#[test]
fn protocol_specific_requirements_fail_closed() {
    // vless/vmess 需要 UUID 形态。
    let mut nodes: Vec<NodeConfig> = serde_json::from_str(&node_json("vless")).unwrap();
    assert!(nodes[0].validate().is_err(), "非 UUID 口令必须被拒");
    nodes[0].auth.password = "11111111-1111-1111-1111-111111111111".into();
    assert!(nodes[0].validate().is_ok());

    // shadowsocks 需要 secret_key + method。
    let mut nodes: Vec<NodeConfig> = serde_json::from_str(&node_json("shadowsocks")).unwrap();
    assert!(nodes[0].validate().is_err(), "缺 secret_key 必须被拒");
    nodes[0].auth.secret_key = Some("test-secret".into());
    assert!(nodes[0].validate().is_err(), "缺 method 必须被拒");
    nodes[0].method = Some("aes-128-gcm".into());
    assert!(nodes[0].validate().is_ok());

    // wireguard 需要一对静态密钥。
    let mut nodes: Vec<NodeConfig> = serde_json::from_str(&node_json("wireguard")).unwrap();
    assert!(nodes[0].validate().is_err(), "缺密钥对必须被拒");
    nodes[0].auth.private_key = Some("k".repeat(43) + "=");
    nodes[0].auth.public_key = Some("k".repeat(43) + "=");
    assert!(nodes[0].validate().is_ok());
}
