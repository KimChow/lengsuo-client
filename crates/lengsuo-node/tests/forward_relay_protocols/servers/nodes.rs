/// vless(TLS) 节点配置。
#[must_use]
pub fn vless_node(name: &str, port: u16, ca_pem: &str, uuid: &str) -> NodeConfig {
    node_from_json(json!({
        "name": name,
        "protocol": "vless",
        "endpoint": { "host": "127.0.0.1", "port": port },
        "tls": { "server_name": "localhost", "ca_pem": ca_pem },
        "auth": { "password": uuid }
    }))
}

/// vmess 节点配置。
#[must_use]
pub fn vmess_node(name: &str, port: u16, ca_pem: &str, uuid: &str) -> NodeConfig {
    node_from_json(json!({
        "name": name,
        "protocol": "vmess",
        "endpoint": { "host": "127.0.0.1", "port": port },
        "tls": { "server_name": "localhost", "ca_pem": ca_pem },
        "auth": { "password": uuid }
    }))
}

/// ss2022 节点配置。
#[must_use]
pub fn ss2022_node(name: &str, port: u16) -> NodeConfig {
    node_from_json(json!({
        "name": name,
        "protocol": "ss2022",
        "endpoint": { "host": "127.0.0.1", "port": port },
        "auth": { "secret_key": SS2022_PSK_B64 },
        "method": "2022-blake3-aes-128-gcm"
    }))
}

/// anytls 节点配置。
#[must_use]
pub fn anytls_node(name: &str, port: u16, ca_pem: &str, password: &str) -> NodeConfig {
    node_from_json(json!({
        "name": name,
        "protocol": "anytls",
        "endpoint": { "host": "127.0.0.1", "port": port },
        "tls": { "server_name": "localhost", "ca_pem": ca_pem },
        "auth": { "password": password }
    }))
}

/// hysteria 节点配置（endpoint 是 UDP 端口）。
#[must_use]
pub fn hysteria_node(name: &str, port: u16, ca_pem: &str, password: &str) -> NodeConfig {
    node_from_json(json!({
        "name": name,
        "protocol": "hysteria",
        "endpoint": { "host": "127.0.0.1", "port": port },
        "tls": { "server_name": "localhost", "ca_pem": ca_pem },
        "auth": { "password": password }
    }))
}

/// wireguard 节点配置（仅用于「结构性不可转发 ⇒ 显式拒绝」反例；
/// 密钥是假值，转发层在建会话前就拒绝，不发起任何连接）。
#[must_use]
pub fn wireguard_node(name: &str, port: u16) -> NodeConfig {
    node_from_json(json!({
        "name": name,
        "protocol": "wireguard",
        "endpoint": { "host": "127.0.0.1", "port": port },
        "auth": {
            "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        }
    }))
}

/// 由 JSON 构造节点配置（走 serde，与真实配置路径同一条）。
#[must_use]
pub fn node_from_json(value: serde_json::Value) -> NodeConfig {
    let nodes: Vec<NodeConfig> = serde_json::from_value(json!([value])).expect("节点配置");
    nodes.into_iter().next().expect("恰好一个节点")
}
