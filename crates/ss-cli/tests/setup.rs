use serial_test::serial;
use ss_cli::config::{Action, Config, OutboundConfig};
use std::fs;

pub struct Fixture {
    pub cfg: Config,
}

impl Default for Fixture {
    fn default() -> Self {
        Self {
            cfg: Config {
                outbound: OutboundConfig {
                    ss_url: "ss://chacha20-ietf-poly1305:c2VjcmV0QABDMg@127.0.0.1:1088".into(),
                    udp: true,
                    mux: ss_cli::config::MuxConfig::default(),
                    connect_timeout_ms: 3000,
                },
                dns: ss_cli::config::DnsConfig::default(),
                rules: vec![
                    ss_cli::config::Rule {
                        name: "lan-direct".into(),
                        r#match: ss_cli::config::Match {
                            ip: vec!["192.168.0.0/16".into(), "10.0.0.0/8".into()],
                            ..Default::default()
                        },
                        action: Action::Direct,
                    },
                    ss_cli::config::Rule {
                        name: "proxy-else".into(),
                        r#match: ss_cli::config::Match::default(),
                        action: Action::Proxy,
                    },
                ],
            },
        }
    }
}

pub fn tempdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp().join(format!(
        "lengsuo-cli-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).expect("create_dir_all");
    p
}

pub fn tmp(tag: &str, name: &str) -> std::path::PathBuf {
    tempdir(tag).join(name)
}

pub async fn bind_ephemeral() -> std::net::TcpListener {
    std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral")
}

pub async fn wait_for_port_release(addr: std::net::SocketAddr) {
    for _ in 0..1000 {
        if std::net::TcpListener::bind(addr).is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("port {:?} still occupied after 5s", addr);
}

#[serial]
#[tokio::test]
async fn smoke_bind_release() {
    let l1 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l1.local_addr().unwrap();
    drop(l1);
    wait_for_port_release(addr).await;
}
