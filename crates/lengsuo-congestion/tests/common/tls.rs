//! 端到端测试用的自签证书与 TLS 配置（仅测试用）。
//!
//! 证书是**预生成的固定测试用证书对**：一个测试用 CA（`ca.der`）与一张由它
//! 签发的叶子证书（`test_cert.der` / `test_key.der`，CN=localhost，SAN 含
//! 127.0.0.1 / ::1）。只用于回环地址上的进程内测试，**不对应任何真实主机
//! 或真实凭据**，私钥公开无敏感性，且**不打印、不记录任何日志**。
//!
//! 用 `rcgen` 之类的 crate 现场签发会新增依赖（改 `Cargo.lock`），故改用
//! 固定证书文件。

use std::sync::Arc;

use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// 返回服务端用的叶子证书（DER 证书与私钥）。
pub fn server_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    const CERT_DER: &[u8] = include_bytes!("test_cert.der");
    const KEY_DER: &[u8] = include_bytes!("test_key.der");

    (
        vec![CertificateDer::from(CERT_DER.to_vec())],
        PrivateKeyDer::try_from(KEY_DER.to_vec()).expect("测试私钥格式"),
    )
}

/// 构造客户端 TLS 配置（信任测试用 CA）。
pub fn client_config() -> quinn::rustls::ClientConfig {
    const CA_DER: &[u8] = include_bytes!("ca.der");
    let provider = Arc::new(quinn::rustls::crypto::ring::default_provider());
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(CA_DER.to_vec()))
        .expect("加入根证书");
    let mut config = quinn::rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS 版本")
        .with_root_certificates(roots)
        .with_no_client_auth();
    // ALPN 必须与服务端一致。
    config.alpn_protocols = vec![b"lengsuo-cc".to_vec()];
    config
}

/// 构造服务端 TLS 配置。
pub fn server_config() -> quinn::rustls::ServerConfig {
    let (certs, key) = server_cert();
    let provider = Arc::new(quinn::rustls::crypto::ring::default_provider());
    let mut config = quinn::rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS 版本")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("自签证书");
    config.alpn_protocols = vec![b"lengsuo-cc".to_vec()];
    config
}
