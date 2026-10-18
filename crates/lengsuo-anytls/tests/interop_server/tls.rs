//! TLS 承载层：本端服务端用 tokio-rustls 的 TlsAcceptor 包住 TcpStream。
//! 证书链由测试临时用 openssl 生成：自建测试 CA → CA 签发 end-entity 服务端证书
//! （CA:FALSE、SAN=localhost/127.0.0.1、serverAuth）。rustls/webpki 拒绝把 CA 证书
//! 当作服务端叶子证书（CaUsedAsEndEntity），因此必须走两级链。
//! 全部为一次性测试凭据：回环、1 天有效、放在 0700 临时目录，用后即删，不提交仓库。
//!
//! 官方 anytls-client v0.0.13 出站固定 TLS 且**不校验**服务端证书
//! （示例客户端 InsecureSkipVerify=true），故官方客户端那一路只证明握手与协议互通；
//! 证书校验与名称匹配由本文件的 verifying_connector 走 Rust↔Rust 一路覆盖。
use crate::report::{transport, Failure};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

/// 证书有效期（天）：只够本轮测试使用。
const VALID_DAYS: &str = "1";
/// 服务端证书的 CN/SAN，与客户端 -sni 及校验名称一致。
const COMMON_NAME: &str = "localhost";
/// 本测试使用的 SNI/校验名称。
pub const TEST_SERVER_NAME: &str = COMMON_NAME;

/// 生成的测试证书链（DER）：服务端出示叶子+CA，客户端只信任 CA。
pub struct TestPki {
    /// 服务端证书链：[叶子, 测试 CA]。
    pub chain: Vec<CertificateDer<'static>>,
    /// 服务端私钥（PKCS#8 DER）。
    pub key: Vec<u8>,
    /// 测试 CA 证书，作为客户端唯一信任锚。
    pub ca: Vec<u8>,
}

/// 只保留 stderr 末尾若干字符，避免把整段 openssl 输出灌进日志。
fn tail(text: &str) -> String {
    let trimmed = text.trim();
    let chars: Vec<char> = trimmed.chars().collect();
    let start = chars.len().saturating_sub(160);
    chars[start..].iter().collect()
}

/// 运行 openssl 并检查退出码；stderr 只回显尾部。
fn run_openssl(args: &[&str]) -> Result<(), Failure> {
    let output = Command::new("openssl")
        .args(args)
        .output()
        .map_err(|err| transport(format!("openssl 不可用：{err}")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(transport(format!(
            "openssl {:?} 失败：{}",
            args.first().unwrap_or(&""),
            tail(String::from_utf8_lossy(&output.stderr).as_ref())
        )))
    }
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, Failure> {
    std::fs::read(path).map_err(|err| transport(format!("读取测试证书失败：{err}")))
}

/// 在临时目录生成两级测试 PKI（CA + 服务端叶子）。
pub fn generate_test_pki(dir: &Path) -> Result<TestPki, Failure> {
    let ca_key = dir.join("ca-key.pem");
    let ca_pem = dir.join("ca.pem");
    let ca_der = dir.join("ca.der");
    let leaf_csr = dir.join("leaf.csr");
    let leaf_key_pem = dir.join("leaf-key.pem");
    let leaf_key_der = dir.join("leaf-key.der");
    let leaf_der = dir.join("leaf.der");
    let ext = dir.join("leaf.ext");

    // 1) 测试 CA（CA:TRUE + keyCertSign）。
    run_openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        ca_key.to_str().unwrap_or_default(),
        "-out",
        ca_pem.to_str().unwrap_or_default(),
        "-days",
        VALID_DAYS,
        "-subj",
        "/CN=lengsuo-interop-test-ca",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    ])?;
    run_openssl(&[
        "x509",
        "-in",
        ca_pem.to_str().unwrap_or_default(),
        "-outform",
        "DER",
        "-out",
        ca_der.to_str().unwrap_or_default(),
    ])?;

    // 2) 叶子证书 CSR（CN=localhost）。
    run_openssl(&[
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        leaf_key_pem.to_str().unwrap_or_default(),
        "-out",
        leaf_csr.to_str().unwrap_or_default(),
        "-subj",
        &format!("/CN={COMMON_NAME}"),
    ])?;
    std::fs::write(
        &ext,
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n\
         basicConstraints=critical,CA:FALSE\n\
         keyUsage=critical,digitalSignature,keyEncipherment\n\
         extendedKeyUsage=serverAuth\n",
    )
    .map_err(|err| transport(format!("写叶子扩展失败：{err}")))?;

    // 3) CA 签发叶子（DER）。
    run_openssl(&[
        "x509",
        "-req",
        "-in",
        leaf_csr.to_str().unwrap_or_default(),
        "-CA",
        ca_pem.to_str().unwrap_or_default(),
        "-CAkey",
        ca_key.to_str().unwrap_or_default(),
        "-set_serial",
        "01",
        "-days",
        VALID_DAYS,
        "-extfile",
        ext.to_str().unwrap_or_default(),
        "-outform",
        "DER",
        "-out",
        leaf_der.to_str().unwrap_or_default(),
    ])?;

    // 4) 叶子私钥转未加密 PKCS#8 DER（`pkey -outform DER` 给的是 PKCS#1，rustls 不收）。
    run_openssl(&[
        "pkcs8",
        "-topk8",
        "-nocrypt",
        "-in",
        leaf_key_pem.to_str().unwrap_or_default(),
        "-outform",
        "DER",
        "-out",
        leaf_key_der.to_str().unwrap_or_default(),
    ])?;

    let leaf = read_bytes(&leaf_der)?;
    let ca = read_bytes(&ca_der)?;
    let key = read_bytes(&leaf_key_der)?;
    println!(
        "tls fixture: leaf {} B, ca {} B, key {} B（临时自签链，用后即删）",
        leaf.len(),
        ca.len(),
        key.len()
    );
    Ok(TestPki {
        chain: vec![CertificateDer::from(leaf), CertificateDer::from(ca.clone())],
        key,
        ca,
    })
}

/// 由测试 PKI 构造 TLS 服务端接受器（TLS1.2/1.3，ring 提供者，无客户端证书）。
pub fn acceptor(pki: &TestPki) -> Result<TlsAcceptor, Failure> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.key.clone()));
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .and_then(|builder| {
        builder
            .with_no_client_auth()
            .with_single_cert(pki.chain.clone(), key)
    })
    .map_err(|err| transport(format!("TLS 服务端配置失败：{err}")))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// 由测试 CA 构造**会校验**服务端的 TLS 客户端（唯一信任锚就是该 CA）。
/// 官方参考示例客户端固定跳过校验，本端不接受该做法；Rust↔Rust 这一路才覆盖
/// 证书链校验与名称匹配。
pub fn verifying_connector(ca_der: &[u8]) -> Result<tokio_rustls::TlsConnector, Failure> {
    let mut store = rustls::RootCertStore::empty();
    store
        .add(CertificateDer::from(ca_der.to_vec()))
        .map_err(|err| transport(format!("信任锚加载失败：{err}")))?;
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map(|builder| builder.with_root_certificates(store).with_no_client_auth())
    .map_err(|err| transport(format!("TLS 客户端配置失败：{err}")))?;
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

/// 完成的 TLS 服务端流：读半与写半由 session::serve 内部再拆分。
pub type TlsStream = tokio_rustls::server::TlsStream<TcpStream>;

/// 用给定的校验名称完成 TLS 客户端握手。
pub async fn client_handshake(
    connector: &tokio_rustls::TlsConnector,
    name: &str,
    socket: TcpStream,
    wait: Duration,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Failure> {
    let name = ServerName::try_from(name.to_owned())
        .map_err(|_| transport("TLS 服务名非法".to_owned()))?;
    timeout(wait, connector.connect(name, socket))
        .await
        .map_err(|_| transport("客户端 TLS 握手超时".to_owned()))?
        .map_err(|err| transport(format!("客户端 TLS 握手失败：{err}")))
}

/// 服务端握手；失败一律拒绝（无明文回退），统一归为 `Failure::Handshake`。
pub async fn handshake(
    acceptor: &TlsAcceptor,
    socket: TcpStream,
    wait: Duration,
) -> Result<TlsStream, Failure> {
    timeout(wait, acceptor.accept(socket))
        .await
        .map_err(|_| Failure::Handshake("TLS 握手超时".to_owned()))?
        .map_err(|err| Failure::Handshake(format!("TLS 握手失败：{err}")))
}
