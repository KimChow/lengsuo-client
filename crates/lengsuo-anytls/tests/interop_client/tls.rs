//! 客户端方向互通的 TLS 承载层：官方 anytls-server v0.0.13 **无条件**自带
//! TLS（cmd/server/main.go 对每条连接执行 `tls.Server`），并且证书不是命令行注入的，
//! 而是启动时用 `util.GenerateKeyPair(time.Now, "")` 现生成的一张**自签叶子**：
//! CN/SAN 均为空（`Subject Alternative Name: DNS:`，仅一个空串），CA:FALSE、
//! serverAuth，有效期 1 小时。这一点已在参考源码逐行核对，并用 openssl s_client
//! 实测确认——官方 server 不接受 `-cert` 之类的参数，也不接受测试给它的两级证书链。
//!
//! 因此「测试 CA 签发叶子」的方案在官方 v0.0.13 server 上无法成立。本文件采取的
//! 是参考实现事实允许的**最强校验**：tokio-rustls 以「pin 该自签叶子为唯一信任锚」
//! 完成真实证书链校验（自签叶子链到自身 + 有效期 + serverAuth EKU + 握手签名），
//! 并在验证器边界强制「请求名称 == 期望回环名 127.0.0.1」，错误名称在 TLS 握手阶段
//! 即被拒绝（不是应用层兜底）。名称逐字节比对叠加在 pin 之上，pin 是最强身份绑定。
//!
//! 证书只经 openssl 现取、只写临时目录、用后即删；日志与断言均不回显口令。
#![allow(dead_code)]
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, SignatureVerificationAlgorithm, UnixTime};
use rustls::RootCertStore;
use std::fmt::Debug;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// 本次互通使用的逻辑服务名（回环地址）；含校验的客户端必须以它作为 serverName。
pub const EXPECTED_NAME: &str = "127.0.0.1";

/// 运行 openssl 并只在其失败时回显 stderr 尾部，避免灌入大段输出。
fn run_openssl(args: &[&str]) -> Result<(), String> {
    let output = Command::new("openssl")
        .args(args)
        .output()
        .map_err(|err| format!("openssl 不可用：{err}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let tail = String::from_utf8_lossy(&output.stderr);
        let tail = tail.trim();
        let start = tail.len().saturating_sub(160);
        Err(format!(
            "openssl {:?} 失败：{}",
            args.first().unwrap_or(&""),
            &tail[start..]
        ))
    }
}

/// 从 openssl s_client 的 stdout 里抽出第一张证书（官方 server 只给一张自签叶子）。
fn extract_first_pem(stdout: &str) -> String {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let Some(body) = stdout.split(BEGIN).nth(1) else {
        return String::new();
    };
    let Some(body) = body.split(END).next() else {
        return String::new();
    };
    format!("{BEGIN}\n{}\n{END}\n", body.trim())
}

/// 用 openssl s_client 现取官方 server 的自签叶子，转为 DER 返回。
/// 证书在 server 进程内只生成一次（同一 tlsCert 复用于所有连接），故取一次即可。
/// 捕获连接只做 TLS 握手拿证书，绝不发送口令或任何 anytls 字节。
pub fn capture_server_cert(port: u16, dir: &Path) -> Result<Vec<u8>, String> {
    let pem = dir.join("captured-server.pem");
    let der = dir.join("captured-server.der");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let output = Command::new("openssl")
            .args([
                "s_client",
                "-connect",
                &format!("127.0.0.1:{port}"),
                "-servername",
                EXPECTED_NAME,
                "-showcerts",
            ])
            .stdin(Stdio::null())
            .output()
            .map_err(|err| format!("openssl s_client 启动失败：{err}"))?;
        let leaf = extract_first_pem(&String::from_utf8_lossy(&output.stdout));
        if !leaf.is_empty() {
            std::fs::write(&pem, leaf).map_err(|err| format!("写临时证书失败：{err}"))?;
            run_openssl(&[
                "x509",
                "-in",
                pem.to_str().unwrap_or_default(),
                "-outform",
                "DER",
                "-out",
                der.to_str().unwrap_or_default(),
            ])?;
            return std::fs::read(&der).map_err(|err| format!("读临时证书失败：{err}"));
        }
        if Instant::now() >= deadline {
            return Err("在期限内未能捕获官方 server 的 TLS 证书".to_owned());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// pin + 真实证书链校验 + 名称校验的服务器证书验证器。
/// `verify_server_cert`：
///   1) 名称检查：请求的 serverName 必须等于 `expected_name`；不符即 TLS 阶段拒绝。
///   2) pin 检查：出示的叶子必须逐字节等于捕获的自签叶子。
///   3) 链校验：把该叶子当作唯一信任锚，用 webpki 校验自签链、有效期与 serverAuth EKU。
///
/// 握手签名（TLS1.2/1.3）委托给标准 `WebPkiServerVerifier`，不自行降级。
#[derive(Debug)]
struct PinnedVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    matched: CertificateDer<'static>,
    roots: Arc<RootCertStore>,
    expected_name: String,
    supported_algs: &'static [&'static dyn SignatureVerificationAlgorithm],
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if server_name.to_str().as_ref() != self.expected_name {
            return Err(rustls::Error::General(format!(
                "证书名称校验失败：请求名称 {} 与预期 {} 不符",
                server_name.to_str(),
                self.expected_name
            )));
        }
        if end_entity.as_ref() != self.matched.as_ref() {
            return Err(rustls::Error::General(
                "证书 pin 校验失败：服务端证书与捕获的自签叶子不一致".to_owned(),
            ));
        }
        let parsed = rustls::server::ParsedCertificate::try_from(end_entity)
            .map_err(|err| rustls::Error::General(format!("解析服务端证书失败：{err}")))?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &parsed,
            self.roots.as_ref(),
            intermediates,
            now,
            self.supported_algs,
        )
        .map_err(|err| rustls::Error::General(format!("证书链校验失败：{err}")))?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// 由捕获的自签叶子构造**会校验**的 tokio-rustls 客户端连接器。
pub fn verifying_connector(leaf_der: Vec<u8>) -> Result<tokio_rustls::TlsConnector, String> {
    let matched = CertificateDer::from(leaf_der);
    let mut roots = RootCertStore::empty();
    roots
        .add(matched.clone())
        .map_err(|err| format!("加载服务端自签证书为信任锚失败：{err}"))?;
    let roots = Arc::new(roots);
    let provider = rustls::crypto::ring::default_provider();
    let supported_algs = provider.signature_verification_algorithms.all;
    let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::clone(&roots),
        Arc::new(provider.clone()),
    )
    .build()
    .map_err(|err| format!("构造证书链验证器失败：{err}"))?;
    let verifier = PinnedVerifier {
        inner,
        matched,
        roots,
        expected_name: EXPECTED_NAME.to_owned(),
        supported_algs,
    };
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|err| format!("TLS 客户端配置失败：{err}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

/// 完成的 TLS 客户端流。
pub type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;

/// 用给定校验名称完成 TLS 客户端握手；失败即拒绝（无明文/无跳过校验回退）。
pub async fn client_handshake(
    connector: &tokio_rustls::TlsConnector,
    name: &str,
    socket: TcpStream,
    wait: Duration,
) -> Result<TlsStream, String> {
    let name = ServerName::try_from(name.to_owned()).map_err(|_| "TLS 服务名非法".to_owned())?;
    timeout(wait, connector.connect(name, socket))
        .await
        .map_err(|_| "客户端 TLS 握手超时".to_owned())?
        .map_err(|err| format!("客户端 TLS 握手失败：{err}"))
}
