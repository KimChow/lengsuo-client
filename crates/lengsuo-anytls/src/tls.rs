//! 产品 TLS 信任链（策略层）：唯一信任锚 = 传入 CA + 显式名称校验。
//!
//! 参考事实（anytls-go fd6167a）：官方示例客户端 `cmd/client/main.go` 用
//! `InsecureSkipVerify: true` 并自认"不能用于生产代码"；官方 server
//! `cmd/server/main.go` 用启动时现生成的自签叶子。本模块是产品侧策略，
//! **不提供**任何跳过校验的开关：CA 不匹配、名称不匹配、空信任锚、
//! 空名称都在配置构造或 TLS 握手阶段 fail-closed，绝不回退明文。
//!
//! 错误统一为 [`Error::TlsConfig`]，原因文案为静态字符串，
//! 证书/私钥/CA 内容不进入 `Display`/`Debug`。
use crate::Error;
use std::sync::Arc;
use tokio_rustls::rustls::pki_types::{
    pem::PemObject, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};

/// 客户端信任策略：只用传入 CA 作为信任锚，`server_name` 显式校验。
///
/// 参考 `cmd/client/main.go` 的 TLS 客户端由 `ServerName` + 跳过校验组成；
/// 这里对齐其「显式服务名」一环并以真实链校验取代跳过校验。
pub struct ClientTrust;

// 策略层刻意直接返回 rustls 配置：调用方拿到的对象不存在「跳过校验」变体，
// 不包一层自有类型也就无从回退到不安全路径；故 `new` 不返回 `Self`。
#[allow(clippy::new_ret_no_self)]
impl ClientTrust {
    /// 由 PEM 编码的 CA（可含多张，逐张入信任锚）构造客户端配置。
    ///
    /// `server_name` 必须显式非空且能解析为 [`ServerName`]（连接时用
    /// [`ClientTrust::server_name`] 取同一解析结果）；空 CA、空名称、
    /// 解析失败一律 fail-closed，不存在关闭校验的配置路径。
    pub fn new(ca_pem: &[u8], server_name: &str) -> Result<ClientConfig, Error> {
        Self::server_name(server_name)?;
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(ca_pem) {
            let cert = cert.map_err(|_| Error::TlsConfig("CA 证书 PEM 解析失败"))?;
            roots
                .add(cert)
                .map_err(|_| Error::TlsConfig("CA 证书不被接受为信任锚"))?;
        }
        if roots.is_empty() {
            return Err(Error::TlsConfig("信任锚为空：PEM 中未找到任何 CA 证书"));
        }
        Ok(ClientConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::TlsConfig("TLS 协议版本配置失败"))?
        .with_root_certificates(roots)
        .with_no_client_auth())
    }

    /// 把服务名解析为 rustls 的 `ServerName`（连接 API 的入参）。
    ///
    /// 空名显式拒绝（参考实现回退 `127.0.0.1` 属于示例行为，产品侧不回退）。
    pub fn server_name(name: &str) -> Result<ServerName<'static>, Error> {
        if name.is_empty() {
            return Err(Error::TlsConfig("服务名为空：必须显式指定"));
        }
        ServerName::try_from(name.to_owned())
            .map_err(|_| Error::TlsConfig("服务名无法解析为合法 TLS 名称"))
    }
}

/// 服务端身份：PEM 证书链 + PKCS#8 私钥，构造即校验配对（fail-closed）。
///
/// 参考 `cmd/server/main.go` 在进程内自签证书；本类型对齐其「证书 + 私钥
/// 装入 tls.Config」一环，但要求调用方显式提供 PEM 并只接受 PKCS#8。
pub struct ServerIdentity;

impl ServerIdentity {
    /// 由 PEM 证书链（首张为叶子，其后为中间/根）与 PKCS#8 PEM 私钥构造
    /// 服务端配置；链解析失败、私钥格式不符、私钥与证书不配对都返回错误。
    ///
    /// 与 [`ClientTrust::new`] 同理：直接交出 rustls 配置，不引入可绕过校验的包装。
    #[allow(clippy::new_ret_no_self)]
    pub fn new(cert_pem: &[u8], key_pem: &[u8]) -> Result<ServerConfig, Error> {
        let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
            .collect::<Result<_, _>>()
            .map_err(|_| Error::TlsConfig("服务端证书链 PEM 解析失败"))?;
        if chain.is_empty() {
            return Err(Error::TlsConfig("服务端证书链为空"));
        }
        let key = PrivatePkcs8KeyDer::from_pem_slice(key_pem)
            .map_err(|_| Error::TlsConfig("私钥 PEM 解析失败（仅接受 PKCS#8）"))?;
        ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::TlsConfig("TLS 协议版本配置失败"))?
        .with_no_client_auth()
        .with_single_cert(chain, PrivateKeyDer::Pkcs8(key))
        .map_err(|_| Error::TlsConfig("私钥与证书链不配对或不可用"))
    }
}
