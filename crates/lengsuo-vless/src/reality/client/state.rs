//! REALITY 客户端握手状态机（TLS 1.3 客户端飞行）。
//!
//! 从 [`super`] 拆出以符合 400 行软目标；公开 API 不变。
//!
//! 参考实现：`github.com/xtls/reality` 的 `handshake_client_tls13.go`
//! （客户端的 ServerHello 处理、Certificate/CertificateVerify 校验、
//! Finished 校验与流量密钥导出）。

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::super::auth::cert_auth_tag;
use super::super::tls13::ed25519;
use super::super::tls13::handshake::{parse_certificate_verify, HandshakeError, Transcript};
use super::super::tls13::messages::{
    parse_server_hello, ServerHelloInfo, CIPHER_SUITE_AES_128_GCM_SHA256, SIG_ED25519,
    VERSION_TLS13,
};
use super::super::tls13::schedule::{finished_verify_data, traffic_key, KeySchedule, TrafficKey};
use super::super::x25519::x25519;
use super::{BuiltClientHello, ClientError};

/// REALITY 客户端握手状态机。
///
/// 典型用法：
///
/// ```text
/// let hello = build_reality_client_hello(...)?;
/// conn.write_all(&hello.raw).await?;
/// let mut client = RealityClient::new(hello.auth_key, hello.random);
/// client.transcript_client_hello(&hello.raw);
/// // 收到 ServerHello（明文记录）后：
/// client.process_server_hello(&server_hello_raw)?;
/// // 收 EncryptedExtensions / Certificate / CertificateVerify / Finished（加密记录）
/// ...
/// ```
pub struct RealityClient {
    /// 认证密钥（用于校验服务端证书的 REALITY 标签）。
    auth_key: [u8; 32],
    /// 客户端随机数。
    random: [u8; 32],
    /// X25519 临时私钥种子。
    seed: [u8; 32],
    /// 转录哈希。
    transcript: Transcript,
    /// 握手阶段读记录层（服务端→客户端方向）。
    handshake_reader: Option<super::super::tls13::record::RecordLayer>,
    /// 握手阶段写记录层（客户端→服务端方向）。
    handshake_writer: Option<super::super::tls13::record::RecordLayer>,
    /// 握手流量密钥（客户端方向）。
    client_handshake_secret: Option<[u8; 32]>,
    /// 握手流量密钥（服务端方向）。
    server_handshake_secret: Option<[u8; 32]>,
    /// ECDHE 共享密钥（应用数据阶段仍需要）。
    shared_secret: Option<[u8; 32]>,
    /// `Hash(ClientHello..ServerHello)` —— 握手流量密钥与（间接）应用流量
    /// 密钥的推导上下文，必须在 `process_server_hello` 时**快照**下来
    /// （之后转录会继续增长）。
    ch_sh: Option<[u8; 32]>,
}

impl From<super::super::tls13::messages::MessageError> for ClientError {
    fn from(e: super::super::tls13::messages::MessageError) -> Self {
        Self::Handshake(e.into())
    }
}

impl Drop for RealityClient {
    fn drop(&mut self) {
        self.auth_key.zeroize();
        self.seed.zeroize();
        if let Some(shared) = self.shared_secret.as_mut() {
            shared.zeroize();
        }
    }
}

impl core::fmt::Debug for RealityClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RealityClient")
            .field("auth_key", &"<redacted>")
            .field("seed", &"<redacted>")
            .finish()
    }
}

impl RealityClient {
    /// 建立客户端状态。
    ///
    /// `seed` 是本次握手的 X25519 临时私钥种子（必须与构造 ClientHello 时
    /// 用的是同一个，否则 ECDHE 算不出正确共享密钥）。
    pub fn new(auth_key: [u8; 32], random: [u8; 32], seed: [u8; 32]) -> Self {
        Self {
            auth_key,
            random,
            seed,
            transcript: Transcript::new(),
            handshake_reader: None,
            handshake_writer: None,
            client_handshake_secret: None,
            server_handshake_secret: None,
            shared_secret: None,
            ch_sh: None,
        }
    }

    /// 从一次 [`build_reality_client_hello`] 的产物建立客户端状态。
    ///
    /// 这是**推荐**的入口：它保证 `auth_key` / `random` / `seed` 三者同源，
    /// 并把 ClientHello 原始字节喂进转录（参考 `handshake_client_tls13.go`
    /// 的 `hs.transcript.Write(c.hs.clientHello.original)`）。
    pub fn from_built(built: &mut BuiltClientHello) -> Result<Self, ClientError> {
        let seed = built.take_seed().ok_or(ClientError::UnexpectedStep)?;
        let mut client = Self::new(built.auth_key, built.random, seed);
        client.transcript_client_hello(&built.raw);
        Ok(client)
    }

    /// 客户端随机数。
    pub fn random(&self) -> [u8; 32] {
        self.random
    }

    /// 把 ClientHello 原始字节喂进转录哈希。
    pub fn transcript_client_hello(&mut self, raw: &[u8]) {
        self.transcript.write(raw);
    }

    /// 把一条已收到的握手消息喂进转录哈希。
    pub fn transcript_handshake(&mut self, raw: &[u8]) {
        self.transcript.write(raw);
    }

    /// 当前转录哈希。
    pub fn transcript_hash(&self) -> [u8; 32] {
        self.transcript.hash()
    }

    /// 处理 ServerHello 并派生握手流量密钥。
    ///
    /// `server_hello_raw` 是 ServerHello 握手消息的**完整**字节（含 4 字节头）。
    pub fn process_server_hello(
        &mut self,
        server_hello_raw: &[u8],
    ) -> Result<ServerHelloInfo, ClientError> {
        if server_hello_raw.len() < 4 {
            return Err(HandshakeError::MalformedMessage.into());
        }
        let body = &server_hello_raw[4..];
        let info: ServerHelloInfo = parse_server_hello(body)?;
        if info.cipher_suite != CIPHER_SUITE_AES_128_GCM_SHA256 {
            return Err(ClientError::UnsupportedNegotiation);
        }
        if info.supported_version != Some(VERSION_TLS13) {
            return Err(ClientError::UnsupportedNegotiation);
        }
        let server_share = info
            .x25519_key_share
            .ok_or(HandshakeError::KeyAgreementFailed)?;
        let shared = x25519(&self.seed, &server_share)
            .map_err(|_| super::super::auth::AuthError::InvalidPublicKey)?;
        // 转录：ClientHello + ServerHello（参考 `conn.go:1253` 写原始字节）。
        self.transcript.write(server_hello_raw);
        let ch_sh = self.transcript.hash();
        // 快照 `Hash(ClientHello..ServerHello)`：应用流量密钥的
        // `c ap traffic` 依赖它（参考 `handshake_client_tls13.go` 的
        // `establishHandshakeKeys` 用的是这个哈希）。
        self.ch_sh = Some(ch_sh);
        let schedule = KeySchedule::new(&shared, &ch_sh, &ch_sh);
        self.client_handshake_secret = Some(schedule.client_handshake_traffic);
        self.server_handshake_secret = Some(schedule.server_handshake_traffic);
        self.handshake_reader = Some(super::super::tls13::record::RecordLayer::new(&traffic_key(
            &schedule.server_handshake_traffic,
        )));
        self.handshake_writer = Some(super::super::tls13::record::RecordLayer::new(&traffic_key(
            &schedule.client_handshake_traffic,
        )));
        self.shared_secret = Some(shared);
        Ok(info)
    }

    /// 握手阶段的读记录层（服务端→客户端方向）。
    pub fn handshake_reader(
        &mut self,
    ) -> Result<&mut super::super::tls13::record::RecordLayer, ClientError> {
        self.handshake_reader
            .as_mut()
            .ok_or(ClientError::UnexpectedStep)
    }

    /// 握手阶段的写记录层（客户端→服务端方向）。
    pub fn handshake_writer(
        &mut self,
    ) -> Result<&mut super::super::tls13::record::RecordLayer, ClientError> {
        self.handshake_writer
            .as_mut()
            .ok_or(ClientError::UnexpectedStep)
    }

    /// 握手阶段的读/写记录层**副本**（一次性取出，避免两次可变借用）。
    ///
    /// 返回的两个副本序号与原实例一致，但**各自独立推进**。调用方必须
    /// 只把副本交给真正收发的驱动；原实例留在状态机里不再使用。
    pub fn handshake_layers(
        &mut self,
    ) -> Result<
        (
            super::super::tls13::record::RecordLayer,
            super::super::tls13::record::RecordLayer,
        ),
        ClientError,
    > {
        let reader = self
            .handshake_reader
            .as_ref()
            .ok_or(ClientError::UnexpectedStep)?
            .clone_layer();
        let writer = self
            .handshake_writer
            .as_ref()
            .ok_or(ClientError::UnexpectedStep)?
            .clone_layer();
        Ok((reader, writer))
    }

    /// 校验服务端证书的 REALITY 认证标签。
    ///
    /// 对齐参考 `UConn.VerifyPeerCertificate`（`reality.go:76-114`）：
    /// 证书公钥必须是 32 字节 Ed25519，且
    /// `cert.Signature == HMAC-SHA512(auth_key, ed25519_pub)`。
    ///
    /// `certificate_der` 是叶子证书的 DER。
    pub fn verify_certificate(&mut self, certificate_der: &[u8]) -> Result<(), ClientError> {
        let (public, signature) = super::cert::parse_reality_certificate(certificate_der)?;
        let expected = cert_auth_tag(&self.auth_key, &public);
        if expected.ct_eq(&signature).unwrap_u8() != 1 {
            return Err(ClientError::CertificateTagMismatch);
        }
        Ok(())
    }

    /// 校验 `CertificateVerify` 的 Ed25519 签名。
    ///
    /// `cert_verify_raw` 是 `CertificateVerify` 消息的完整字节（含 4 字节头）。
    /// 被签消息按 RFC 8446 §4.4.3 构造（参考 `auth.go:82` 的 `signedMessage`）。
    pub fn verify_certificate_verify(
        &mut self,
        certificate_der: &[u8],
        cert_verify_raw: &[u8],
    ) -> Result<(), ClientError> {
        if cert_verify_raw.len() < 4 {
            return Err(HandshakeError::MalformedMessage.into());
        }
        let (public, _) = super::cert::parse_reality_certificate(certificate_der)?;
        let (algorithm, signature) = parse_certificate_verify(&cert_verify_raw[4..])?;
        if algorithm != SIG_ED25519 {
            return Err(ClientError::UnsupportedNegotiation);
        }
        let signed = super::cert::server_signed_message(&self.transcript.hash());
        let signature: &[u8; 64] = signature
            .try_into()
            .map_err(|_| ClientError::UnsupportedNegotiation)?;
        ed25519::verify(&public, &signed, signature)
            .map_err(|_| ClientError::CertificateTagMismatch)?;
        Ok(())
    }

    /// 校验服务端 `Finished` 并导出应用数据密钥。
    ///
    /// `server_finished_verify_data` 是服务端 Finished 消息里的 `verify_data`。
    /// 参考 `handshake_client_tls13.go:722` 用 `c.in.trafficSecret`
    /// （服务端握手流量密钥）计算期望值。
    ///
    /// **转录时机**：参考 `readServerFinished` 是「先校验，再把 Finished
    /// 计入转录」，然后才用**含服务端 Finished** 的转录导出应用流量密钥
    /// （`ClientApplicationTrafficSecret(hs.transcript)`）。
    /// 因此本函数在校验通过后**自己**把服务端 Finished 计入转录，
    /// 调用方**不得**再重复计入。
    pub fn finish_handshake(
        &mut self,
        server_finished_verify_data: &[u8],
    ) -> Result<ClientSessionKeys, ClientError> {
        let server_secret = self
            .server_handshake_secret
            .ok_or(ClientError::UnexpectedStep)?;
        let ch_sh = self.ch_sh.ok_or(ClientError::UnexpectedStep)?;
        // 校验用的转录哈希是「服务端 Finished 之前」的（参考
        // `readServerFinished`：Finished 校验用的就是消息发出前的状态）。
        let expected = finished_verify_data(&server_secret, &self.transcript.hash());
        if expected.ct_eq(server_finished_verify_data).unwrap_u8() != 1 {
            return Err(HandshakeError::FinishedMismatch.into());
        }
        // 校验通过：服务端 Finished 计入转录（参考 `transcriptMsg(finished, …)`）。
        self.transcript
            .write(&super::super::tls13::handshake::build_finished(
                server_finished_verify_data,
            ));
        let ch_sfin = self.transcript.hash();
        let shared = self.shared_secret.ok_or(ClientError::UnexpectedStep)?;
        let schedule = KeySchedule::new(&shared, &ch_sh, &ch_sfin);
        Ok(ClientSessionKeys {
            client: traffic_key(&schedule.client_application_traffic),
            server: traffic_key(&schedule.server_application_traffic),
        })
    }

    /// 客户端 `Finished` 的 `verify_data`。
    ///
    /// 参考 `handshake_client_tls13.go:832` 用 `c.out.trafficSecret`
    /// （客户端握手流量密钥）计算，且转录**已含**服务端 Finished。
    pub fn client_finished_verify_data(&self) -> Result<[u8; 32], ClientError> {
        let client_secret = self
            .client_handshake_secret
            .ok_or(ClientError::UnexpectedStep)?;
        Ok(finished_verify_data(
            &client_secret,
            &self.transcript.hash(),
        ))
    }
}

/// 应用数据阶段的双向记录层密钥。
pub struct ClientSessionKeys {
    /// 客户端 → 服务端。
    pub client: TrafficKey,
    /// 服务端 → 客户端。
    pub server: TrafficKey,
}
