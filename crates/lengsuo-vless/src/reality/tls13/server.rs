//! REALITY 服务端：TLS 1.3 服务端飞行 + 证书伪造 + 认证标签。
//!
//! 参考实现：`github.com/xtls/reality` 的 `handshake_server_tls13.go`
//! （服务端飞行）与 `tls.go:207-288`（REALITY 认证块）。
//!
//! # 与参考的对应关系
//!
//! | 参考 | 本模块 |
//! |---|---|
//! | `curve25519.X25519(config.PrivateKey, peerPub)` + `hkdf(... "REALITY")` | [`crate::reality::server::accept_hello`] |
//! | `aead.Open(plainText[:0], random[20:], ciphertext, clientHello.original)` | 同上（[`crate::reality::auth::open_auth_payload`]） |
//! | `hs.cert = &Certificate{Certificate: [][]byte{cert}, PrivateKey: ed25519Priv}` | [`ServerHandshake::new`] |
//! | `h.Sum(cert[:len(cert)-64])`（把 HMAC-SHA512 写进证书末尾） | [`ServerHandshake::certificate_der`] |
//! | `hs.sigAlg = Ed25519` | 同 |
//! | `sendServerParameters` / `sendServerCertificate` / `sendServerFinished` | [`ServerHandshake`] 的 `server_hello` / `encrypted_extensions` / `certificate` / `certificate_verify` / `finished` |
//!
//! # 与参考的差异（协议等价，非偏离）
//!
//! * 参考在服务端握手完成前会**同时**向 `dest` 拨一条连接并镜像数据
//!   （`MirrorConn`）；本模块**不做回落**，认证失败直接返回错误——回落是
//!   「服务端策略」，见报告「偏离清单」。
//! * 参考的 ALPN 协商用 `Config.NextProtos`（REALITY 配置里为 `nil`），
//!   故服务端**不选**任何 ALPN。本模块对齐：即使客户端宣告了 ALPN，
//!   `EncryptedExtensions` 也不回 ALPN 扩展（参考 `negotiateALPN` 在
//!   `NextProtos` 为空时返回 `""`）。
//! * 参考会发一条 `change_cipher_spec` 兼容记录（`sendDummyChangeCipherSpec`），
//!   本模块同样发（中间盒兼容性）。

use aes_gcm::aead::rand_core::{CryptoRng, RngCore};
use thiserror::Error;
use zeroize::Zeroize;

use super::certificate::SelfSignedCertificate;
use super::handshake::{
    build_certificate, build_certificate_verify, build_encrypted_extensions, build_finished,
    build_server_hello, HandshakeError, Transcript,
};
use super::messages::SIG_ED25519;
use super::record::RecordLayer;
use super::schedule::{finished_verify_data, traffic_key, KeySchedule};
use util::{client_session_id, ConstantTimeSliceEq};

mod util;

pub use util::{
    server_signed_message, sign, ServerSessionKeys, ED25519_SIGNATURE_ALGORITHM, FINISHED_TYPE,
};

/// 服务端握手错误。全部 fail-closed。
#[derive(Debug, Error)]
pub enum ServerHandshakeError {
    /// 握手消息相关错误。
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
    /// 记录层错误。
    #[error(transparent)]
    Record(#[from] super::record::RecordError),
    /// 客户端没有提供可用的 X25519 key_share。
    #[error("REALITY server: client did not offer an x25519 key share")]
    NoKeyShare,
    /// 客户端的 `Finished` 校验失败。
    #[error("REALITY server: client finished verify data mismatch")]
    FinishedMismatch,
    /// 客户端宣告了不支持的 TLS 版本/套件。
    #[error("REALITY server: unsupported client negotiation")]
    UnsupportedNegotiation,
}

/// REALITY 服务端握手状态。
///
/// 生命周期（对齐参考 `handshake_server_tls13.go` 的 `handshake()`）：
///
/// 1. `new` —— 生成 Ed25519 证书与 X25519 临时密钥对。
/// 2. `process_client_hello` —— 校验 REALITY 认证、派生 ECDHE、算 ServerHello。
/// 3. `server_hello` / `encrypted_extensions` / `certificate` /
///    `certificate_verify` / `finished` —— 逐条产出服务端飞行消息。
/// 4. `read_client_finished` —— 校验客户端 Finished，导出应用数据密钥。
pub struct ServerHandshake {
    /// 自签 Ed25519 证书（供 `Certificate` 消息与 `CertificateVerify` 签名用）。
    certificate: SelfSignedCertificate,
    /// REALITY 认证密钥（用于把 HMAC-SHA512 写进证书末尾）。
    auth_key: [u8; 32],
    /// 服务端 X25519 临时私钥种子。
    seed: [u8; 32],
    /// 服务端 X25519 临时公钥。
    public: [u8; 32],
    /// ECDHE 共享密钥。
    shared: [u8; 32],
    /// 转录哈希。
    transcript: Transcript,
    /// 握手阶段读记录层。
    handshake_reader: Option<RecordLayer>,
    /// 握手阶段写记录层。
    handshake_writer: Option<RecordLayer>,
    /// 服务端握手流量密钥（写方向）。
    server_handshake_secret: Option<[u8; 32]>,
    /// 客户端握手流量密钥（读方向）。
    client_handshake_secret: Option<[u8; 32]>,
    /// `Hash(ClientHello..ServerHello)` —— 握手流量密钥与（间接）应用流量
    /// 密钥的推导上下文，必须在 `after_server_hello` 时**快照**下来。
    ch_sh: Option<[u8; 32]>,
    /// 服务端随机数（`ServerHello.random`）。
    ///
    /// 参考 `handshake_server_tls13.go:243-244`：
    /// `hs.hello.random = make([]byte, 32)` + `io.ReadFull(c.config.rand(), …)`。
    /// **必须**与服务端私钥无关地独立生成（不得复用客户端随机数）。
    server_random: [u8; 32],
    /// 客户端的 `legacy_session_id`（原样回显）。
    ///
    /// 参考 `handshake_server_tls13.go:270`：
    /// `hs.hello.sessionId = hs.clientHello.sessionId`。
    client_session_id: Vec<u8>,
    /// 是否已经算过 ECDHE。
    key_agreement_done: bool,
}

impl Drop for ServerHandshake {
    fn drop(&mut self) {
        self.auth_key.zeroize();
        self.seed.zeroize();
        self.shared.zeroize();
    }
}

impl core::fmt::Debug for ServerHandshake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerHandshake")
            .field("certificate_len", &self.certificate.der.len())
            .field("auth_key", &"<redacted>")
            .field("seed", &"<redacted>")
            .finish()
    }
}

impl ServerHandshake {
    /// 建立服务端握手状态。
    ///
    /// * `auth_key`：REALITY 认证密钥（32 字节）——必须与服务端从 ClientHello
    ///   派生出的一致。
    /// * `seed`：Ed25519 种子（用于自签证书）与 X25519 临时私钥的来源。
    ///   参考用 `ed25519.GenerateKey` 与 `generateECDHEKey` 各生成一次；
    ///   本仓用两个独立种子，语义相同。
    pub fn new<R: RngCore + CryptoRng>(
        auth_key: [u8; 32],
        cert_seed: [u8; 32],
        key_seed: [u8; 32],
        rng: &mut R,
    ) -> Result<Self, ServerHandshakeError> {
        let certificate = SelfSignedCertificate::generate(cert_seed);
        let seed = key_seed;
        // 参考 `generateECDHEKey(c.config.rand(), X25519)`：随机私钥。
        // 参考 `handshake_server_tls13.go:243-244`：`hs.hello.random` 也是
        // 现场随机的 32 字节（与客户端随机数无关）。
        let mut server_random = [0u8; 32];
        rng.fill_bytes(&mut server_random);
        let public = super::super::x25519::x25519_base(&seed);
        Ok(Self {
            certificate,
            auth_key,
            seed,
            public,
            shared: [0u8; 32],
            transcript: Transcript::new(),
            handshake_reader: None,
            handshake_writer: None,
            server_handshake_secret: None,
            client_handshake_secret: None,
            ch_sh: None,
            server_random,
            client_session_id: Vec::new(),
            key_agreement_done: false,
        })
    }

    /// 自签证书（尚未写入 REALITY 认证标签）。
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate.der
    }

    /// 服务端随机数（`ServerHello.random`）。
    pub fn server_random(&self) -> [u8; 32] {
        self.server_random
    }

    /// 处理 ClientHello：记录转录、派生 ECDHE、记录要回显的 session_id。
    ///
    /// `client_hello_raw` 是**完整**的 ClientHello 握手消息（含 4 字节头），
    /// `peer_public` 是客户端的 X25519 临时公钥。
    ///
    /// 参考 `handshake_server_tls13.go:270`：
    /// `hs.hello.sessionId = hs.clientHello.sessionId`（原样回显）。
    pub fn process_client_hello(
        &mut self,
        client_hello_raw: &[u8],
        peer_public: &[u8; 32],
    ) -> Result<(), ServerHandshakeError> {
        let shared = super::super::x25519::x25519(&self.seed, peer_public)
            .map_err(|_| ServerHandshakeError::NoKeyShare)?;
        self.shared = shared;
        self.key_agreement_done = true;
        // 记录客户端的 `legacy_session_id` 以便回显（参考 `hs.hello.sessionId`）。
        self.client_session_id = client_session_id(client_hello_raw);
        self.transcript.write(client_hello_raw);
        Ok(())
    }

    /// 服务端 `ServerHello` 消息（含 4 字节头）。
    ///
    /// `session_id` 是回显客户端的 `legacy_session_id`。
    /// `random` 是服务端随机数。
    pub fn server_hello(&self, random: [u8; 32], session_id: &[u8]) -> Vec<u8> {
        build_server_hello(random, session_id, &self.public)
    }

    /// 按参考语义生成 `ServerHello`：
    /// `random` 用服务端自己的随机数，`session_id` 回显客户端的
    /// `legacy_session_id`。
    ///
    /// 参考 `handshake_server_tls13.go:243`（`hs.hello.random`）与
    /// `:270`（`hs.hello.sessionId = hs.clientHello.sessionId`）。
    pub fn server_hello_default(&self) -> Vec<u8> {
        build_server_hello(self.server_random, &self.client_session_id, &self.public)
    }

    /// 把 ServerHello 记入转录并派生握手流量密钥。
    pub fn after_server_hello(
        &mut self,
        server_hello_raw: &[u8],
    ) -> Result<(), ServerHandshakeError> {
        if !self.key_agreement_done {
            return Err(ServerHandshakeError::NoKeyShare);
        }
        self.transcript.write(server_hello_raw);
        let ch_sh = self.transcript.hash();
        // 快照 `Hash(ClientHello..ServerHello)`：应用流量密钥的
        // `c ap traffic` 依赖它（参考 `sendServerParameters` 之后
        // `sendServerFinished` 里的 `ClientApplicationTrafficSecret`）。
        self.ch_sh = Some(ch_sh);
        let schedule = KeySchedule::new(&self.shared, &ch_sh, &ch_sh);
        self.client_handshake_secret = Some(schedule.client_handshake_traffic);
        self.server_handshake_secret = Some(schedule.server_handshake_traffic);
        self.handshake_reader = Some(RecordLayer::new(&traffic_key(
            &schedule.client_handshake_traffic,
        )));
        self.handshake_writer = Some(RecordLayer::new(&traffic_key(
            &schedule.server_handshake_traffic,
        )));
        Ok(())
    }

    /// 握手阶段的读记录层。
    pub fn handshake_reader(&mut self) -> Result<&mut RecordLayer, ServerHandshakeError> {
        self.handshake_reader
            .as_mut()
            .ok_or(ServerHandshakeError::UnsupportedNegotiation)
    }

    /// 握手阶段的写记录层。
    pub fn handshake_writer(&mut self) -> Result<&mut RecordLayer, ServerHandshakeError> {
        self.handshake_writer
            .as_mut()
            .ok_or(ServerHandshakeError::UnsupportedNegotiation)
    }

    /// 握手阶段的读/写记录层**副本**（一次性取出，避免两次可变借用）。
    ///
    /// 返回的两个副本序号与原实例一致，但**各自独立推进**。调用方必须
    /// 只把副本交给真正收发的驱动；原实例留在状态机里不再使用。
    pub fn handshake_layers(&mut self) -> Result<(RecordLayer, RecordLayer), ServerHandshakeError> {
        let reader = self
            .handshake_reader
            .as_ref()
            .ok_or(ServerHandshakeError::UnsupportedNegotiation)?
            .clone_layer();
        let writer = self
            .handshake_writer
            .as_ref()
            .ok_or(ServerHandshakeError::UnsupportedNegotiation)?
            .clone_layer();
        Ok((reader, writer))
    }

    /// `EncryptedExtensions` 消息。
    ///
    /// 参考的 REALITY 服务端 `NextProtos` 为 `nil`，`negotiateALPN` 返回空串，
    /// 故 `encryptedExtensionsMsg.alpnProtocol` 为空 → **不带** ALPN 扩展。
    pub fn encrypted_extensions(&self) -> Vec<u8> {
        build_encrypted_extensions()
    }

    /// `Certificate` 消息（含 4 字节头）。
    ///
    /// 证书末尾 64 字节被改写成 `HMAC-SHA512(auth_key, ed25519_pub)`
    /// （参考 `handshake_server_tls13.go:149-151`）。
    pub fn certificate(&self) -> Vec<u8> {
        let mut der = self.certificate.der.clone();
        let tag =
            crate::reality::auth::cert_auth_tag(&self.auth_key, &self.certificate.public_key());
        let end = der.len();
        der[end - 64..end].copy_from_slice(&tag);
        build_certificate(&der)
    }

    /// `CertificateVerify` 消息（含 4 字节头）。
    ///
    /// 被签消息 = `64 × 0x20` + `"TLS 1.3, server CertificateVerify\0"` +
    /// 转录哈希（参考 `auth.go:82` 的 `signedMessage`）。
    pub fn certificate_verify(&self) -> Vec<u8> {
        let signed = server_signed_message(&self.transcript.hash());
        let signature = self.certificate.signing_key.sign(&signed);
        build_certificate_verify(SIG_ED25519, &signature)
    }

    /// 把 `Certificate` 与 `CertificateVerify` 记入转录。
    ///
    /// 参考 `writeHandshakeRecord` 在写每条消息时把**原始字节**喂进转录
    /// （`conn.go:1100`）。
    pub fn transcript_handshake(&mut self, raw: &[u8]) {
        self.transcript.write(raw);
    }

    /// 服务端 `Finished` 消息（含 4 字节头）。
    ///
    /// `verify_data` = `HMAC(finished_key, transcript)`，其中 `finished_key` 由
    /// **服务端握手流量密钥**派生（参考 `sendServerFinished` 用
    /// `hs.c.out.trafficSecret`）。
    pub fn finished(&self) -> Result<Vec<u8>, ServerHandshakeError> {
        let secret = self
            .server_handshake_secret
            .ok_or(ServerHandshakeError::UnsupportedNegotiation)?;
        let verify_data = finished_verify_data(&secret, &self.transcript.hash());
        Ok(build_finished(&verify_data))
    }

    /// 把服务端 `Finished` 记入转录。
    ///
    /// 参考 `writeHandshakeRecord(finished, hs.transcript)`（`conn.go:1099`）
    /// 会把写出的每条握手消息喂进转录，因此服务端 `Finished` **在**服务端
    /// 这一侧**是**计入转录的。它决定了两件事：
    ///
    /// * 应用流量密钥（`c ap traffic` / `s ap traffic`）的上下文是
    ///   「含服务端 Finished」的转录；
    /// * 期望的**客户端** `Finished` 也用这个转录计算
    ///   （参考 `sendSessionTickets`：`hs.clientFinished =
    ///   finishedHash(c.in.trafficSecret, hs.transcript)`）。
    ///
    /// 客户端的 `Finished` **不**计入服务端转录（参考 `readClientFinished`
    /// 的注释「finishedMsg is not included in the transcript」）。
    pub fn transcript_finished(&mut self, raw: &[u8]) {
        self.transcript.write(raw);
    }

    /// 校验客户端 `Finished` 并导出应用数据密钥。
    ///
    /// `client_finished_verify_data` 是客户端 Finished 消息里的 `verify_data`。
    /// 参考 `readClientFinished`（`handshake_server_tls13.go:1250`）用
    /// `hs.clientFinished` 比对；后者由
    /// `hs.suite.finishedHash(c.in.trafficSecret, hs.transcript)` 算出，
    /// 即**客户端**握手流量密钥 + 「转录到服务端 Finished 为止」的哈希。
    ///
    /// 调用前必须已经调用过 [`Self::transcript_finished`]（把服务端 Finished
    /// 计入转录），否则期望值与参考对不上。
    pub fn read_client_finished(
        &mut self,
        client_finished_verify_data: &[u8],
    ) -> Result<ServerSessionKeys, ServerHandshakeError> {
        let client_secret = self
            .client_handshake_secret
            .ok_or(ServerHandshakeError::UnsupportedNegotiation)?;
        let expected = finished_verify_data(&client_secret, &self.transcript.hash());
        if expected.ct_eq_slice(client_finished_verify_data) != 1 {
            return Err(ServerHandshakeError::FinishedMismatch);
        }
        // `c ap traffic` 的上下文是 `Hash(ClientHello..ServerHello)`，
        // 必须用 `after_server_hello` 时的快照（转录此后已增长）。
        let ch_sh = self
            .ch_sh
            .ok_or(ServerHandshakeError::UnsupportedNegotiation)?;
        // `c ap traffic` 的上下文是「含服务端 Finished」的转录。
        let ch_sfin = self.transcript.hash();
        let schedule = KeySchedule::new(&self.shared, &ch_sh, &ch_sfin);
        Ok(ServerSessionKeys {
            client: traffic_key(&schedule.client_application_traffic),
            server: traffic_key(&schedule.server_application_traffic),
        })
    }
}
