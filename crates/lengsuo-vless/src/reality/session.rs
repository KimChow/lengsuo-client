//! REALITY 客户端 / 服务端的**端到端**握手驱动（`tokio` 异步）。
//!
//! 本模块把
//! [`crate::reality::client`]（客户端状态机）、
//! [`crate::reality::tls13::server`]（服务端状态机）与
//! [`crate::reality::tls13::io`]（记录层收发）串起来，形成一次完整的
//! TLS 1.3 握手。
//!
//! # 客户端流程（对齐参考 `handshake_client_tls13.go`）
//!
//! 1. 发 ClientHello（**明文**记录）。
//! 2. 收 ServerHello（**明文**记录）→ 派生握手流量密钥。
//! 3. 发 `change_cipher_spec` 兼容记录（参考 `sendDummyChangeCipherSpec`）。
//! 4. 切换到加密阶段：收 EncryptedExtensions / Certificate /
//!    CertificateVerify / Finished。
//! 5. 校验证书的 REALITY 标签与 `CertificateVerify` 签名、校验 `Finished`。
//! 6. 发客户端 `Finished`（加密）→ 切换到应用数据密钥。
//!
//! # 服务端流程（对齐参考 `handshake_server_tls13.go`）
//!
//! 1. 收 ClientHello（明文）→ REALITY 认证（由调用方完成）→ 派生 ECDHE。
//! 2. 发 ServerHello（明文）→ 派生握手流量密钥。
//! 3. 发 `change_cipher_spec` 兼容记录。
//! 4. 切换到加密阶段：发 EncryptedExtensions / Certificate /
//!    CertificateVerify / Finished。
//! 5. 收客户端 `Finished`（加密）→ 校验 → 应用数据密钥。
//!
//! # 转录顺序（RFC 8446 §4.4.1 / 参考 `writeHandshakeRecord`）
//!
//! 转录哈希的输入顺序必须与参考**逐条**一致，否则 `Finished` 与
//! `CertificateVerify` 全部对不上：
//!
//! | 消息 | 计入转录的时机 |
//! |---|---|
//! | ClientHello | 服务端：读入时；客户端：发出时 |
//! | ServerHello | 双方：写出/读入时 |
//! | EncryptedExtensions | 写出/读入时 |
//! | Certificate | 写出/读入时 |
//! | CertificateVerify | **验签之后**才计入（参考 `readServerCertificate`） |
//! | Finished（服务端） | **校验之后**才计入（参考 `readServerFinished`） |
//! | Finished（客户端） | 写出时计入（参考 `sendClientFinished`） |
//!
//! 服务端的 `Finished` **不**计入转录（参考 `readClientFinished` 的注释
//! 「finishedMsg is not included in the transcript」），所以服务端算
//! `clientFinished` 时用的转录哈希与服务端 `Finished` **之前**的转录一致。

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::reality::client::{ClientError, ClientSessionKeys, RealityClient};
use crate::reality::tls13::handshake::{build_finished, HandshakeError, Transcript};
use crate::reality::tls13::io::{
    split_message, HandshakeCollector, Inbound, IoError, Outbound, RecordReader, RecordWriter,
};
use crate::reality::tls13::messages::handshake_type;
use crate::reality::tls13::record::RecordLayer;

/// 客户端握手结果。
pub struct ClientHandshakeOutcome {
    /// 应用数据阶段的读写记录层。
    pub reader: RecordLayer,
    /// 应用数据阶段的写记录层。
    pub writer: RecordLayer,
    /// 服务端叶子证书 DER。
    pub peer_certificate: Vec<u8>,
}

/// 客户端：完成一次 REALITY/TLS 1.3 握手。
///
/// `client` 必须是已经喂过 ClientHello 转录的
/// [`RealityClient`]（见 [`crate::reality::client::RealityClient::from_built`]）。
///
/// `deadline` 是整次握手的截止时间（卡片硬约束：所有网络操作必须有界）。
pub async fn client_handshake<S>(
    client: &mut RealityClient,
    stream: &mut S,
    deadline: Duration,
) -> Result<ClientHandshakeOutcome, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let result =
        crate::reality::tls13::io::with_deadline(deadline, drive_client(client, stream)).await;
    match result {
        Ok(outcome) => Ok(outcome),
        Err(IoError::Timeout) => Err(ClientError::Handshake(HandshakeError::Io("timeout".into()))),
        Err(IoError::Handshake(error)) => Err(ClientError::Handshake(error)),
        Err(IoError::Record(error)) => Err(ClientError::Record(error)),
        Err(IoError::Alert(code)) => Err(ClientError::Handshake(HandshakeError::Alert(code))),
        Err(IoError::Io(error)) => Err(ClientError::Handshake(HandshakeError::Io(
            error.to_string(),
        ))),
    }
}

/// 客户端握手的主体（不带超时包装，便于测试直接驱动）。
async fn drive_client<S>(
    client: &mut RealityClient,
    stream: &mut S,
) -> Result<ClientHandshakeOutcome, IoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = RecordReader::new();
    let mut writer = RecordWriter::new();
    let mut collector = HandshakeCollector::new();

    // ---- 1. 收 ServerHello（明文记录）----
    let server_hello = loop {
        match reader.next_record(stream).await? {
            Some(Inbound::PlainHandshake(payload)) => {
                collector.push(&payload);
                if let Some(message) = collector.take()? {
                    break message;
                }
            }
            Some(Inbound::PlainChangeCipherSpec) => continue,
            Some(Inbound::Encrypted(_)) => {
                return Err(IoError::Handshake(HandshakeError::UnexpectedStep));
            }
            None => return Err(IoError::Handshake(HandshakeError::Io("eof".into()))),
        }
    };
    let (kind, _) = split_message(&server_hello)?;
    if kind != handshake_type::SERVER_HELLO {
        return Err(IoError::Handshake(HandshakeError::UnexpectedMessage(kind)));
    }
    client.process_server_hello(&server_hello)?;

    // ---- 2. 发 change_cipher_spec 并切到加密阶段 ----
    //
    // 参考 `sendDummyChangeCipherSpec` 在 `processServerHello` 之后、
    // `establishHandshakeKeys` 之前发；本仓在派生密钥后发同样可行
    // （该记录永不加密，见 `tls13::io::RecordReader` 的说明）。
    writer
        .write(stream, &Outbound::PlainChangeCipherSpec)
        .await?;
    // 记录层实例要被复用（序号连续），故**复制**一份给记录层驱动器
    // （真正收发的是副本；原实例留在客户端状态机里，序号不会重复推进）。
    let (handshake_reader, handshake_writer) = client.handshake_layers()?;
    let mut server_reader = RecordReader::new();
    server_reader.enable_cipher(handshake_reader);
    let mut client_writer = RecordWriter::new();
    client_writer.enable_cipher(handshake_writer);

    // ---- 3. 收 EncryptedExtensions / Certificate / CertificateVerify / Finished ----
    let mut certificate_der: Option<Vec<u8>> = None;
    let mut certificate_verify: Option<Vec<u8>> = None;
    let mut server_finished: Option<Vec<u8>> = None;
    while server_finished.is_none() {
        let record = loop {
            match server_reader.next_record(stream).await? {
                Some(Inbound::Encrypted(record)) => break record,
                Some(Inbound::PlainChangeCipherSpec) => continue,
                Some(Inbound::PlainHandshake(_)) => {
                    return Err(IoError::Handshake(HandshakeError::UnexpectedStep));
                }
                None => return Err(IoError::Handshake(HandshakeError::Io("eof".into()))),
            }
        };
        let (content, payload) = crate::reality::tls13::io::unpack(&record)?;
        if content == crate::reality::tls13::record::content_type::ALERT {
            return Err(IoError::Alert(payload.first().copied().unwrap_or(0)));
        }
        collector.push(payload);
        while let Some(message) = collector.take()? {
            let (kind, body) = split_message(&message)?;
            match kind {
                handshake_type::ENCRYPTED_EXTENSIONS => {
                    client.transcript_handshake(&message);
                }
                handshake_type::CERTIFICATE => {
                    certificate_der = Some(crate::reality::client::leaf_certificate(body)?);
                    client.transcript_handshake(&message);
                }
                handshake_type::CERTIFICATE_VERIFY => {
                    // `CertificateVerify` **不**在验签前计入转录
                    // （参考 `readServerCertificate`：验签后才 `transcriptMsg`）。
                    certificate_verify = Some(message);
                }
                handshake_type::FINISHED => {
                    // 服务端 Finished **不**在校验前计入转录
                    // （参考 `readServerFinished`：先校验再 `transcriptMsg`）。
                    server_finished = Some(body.to_vec());
                }
                other => {
                    return Err(IoError::Handshake(HandshakeError::UnexpectedMessage(other)));
                }
            }
        }
    }

    let certificate_der =
        certificate_der.ok_or(IoError::Handshake(HandshakeError::MissingCertificate))?;
    let certificate_verify =
        certificate_verify.ok_or(IoError::Handshake(HandshakeError::MissingCertificateVerify))?;
    let server_finished = server_finished.expect("循环退出时必有值");

    // ---- 4. 校验证书标签与 CertificateVerify 签名 ----
    client
        .verify_certificate(&certificate_der)
        .map_err(ClientError::into_io_error)?;
    client
        .verify_certificate_verify(&certificate_der, &certificate_verify)
        .map_err(ClientError::into_io_error)?;
    // 验签通过后，`CertificateVerify` 才计入转录（对齐参考）。
    client.transcript_handshake(&certificate_verify);

    // ---- 5. 校验服务端 Finished 并导出应用数据密钥 ----
    //
    // `finish_handshake` 内部会在校验通过后把服务端 Finished 计入转录
    // （参考 `readServerFinished`：先校验再 `transcriptMsg`），并用**含
    // 服务端 Finished** 的转录导出应用流量密钥。调用方不得重复计入。
    let keys: ClientSessionKeys = client
        .finish_handshake(&server_finished)
        .map_err(ClientError::into_io_error)?;

    // ---- 6. 发客户端 Finished ----
    let verify_data = client
        .client_finished_verify_data()
        .map_err(ClientError::into_io_error)?;
    let finished = build_finished(&verify_data);
    client_writer
        .write(stream, &Outbound::EncryptedHandshake(finished))
        .await?;

    Ok(ClientHandshakeOutcome {
        reader: RecordLayer::new(&keys.server),
        writer: RecordLayer::new(&keys.client),
        peer_certificate: certificate_der,
    })
}

/// 服务端握手结果。
pub struct ServerHandshakeOutcome {
    /// 应用数据阶段的读记录层。
    pub reader: RecordLayer,
    /// 应用数据阶段的写记录层。
    pub writer: RecordLayer,
}

/// 服务端：完成一次 REALITY/TLS 1.3 握手。
///
/// `server` 必须是已经跑过 REALITY 认证（[`crate::reality::server::accept_hello`]）
/// 并调用过 `process_client_hello` 的 [`crate::reality::tls13::server::ServerHandshake`]。
pub async fn server_handshake<S>(
    server: &mut crate::reality::tls13::server::ServerHandshake,
    stream: &mut S,
    client_random: &[u8; 32],
) -> Result<ServerHandshakeOutcome, IoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut writer = RecordWriter::new();
    let mut collector = HandshakeCollector::new();

    // ---- 1. 发 ServerHello（明文记录）----
    //
    // 参考 `sendServerParameters`：`hs.hello.random` 是服务端**自己**的
    // 随机数（`handshake_server_tls13.go:243-244`），`hs.hello.sessionId`
    // 回显客户端的 `legacy_session_id`（`:270`）。
    // 两者都参与转录哈希，写错会导致 `Finished` 与应用流量密钥全部不匹配。
    let _ = client_random;
    let server_hello = server.server_hello_default();
    writer
        .write(stream, &Outbound::PlainHandshake(server_hello.clone()))
        .await?;
    server.after_server_hello(&server_hello)?;

    // ---- 2. 发 change_cipher_spec 并切到加密阶段 ----
    writer
        .write(stream, &Outbound::PlainChangeCipherSpec)
        .await?;
    let (handshake_reader, handshake_writer) = server.handshake_layers()?;
    let mut server_reader = RecordReader::new();
    server_reader.enable_cipher(handshake_reader);
    let mut server_writer = RecordWriter::new();
    server_writer.enable_cipher(handshake_writer);

    // ---- 3. 发 EncryptedExtensions / Certificate / CertificateVerify / Finished ----
    let encrypted_extensions = server.encrypted_extensions();
    server.transcript_handshake(&encrypted_extensions);
    server_writer
        .write(stream, &Outbound::EncryptedHandshake(encrypted_extensions))
        .await?;

    let certificate = server.certificate();
    server.transcript_handshake(&certificate);
    server_writer
        .write(stream, &Outbound::EncryptedHandshake(certificate))
        .await?;

    let certificate_verify = server.certificate_verify();
    server.transcript_handshake(&certificate_verify);
    server_writer
        .write(stream, &Outbound::EncryptedHandshake(certificate_verify))
        .await?;

    let finished = server.finished()?;
    server_writer
        .write(stream, &Outbound::EncryptedHandshake(finished.clone()))
        .await?;
    // 服务端 Finished 计入**服务端**转录：参考 `writeHandshakeRecord`
    // （`conn.go:1099`）把写出的每条握手消息喂进转录。它决定了两件事：
    // 应用流量密钥的上下文，以及期望的客户端 `Finished`。
    server.transcript_finished(&finished);

    // ---- 4. 收客户端 Finished ----
    let client_finished = loop {
        let record = loop {
            match server_reader.next_record(stream).await? {
                Some(Inbound::Encrypted(record)) => break record,
                Some(Inbound::PlainChangeCipherSpec) => continue,
                Some(Inbound::PlainHandshake(_)) => {
                    return Err(IoError::Handshake(HandshakeError::UnexpectedStep));
                }
                None => return Err(IoError::Handshake(HandshakeError::Io("eof".into()))),
            }
        };
        let (content, payload) = crate::reality::tls13::io::unpack(&record)?;
        if content == crate::reality::tls13::record::content_type::ALERT {
            return Err(IoError::Alert(payload.first().copied().unwrap_or(0)));
        }
        collector.push(payload);
        let mut found = None;
        // 客户端 Finished 之后不应再有别的握手消息；本循环在拿到
        // `Finished` 时退出，否则遇到任何非 `Finished` 消息都 fail-closed。
        while let Some(message) = collector.take()? {
            let (kind, body) = split_message(&message)?;
            if kind == handshake_type::FINISHED {
                found = Some(body.to_vec());
            } else {
                return Err(IoError::Handshake(HandshakeError::UnexpectedMessage(kind)));
            }
        }
        if let Some(body) = found {
            break body;
        }
    };

    let keys = server.read_client_finished(&client_finished)?;
    Ok(ServerHandshakeOutcome {
        reader: RecordLayer::new(&keys.client),
        writer: RecordLayer::new(&keys.server),
    })
}

/// 转录哈希薄封装。
pub fn transcript_hash(transcript: &Transcript) -> [u8; 32] {
    transcript.hash()
}
