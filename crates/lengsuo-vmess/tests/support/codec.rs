//! VMess 客户端编解码胶水（仅供集成测试复用，非 crate API）。
//!
//! 这里**不实现任何新密码学**，只把 `lengsuo_vmess` 的客户端原语拼成一条可写进
//! socket 的请求，以及把服务端回包读回并解密。语义逐条来自参考实现：
//! - 请求头明文字段顺序与 FNV 尾：`proxy/vmess/encoding/client.go` `EncodeRequestHeader`；
//! - 请求头 AEAD 封装：`proxy/vmess/aead/encrypt.go` `SealVMessAEADHeader`；
//! - 数据段分帧（AEAD + 无掩码）：`common/crypto/auth.go` `AuthenticationWriter/Reader`；
//! - 响应头两段 AEAD：`proxy/vmess/encoding/server.go` `EncodeResponseHeader`；
//! - 响应体密钥派生：`responseBodyKey = SHA256(requestBodyKey)[:16]`，IV 同理；
//! - UUID→CmdKey：`common/protocol/id.go` `NewID`（MD5(uuid || 固定盐)）。
//!
//! 本测试客户端固定「无掩码、无 GlobalPadding、无 AuthenticatedLength」的合法简化
//! 请求（option = 0，security 解析 auto → AES-128-GCM），Xray 入站对 AES-128-GCM
//! 的 chunkStream 请求头本来就走 `AuthenticationReader`，option=0 完全合法。

use lengsuo_vmess::aead;
use lengsuo_vmess::chunkframe::{self, DataCipher, MAX_CHUNK_PAYLOAD};
use lengsuo_vmess::consts::SECURITY_AES_128_GCM;
use lengsuo_vmess::request::{Command, HeaderPlanner, KeySource, RequestHeader, SecurityOption};
use lengsuo_vmess::Error;
use sha2::{Digest as _, Sha256};
use ss_core::target::TargetAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// `responseBodyKey = SHA256(requestBodyKey)[..16]`，`responseBodyIV = SHA256(requestBodyIV)[..16]`
/// （`server.go` `EncodeResponseHeader` 与 `client.go` `NewClientSession` 的同一组派生）。
#[must_use]
pub fn response_key_iv(body_key: &[u8; 16], body_iv: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&Sha256::digest(body_key)[..16]);
    iv.copy_from_slice(&Sha256::digest(body_iv)[..16]);
    (key, iv)
}

/// `MD5(uuid_bytes || "c48619fe-8f02-49e0-b9e9-edf763e17e21")`（`common/protocol/id.go` NewID）。
#[must_use]
pub fn cmd_key_from_uuid(uuid_bytes: &[u8; 16]) -> [u8; 16] {
    let mut hasher = md5::Md5::default();
    hasher.update(uuid_bytes);
    hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    hasher.finalize().into()
}

/// 生成 RFC4122 v4 UUID 字节（版本/变体位已置），用于 xray 配置与 cmdKey 派生同一来源。
#[must_use]
pub fn generate_uuid_bytes() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("getrandom 生成 UUID");
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    bytes
}

/// UUID 字节 → 连字符小写十六进制字符串（写进 xray 配置）。
#[must_use]
pub fn uuid_string(bytes: &[u8; 16]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// 由请求头字段集拼出**封装前**的明文字节（`EncodeRequestHeader` 明文段 + FNV 尾）。
pub fn build_request_plaintext(
    keys: &KeySource,
    target: &TargetAddr,
    option: u8,
    padding_len: u8,
) -> Result<Vec<u8>, Error> {
    let planner = HeaderPlanner::new(KeySource {
        body_key: keys.body_key,
        body_iv: keys.body_iv,
        response_header: keys.response_header,
    });
    let header = RequestHeader {
        target: Some(target.clone()),
        command: Command::Tcp,
        security: SecurityOption::Aes128Gcm,
        option,
        padding_len,
    };
    planner.plan(&header)
}

/// 完整请求头线上字节：AuthID || lenCT(18) || connNonce(8) || payloadCT。
/// AuthID 时间戳与连接 nonce 由系统随机源生成（与 `SealVMessAEADHeader` 一致）。
pub fn seal_request_header(
    cmd_key: &[u8; 16],
    keys: &KeySource,
    target: &TargetAddr,
) -> Result<Vec<u8>, Error> {
    let plain = build_request_plaintext(keys, target, 0, 0)?;
    aead::seal_vmess_aead_header(cmd_key, &plain)
}

fn io_error(err: &std::io::Error) -> Error {
    Error::Io(format!("{:?}", err.kind()))
}

/// 连接是否已被对端优雅/非优雅关闭（读取路径的"已到末尾"判据）。
/// `read_exact` 在 EOF/RST/ABORT/BROKEN_PIPE 下分别产出这些 kind。
pub fn is_clean_close(err: &Error) -> bool {
    match err {
        Error::Io(kind) => matches!(
            kind.as_str(),
            "UnexpectedEof" | "ConnectionReset" | "ConnectionAborted" | "BrokenPipe"
        ),
        _ => false,
    }
}

/// 写出一条完整 VMess 请求：请求头 + 每个数据 chunk（大载荷按 `MAX_CHUNK_PAYLOAD`
/// 切分）+ 空 chunk（声明长度 == AEAD overhead == 16，即服务端 `AuthenticationReader`
/// 的 EOF 标记）。
pub async fn write_request<W>(
    writer: &mut W,
    cmd_key: &[u8; 16],
    keys: &KeySource,
    target: &TargetAddr,
    payloads: &[&[u8]],
) -> Result<(), Error>
where
    W: AsyncWrite + Unpin,
{
    let header = seal_request_header(cmd_key, keys, target)?;
    writer.write_all(&header).await.map_err(|e| io_error(&e))?;

    let mut cipher = DataCipher::new(SECURITY_AES_128_GCM, &keys.body_key, &keys.body_iv);
    for &payload in payloads {
        for piece in payload.chunks(MAX_CHUNK_PAYLOAD) {
            chunkframe::write_data_chunk(&mut cipher, None, writer, piece).await?;
        }
    }
    chunkframe::write_eof(&mut cipher, None, writer).await?;
    writer.flush().await.map_err(|e| io_error(&e))?;
    Ok(())
}

/// 读取并解密响应头：18 字节长度段 → `len+16` 字节载荷段，返回解密后的头部明文。
pub async fn read_response_header<R>(
    reader: &mut R,
    body_key: &[u8; 16],
    body_iv: &[u8; 16],
) -> Result<Vec<u8>, Error>
where
    R: AsyncRead + Unpin,
{
    let (resp_key, resp_iv) = response_key_iv(body_key, body_iv);
    let mut length_ct = [0u8; 18];
    reader
        .read_exact(&mut length_ct)
        .await
        .map_err(|e| io_error(&e))?;
    let payload_len = aead::open_response_header_length(&resp_key, &resp_iv, &length_ct)?;

    let mut payload_ct = vec![0u8; payload_len as usize + 16];
    reader
        .read_exact(&mut payload_ct)
        .await
        .map_err(|e| io_error(&e))?;
    aead::open_response_header_payload(&resp_key, &resp_iv, &payload_ct)
}

/// 读取响应体数据段，直到显式 EOF chunk（声明长度 == overhead）或对端关闭连接。
pub async fn read_response_body<R>(
    reader: &mut R,
    body_key: &[u8; 16],
    body_iv: &[u8; 16],
) -> Result<Vec<u8>, Error>
where
    R: AsyncRead + Unpin,
{
    let (resp_key, resp_iv) = response_key_iv(body_key, body_iv);
    let mut cipher = DataCipher::new(SECURITY_AES_128_GCM, &resp_key, &resp_iv);
    let mut out = Vec::new();
    loop {
        match chunkframe::read_data_chunk(&mut cipher, None, reader).await {
            Ok(Some(plain)) => out.extend_from_slice(&plain),
            Ok(None) => break,
            Err(err) if is_clean_close(&err) => break,
            Err(err) => return Err(err),
        }
    }
    Ok(out)
}

/// 读取完整响应（头 + 体），并校验响应头首字节 == 我们写进请求头的 responseHeader。
pub async fn read_response<R>(
    reader: &mut R,
    body_key: &[u8; 16],
    body_iv: &[u8; 16],
    expected_response_header: u8,
) -> Result<Vec<u8>, Error>
where
    R: AsyncRead + Unpin,
{
    let header = read_response_header(reader, body_key, body_iv).await?;
    if header.first() != Some(&expected_response_header) {
        return Err(Error::AuthFailed);
    }
    read_response_body(reader, body_key, body_iv).await
}

/// 本地 TCP 回显后端：把读到的字节原样写回，读到对端关闭后 shutdown 写方向。
pub async fn spawn_echo() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("回显后端绑定 127.0.0.1:0");
    let addr = listener.local_addr().expect("回显后端地址");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 16384];
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if socket.write_all(&buffer[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = socket.shutdown().await;
            });
        }
    });
    (addr, handle)
}