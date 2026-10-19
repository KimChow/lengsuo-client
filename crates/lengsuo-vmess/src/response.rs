//! VMess 客户端响应读取端（对齐 `proxy/vmess/encoding/client.go` 的
//! `DecodeResponseHeader`，固定 commit d2758a02）。
//!
//! 流程：18B 长度段密文 → 解出载荷长度 → `len+16`B 载荷段密文 → 解出明文 →
//! 校验首字节 == 请求头里声明的 responseHeader（"unexpected response header"）→
//! 取 Option 字节。明文第 3 字节非 0 表示 switch 命令（参考会继续解析
//! `cmdID/cmdLen/auth`；本层不实现，fail-closed 拒绝）。
//!
//! 响应体读取：密钥换用 `SHA256(requestBodyKey/IV)[:16]`（见
//! [`crate::server::respond::response_key_iv`]），数据段分帧复用
//! [`crate::chunkframe`]。

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::aead::{open_response_header_length, open_response_header_payload};
use crate::chunkframe::{read_data_chunk, DataCipher, DataSizeParser};
use crate::server::respond::response_key_iv;
use crate::{Error, Result};

/// 响应头解析产物。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Response {
    /// 响应选项字节（明文第 2 字节）。
    pub option: u8,
}

/// 解析已解密的响应头明文（client.go:225-235 的字段段）。
///
/// `expected_seed` 是本端写进请求头的响应种子；不匹配即 [`Error::AuthFailed`]
/// （对齐参考 "unexpected response header"）。明文第 3 字节非 0 表示 switch
/// 命令，本层不实现（fail-closed）。
pub fn parse_response_header(plain: &[u8], expected_seed: u8) -> Result<Response> {
    if plain.len() < 4 {
        return Err(Error::Truncated {
            need: 4,
            got: plain.len(),
        });
    }
    if plain[0] != expected_seed {
        return Err(Error::AuthFailed);
    }
    if plain[2] != 0 {
        // 参考继续解析 switch 命令（cmdID/cmdLen/auth）；本层不支持，fail-closed。
        return Err(Error::Unsupported {
            feature: "response switch command",
        });
    }
    Ok(Response { option: plain[1] })
}

/// 读取并解密一条完整响应头（38 字节）。
pub async fn read_response_header<R>(
    reader: &mut R,
    request_body_key: &[u8; 16],
    request_body_iv: &[u8; 16],
    expected_seed: u8,
) -> Result<Response>
where
    R: AsyncRead + Unpin,
{
    let (resp_key, resp_iv) = response_key_iv(request_body_key, request_body_iv);

    let mut length_ct = [0u8; 18];
    reader
        .read_exact(&mut length_ct)
        .await
        .map_err(|e| crate::io_err(&e))?;
    let payload_len = open_response_header_length(&resp_key, &resp_iv, &length_ct)?;

    let mut payload_ct = vec![0u8; payload_len as usize + 16];
    reader
        .read_exact(&mut payload_ct)
        .await
        .map_err(|e| crate::io_err(&e))?;
    let plain = open_response_header_payload(&resp_key, &resp_iv, &payload_ct)?;
    parse_response_header(&plain, expected_seed)
}

/// 读取响应体数据段直到 EOF 帧（声明长度 0 / 明文 0）或对端干净关闭。
///
/// 与 `tests/support/codec.rs::read_response_body` 同语义，但密钥派生内聚到
/// crate 层供正式客户端复用。`security` 为线上安全选项字节（本层支持
/// AES-128-GCM；none/chacha 由 [`DataCipher`] 语义覆盖）。
pub async fn read_response_body<R>(
    reader: &mut R,
    request_body_key: &[u8; 16],
    request_body_iv: &[u8; 16],
    security: u8,
    chunk_masking: bool,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let (resp_key, resp_iv) = response_key_iv(request_body_key, request_body_iv);
    let mut cipher = DataCipher::new(security, &resp_key, &resp_iv);
    let mut mask = chunk_masking.then(|| DataSizeParser::new(&resp_iv));
    let mut out = Vec::new();
    loop {
        match read_data_chunk(
            &mut cipher,
            mask.as_mut(),
            reader,
        )
        .await
        {
            Ok(Some(plain)) => out.extend_from_slice(&plain),
            Ok(None) => break,
            Err(Error::Io(kind))
                if matches!(
                    kind.as_str(),
                    "UnexpectedEof" | "ConnectionReset" | "ConnectionAborted" | "BrokenPipe"
                ) =>
            {
                // 对端关闭：按流末尾处理（与参考 AuthenticationReader 的 EOF 语义一致）。
                break;
            }
            Err(err) => return Err(err),
        }
    }
    Ok(out)
}

/// 便捷组合：读响应头 + 响应体。`security` 默认按 AES-128-GCM 调用方可传
/// [`SECURITY_AES_128_GCM`]；如需其他套件请分别调用上面两个函数。
pub async fn read_response<R>(
    reader: &mut R,
    request_body_key: &[u8; 16],
    request_body_iv: &[u8; 16],
    expected_seed: u8,
    security: u8,
    chunk_masking: bool,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    read_response_header(reader, request_body_key, request_body_iv, expected_seed).await?;
    read_response_body(reader, request_body_key, request_body_iv, security, chunk_masking).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunkframe::{seal_data_chunk, write_data_eof, DataCipher, DataSizeParser};
    use crate::consts::SECURITY_AES_128_GCM;
    use crate::server::respond::{encode_response_header, ResponseHeader};
    use tokio::io::duplex;

    const REQ_KEY: [u8; 16] = [0x31u8; 16];
    const REQ_IV: [u8; 16] = [0x42u8; 16];
    const SEED: u8 = 0x5C;

    fn seal_body(mut writer: &mut Vec<u8>, payload: &[u8]) {
        let (resp_key, resp_iv) = response_key_iv(&REQ_KEY, &REQ_IV);
        let mut cipher = DataCipher::new(SECURITY_AES_128_GCM, &resp_key, &resp_iv);
        let mut mask = DataSizeParser::new(&resp_iv);
        seal_data_chunk(&mut cipher, Some(&mut mask), &mut writer, payload).expect("可写");
        write_data_eof(&mut cipher, Some(&mut mask), &mut writer).expect("EOF 可写");
    }

    #[tokio::test]
    async fn respond_and_response_roundtrip_with_masked_body() {
        let mut wire = Vec::new();
        encode_response_header(SEED, &REQ_KEY, &REQ_IV, &ResponseHeader::new(), &mut wire)
            .expect("响应头可封");
        seal_body(&mut wire, b"echo-payload");

        let (mut client, mut server) = duplex(8192);
        use tokio::io::AsyncWriteExt;
        server.write_all(&wire).await.expect("写入管道");
        drop(server);

        let body = read_response(&mut client, &REQ_KEY, &REQ_IV, SEED, SECURITY_AES_128_GCM, true)
            .await
            .expect("可读回");
        assert_eq!(body, b"echo-payload");
    }

    #[tokio::test]
    async fn wrong_seed_is_rejected() {
        let mut wire = Vec::new();
        encode_response_header(SEED, &REQ_KEY, &REQ_IV, &ResponseHeader::new(), &mut wire)
            .expect("响应头可封");
        let (mut client, mut server) = duplex(8192);
        use tokio::io::AsyncWriteExt;
        server.write_all(&wire).await.expect("写入管道");
        drop(server);

        let err = read_response_header(&mut client, &REQ_KEY, &REQ_IV, SEED ^ 0xFF)
            .await
            .expect_err("种子不符必须拒绝");
        assert!(matches!(err, Error::AuthFailed));
    }
}
