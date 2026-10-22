//! vmess 出站会话：TLS → AEAD 请求头 → **响应头** 正向确认 → 数据帧转发。
//!
//! 不复用 `outbound_vmess::dial_vmess`：dry-run 路径会写一个载荷 chunk
//! （`b"lengsuo-node-dryrun"`）**和一个 EOF chunk**——EOF chunk 对服务端意味着
//! 「本流已结束」，业务载荷无法再转发。这里只写请求头、读完响应头，
//! 之后的字节全部是业务载荷。
//!
//! 请求方向与响应方向用**两套** `DataCipher`：请求方向用本端生成的
//! body key/iv，响应方向用 `response_key_iv(body_key, body_iv)` 派生
//! （参考 `proxy/vmess/encoding/server.go` `EncodeResponseHeader`）。
//!
//! 请求头明文规划用 `request::HeaderPlanner`，封装用
//! `aead::seal_vmess_aead_header`，数据帧用 `chunkframe::{DataCipher,
//! write_data_chunk, read_data_chunk, write_eof}`——本模块不复制密码学。
//!
//! 偏离：`NewID`（`MD5(uuid || "c48619fe-8f02-49e0-b9e9-edf763e17e21")`，
//! 参考 `common/protocol/id.go`）在 `lengsuo-vmess` crate 里没有导出，
//! 而 `outbound_vmess.rs` 不在本卡边界内，故此处按同一公式复算 4 行
//! （`outbound_vmess.rs` 里已有同一份，本卡不改它）。

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use lengsuo_vmess::aead;
use lengsuo_vmess::chunkframe::{self, DataCipher};
use lengsuo_vmess::consts::SECURITY_AES_128_GCM;
use lengsuo_vmess::request::{
    Command as VmessCommand, HeaderPlanner, KeySource, RequestHeader, SecurityOption,
};
use lengsuo_vmess::server::respond::response_key_iv;
use md5::Digest as _;
use ss_core::target::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::time::timeout;

use super::{LiveSession, OutboundReader, OutboundWriter, SessionError};
use crate::config::NodeConfig;
use crate::outbound::{connect_tls, NodeTlsStream};
use crate::outbound_vless::uuid_bytes;

/// 响应头明文长度上限（本仓服务端恒 4 字节；给出宽松上界防越界分配）。
const MAX_RESPONSE_HEADER_WIRE: usize = 1024;

/// 建立 vmess 出站会话并返回可转发的读 / 写两半。
pub(super) async fn open(
    node: &NodeConfig,
    target: &TargetAddr,
    wait: Duration,
) -> Result<LiveSession, SessionError> {
    let mut stream = connect_tls(node, wait).await?;
    let cmd_key = cmd_key_from_uuid(&uuid_bytes(&node.auth.password)?);
    let keys = KeySource::generate()?;

    let planner = HeaderPlanner::new(KeySource {
        body_key: keys.body_key,
        body_iv: keys.body_iv,
        response_header: keys.response_header,
    });
    let plain = planner.plan(&RequestHeader {
        target: Some(target.clone()),
        command: VmessCommand::Tcp,
        security: SecurityOption::Aes128Gcm,
        option: 0,
        padding_len: 0,
    })?;
    let header = aead::seal_vmess_aead_header(&cmd_key, &plain)?;
    stream.write_all(&header).await?;
    stream.flush().await?;

    // 正向证据：服务端认证并成功建立目标连接后才回响应头。
    let (resp_key, resp_iv) = response_key_iv(&keys.body_key, &keys.body_iv);
    let mut length_ct = [0u8; 18];
    stream.read_exact(&mut length_ct).await?;
    let payload_len = aead::open_response_header_length(&resp_key, &resp_iv, &length_ct)?;
    if usize::from(payload_len) + 16 > MAX_RESPONSE_HEADER_WIRE {
        return Err(SessionError::Vmess(lengsuo_vmess::Error::AuthFailed));
    }
    let mut payload_ct = vec![0u8; usize::from(payload_len) + 16];
    stream.read_exact(&mut payload_ct).await?;
    let response_header = aead::open_response_header_payload(&resp_key, &resp_iv, &payload_ct)?;
    if response_header.first() != Some(&keys.response_header) {
        return Err(SessionError::Vmess(lengsuo_vmess::Error::AuthFailed));
    }

    let (read, write) = tokio::io::split(stream);
    Ok(LiveSession {
        reader: Box::new(VmessReader {
            reader: read,
            cipher: DataCipher::new(SECURITY_AES_128_GCM, &resp_key, &resp_iv),
            pending: Vec::new(),
        }),
        writer: Box::new(VmessWriter {
            writer: write,
            cipher: DataCipher::new(SECURITY_AES_128_GCM, &keys.body_key, &keys.body_iv),
        }),
    })
}

/// `NewID`：`MD5(uuid_bytes || "c48619fe-8f02-49e0-b9e9-edf763e17e21")`。
fn cmd_key_from_uuid(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hasher = md5::Md5::default();
    hasher.update(uuid);
    hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    hasher.finalize().into()
}

/// vmess 读侧：AEAD chunk 解密（响应方向）。
struct VmessReader {
    reader: ReadHalf<NodeTlsStream>,
    cipher: DataCipher,
    /// 上一次解出的 chunk 里没被本次读走的余量。
    pending: Vec<u8>,
}

impl OutboundReader for VmessReader {
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
        wait: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<usize, SessionError>> + Send + 'a>> {
        Box::pin(async move {
            if !self.pending.is_empty() {
                let take = self.pending.len().min(buf.len());
                buf[..take].copy_from_slice(&self.pending[..take]);
                self.pending.drain(..take);
                return Ok(take);
            }
            // 超时是**会话级**终止条件：chunk 半读被打断会让流失步，
            // 所以这里只把超时上抛（relay 层据此断连），不做续读。
            let chunk = timeout(
                wait,
                chunkframe::read_data_chunk(&mut self.cipher, None, &mut self.reader),
            )
            .await
            .map_err(|_| SessionError::Idle)?
            .map_err(SessionError::Vmess)?;
            match chunk {
                Some(plain) => {
                    let take = plain.len().min(buf.len());
                    buf[..take].copy_from_slice(&plain[..take]);
                    if take < plain.len() {
                        self.pending.extend_from_slice(&plain[take..]);
                    }
                    Ok(take)
                }
                // 显式 EOF chunk。
                None => Ok(0),
            }
        })
    }
}

/// vmess 写侧：AEAD chunk 加密（请求方向）。
struct VmessWriter {
    writer: WriteHalf<NodeTlsStream>,
    cipher: DataCipher,
}

impl OutboundWriter for VmessWriter {
    fn send<'a>(
        &'a mut self,
        payload: &'a [u8],
        wait: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), SessionError>> + Send + 'a>> {
        Box::pin(async move {
            timeout(
                wait,
                chunkframe::write_data_chunk(&mut self.cipher, None, &mut self.writer, payload),
            )
            .await
            .map_err(|_| SessionError::Idle)?
            .map_err(SessionError::Vmess)?;
            timeout(wait, self.writer.flush())
                .await
                .map_err(|_| SessionError::Idle)?
                .map_err(SessionError::Io)
        })
    }

    fn half_close<'a>(
        &'a mut self,
        wait: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), SessionError>> + Send + 'a>> {
        // EOF chunk：告诉服务端「请求方向到此为止」，回程仍可继续收。
        Box::pin(async move {
            timeout(
                wait,
                chunkframe::write_eof(&mut self.cipher, None, &mut self.writer),
            )
            .await
            .map_err(|_| SessionError::Idle)?
            .map_err(SessionError::Vmess)?;
            timeout(wait, self.writer.flush())
                .await
                .map_err(|_| SessionError::Idle)?
                .map_err(SessionError::Io)
        })
    }
}
