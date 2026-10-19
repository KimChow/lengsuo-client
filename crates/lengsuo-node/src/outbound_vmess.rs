//! VMess 出口：TLS → AEAD 请求头 → 加密数据帧 → **认证响应头** 正向确认。
//!
//! 语义来源（只读参考，固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）：
//! - 请求头：`proxy/vmess/encoding/client.go` `EncodeRequestHeader` 明文段 +
//!   `proxy/vmess/aead/encrypt.go` `SealVMessAEADHeader` 的 AEAD 封装；
//! - 数据段：`common/crypto/auth.go` 的 `AuthenticationWriter`（本卡固定
//!   option=0 的合法简化：无掩码、无 GlobalPadding、无 AuthenticatedLength）；
//! - 响应对照：服务端只有**认证并成功建立目标连接后**才回响应头
//!   （`proxy/vmess/encoding/server.go` `EncodeResponseHeader`），认证失败时
//!   入站按 `drain` 策略读走若干字节后**关闭连接**。因此「在超时内读到并解开
//!   响应头」是认证完成的正向证据，「连接被关闭且无响应头」是拒绝的证据。
//!
//! 本模块不自造密码学：明文规划用 `request::HeaderPlanner`，封装用
//! `aead::seal_vmess_aead_header`，数据帧用 `chunkframe::{DataCipher, write_data_chunk}`，
//! 响应头解封用 `aead::{open_response_header_length, open_response_header_payload}`
//! 与 `server::respond::response_key_iv`（与测试胶水同一套原语）。
//!
//! 偏离：uuid → cmdKey 的 `MD5(uuid || "c48619fe-8f02-49e0-b9e9-edf763e17e21")`
//! （参考 `common/protocol/id.go` `NewID`）在本模块内用 `md5` 复算——该依赖已
//! 由 `lengsuo-vmess` 引入，node 不新增依赖。

use std::time::Duration;

use lengsuo_vmess::aead;
use lengsuo_vmess::chunkframe::{self, DataCipher};
use lengsuo_vmess::consts::SECURITY_AES_128_GCM;
use lengsuo_vmess::request::{
    Command as VmessCommand, HeaderPlanner, KeySource, RequestHeader, SecurityOption,
};
use lengsuo_vmess::server::respond::response_key_iv;
use tokio::io::AsyncReadExt as _;

use crate::config::NodeConfig;
use crate::outbound::{connect_tls, probe_target, DialError, NodeTlsStream};
use crate::outbound_vless::uuid_bytes;

/// 数据段密钥（请求方向），供 dry-run 之后继续转发业务。
pub type VmessBodyKey = ([u8; 16], [u8; 16]);

/// vmess 出站会话：请求头 + 数据帧已写出，响应头已认证解开。
pub struct VmessOutbound {
    pub stream: NodeTlsStream,
    /// 服务端回带的响应头明文（首个字节为本端写入的 response seed）。
    pub response_header: Vec<u8>,
    /// 请求方向 body key/iv（后续业务帧含 EOF 帧都需要它）。
    pub body: VmessBodyKey,
}

/// vmess 出站：TLS → 请求头 → 数据帧 → 等认证响应头。
pub async fn dial_vmess(config: &NodeConfig, wait: Duration) -> Result<VmessOutbound, DialError> {
    let mut stream = connect_tls(config, wait).await?;
    let cmd_key = cmd_key_from_uuid(&uuid_bytes(&config.auth.password)?);
    let target = probe_target(config);
    let keys = KeySource::generate()?;

    // 请求头明文（option=0：无掩码/无 GlobalPadding/无 AuthenticatedLength 的
    // 合法简化，Xray 对该组合走 AuthenticationReader 的默认分支）。
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
    use tokio::io::AsyncWriteExt as _;
    stream.write_all(&header).await.map_err(io)?;

    // dry-run 数据帧：一个载荷 chunk + 终止 chunk（声明长度 0）。
    // 不是业务载荷，只是让「服务端确已解出请求头」成为可观测事实。
    let mut cipher = DataCipher::new(SECURITY_AES_128_GCM, &keys.body_key, &keys.body_iv);
    chunkframe::write_data_chunk(&mut cipher, None, &mut stream, b"lengsuo-node-dryrun").await?;
    chunkframe::write_eof(&mut cipher, None, &mut stream).await?;

    let response_header = read_response_header(&mut stream, &keys.body_key, &keys.body_iv).await?;
    if response_header.first() != Some(&keys.response_header) {
        // 参考客户端以响应头首字节校验响应归属；不符即认证失败。
        return Err(DialError::Rejected("vmess 响应头种子不匹配".to_owned()));
    }
    Ok(VmessOutbound {
        stream,
        response_header,
        body: (keys.body_key, keys.body_iv),
    })
}

/// 读取并解开响应头（18B 长度段 + `len+16` 载荷段），返回头部明文。
async fn read_response_header(
    stream: &mut NodeTlsStream,
    body_key: &[u8; 16],
    body_iv: &[u8; 16],
) -> Result<Vec<u8>, DialError> {
    let (resp_key, resp_iv) = response_key_iv(body_key, body_iv);
    let mut length_ct = [0u8; 18];
    stream.read_exact(&mut length_ct).await.map_err(io)?;
    let payload_len = aead::open_response_header_length(&resp_key, &resp_iv, &length_ct)?;
    let mut payload_ct = vec![0u8; payload_len as usize + 16];
    // 响应头长度受服务端控制；这里与 `MAX_RESPONSE_BUFFER` 量级一致的上限保护，
    // 超限直接拒绝而不是继续分配（fail-closed）。
    if payload_ct.len() > MAX_RESPONSE_HEADER_WIRE {
        return Err(DialError::Rejected("vmess 响应头长度越界".to_owned()));
    }
    stream.read_exact(&mut payload_ct).await.map_err(io)?;
    Ok(aead::open_response_header_payload(
        &resp_key,
        &resp_iv,
        &payload_ct,
    )?)
}

/// 响应头明文长度上限（本仓服务端恒 4 字节；给出宽松上界防越界分配）。
const MAX_RESPONSE_HEADER_WIRE: usize = 1024;

/// `NewID`：`MD5(uuid_bytes || "c48619fe-8f02-49e0-b9e9-edf763e17e21")`。
fn cmd_key_from_uuid(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hasher = md5::Md5::default();
    use md5::Digest as _;
    hasher.update(uuid);
    hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    hasher.finalize().into()
}

fn io(err: std::io::Error) -> DialError {
    DialError::Rejected(format!("vmess 连接读写出错：{:?}", err.kind()))
}
