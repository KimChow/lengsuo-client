//! 请求头字段集与明文规划器。
//!
//! 语义来源：参考 `proxy/vmess/encoding/client.go` 的 `EncodeRequestHeader`
//! 明文段，固定 commit `d2758a02`。

use ss_core::target::TargetAddr;

use crate::address::encoded_addr_len;
use crate::{fill_random, Error, Result};

use super::model::{Command, KeySource, SecurityOption};
use super::{CMD_MUX, VMESS_VERSION_BYTE};

/// 单条请求的头部字段集（不含会话密钥）。
#[derive(Clone, PartialEq, Eq)]
pub struct RequestHeader {
    /// 目标地址；Mux 命令必须为 `None`，其余命令必须为 `Some`。
    pub target: Option<TargetAddr>,
    /// 命令。
    pub command: Command,
    /// 安全选项。
    pub security: SecurityOption,
    /// 选项字节（由 [`HeaderPlanner`] 计算或调用方显式指定）。
    pub option: u8,
    /// 填充长度（0..=15；`dice.Roll(16)` 语义，测试可注入固定值）。
    pub padding_len: u8,
}

impl RequestHeader {
    /// Mux 命令（本层不支持）。
    pub fn is_mux(&self) -> bool {
        self.command == Command::from_byte(CMD_MUX).unwrap_or(self.command)
    }
}

/// 请求头规划器：把字段集编成明文（封装前字节），供 [`crate::aead`] 封装。
pub struct HeaderPlanner {
    /// 会话密钥与响应种子。
    pub key_source: KeySource,
}

impl HeaderPlanner {
    /// 由生成的会话密钥构造。
    pub fn new(key_source: KeySource) -> Self {
        HeaderPlanner { key_source }
    }

    /// `EncodeRequestHeader` 明文段：padding 随机由系统 CSPRNG 提供。
    pub fn plan(&self, header: &RequestHeader) -> Result<Vec<u8>> {
        let mut padding = vec![0u8; header.padding_len as usize];
        if !padding.is_empty() {
            fill_random(&mut padding)?;
        }
        self.plan_with(header, &padding)
    }

    /// 确定性变体：padding 字节由调用方注入（长度必须与 `padding_len` 一致）。
    pub fn plan_with(&self, header: &RequestHeader, padding: &[u8]) -> Result<Vec<u8>> {
        if header.padding_len > 15 {
            return Err(Error::InvalidField {
                field: "padding_len",
            });
        }
        if padding.len() != header.padding_len as usize {
            return Err(Error::BadLength {
                declared: padding.len(),
                got: header.padding_len as usize,
            });
        }
        // 安全选项校验（fail-closed：autocipher 哨兵必须先被调用方解析）。
        if header.security == SecurityOption::AutoCipher {
            return Err(Error::Unsupported {
                feature: "autocipher sentinel must be resolved by caller",
            });
        }
        // Mux（字节 3）在本层不支持：直接按线上字节判定，命中即拒绝。
        let mux = header.command.to_byte() == CMD_MUX;
        match (header.target.as_ref(), mux) {
            (Some(_), true) | (None, false) => {
                return Err(Error::InvalidField { field: "target" });
            }
            _ => {}
        }
        // security 字节：高 4 位 paddingLen，低 4 位 Security。
        let security_byte = (header.padding_len << 4) | (header.security.to_byte() & 0x0F);

        let mut buffer = Vec::with_capacity(
            1 + 16
                + 16
                + 1
                + 1
                + 3
                + header.target.as_ref().map_or(0, encoded_addr_len)
                + padding.len()
                + 4,
        );
        buffer.push(VMESS_VERSION_BYTE);
        buffer.extend_from_slice(&self.key_source.body_iv);
        buffer.extend_from_slice(&self.key_source.body_key);
        buffer.push(self.key_source.response_header);
        buffer.push(header.option);
        buffer.extend_from_slice(&[security_byte, 0x00, header.command.to_byte()]);
        if let Some(target) = header.target.as_ref() {
            crate::address::encode_target_addr(target, &mut buffer)?;
        }
        buffer.extend_from_slice(padding);
        buffer.extend_from_slice(&super::checksum::fnv1a32(&buffer).to_be_bytes());
        Ok(buffer)
    }
}
