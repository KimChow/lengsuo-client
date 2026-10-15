//! SIP022 TCP 发送侧：salt + 固定头 chunk + 变长头 chunk + `ss_core::chunk` 载荷帧。
//!
//! nonce 由子密钥会话 AEAD 的单一小端递增序列贯穿：固定头消耗第 1 个 nonce，变长头
//! 消耗第 2 个，之后每个载荷帧的 length chunk / payload chunk 各消耗一个，起步为全 0。
//! salt 与两个头部 chunk 合并成一次 `write_all`，避免产生可预测的分包尺寸。
//! 任何编码、校验或写出失败都会永久 poison 本 [`Writer`]：不降级明文、不复用半途状态。
use ss_core::{
    chunk::{write_chunk, write_eof},
    crypto::SessionAead,
    target::TargetAddr,
};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::{
    map_core, random_bytes, suite, Direction, Header, Opening, FIXED_HEADER_LEN,
    FIXED_HEADER_WIRE_LEN, MAX_VAR_HEADER_LEN, PADDING_FIELD_LEN,
};
use crate::{crypto::Key, Error};

/// 一条流的发送侧状态。
pub struct Writer {
    aead: SessionAead,
    opening: Opening,
    direction: Direction,
    headers_written: bool,
    poisoned: bool,
}

impl Writer {
    /// 由显式 `Opening`（salt + 会话标识）创建；salt 长度必须匹配套件。
    pub fn new(key: &Key, direction: Direction, opening: Opening) -> Result<Self, Error> {
        opening.check_salt(key)?;
        let subkey = key.subkey(opening.salt());
        Ok(Self {
            aead: SessionAead::new(suite(key.method()), subkey),
            opening,
            direction,
            headers_written: false,
            poisoned: false,
        })
    }
    /// 用系统随机数生成 salt 与会话标识。
    pub fn random(key: &Key, direction: Direction) -> Result<Self, Error> {
        Self::new(key, direction, Opening::random(key)?)
    }
    pub fn salt(&self) -> &[u8] {
        self.opening.salt()
    }
    pub fn session_id(&self) -> u64 {
        self.opening.session_id()
    }
    pub fn direction(&self) -> Direction {
        self.direction
    }
    /// 是否已因失败永久失效。
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    /// 两个头部 chunk 是否已写出（写出后才允许载荷帧）。
    pub fn is_opened(&self) -> bool {
        self.headers_written
    }

    /// 请求流开场：变长头 = 目标地址 + padding 声明 + 随机 padding + 首批载荷。
    /// 载荷为空时填充必须非零（SIP022：变长头须含载荷或非零填充）。
    pub async fn write_request_header<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        target: &TargetAddr,
        payload: &[u8],
        now: u64,
        padding: u16,
    ) -> Result<(), Error> {
        let mut association = Vec::new();
        if let Err(error) = target.encode_checked(&mut association) {
            return Err(self.fail(map_core(error)));
        }
        self.write_opening(writer, &association, payload, now, padding)
            .await
    }

    /// 响应流开场：变长头 = 请求会话标识（u64be）+ padding 声明 + 随机 padding + 首批载荷。
    pub async fn write_response_header<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        peer_session_id: u64,
        payload: &[u8],
        now: u64,
        padding: u16,
    ) -> Result<(), Error> {
        self.write_opening(
            writer,
            &peer_session_id.to_be_bytes(),
            payload,
            now,
            padding,
        )
        .await
    }

    async fn write_opening<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        association: &[u8],
        payload: &[u8],
        now: u64,
        padding: u16,
    ) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.headers_written {
            return Err(self.fail(Error::SessionPolicy));
        }
        if payload.is_empty() && padding == 0 {
            return Err(self.fail(Error::HeaderPadding));
        }
        let var_len = association
            .len()
            .checked_add(PADDING_FIELD_LEN)
            .and_then(|length| length.checked_add(padding as usize))
            .and_then(|length| length.checked_add(payload.len()))
            .ok_or(Error::Length)?;
        if var_len > MAX_VAR_HEADER_LEN as usize {
            return Err(self.fail(Error::Length));
        }
        let header = Header {
            kind: self.direction.header_type(),
            session_id: self.opening.session_id(),
            timestamp: now,
            var_len: var_len as u16,
            padding,
        };
        let wire = match self.build_wire(header, association, payload, padding) {
            Ok(wire) => wire,
            Err(error) => return Err(self.fail(error)),
        };
        if let Err(error) = writer.write_all(&wire).await {
            return Err(self.fail(Error::Io(error)));
        }
        // 头部已完整落盘后才提交状态：nonce 序列与线上顺序保持一致。
        self.headers_written = true;
        Ok(())
    }

    /// salt || AEAD(固定头明文) || AEAD(关联块 || padding 声明 || 随机 padding || 首批载荷)。
    fn build_wire(
        &mut self,
        header: Header,
        association: &[u8],
        payload: &[u8],
        padding: u16,
    ) -> Result<Vec<u8>, Error> {
        let mut var_plain = Vec::with_capacity(
            association.len() + PADDING_FIELD_LEN + padding as usize + payload.len(),
        );
        var_plain.extend_from_slice(association);
        var_plain.extend_from_slice(&padding.to_be_bytes());
        // 填充使用随机字节：全零填充会暴露载荷边界。
        let pad = random_bytes(padding as usize)?;
        var_plain.extend_from_slice(&pad);
        var_plain.extend_from_slice(payload);
        let fixed_plain = header.encode();
        debug_assert_eq!(fixed_plain.len(), FIXED_HEADER_LEN);
        let fixed_ct = self.aead.seal(&fixed_plain).map_err(map_core)?;
        if fixed_ct.len() != FIXED_HEADER_WIRE_LEN {
            return Err(Error::Seal);
        }
        let var_ct = self.aead.seal(&var_plain).map_err(map_core)?;
        let salt = self.opening.salt();
        let mut wire = Vec::with_capacity(salt.len() + fixed_ct.len() + var_ct.len());
        wire.extend_from_slice(salt);
        wire.extend_from_slice(&fixed_ct);
        wire.extend_from_slice(&var_ct);
        Ok(wire)
    }

    /// 写出一个载荷帧（length chunk + payload chunk）。空载荷请用 [`Writer::write_finish`]。
    pub async fn write_payload<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        payload: &[u8],
    ) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if !self.headers_written {
            return Err(self.fail(Error::SessionPolicy));
        }
        if payload.is_empty() {
            // 零长 chunk 在本实现里是流终止信号，不能表示“零字节载荷”。
            return Err(self.fail(Error::Length));
        }
        match write_chunk(writer, &mut self.aead, payload).await {
            Ok(()) => Ok(()),
            Err(error) => Err(self.fail(map_core(error))),
        }
    }

    /// 写出终止 chunk（length 明文为 0），对端读到 `Ok(None)` 表示该方向正常收尾。
    pub async fn write_finish<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if !self.headers_written {
            return Err(self.fail(Error::SessionPolicy));
        }
        match write_eof(writer, &mut self.aead).await {
            Ok(()) => Ok(()),
            Err(error) => Err(self.fail(map_core(error))),
        }
    }

    fn fail(&mut self, error: Error) -> Error {
        self.poisoned = true;
        error
    }
}
