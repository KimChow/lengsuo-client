//! SIP022 TCP 发送侧：请求 = salt + 固定头 + 变长头；响应 = salt + 固定头（兼首个
//! length chunk）+ 首批载荷 chunk；其后两方向都是 `ss_core::chunk` 载荷帧。
//!
//! nonce（u96le）跨整条流连续：请求固定头 = 0、变长头 = 1、之后逐帧递增；响应固定
//! 头 = 0、首批载荷 = 1、之后逐帧递增。
//! salt 与头部 chunk（响应还含首批载荷）合并成一次 `write_all`（SIP022 §3.1.3 反
//! 指纹要求）。任何编码、校验或写出失败都会永久 poison 本 [`Writer`]：不降级明文。
use ss_core::{
    chunk::{write_chunk, write_eof, MAX_CHUNK_PAYLOAD},
    crypto::SessionAead,
    target::TargetAddr,
};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::{
    header::FixedHeader, map_core, random_bytes, suite, Direction, Opening, MAX_VAR_HEADER_LEN,
    PADDING_FIELD_LEN,
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
    /// 由显式 `Opening`（salt）创建；salt 长度必须匹配套件。
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
    /// 用系统随机数生成 salt。
    pub fn random(key: &Key, direction: Direction) -> Result<Self, Error> {
        Self::new(key, direction, Opening::random(key)?)
    }
    pub fn salt(&self) -> &[u8] {
        self.opening.salt()
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
    /// 载荷与 padding 至少一个非零（变长头不得为空壳）。
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
        if self.direction != Direction::Request {
            return Err(self.fail(Error::Direction));
        }
        if self.headers_written {
            return Err(self.fail(Error::SessionPolicy));
        }
        if payload.is_empty() && padding == 0 {
            return Err(self.fail(Error::HeaderPadding));
        }
        // SIP022 MinPaddingLength=0 / MaxPaddingLength=900。
        if let Err(error) = FixedHeader::check_padding_decl(padding) {
            return Err(self.fail(error));
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
        let header = FixedHeader::request(now, var_len as u16);
        let wire = match self.build_wire(header, association, payload, padding) {
            Ok(wire) => wire,
            Err(error) => return Err(self.fail(error)),
        };
        if let Err(error) = writer.write_all(&wire).await {
            return Err(self.fail(Error::Io(error)));
        }
        self.headers_written = true;
        Ok(())
    }

    /// 响应流开场（§3.1.2/§3.1.3）：固定头 = type(1)+timestamp+request salt+首批载荷长，
    /// 该 chunk 同时充当第一个 length chunk，**没有变长头**；`request_salt` 必须是本端
    /// 请求流的原样 salt（客户端归属依据）。首批载荷与固定头合并一次 `write_all`；
    /// 载荷为空时 length 声明 0，对端开场不带载荷、随后按普通帧读。响应不需要填充。
    pub async fn write_response_header<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        request_salt: &[u8],
        payload: &[u8],
        now: u64,
    ) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.headers_written {
            return Err(self.fail(Error::SessionPolicy));
        }
        if self.direction != Direction::Response {
            return Err(self.fail(Error::Direction));
        }
        if payload.len() > MAX_CHUNK_PAYLOAD {
            return Err(self.fail(Error::Length));
        }
        let header = FixedHeader::response(now, request_salt, payload.len() as u16);
        let wire = match self.build_response_wire(header, payload) {
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

    /// salt || AEAD(固定头) || AEAD(首批载荷，可缺省)。三个字段一次写出。
    fn build_response_wire(
        &mut self,
        header: FixedHeader,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let fixed_ct = self
            .aead
            .seal(&header.encode(self.direction, self.opening.salt().len())?)
            .map_err(map_core)?;
        let salt = self.opening.salt();
        let mut wire = Vec::with_capacity(salt.len() + fixed_ct.len() + payload.len() + 16);
        wire.extend_from_slice(salt);
        wire.extend_from_slice(&fixed_ct);
        if !payload.is_empty() {
            let payload_ct = self.aead.seal(payload).map_err(map_core)?;
            wire.extend_from_slice(&payload_ct);
        }
        Ok(wire)
    }

    /// salt || AEAD(请求固定头 11B) || AEAD(关联块 || padding 声明 || 随机 padding || 首批载荷)。
    fn build_wire(
        &mut self,
        header: FixedHeader,
        association: &[u8],
        payload: &[u8],
        padding: u16,
    ) -> Result<Vec<u8>, Error> {
        let mut var_plain = Vec::with_capacity(
            association.len() + PADDING_FIELD_LEN + padding as usize + payload.len(),
        );
        var_plain.extend_from_slice(association);
        var_plain.extend_from_slice(&padding.to_be_bytes());
        let pad = random_bytes(padding as usize)?;
        var_plain.extend_from_slice(&pad);
        var_plain.extend_from_slice(payload);
        let fixed_ct = self
            .aead
            .seal(&header.encode(self.direction, self.opening.salt().len())?)
            .map_err(map_core)?;
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
            return Err(self.fail(Error::Length));
        }
        match write_chunk(writer, &mut self.aead, payload).await {
            Ok(()) => Ok(()),
            Err(error) => Err(self.fail(map_core(error))),
        }
    }

    /// 终止 chunk（length 明文为 0），对端读到 `Ok(None)` 表示该方向正常收尾。
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
