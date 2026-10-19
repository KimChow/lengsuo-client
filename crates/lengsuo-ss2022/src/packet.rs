//! UDP separate header + AEAD body，覆盖 SIP022 §3.2 的两种 UDP 布局。
//!
//! - **AES 系列**：16 字节 separate header（前 8 字节 session id，后 8 字节 packet id）
//!   由 AES 块加密承载；AEAD 用 12 字节 nonce（取 header[4..16]），subkey 由 psk+salt 派生。
//! - **ChaCha 系列**：24 字节随机 nonce 明文置于包首，AEAD 直接用 PSK，
//!   nonce 为完整 24 字节；session id / packet id 在密文内。
//!
//! 本模块解码不做重放判定；返回值不得直接当作可转发请求。
use crate::{
    crypto::{Key, Method},
    Error,
};
use ss_core::target::TargetAddr;

/// ChaCha UDP 明文头中 session id / packet id 的字节数（各 8 字节大端）。
pub const UDP_SESSION_ID_LEN: usize = 8;
/// ChaCha UDP 明文头中固定的 session id + packet id 前缀长度。
pub const UDP_PACKET_PREFIX_LEN: usize = UDP_SESSION_ID_LEN * 2;
/// AEAD 认证标签长度。
pub const TAG_LEN: usize = 16;

/// 类型不含 Debug，避免应用载荷进入日志。
pub struct Decoded {
    pub session_id: [u8; 8],
    pub packet_id: u64,
    pub client_session: Option<[u8; 8]>,
    pub target: TargetAddr,
    pub payload: Vec<u8>,
}

pub struct Sender {
    key: Key,
    subkey: Vec<u8>,
    session_id: [u8; 8],
    next: Option<u64>,
    client_session: Option<[u8; 8]>,
}
impl Sender {
    /// None 创建请求方向；Some 将响应方向固定绑定到已验证的客户端会话。
    pub fn new(key: Key, client_session: Option<[u8; 8]>) -> Result<Self, Error> {
        let mut session_id = [0; 8];
        getrandom::getrandom(&mut session_id).map_err(|_| Error::Entropy)?;
        let subkey = key.subkey(&session_id);
        Ok(Self {
            key,
            subkey,
            session_id,
            next: Some(0),
            client_session,
        })
    }
    pub fn session_id(&self) -> [u8; 8] {
        self.session_id
    }
    /// 使用已注入时钟的 Unix 秒数；调用方不得传入不可信客户端时间。
    /// UDP 填充可为零；本实现使用零字节填充，尚无 padding 策略模块。
    pub fn seal(
        &mut self,
        target: &TargetAddr,
        payload: &[u8],
        now: u64,
        padding: u16,
    ) -> Result<Vec<u8>, Error> {
        let id = self.next.ok_or(Error::Exhausted)?;
        let mut header = [0; 16];
        header[..8].copy_from_slice(&self.session_id);
        header[8..].copy_from_slice(&id.to_be_bytes());
        let mut body = self.body_prefix(now);
        body.extend_from_slice(&padding.to_be_bytes());
        self.next = id.checked_add(1);
        match self.key.method() {
            Method::ChaCha20 => self.seal_chacha(id, &body, target, payload, padding),
            _ => self.seal_aes(header, &body, target, payload, padding),
        }
    }
    /// 明文体前缀：方向字节、时间戳、响应方向的客户端会话 id。
    fn body_prefix(&self, now: u64) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(u8::from(self.client_session.is_some()));
        body.extend_from_slice(&now.to_be_bytes());
        if let Some(client) = self.client_session {
            body.extend_from_slice(&client);
        }
        body
    }
    /// Aes 系列：16 字节 separate header（块加密）+ AEAD（nonce = header[4..16]）。
    fn seal_aes(
        &self,
        header: [u8; 16],
        body: &[u8],
        target: &TargetAddr,
        payload: &[u8],
        padding: u16,
    ) -> Result<Vec<u8>, Error> {
        self.total_len(body.len(), target, payload, padding)?;
        let mut plain = body.to_vec();
        plain.resize(plain.len() + padding as usize, 0);
        target.encode_checked(&mut plain)?;
        plain.extend_from_slice(payload);
        let ciphertext = self.key.body(&self.subkey, &header[4..16], &plain, true)?;
        let mut packet = self.key.header(header, true)?.to_vec();
        packet.extend_from_slice(&ciphertext);
        Ok(packet)
    }
    /// ChaCha：24 字节明文 nonce + AEAD 密文；密文内先有 session id / packet id。
    fn seal_chacha(
        &self,
        id: u64,
        body: &[u8],
        target: &TargetAddr,
        payload: &[u8],
        padding: u16,
    ) -> Result<Vec<u8>, Error> {
        let prefix_len = UDP_PACKET_PREFIX_LEN
            .checked_add(body.len())
            .ok_or(Error::Length)?;
        self.total_len(prefix_len, target, payload, padding)?;
        let mut nonce = [0; 24];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::Entropy)?;
        let mut plain = Vec::with_capacity(prefix_len);
        plain.extend_from_slice(&self.session_id);
        plain.extend_from_slice(&id.to_be_bytes());
        plain.extend_from_slice(body);
        plain.resize(plain.len() + padding as usize, 0);
        target.encode_checked(&mut plain)?;
        plain.extend_from_slice(payload);
        let ciphertext = self.key.body(&[], &nonce, &plain, true)?;
        let mut packet = nonce.to_vec();
        packet.extend_from_slice(&ciphertext);
        Ok(packet)
    }
    fn total_len(
        &self,
        body_len: usize,
        target: &TargetAddr,
        payload: &[u8],
        padding: u16,
    ) -> Result<usize, Error> {
        let address_len = {
            let mut buffer = Vec::new();
            target.encode_checked(&mut buffer)?;
            buffer.len()
        };
        let total = body_len
            .checked_add(padding as usize)
            .and_then(|n| n.checked_add(address_len))
            .and_then(|n| n.checked_add(payload.len()))
            .ok_or(Error::Length)?;
        if total > 65507 {
            return Err(Error::Length);
        }
        Ok(total)
    }
}

impl Key {
    /// 仅在 AEAD、方向、时间和目标验证成功后返回。上层还须检查每会话重放窗口。
    pub fn open_client(&self, packet: &[u8], now: u64) -> Result<Decoded, Error> {
        self.open(packet, now, None)
    }
    /// 响应中的 client session 必须与当前发送会话精确匹配。
    pub fn open_server(&self, packet: &[u8], now: u64, client: [u8; 8]) -> Result<Decoded, Error> {
        self.open(packet, now, Some(client))
    }
    fn open(
        &self,
        packet: &[u8],
        now: u64,
        expected_client: Option<[u8; 8]>,
    ) -> Result<Decoded, Error> {
        match self.method() {
            Method::ChaCha20 => self.open_chacha(packet, now, expected_client),
            _ => self.open_aes(packet, now, expected_client),
        }
    }
    fn open_aes(
        &self,
        packet: &[u8],
        now: u64,
        expected_client: Option<[u8; 8]>,
    ) -> Result<Decoded, Error> {
        if packet.len() < 32 || packet.len() > 65507 {
            return Err(Error::Length);
        }
        let header = self.header(packet[..16].try_into().expect("已校验长度"), false)?;
        let session_id = header[..8].try_into().expect("固定长度");
        let packet_id = u64::from_be_bytes(header[8..].try_into().expect("固定长度"));
        let subkey = self.subkey(&header[..8]);
        let plaintext = self.body(&subkey, &header[4..16], &packet[16..], false)?;
        decode_body(plaintext, session_id, packet_id, now, expected_client)
    }
    /// ChaCha：包首 24 字节明文 nonce，其后是 AEAD 密文；session/packet id 在密文内。
    fn open_chacha(
        &self,
        packet: &[u8],
        now: u64,
        expected_client: Option<[u8; 8]>,
    ) -> Result<Decoded, Error> {
        let nonce_len = self.method().udp_nonce_len();
        if packet.len() < nonce_len + TAG_LEN || packet.len() > 65507 {
            return Err(Error::Length);
        }
        let (nonce, ciphertext) = packet.split_at(nonce_len);
        let plaintext = self.body(&[], nonce, ciphertext, false)?;
        if plaintext.len() < UDP_PACKET_PREFIX_LEN {
            return Err(Error::Length);
        }
        let session_id = plaintext[..8].try_into().expect("固定长度");
        let packet_id = u64::from_be_bytes(plaintext[8..16].try_into().expect("固定长度"));
        decode_body(
            plaintext[16..].to_vec(),
            session_id,
            packet_id,
            now,
            expected_client,
        )
    }
}

/// 解码认证后的明文体（方向字节起），校验方向、时间戳、客户端会话。
fn decode_body(
    plaintext: Vec<u8>,
    session_id: [u8; 8],
    packet_id: u64,
    now: u64,
    expected_client: Option<[u8; 8]>,
) -> Result<Decoded, Error> {
    let mut cursor = Cursor {
        bytes: &plaintext,
        offset: 0,
    };
    if cursor.take(1)?[0] != u8::from(expected_client.is_some()) {
        return Err(Error::Direction);
    }
    let timestamp = u64::from_be_bytes(cursor.take(8)?.try_into().expect("固定长度"));
    if timestamp.abs_diff(now) > 30 {
        return Err(Error::Timestamp);
    }
    let client_session = if let Some(expected) = expected_client {
        let actual: [u8; 8] = cursor.take(8)?.try_into().expect("固定长度");
        if actual != expected {
            return Err(Error::ClientSession);
        }
        Some(actual)
    } else {
        None
    };
    let padding = u16::from_be_bytes(cursor.take(2)?.try_into().expect("固定长度"));
    cursor.take(padding as usize)?;
    let (target, used) = TargetAddr::decode(&plaintext[cursor.offset..])?;
    cursor.offset += used;
    Ok(Decoded {
        session_id,
        packet_id,
        client_session,
        target,
        payload: plaintext[cursor.offset..].to_vec(),
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(length).ok_or(Error::Length)?;
        let bytes = self.bytes.get(self.offset..end).ok_or(Error::Length)?;
        self.offset = end;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Method;

    /// 最后一个计数器只能用一次，随后耗尽；AES 与 ChaCha 都要覆盖。
    #[test]
    fn final_counter_is_used_once_then_exhausted() {
        for (method, psk) in [
            (Method::Aes128, vec![0x11; 16]),
            (Method::ChaCha20, vec![0x11; 32]),
        ] {
            let key = Key::new(method, &psk).unwrap();
            let mut sender = Sender::new(key.clone(), None).unwrap();
            sender.next = Some(u64::MAX);
            let packet = sender
                .seal(&TargetAddr::V4([1; 4], 1), b"", 1000, 0)
                .unwrap();
            assert_eq!(key.open_client(&packet, 1000).unwrap().packet_id, u64::MAX);
            assert!(matches!(
                sender.seal(&TargetAddr::V4([1; 4], 1), b"", 1000, 0),
                Err(Error::Exhausted)
            ));
        }
    }

    /// 认证通过但 padding 声明越界，必须在读取时拒绝（fail-closed）。
    #[test]
    fn authenticated_malformed_padding_is_rejected() {
        let key = Key::new(Method::Aes128, &[0x11; 16]).unwrap();
        let sender = Sender::new(key.clone(), None).unwrap();
        let mut header = [0; 16];
        header[..8].copy_from_slice(&sender.session_id());
        let mut body = vec![0];
        body.extend_from_slice(&1000u64.to_be_bytes());
        body.extend_from_slice(&u16::MAX.to_be_bytes());
        let mut packet = key.header(header, true).unwrap().to_vec();
        packet.extend_from_slice(&key.body(&sender.subkey, &header[4..], &body, true).unwrap());
        assert!(matches!(key.open_client(&packet, 1000), Err(Error::Length)));
    }

    /// ChaCha 的线上布局：24 字节明文 nonce + 密文，密文内先 session id 再 packet id。
    #[test]
    fn chacha_roundtrip_uses_24_byte_plaintext_nonce() {
        let key = Key::new(Method::ChaCha20, &[0x11; 32]).unwrap();
        let mut sender = Sender::new(key.clone(), None).unwrap();
        let packet = sender
            .seal(&TargetAddr::V4([127, 0, 0, 1], 53), b"hello", 1000, 0)
            .unwrap();
        // 24 nonce + 8 session + 8 packet id + 1 direction + 8 ts + 2 pad
        // + addrport(1+4+2) + payload(5) + tag(16)
        assert_eq!(packet.len(), 24 + 16 + 1 + 8 + 2 + 7 + 5 + 16);
        let decoded = key.open_client(&packet, 1000).unwrap();
        assert_eq!(decoded.session_id, sender.session_id());
        assert_eq!(decoded.packet_id, 0);
        assert_eq!(decoded.payload, b"hello");
        assert_eq!(decoded.target, TargetAddr::V4([127, 0, 0, 1], 53));
    }

    /// 长度上限：ChaCha 的 nonce 属于开销，可用载荷比 AES 少 8 字节。
    #[test]
    fn chacha_enforces_datagram_ceiling() {
        let key = Key::new(Method::ChaCha20, &[0x11; 32]).unwrap();
        let mut sender = Sender::new(key.clone(), None).unwrap();
        let target = TargetAddr::V4([1; 4], 1);
        assert!(matches!(
            sender.seal(&target, &vec![0; 65507], 1, 0),
            Err(Error::Length)
        ));
        // 24 nonce + 16 session/packet id + 1 direction + 8 ts + 2 padlen
        // + 7 addrport + 16 tag = 74 字节固定开销。
        let limit = 65507 - 74;
        let packet = sender.seal(&target, &vec![0; limit], 1, 0).unwrap();
        assert_eq!(packet.len(), 65507);
        assert_eq!(key.open_client(&packet, 1).unwrap().payload.len(), limit);
    }

    /// 不足一个 nonce + tag 的短包必须在解密前拒绝。
    #[test]
    fn chacha_short_packet_is_rejected() {
        let key = Key::new(Method::ChaCha20, &[0x11; 32]).unwrap();
        assert!(matches!(
            key.open_client(&[0; 39], 1000),
            Err(Error::Length)
        ));
    }
}
