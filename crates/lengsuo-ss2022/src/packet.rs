//! AES UDP separate header + AEAD body。会话状态必须由可信、按环境隔离的运行时保存。
//! 本模块解码不做重放判定；返回值不得直接当作可转发请求。
use crate::{crypto::Key, Error};
use ss_core::target::TargetAddr;

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
        let mut address = Vec::new();
        target.encode_checked(&mut address)?;
        let header_len = if self.client_session.is_some() {
            19
        } else {
            11
        };
        let total = 32usize
            .checked_add(header_len)
            .and_then(|n| n.checked_add(padding as usize))
            .and_then(|n| n.checked_add(address.len()))
            .and_then(|n| n.checked_add(payload.len()))
            .ok_or(Error::Length)?;
        if total > 65507 {
            return Err(Error::Length);
        }
        let mut header = [0; 16];
        header[..8].copy_from_slice(&self.session_id);
        header[8..].copy_from_slice(&id.to_be_bytes());
        let mut body = Vec::with_capacity(total - 32);
        body.push(u8::from(self.client_session.is_some()));
        body.extend_from_slice(&now.to_be_bytes());
        if let Some(client) = self.client_session {
            body.extend_from_slice(&client);
        }
        body.extend_from_slice(&padding.to_be_bytes());
        body.resize(body.len() + padding as usize, 0);
        body.extend_from_slice(&address);
        body.extend_from_slice(payload);
        let ciphertext = self.key.body(&self.subkey, &header[4..16], &body, true)?;
        let mut packet = self.key.header(header, true)?.to_vec();
        packet.extend_from_slice(&ciphertext);
        self.next = id.checked_add(1);
        Ok(packet)
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
        if packet.len() < 32 || packet.len() > 65507 {
            return Err(Error::Length);
        }
        let header = self.header(packet[..16].try_into().expect("已校验长度"), false)?;
        let session_id = header[..8].try_into().expect("固定长度");
        let packet_id = u64::from_be_bytes(header[8..].try_into().expect("固定长度"));
        let subkey = self.subkey(&header[..8]);
        let plaintext = self.body(&subkey, &header[4..16], &packet[16..], false)?;
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

    #[test]
    fn final_counter_is_used_once_then_exhausted() {
        let key = Key::new(Method::Aes128, &[0x11; 16]).unwrap();
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
}
