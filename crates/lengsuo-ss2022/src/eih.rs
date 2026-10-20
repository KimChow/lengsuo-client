//! SIP023 可扩展身份头（EIH）：TCP 多用户身份链。
//!
//! 逐字节对齐固定参考 Xray `d2758a02` 经 `sing-shadowsocks v0.2.7`
//! `shadowaead_2022` 的实现（`writeExtendedIdentityHeaders` /
//! `MultiService.NewConnection0`）：
//!
//! - 身份头固定 **16 字节**（一个 AES 块），位于请求 salt 之后、AEAD 固定头之前；
//! - 第 n 层：`identity_subkey = BLAKE3-derive_key("shadowsocks 2022 identity subkey",
//!   iPSK_n || salt)`，`plaintext = BLAKE3-512(iPSK_{n+1})[0..16]`，
//!   `header = AES-ECB-encrypt(identity_subkey, plaintext)`；
//! - 客户端有 N 个身份 PSK 时写 N 层，最后一层的明文中是**最终用户 PSK**的指纹；
//! - 服务端解一层后用 16 字节指纹查用户表；AXray `MultiService` 只解一层，
//!   中继可以逐层剥离并把余下请求原样转发。
//!
//! 与任务书文字的差异（详见 `docs/ss2022-status.md` 偏离清单）：固定参考的线上
//! **没有** `0xEIH` 标记、u64 uid 或变长整数编码，身份由 16 字节 PSK 指纹标识。
//! 本模块因此以参考线格式为准；`uid` 只是本 crate 为服务端路由分配的**本地**
//! 用户标识，不进入线上字节。SIP023 的 UDP 侧扩展（separate header 重加密）
//! **未实现**，本模块只服务 TCP。
//!
//! 失败一律 fail-closed：身份头截断、未知指纹、链超限、算法不支持都返回
//! [`Error`]，绝不回退到单用户 PSK。所有错误与 `Debug` 均不含 PSK 或密文。
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{
    crypto::{Key, Method},
    receiver::Clock,
    tcp::{
        receive::{Opened, Reader, SessionReplay},
        Direction,
    },
    Error,
};

/// 单个身份头线上长度：一个 AES 块。
pub const IDENTITY_HEADER_LEN: usize = 16;
/// 身份指纹长度：`BLAKE3-512(PSK)` 的前 16 字节。
pub const IDENTITY_HASH_LEN: usize = 16;
/// 身份子密钥派生上下文，与参考 `blake3.DeriveKey` 逐字节一致。
pub const IDENTITY_SUBKEY_CONTEXT: &str = "shadowsocks 2022 identity subkey";
/// 本实现允许的最大身份层数（策略上限，参考实现未设上限）。
///
/// 不设上限会让对端用无限身份头拖住解析；超过该值一律
/// [`Error::EihChainTooLong`]。与参考的差异记入偏离清单。
pub const MAX_IDENTITY_LAYERS: usize = 8;

/// 一个本地用户：`uid` 只在本 crate 内有意义，线上标识是 `key` 的 16 字节指纹。
pub struct User {
    pub uid: u64,
    pub key: Key,
}

/// 用户表：按 16 字节指纹索引，重复 uid 或重复指纹在构造期拒绝。
pub struct UserTable {
    users: Vec<User>,
    by_hash: BTreeMap<[u8; IDENTITY_HASH_LEN], usize>,
    method: Method,
}

impl UserTable {
    /// 用户不得为空；所有用户必须同属一种 AES 套件，uid 与指纹均不得重复。
    pub fn new(users: Vec<User>) -> Result<Self, Error> {
        if users.is_empty() {
            return Err(Error::EihUserTable);
        }
        let method = users[0].key.method();
        require_aes(method)?;
        let mut by_hash = BTreeMap::new();
        let mut uids = BTreeSet::new();
        for (index, user) in users.iter().enumerate() {
            if user.key.method() != method || !uids.insert(user.uid) {
                return Err(Error::EihUserTable);
            }
            if by_hash.insert(user.key.identity_hash(), index).is_some() {
                return Err(Error::EihUserTable);
            }
        }
        Ok(Self {
            users,
            by_hash,
            method,
        })
    }

    /// 用户表所属套件。
    pub fn method(&self) -> Method {
        self.method
    }

    /// 用户数。
    pub fn len(&self) -> usize {
        self.users.len()
    }

    /// 是否为空（构造期已拒绝空表，恒为 `false`；保留以配合 clippy）。
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    /// 按身份指纹查找用户。
    pub fn lookup(&self, hash: &[u8; IDENTITY_HASH_LEN]) -> Option<&User> {
        self.by_hash.get(hash).map(|index| &self.users[*index])
    }

    /// 按本地 uid 查找用户。
    pub fn by_uid(&self, uid: u64) -> Option<&User> {
        self.users.iter().find(|user| user.uid == uid)
    }
}

/// 客户端身份链：前 n 个是身份 PSK，最后一个 `final_key` 是最终用户 PSK。
pub struct IdentityChain {
    identity_keys: Vec<Key>,
    final_key: Key,
}

impl IdentityChain {
    /// 构造链；层数受 [`MAX_IDENTITY_LAYERS`] 约束，所有密钥必须同套件且为 AES。
    pub fn new(identity_keys: Vec<Key>, final_key: Key) -> Result<Self, Error> {
        if identity_keys.len() > MAX_IDENTITY_LAYERS {
            return Err(Error::EihChainTooLong);
        }
        require_aes(final_key.method())?;
        for key in &identity_keys {
            if key.method() != final_key.method() {
                return Err(Error::KeyLength);
            }
        }
        Ok(Self {
            identity_keys,
            final_key,
        })
    }

    /// 由有序 PSK 列表构造：`[iPSK0, iPSK1, ..., uPSK]`；只有一个元素即单用户。
    pub fn from_psks(psks: &[Key]) -> Result<Self, Error> {
        let (final_key, identity_keys) = psks.split_last().ok_or(Error::EihMissing)?;
        Self::new(identity_keys.to_vec(), final_key.clone())
    }

    /// 最终用户 PSK 对应的密钥（AEAD 会话密钥由它与 salt 派生）。
    pub fn final_key(&self) -> &Key {
        &self.final_key
    }

    /// 身份头层数；0 表示单用户（不写任何身份头）。
    pub fn layers(&self) -> usize {
        self.identity_keys.len()
    }

    /// 按参考线格式生成 `layers * 16` 字节身份头。
    pub fn headers(&self, salt: &[u8]) -> Result<Vec<u8>, Error> {
        if salt.len() != self.final_key.method().key_len() {
            return Err(Error::KeyLength);
        }
        let mut headers = Vec::with_capacity(self.identity_keys.len() * IDENTITY_HEADER_LEN);
        for (index, current) in self.identity_keys.iter().enumerate() {
            let next = self.identity_keys.get(index + 1).unwrap_or(&self.final_key);
            let subkey = current.identity_subkey(salt);
            let encrypted = Key::identity_block(&subkey, next.identity_hash(), true)?;
            headers.extend_from_slice(&encrypted);
        }
        Ok(headers)
    }
}

/// 解出的身份链（本地语义）。线上没有 uid；`uid` 由 [`UserTable`] 把指纹映射而来。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EihHeader {
    pub uid: u64,
    pub next: Option<Box<EihHeader>>,
}

impl EihHeader {
    /// 链上节点数（含本节点）。
    pub fn len(&self) -> usize {
        1 + self.next.as_ref().map_or(0, |next| next.len())
    }

    /// 至少有一个节点，恒为 `false`；保留以配合 clippy。
    pub fn is_empty(&self) -> bool {
        false
    }

    /// 按链序收集 uid。
    pub fn uids(&self) -> Vec<u64> {
        let mut uids = Vec::with_capacity(self.len());
        let mut cursor = Some(self);
        while let Some(node) = cursor {
            uids.push(node.uid);
            cursor = node.next.as_deref();
        }
        uids
    }

    /// 把本地 uid 链编码为参考线格式：`identity` 是当前身份 PSK（服务端 PSK 或
    /// 上一跳解析出的 PSK），`salt` 是请求 salt。链上每个 uid 都必须在用户表中；
    /// 未知 uid 一律 [`Error::IdentityUnknown`]，不回退。
    pub fn encode(&self, identity: &Key, users: &UserTable, salt: &[u8]) -> Result<Vec<u8>, Error> {
        require_aes(identity.method())?;
        if identity.method() != users.method() || salt.len() != identity.method().key_len() {
            return Err(Error::KeyLength);
        }
        let mut node_keys = Vec::with_capacity(self.len());
        let mut cursor = Some(self);
        while let Some(node) = cursor {
            node_keys.push(
                users
                    .by_uid(node.uid)
                    .ok_or(Error::IdentityUnknown)?
                    .key
                    .clone(),
            );
            cursor = node.next.as_deref();
        }
        if node_keys.len() > MAX_IDENTITY_LAYERS {
            return Err(Error::EihChainTooLong);
        }
        let mut current = identity.clone();
        let mut headers = Vec::with_capacity(node_keys.len() * IDENTITY_HEADER_LEN);
        for user_key in node_keys {
            let subkey = current.identity_subkey(salt);
            let encrypted = Key::identity_block(&subkey, user_key.identity_hash(), true)?;
            headers.extend_from_slice(&encrypted);
            current = user_key;
        }
        Ok(headers)
    }
}

/// 服务端解开的一层身份：本地 uid + 该用户 PSK（后续层或 AEAD 使用）。
pub struct ResolvedIdentity {
    pub uid: u64,
    pub key: Key,
}

/// 解开**一层**身份头。`headers` 至少 16 字节，多余字节留给下一层/中继。
///
/// 未知指纹、截断、非 AES 套件、salt 长度不符一律 `Err`，不回退单用户。
pub fn decode_header(
    identity: &Key,
    users: &UserTable,
    salt: &[u8],
    headers: &[u8],
) -> Result<ResolvedIdentity, Error> {
    require_aes(identity.method())?;
    if identity.method() != users.method() {
        return Err(Error::KeyLength);
    }
    if salt.len() != identity.method().key_len() {
        return Err(Error::KeyLength);
    }
    if headers.len() < IDENTITY_HEADER_LEN {
        return Err(Error::EihTruncated);
    }
    let block = headers[..IDENTITY_HEADER_LEN]
        .try_into()
        .map_err(|_| Error::EihTruncated)?;
    let subkey = identity.identity_subkey(salt);
    let hash = Key::identity_block(&subkey, block, false)?;
    let user = users.lookup(&hash).ok_or(Error::IdentityUnknown)?;
    Ok(ResolvedIdentity {
        uid: user.uid,
        key: user.key.clone(),
    })
}

/// 逐层解开 `layers` 层身份头，返回链式 [`EihHeader`] 与实际消费的字节数。
///
/// 每一层的下一个身份 PSK 都来自上一层的指纹查找；任何一层未知即整体失败。
/// `layers == 0` 视为缺少 EIH，`layers > MAX_IDENTITY_LAYERS` 直接拒绝。
pub fn decode_chain(
    identity: &Key,
    users: &UserTable,
    salt: &[u8],
    headers: &[u8],
    layers: usize,
) -> Result<(EihHeader, usize), Error> {
    if layers == 0 {
        return Err(Error::EihMissing);
    }
    if layers > MAX_IDENTITY_LAYERS {
        return Err(Error::EihChainTooLong);
    }
    let consumed = layers
        .checked_mul(IDENTITY_HEADER_LEN)
        .ok_or(Error::Length)?;
    if headers.len() < consumed {
        return Err(Error::EihTruncated);
    }
    let mut current = identity.clone();
    let mut uids = Vec::with_capacity(layers);
    for index in 0..layers {
        let start = index * IDENTITY_HEADER_LEN;
        let resolved = decode_header(
            &current,
            users,
            salt,
            &headers[start..start + IDENTITY_HEADER_LEN],
        )?;
        uids.push(resolved.uid);
        current = resolved.key;
    }
    // 按链序反转构建，`next` 指向下一层（最后一层为 None）。
    let mut chain: Option<EihHeader> = None;
    for uid in uids.into_iter().rev() {
        chain = Some(EihHeader {
            uid,
            next: chain.map(Box::new),
        });
    }
    Ok((chain.ok_or(Error::EihMissing)?, consumed))
}

/// 服务端身份读取器：固定「服务端身份 PSK + 用户表」，只解一层（与 Xray 对齐）。
pub struct EihServer {
    identity: Key,
    users: UserTable,
    read_timeout: Duration,
}

impl EihServer {
    /// 身份 PSK 与用户表必须同套件；读超时必须为正。
    pub fn new(identity: Key, users: UserTable, read_timeout: Duration) -> Result<Self, Error> {
        require_aes(identity.method())?;
        if identity.method() != users.method() {
            return Err(Error::KeyLength);
        }
        if read_timeout.is_zero() {
            return Err(Error::SessionPolicy);
        }
        Ok(Self {
            identity,
            users,
            read_timeout,
        })
    }

    /// 读取 `salt || 一层身份头` 并解析出用户。缺 EIH 时直接
    /// [`Error::IdentityUnknown`]（截断则是 [`Error::EihTruncated`]），绝不回退。
    pub async fn read_identity<R: AsyncRead + Unpin>(
        &self,
        stream: &mut R,
    ) -> Result<(Vec<u8>, ResolvedIdentity), Error> {
        let mut salt = vec![0u8; self.identity.method().key_len()];
        self.read_exact(stream, &mut salt).await?;
        let mut header = [0u8; IDENTITY_HEADER_LEN];
        self.read_exact(stream, &mut header).await?;
        let resolved = decode_header(&self.identity, &self.users, &salt, &header)?;
        Ok((salt, resolved))
    }

    /// 完整服务端开场：读出身份 → 用该用户密钥构造 [`Reader`] → 校验余下开场。
    /// 返回 `(reader, opened, uid)`；任何失败都不会退回单用户 PSK。
    pub async fn accept<R: AsyncRead + Unpin>(
        &self,
        stream: &mut R,
        replay: &mut SessionReplay,
        now: Clock,
    ) -> Result<(Reader, Opened, u64), Error> {
        let (salt, resolved) = self.read_identity(stream).await?;
        let uid = resolved.uid;
        let mut reader = Reader::new(resolved.key, Direction::Request, self.read_timeout)?;
        let opened = reader
            .open_after_salt(stream, replay, now, None, salt)
            .await?;
        Ok((reader, opened, uid))
    }

    async fn read_exact<R: AsyncRead + Unpin>(
        &self,
        stream: &mut R,
        buffer: &mut [u8],
    ) -> Result<(), Error> {
        match tokio::time::timeout(self.read_timeout, stream.read_exact(buffer)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                Err(Error::EihTruncated)
            }
            Ok(Err(error)) => Err(Error::Io(error)),
            Err(_) => Err(Error::Timeout),
        }
    }
}

/// 身份头只定义在 AES 套件上；参考 `MultiService` 也显式拒绝 ChaCha20。
fn require_aes(method: Method) -> Result<(), Error> {
    match method {
        Method::Aes128 | Method::Aes256 => Ok(()),
        Method::ChaCha20 => Err(Error::Unsupported),
    }
}
