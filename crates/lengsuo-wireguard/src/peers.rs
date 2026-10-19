//! 多 peer 配置装载与定向：本端可同时与多个对端并存，每个 peer 有独立的
//! allowedIPs、keepalive 与 index。
//!
//! 对照参考：
//! - Xray `proxy/wireguard/config.pb.go` 的 `PeerConfig{PublicKey, PreSharedKey,
//!   Endpoint, KeepAlive, AllowedIps}` 与 `wireguard.go:createIPCRequest` 的
//!   peers 数组语义（一对多条 `public_key=` / `allowed_ip=` / ... 记录）。
//! - wireguard-go `device/peer.go`：`Peer` 持 `handshake`/`keypairs`，
//!   通过 device 的全局 index 表把接收报文定向回 peer。
//!
//! 本模块只做**纯配置装载 + 定向查询**，不建立 socket / TUN。

use crate::allowedips::AllowedIps;

/// peer 的最大数量，对照 `MaxPeers = 1 << 16`。
pub const MAX_PEERS: usize = 1 << 16;

/// 单个 peer 的配置。对照 Xray `PeerConfig`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    /// 对端公钥（32 字节，WireGuard 公钥长度）。
    pub public_key: [u8; 32],
    /// 可选预共享密钥（32 字节）。
    pub preshared_key: Option<[u8; 32]>,
    /// `PersistentKeepalive` 秒数，0 表示关闭。
    pub keepalive: u16,
}

/// 已装载的一个 peer 及其在本地的编号。
///
/// 注意：`AllowedIps` 未实现 `Debug`/`Clone`（既有模块如此），故 `Peer`
/// 同样不派生这些 trait；查询走 `get`/`iter` 的借用接口。
pub struct Peer {
    /// 本 crate 内部编号，同时是 index 表里 `IndexEntry.peer` 的取值。
    pub id: usize,
    /// 配置。
    pub config: PeerConfig,
    /// 该 peer 的 allowedIPs 集合（与此 peer 绑定）。
    pub allowed_ips: AllowedIps,
}

/// 装载/查询失败（fail-closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerError {
    /// 公钥重复：同一公钥只能配置一次（对照参考按公钥去重）。
    DuplicatePublicKey,
    /// 超过 `MAX_PEERS`。
    TooManyPeers,
    /// 找不到指定 peer。
    NotFound,
}

/// 多 peer 表。按 id 与公钥双向索引。
pub struct PeerSet {
    peers: Vec<Peer>,
}

impl Default for PeerSet {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerSet {
    #[must_use]
    pub fn new() -> Self {
        Self { peers: Vec::new() }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// 装载一个 peer，返回其内部 id。
    ///
    /// fail-closed：公钥重复或超上限都返回 `Err`，不静默覆盖既有 peer。
    pub fn add(&mut self, config: PeerConfig) -> Result<usize, PeerError> {
        if self.peers.len() >= MAX_PEERS {
            return Err(PeerError::TooManyPeers);
        }
        if self
            .peers
            .iter()
            .any(|p| p.config.public_key == config.public_key)
        {
            return Err(PeerError::DuplicatePublicKey);
        }
        let id = self.peers.len();
        self.peers.push(Peer {
            id,
            config,
            allowed_ips: AllowedIps::new(),
        });
        Ok(id)
    }

    /// 按 id 查 peer。
    #[must_use]
    pub fn get(&self, id: usize) -> Option<&Peer> {
        self.peers.get(id)
    }

    /// 按 id 查 peer（可变，用于装配 allowedIPs）。
    pub fn get_mut(&mut self, id: usize) -> Option<&mut Peer> {
        self.peers.get_mut(id)
    }

    /// 按公钥查 peer（对照参考以公钥为 peer 身份）。
    #[must_use]
    pub fn find_by_key(&self, public_key: &[u8; 32]) -> Option<&Peer> {
        self.peers
            .iter()
            .find(|p| &p.config.public_key == public_key)
    }

    /// 移除一个 peer，返回其配置。移除后应同时回收其 index
    /// （由调用方配合 `IndexTable::delete_peer`，见 `device`）。
    ///
    /// 注意：移除会**重排后续 peer 的 id**（这是本实现的简化的代价，
    /// 见偏离清单）；调用方应在移除后重建指向 id 的外部引用。
    pub fn remove_by_key(&mut self, public_key: &[u8; 32]) -> Option<PeerConfig> {
        let pos = self
            .peers
            .iter()
            .position(|p| &p.config.public_key == public_key)?;
        let removed = self.peers.remove(pos);
        for (i, p) in self.peers.iter_mut().enumerate() {
            p.id = i;
        }
        Some(removed.config)
    }

    /// 遍历所有 peer。
    pub fn iter(&self) -> impl Iterator<Item = &Peer> {
        self.peers.iter()
    }
}
