//! 多 peer 配置装载与定向：本端可同时与多个对端并存，每个 peer 有独立的
//! allowedIPs、keepalive、index 与 endpoint（源地址）。
//!
//! 对照参考：
//! - Xray `proxy/wireguard/config.pb.go` 的 `PeerConfig{PublicKey, PreSharedKey,
//!   Endpoint, KeepAlive, AllowedIps}` 与 `wireguard.go:createIPCRequest` 的
//!   peers 数组语义（一对多条 `public_key=` / `allowed_ip=` / ... 记录）。
//! - wireguard-go `device/peer.go`：`Peer` 持 `handshake`/`keypairs`，
//!   通过 device 的全局 index 表把接收报文定向回 peer；同文件的
//!   `Peer.SetEndpointFromPacket`（commit
//!   `2631ce99a06f27120d581611cf125d68bc6aa565`）用**收到报文的源地址**
//!   覆盖 `Peer.endpoint`（`endpoint-mutex` 保护）⇒ 对端换网络后仍能回包。
//!
//! 本模块只做**纯配置装载 + 定向查询 + endpoint 漫游判定**，不建立 socket / TUN。

use std::net::SocketAddr;

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
    /// 该 peer 当前的 endpoint（源地址），`None` 表示尚未建立。
    ///
    /// 这是**运行时状态**而非配置项（故不在 `PeerConfig` 里）：它随对端
    /// 网络切换而变，由 `PeerSet::set_peer_endpoint` 更新。
    pub endpoint: Option<SocketAddr>,
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
            endpoint: None,
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

    /// 设置/更新某个 peer 的 endpoint（漫游）。`None` 表示清除。
    ///
    /// 找不到 peer ⇒ 返回 `Err(PeerError::NotFound)`（fail-closed，不静默忽略）。
    ///
    /// 对照参考 wireguard-go `device/peer.go` 的 `Peer.SetEndpointFromPacket`
    /// （commit `2631ce99a06f27120d581611cf125d68bc6aa565`）：用报文的源
    /// 地址直接覆盖旧值，不比较新旧是否相同。
    pub fn set_peer_endpoint(
        &mut self,
        id: usize,
        endpoint: Option<SocketAddr>,
    ) -> Result<(), PeerError> {
        let peer = self.peers.get_mut(id).ok_or(PeerError::NotFound)?;
        peer.endpoint = endpoint;
        Ok(())
    }

    /// 读某个 peer 的 endpoint。peer 不存在或尚未建立 ⇒ `None`。
    #[must_use]
    pub fn endpoint(&self, id: usize) -> Option<SocketAddr> {
        self.peers.get(id).and_then(|p| p.endpoint)
    }
}

/// 漫游判定：收到一个「源地址」，与该 peer 当前 endpoint 比较。
///
/// - `None`（本端还不知道 endpoint）⇒ 接受（首次建链）
/// - 与当前 endpoint 相同 ⇒ 接受（未漫游）
/// - 与当前 endpoint 不同 ⇒ **接受并要求更新**（漫游，源地址已变）
///
/// 返回 `true` 表示「需要把该 peer 的 endpoint 更新为 `src`」。
///
/// 判定**只用地址相等性**，不做端口范围 / 同网段猜测。
///
/// ⛔ 漫游是**允许**的：地址变了**不得**据此拒绝收包——那会打断漫游。
/// 对端在 NAT 后换网络时源 IP 与源端口都可能变，若不更新 endpoint，
/// 之后所有响应仍发往旧地址 ⇒ 链路直接断。
#[must_use]
pub fn should_roam(current: Option<SocketAddr>, src: SocketAddr) -> bool {
    current != Some(src)
}
