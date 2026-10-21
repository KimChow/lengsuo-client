//! endpoint 漫游：peer 源地址的更新 / 清除 + 漫游判定 + 源地址校验。
//!
//! 跨端 P2P 的前提：移动端在 NAT 后切换网络（换 Wi-Fi / 4G 切换）时
//! **公网映射地址会变**（源 IP 与源端口都可能变）。对端若不更新 endpoint，
//! 漫游后所有响应仍发往旧地址 ⇒ 链路直接断。
//!
//! 参考：wireguard-go `device/peer.go` 的 `Peer.SetEndpointFromPacket`
//! （commit `2631ce99a06f27120d581611cf125d68bc6aa565`）——在收到合法
//! 握手/传输报文后用报文的**源地址**覆盖 `Peer.endpoint`（`endpoint-mutex`
//! 保护）；`device/receive.go` 里认证失败的报文直接 `goto skip`，
//! **不碰** endpoint。
//!
//! 本仓只提供**纯逻辑 API**：隧道层拿到 UDP 收包的源地址后调
//! `PeerSet::set_peer_endpoint`，接线属 `wg-tunnel` 卡。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

// `peers` 以**模块名**引入：使 `#[path]` 包含进来的 device.rs 内部
// `crate::peers::...` 路径能解析（本测试 crate 的 crate root）。
use lengsuo_wireguard::peers::{should_roam, PeerConfig, PeerError, PeerSet};

// `src/device.rs` 目前**未在 `src/lib.rs` 声明**（不在 crate 的编译单元里），
// 故此处用 `#[path]` 直接包含该文件，使本卡的 device 侧逻辑真正被编译与
// 测试覆盖。`use` 列表提供 device.rs 内部 `crate::` 路径所需的模块名。

fn key(b: u8) -> [u8; 32] {
    [b; 32]
}

fn cfg(b: u8) -> PeerConfig {
    PeerConfig {
        public_key: key(b),
        preshared_key: None,
        keepalive: 25,
    }
}

fn v4(last: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)), port)
}

fn v6(port: u16) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        port,
    )
}

// ---------- PeerSet::set_peer_endpoint / endpoint ----------

#[test]
fn newly_added_peer_has_no_endpoint() {
    let mut set = PeerSet::new();
    let id = set.add(cfg(1)).unwrap();
    assert_eq!(set.endpoint(id), None);
}

#[test]
fn set_peer_endpoint_on_existing_peer_reads_back() {
    let mut set = PeerSet::new();
    let id = set.add(cfg(1)).unwrap();
    let addr = v4(10, 51820);
    assert_eq!(set.set_peer_endpoint(id, Some(addr)), Ok(()));
    assert_eq!(set.endpoint(id), Some(addr));
    // Peer 自身的字段与 PeerSet 读接口一致。
    assert_eq!(set.get(id).unwrap().endpoint, Some(addr));
}

#[test]
fn set_peer_endpoint_on_missing_peer_is_rejected() {
    // fail-closed：找不到 peer 必须报错，不得静默成功。
    let mut set = PeerSet::new();
    set.add(cfg(1)).unwrap();
    assert_eq!(
        set.set_peer_endpoint(9, Some(v4(10, 51820))),
        Err(PeerError::NotFound)
    );
    // 失败不得改动任何 peer 的 endpoint。
    assert_eq!(set.endpoint(0), None);
}

#[test]
fn set_peer_endpoint_with_none_clears_endpoint() {
    let mut set = PeerSet::new();
    let id = set.add(cfg(1)).unwrap();
    set.set_peer_endpoint(id, Some(v4(10, 51820))).unwrap();
    assert_eq!(set.endpoint(id), Some(v4(10, 51820)));
    assert_eq!(set.set_peer_endpoint(id, None), Ok(()));
    assert_eq!(set.endpoint(id), None);
}

#[test]
fn set_peer_endpoint_overwrites_previous_address() {
    // 对照参考 `SetEndpointFromPacket`：新源地址直接覆盖旧值。
    let mut set = PeerSet::new();
    let id = set.add(cfg(1)).unwrap();
    set.set_peer_endpoint(id, Some(v4(10, 51820))).unwrap();
    set.set_peer_endpoint(id, Some(v4(11, 40001))).unwrap();
    assert_eq!(set.endpoint(id), Some(v4(11, 40001)));
}

#[test]
fn endpoint_is_bound_per_peer() {
    let mut set = PeerSet::new();
    let a = set.add(cfg(1)).unwrap();
    let b = set.add(cfg(2)).unwrap();
    set.set_peer_endpoint(a, Some(v4(10, 51820))).unwrap();
    assert_eq!(set.endpoint(a), Some(v4(10, 51820)));
    assert_eq!(set.endpoint(b), None);
}

#[test]
fn endpoint_of_missing_peer_is_none() {
    let set = PeerSet::new();
    assert_eq!(set.endpoint(0), None);
}

// ---------- should_roam ----------

#[test]
fn should_roam_is_true_for_unknown_endpoint() {
    // 首次建链：本端尚不知道 endpoint ⇒ 接受并需要写入。
    assert!(should_roam(None, v4(10, 51820)));
}

#[test]
fn should_roam_is_false_when_address_is_unchanged() {
    let addr = v4(10, 51820);
    assert!(!should_roam(Some(addr), addr));
}

#[test]
fn should_roam_is_true_when_address_changed() {
    assert!(should_roam(Some(v4(10, 51820)), v4(11, 51820)));
}

#[test]
fn should_roam_detects_source_port_change() {
    // NAT 后源端口也会变（换网络 ⇒ 源 IP 与源端口都变）。
    assert!(should_roam(Some(v4(10, 51820)), v4(10, 40001)));
}

#[test]
fn should_roam_detects_address_family_change() {
    assert!(should_roam(Some(v4(10, 51820)), v6(51820)));
    assert!(should_roam(Some(v6(51820)), v4(10, 51820)));
}

#[test]
fn should_roam_uses_exact_address_equality() {
    // 判定只用地址相等性：不做端口范围 / 同网段猜测。
    let addr = v4(10, 51820);
    assert!(!should_roam(Some(addr), addr));
    assert!(should_roam(Some(addr), v4(10, 51821)));
}

// ---------- 判定 + 更新的组合语义 ----------

#[test]
fn roam_updates_endpoint_to_the_new_address() {
    let mut set = PeerSet::new();
    let id = set.add(cfg(1)).unwrap();
    set.set_peer_endpoint(id, Some(v4(10, 51820))).unwrap();

    let src = v4(11, 40001);
    assert!(should_roam(set.endpoint(id), src));
    set.set_peer_endpoint(id, Some(src)).unwrap();
    assert_eq!(set.endpoint(id), Some(src));
}

#[test]
fn unchanged_address_does_not_rewrite_the_endpoint() {
    // 源地址未变时无需更新：写回同一个值（幂等）。
    let mut set = PeerSet::new();
    let id = set.add(cfg(1)).unwrap();
    let addr = v4(10, 51820);
    set.set_peer_endpoint(id, Some(addr)).unwrap();

    assert!(!should_roam(set.endpoint(id), addr));
    assert_eq!(set.endpoint(id), Some(addr));
}

#[test]
fn changed_address_is_never_rejected() {
    // 漫游是**允许**的：地址变了不得拒绝收包，只更新 endpoint。
    let mut set = PeerSet::new();
    let id = set.add(cfg(1)).unwrap();
    set.set_peer_endpoint(id, Some(v4(10, 51820))).unwrap();

    let src = v4(11, 40001);
    assert!(should_roam(set.endpoint(id), src));
    assert_eq!(set.set_peer_endpoint(id, Some(src)), Ok(()));
}

// ---------- device 侧：源地址校验 ----------

use lengsuo_wireguard::device::{endpoint_after_receive, Output};

fn deliver() -> Output {
    Output::Deliver {
        peer: 0,
        payload: vec![1, 2, 3],
    }
}

#[test]
fn unauthenticated_packet_never_moves_the_endpoint() {
    // 对照参考 `device/receive.go`：认证失败 ⇒ `goto skip`，endpoint 不动。
    // 未认证的报文不得改动 endpoint（否则伪造包即可把对端引到攻击者地址）。
    let current = v4(10, 51820);
    let forged = v4(99, 1234);
    assert_eq!(
        endpoint_after_receive(&Output::DroppedUnparsable, Some(current), forged),
        None
    );
    assert_eq!(
        endpoint_after_receive(
            &Output::DroppedExpiredKeypair { local_index: 7 },
            Some(current),
            forged
        ),
        None
    );
}

#[test]
fn authenticated_packet_establishes_the_first_endpoint() {
    let src = v4(10, 51820);
    assert_eq!(endpoint_after_receive(&deliver(), None, src), Some(src));
}

#[test]
fn authenticated_packet_roams_to_the_new_source_address() {
    let src = v4(11, 40001);
    assert_eq!(
        endpoint_after_receive(&deliver(), Some(v4(10, 51820)), src),
        Some(src)
    );
}

#[test]
fn authenticated_packet_from_the_same_address_needs_no_update() {
    let addr = v4(10, 51820);
    assert_eq!(endpoint_after_receive(&deliver(), Some(addr), addr), None);
}
