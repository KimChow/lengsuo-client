//! 边界用例的共用小工具：地址构造与「期望值来源」说明。
//!
//! 期望值全部来自**参考实现的真实行为**：在参考仓内直接调用
//! `device.AllowedIPs`（wireguard-go commit
//! `2631ce99a06f27120d581611cf125d68bc6aa565`）回放同一串操作，取回
//! lookup 的归属 peer；本仓断言逐条等于该结果。
//!
//! ⛔ 这些工具**不**是产品代码，也**不**用自家 roundtrip 冒充互通：它们只
//! 构造假地址、给出 peer 编号与断言辅助。

use lengsuo_wireguard::AllowedIps;

/// 本仓 peer 编号，与参考回放里的 peer 名字一一对应。
pub const PEER_A: usize = 0;
pub const PEER_B: usize = 1;
pub const PEER_C: usize = 2;

/// 构造 IPv4 地址字节。
pub fn v4(a: u8, b: u8, c: u8, d: u8) -> [u8; 4] {
    [a, b, c, d]
}

/// 构造 IPv6 地址字节：取 `prefix` 前若干字节，其余补零。
pub fn v6(prefix: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..prefix.len()].copy_from_slice(prefix);
    out
}

/// 构造 `2001:db8::x` 形式的 IPv6 地址。
pub fn v6_2001db8(last: u8) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0] = 0x20;
    out[1] = 0x01;
    out[2] = 0x0d;
    out[3] = 0xb8;
    out[15] = last;
    out
}

/// 断言「该地址由该 peer 拥有」。`None` 表示无归属（fail-closed 丢弃）。
#[track_caller]
pub fn assert_owner(table: &AllowedIps, ip: &[u8], expected: Option<usize>) {
    assert_eq!(
        table.lookup(ip),
        expected,
        "lookup({ip:?}) 的归属与参考实现不一致"
    );
}

/// 断言「该地址没有归属」。
#[track_caller]
pub fn assert_unowned(table: &AllowedIps, ip: &[u8]) {
    assert_eq!(
        table.lookup(ip),
        None,
        "lookup({ip:?}) 应无归属（参考实现返回 nil）"
    );
}
