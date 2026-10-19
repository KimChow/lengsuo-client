//! IP 包填充（padding）与 MTU 分片：发送侧把明文填充到 16 字节倍数并按 MTU
//! 切分，接收侧剥离填充、校验重组判据与上限。
//!
//! 对照 wireguard-go：
//! - `device/send.go:419 calculatePaddingSize(packetSize, mtu)` — 填充规则：
//!   对 `packetSize % mtu` 取整到 16 的倍数；`mtu==0` 表示不封顶。
//! - `device/constants.go:26 PaddingMultiple = 16`。
//! - `RoutineEncryption` 在 Seal 之前 `append(paddingZeros[:paddingSize])`。
//!
//! 接收侧：WireGuard 的填充是**零字节**且**无显式长度字段**；接收方按 IP 头
//! 里的总长度字段裁掉尾部零填充。sentinel 常量 `PADDING_MULTIPLE` 与参考一致。
//!
//! 偏离清单见 `docs/wireguard-status.md`：参考把分片交给 TUN/内核（`tun.go` 的
//! MTU 由内核按接口 MTU 处理），本 crate 不涉及 TUN，故在此显式实现按 MTU 的
//! 分片/重组判据（任务书要求），填充函数与参考逐字节对齐。

/// 填充倍数，对照 `PaddingMultiple`。
pub const PADDING_MULTIPLE: usize = 16;

/// 单个 IP 包的长度上限（IPv4/IPv6 兼容：65535 字节 IP 载荷）。
pub const MAX_IP_PACKET: usize = 65535;

/// 分片/重组失败原因（fail-closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PadError {
    /// 输入超过 IP 包上限。
    PacketTooLarge,
    /// MTU 为 0 或非法（分片要求 MTU >= 头长度）。
    InvalidMtu,
    /// 载荷为空（IP 包至少要有头）。
    EmptyPacket,
}

/// 计算填充字节数。**逐字节对齐** `calculatePaddingSize`：
///
/// ```text
/// lastUnit := packetSize
/// if mtu == 0: return round_up(lastUnit) - lastUnit
/// if lastUnit > mtu: lastUnit %= mtu
/// padded := round_up(lastUnit); if padded > mtu: padded = mtu
/// return padded - lastUnit
/// ```
///
/// 其中 `round_up(x) = (x + 15) &^ 15`（向上取整到 16 的倍数）。
#[must_use]
pub fn calculate_padding_size(packet_size: usize, mtu: usize) -> usize {
    let mut last_unit = packet_size;
    if mtu == 0 {
        return round_up_16(last_unit) - last_unit;
    }
    if last_unit > mtu {
        last_unit %= mtu;
    }
    let mut padded = round_up_16(last_unit);
    if padded > mtu {
        padded = mtu;
    }
    padded - last_unit
}

#[inline]
fn round_up_16(x: usize) -> usize {
    (x + PADDING_MULTIPLE - 1) & !(PADDING_MULTIPLE - 1)
}

/// 把明文填充到 16 字节倍数（对照 `RoutineEncryption` 的 `append`）。
/// 返回填充后的新 buffer；填充字节为 0。
#[must_use]
pub fn pad(payload: &[u8], mtu: usize) -> Vec<u8> {
    let n = calculate_padding_size(payload.len(), mtu);
    let mut out = Vec::with_capacity(payload.len() + n);
    out.extend_from_slice(payload);
    out.resize(payload.len() + n, 0);
    out
}

/// 剥离填充：`length_field` 是 IP 头里的真实总长度。
///
/// fail-closed：`length_field` 为 0、大于传入 buffer、或小于丢弃后为空，
/// 都返回 `None`（拒绝畸形）。对照接收侧「按 IP 头总长裁切」。
#[must_use]
pub fn unpad(padded: &[u8], length_field: usize) -> Option<&[u8]> {
    if length_field == 0 || length_field > padded.len() {
        return None;
    }
    let payload = &padded[..length_field];
    // 填充必须全为 0（WireGuard 发送侧填零）；非零尾字节视为畸形，
    // 但长度字段本身已界定内容，故只校验被裁掉的部分是否为零。
    if padded[length_field..].iter().any(|&b| b != 0) {
        return None;
    }
    Some(payload)
}

/// 按 MTU 把一个 IP 包切成分片（每片长度 <= mtu）。
///
/// 对照任务书「按 MTU 计算分片」。IP 分片本身由 IP 层负责；此处提供**判据级**
/// 的切分，用于测试与调用方在无 TUN 时模拟。
///
/// fail-closed：空包 / mtu 为 0 / 包超上限 均返回 `Err`。
pub fn fragment(packet: &[u8], mtu: usize) -> Result<Vec<&[u8]>, PadError> {
    if packet.is_empty() {
        return Err(PadError::EmptyPacket);
    }
    if mtu == 0 {
        return Err(PadError::InvalidMtu);
    }
    if packet.len() > MAX_IP_PACKET {
        return Err(PadError::PacketTooLarge);
    }
    Ok(packet.chunks(mtu).collect())
}

/// 重组判据：把分片按序拼回，校验总长不超过上限、且非空。
///
/// fail-closed：任一分片为空、总数超上限、拼接后超 `MAX_IP_PACKET`，返回 `Err`。
pub fn reassemble(fragments: &[&[u8]]) -> Result<Vec<u8>, PadError> {
    if fragments.is_empty() {
        return Err(PadError::EmptyPacket);
    }
    let total: usize = fragments.iter().map(|f| f.len()).sum();
    if total > MAX_IP_PACKET {
        return Err(PadError::PacketTooLarge);
    }
    if fragments.iter().any(|f| f.is_empty()) {
        return Err(PadError::EmptyPacket);
    }
    let mut out = Vec::with_capacity(total);
    for f in fragments {
        out.extend_from_slice(f);
    }
    Ok(out)
}
