//! Hysteria2 传输层伪装：Salamander 混淆（`obfs.rs`）与端口跳跃（`hop.rs`）。
//!
//! 对照参考路径：`transport/internet/hysteria/dialer.go` 对
//! `udphop.NewUDPHopPacketConn` 与 `udpmaskManager.WrapPacketConnClient`
//! 的调用，以及 `transport/internet/finalmask/salamander/`、
//! `transport/internet/hysteria/udphop/` 两个包。

pub mod endpoint;
pub mod hop;
pub mod packet;
pub mod socket;
pub mod wire;

pub use hop::{HopScheduler, HopSpec, PortList, PortRange};
pub use packet::HopSocket;
pub use socket::MaskedUdpSocket;
pub use wire::WireMask;

/// 传输层的随机源：端口选择与 hop 间隔都从它取（对照参考的
/// `math/rand.Intn` 与 `crypto.RandBetween`）。
///
/// 默认实现 [`OsRng`] 走 `getrandom`（工作区依赖，非 `unsafe`）；
/// 测试注入固定流即可得到确定的端口/间隔序列。
pub trait TransportRng: Send + Sync {
    /// 均匀取 `[0, bound)`；`bound == 0` 时按 0 处理（对照 `rand.Intn` 的
    /// 调用点都会先保证 `len > 0`）。
    fn gen_index(&self, bound: usize) -> usize;

    /// 均匀取 `[0, bound)` 的 64 位无符号数。
    fn gen_u64(&self, bound: u64) -> u64;

    /// 用随机字节填充 `out`（Salamander 的 8 字节盐）。
    fn fill_bytes(&self, out: &mut [u8]);
}

/// 生产随机源：`/dev/urandom`（Linux 内核熵源，等价参考 `crypto/rand`）。
///
/// 说明：`getrandom` crate 不在 `lengsuo-hysteria` 的冻结依赖里
/// （工作区只有 `tokio`/`quinn`/`h3` 等，且 /dev/urandom 是完全等价的
/// Linux 熵源），因此直接读取设备节点，不新增依赖。
pub struct OsRng;

impl TransportRng for OsRng {
    fn gen_index(&self, bound: usize) -> usize {
        if bound <= 1 {
            return 0;
        }
        self.gen_u64(bound as u64) as usize
    }

    fn gen_u64(&self, bound: u64) -> u64 {
        if bound <= 1 {
            return 0;
        }
        // 拒绝采样消除取模偏置（bound 远小于 2^64）。
        let zone = u64::MAX - (u64::MAX % bound);
        loop {
            let mut buf = [0u8; 8];
            self.fill_bytes(&mut buf);
            let value = u64::from_le_bytes(buf);
            if value < zone {
                return value % bound;
            }
        }
    }

    fn fill_bytes(&self, out: &mut [u8]) {
        // 读不到熵源意味着系统不可用；静默退化成全零盐会把混淆降级为
        // 固定流（可被被动识别），因此直接 panic 而非降级。
        use std::io::Read;
        let mut f = std::fs::File::open("/dev/urandom").expect("打开 /dev/urandom 失败");
        f.read_exact(out).expect("读取 /dev/urandom 失败");
    }
}
