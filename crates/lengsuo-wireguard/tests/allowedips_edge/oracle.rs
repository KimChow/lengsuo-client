//! 与固定参考的**差分回放**：同一串操作分别喂给参考自己的
//! `device.AllowedIPs` 与本仓的 `AllowedIps`，逐条比对 lookup 的归属。
//!
//! 参考：wireguard-go `device/allowedips.go`（commit
//! `2631ce99a06f27120d581611cf125d68bc6aa565`）。
//!
//! 参考侧的探针二进制**直接调用参考自己的 `device.AllowedIPs`**
//! （`Insert`/`Remove`/`RemoveByPeer`/`Lookup`），由仓外构建、仓外运行，路径由
//! 环境变量 `LENGSUO_WG_ALLOWEDIPS_ORACLE` 给出；缺失即报错退出，绝不静默跳过，
//! 也不拿自家 roundtrip 冒充参考。
//!
//! 探针的 ops 行格式（`I`/`R`/`D`/`L`）与本仓的操作一一对应，peer 名
//! `A`/`B`/`C` 对应本仓 peer 编号 `0`/`1`/`2`。
//!
//! ⛔ 本文件只做**路由表层面**的差分，不涉及握手/传输层，也不做 socket 互通。
//! ⛔ 生成的 cidr 始终与地址族位宽匹配：参考对越界 cidr 会越界 panic
//! （见 `docs/wireguard-allowedips-edge.md` 偏离清单第 4 条），本仓返回 `false`。

use std::{
    fmt::Write as _,
    fs,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU32, Ordering},
};

use lengsuo_wireguard::AllowedIps;

use super::fixture::{v4, v6, v6_2001db8};

/// 探针的 peer 名与本仓 peer 编号的对应。
const PEER_NAMES: [&str; 3] = ["A", "B", "C"];

/// 临时 ops 文件的序号（多线程下互不覆盖）。
static OPS_SEQ: AtomicU32 = AtomicU32::new(0);

/// 待回放的地址：4 字节走 v4 树，16 字节走 v6 树。
#[derive(Clone, Copy, Debug)]
enum Ip {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl Ip {
    /// 探针 ops 文件里的文本形式（探针用 `netip.ParseAddr` 解析）。
    fn text(self) -> String {
        match self {
            Ip::V4(o) => Ipv4Addr::new(o[0], o[1], o[2], o[3]).to_string(),
            Ip::V6(o) => Ipv6Addr::from(o).to_string(),
        }
    }

    /// 喂给本仓 `AllowedIps` 的字节（4 或 16 字节 ⇒ 走对应的族树）。
    fn bytes(self) -> Vec<u8> {
        match self {
            Ip::V4(o) => o.to_vec(),
            Ip::V6(o) => o.to_vec(),
        }
    }
}

/// 待回放的操作，与探针的 ops 行一一对应。
#[derive(Clone, Copy, Debug)]
enum Op {
    /// 插入前缀（`I`）。
    Insert(usize, Ip, u8),
    /// 删除前缀（`R`）。
    Remove(usize, Ip, u8),
    /// 摘掉该 peer 的全部前缀（`D`）。
    RemoveByPeer(usize),
    /// 查询归属（`L`）。
    Lookup(Ip),
}

/// 极小的 xorshift64 随机源：本卡不引入新依赖，测试专用。
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// 返回 `[0, n)` 内的数。
    fn below(&mut self, n: u32) -> u32 {
        (self.next_u64() % u64::from(n)) as u32
    }
}

fn rand_v4(rng: &mut Rng) -> [u8; 4] {
    let mut out = [0u8; 4];
    for slot in out.iter_mut() {
        *slot = rng.below(256) as u8;
    }
    out
}

fn rand_v6(rng: &mut Rng) -> [u8; 16] {
    let mut out = [0u8; 16];
    for slot in out.iter_mut() {
        *slot = rng.below(256) as u8;
    }
    out
}

/// 随机差分的生成模式。
#[derive(Clone, Copy, Debug)]
enum Mode {
    /// 同网段反复碰撞：少量网段 + 频繁换 peer。
    Collide,
    /// 两族混插：前缀长度随机 ⇒ 大量**非规范前缀**（主机位非零）。
    Mixed,
    /// 默认路由与窄前缀共存。
    Default,
}

impl Mode {
    const ALL: [Mode; 3] = [Mode::Collide, Mode::Mixed, Mode::Default];

    fn name(self) -> &'static str {
        match self {
            Mode::Collide => "collide",
            Mode::Mixed => "mixed",
            Mode::Default => "default",
        }
    }
}

/// 生成一串随机操作。
fn random_ops(seed: u64, mode: Mode, steps: usize) -> Vec<Op> {
    let mut rng = Rng::new(seed);
    let mut ops = Vec::with_capacity(steps);
    for _ in 0..steps {
        let roll = rng.below(100);
        let peer = rng.below(3) as usize;
        let (ip, cidr) = match mode {
            Mode::Collide => {
                let pool: [[u8; 4]; 3] = [[10, 0, 0, 0], [192, 168, 0, 0], [172, 16, 0, 0]];
                let mut bytes = pool[rng.below(3) as usize];
                // 主机位随机 ⇒ 非规范前缀。
                for slot in bytes.iter_mut().skip(1) {
                    *slot = rng.below(256) as u8;
                }
                let cidr = [8u8, 16, 24, 32][rng.below(4) as usize];
                (Ip::V4(bytes), cidr)
            }
            Mode::Mixed => {
                if rng.below(2) == 0 {
                    (Ip::V4(rand_v4(&mut rng)), rng.below(33) as u8)
                } else {
                    (Ip::V6(rand_v6(&mut rng)), rng.below(129) as u8)
                }
            }
            Mode::Default => {
                if rng.below(10) < 6 {
                    let cidr = [0u8, 0, 1, 31, 32][rng.below(5) as usize];
                    (Ip::V4(rand_v4(&mut rng)), cidr)
                } else {
                    let cidr = [0u8, 0, 1, 127, 128][rng.below(5) as usize];
                    (Ip::V6(rand_v6(&mut rng)), cidr)
                }
            }
        };
        if roll < 45 {
            ops.push(Op::Insert(peer, ip, cidr));
        } else if roll < 70 {
            ops.push(Op::Remove(peer, ip, cidr));
        } else if roll < 78 {
            ops.push(Op::RemoveByPeer(peer));
        } else {
            let probe = match mode {
                Mode::Collide if rng.below(2) == 0 => Ip::V4(rand_v4(&mut rng)),
                Mode::Default if rng.below(10) < 6 => Ip::V4(rand_v4(&mut rng)),
                _ if rng.below(4) == 0 => {
                    // IPv4-mapped IPv6：探针按 16 字节进 v6 树。
                    let mut bytes = [0u8; 16];
                    bytes[10] = 0xff;
                    bytes[11] = 0xff;
                    bytes[12..].copy_from_slice(&rand_v4(&mut rng));
                    Ip::V6(bytes)
                }
                _ if rng.below(2) == 0 => Ip::V4(rand_v4(&mut rng)),
                _ => Ip::V6(rand_v6(&mut rng)),
            };
            ops.push(Op::Lookup(probe));
        }
    }
    ops
}

/// 手写的边界操作串：覆盖本卡登记的每个边界维度
/// （非规范前缀 / 默认路由 / `/0` 与 `/32` / IPv6 混合 / 移除 peer 后
/// fail-closed / 多 peer 路由隔离）。
fn boundary_ops() -> Vec<Op> {
    // IPv4-mapped IPv6：归 v6 树（参考按地址长度分派）。
    let mapped = v6(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4]);
    vec![
        // 非规范前缀：10.1.2.3/8 存成 10.0.0.0/8。
        Op::Insert(0, Ip::V4(v4(10, 1, 2, 3)), 8),
        Op::Lookup(Ip::V4(v4(10, 0, 0, 1))),
        Op::Lookup(Ip::V4(v4(10, 255, 255, 255))),
        Op::Lookup(Ip::V4(v4(11, 0, 0, 1))),
        // 同一网段的两种写法命中同一节点，后插入者接管；删除后不回落。
        Op::Insert(1, Ip::V4(v4(10, 9, 9, 9)), 8),
        Op::Lookup(Ip::V4(v4(10, 1, 2, 3))),
        Op::Remove(1, Ip::V4(v4(10, 5, 5, 5)), 8),
        Op::Lookup(Ip::V4(v4(10, 1, 2, 3))),
        // 默认路由需显式允许，且只覆盖本族。
        Op::Insert(0, Ip::V4(v4(0, 0, 0, 0)), 0),
        Op::Lookup(Ip::V4(v4(8, 8, 8, 8))),
        Op::Lookup(Ip::V4(v4(255, 255, 255, 255))),
        Op::Lookup(Ip::V6(v6_2001db8(1))),
        // 窄前缀在默认路由之下：最长前缀匹配。
        Op::Insert(2, Ip::V4(v4(10, 0, 0, 0)), 8),
        Op::Lookup(Ip::V4(v4(8, 8, 8, 8))),
        Op::Lookup(Ip::V4(v4(10, 1, 2, 3))),
        // 嵌套前缀：逐层收窄。
        Op::Insert(1, Ip::V4(v4(10, 1, 0, 0)), 16),
        Op::Lookup(Ip::V4(v4(10, 1, 9, 9))),
        Op::Insert(0, Ip::V4(v4(10, 1, 2, 0)), 24),
        Op::Lookup(Ip::V4(v4(10, 1, 2, 9))),
        // 删掉最窄的 ⇒ 回落一层。
        Op::Remove(0, Ip::V4(v4(10, 1, 2, 0)), 24),
        Op::Lookup(Ip::V4(v4(10, 1, 2, 9))),
        // `/32` 在 `/0` 之下。
        Op::Insert(1, Ip::V4(v4(192, 0, 2, 1)), 32),
        Op::Lookup(Ip::V4(v4(192, 0, 2, 1))),
        Op::Lookup(Ip::V4(v4(192, 0, 2, 2))),
        Op::Remove(1, Ip::V4(v4(192, 0, 2, 1)), 32),
        Op::Lookup(Ip::V4(v4(192, 0, 2, 1))),
        // v6 树独立。
        Op::Insert(1, Ip::V6(v6_2001db8(0)), 32),
        Op::Lookup(Ip::V6(v6_2001db8(1))),
        Op::Lookup(Ip::V4(v4(10, 1, 2, 9))),
        // IPv4-mapped IPv6 归 v6 树。
        Op::Insert(2, Ip::V6(mapped), 120),
        Op::Lookup(Ip::V6(mapped)),
        Op::Lookup(Ip::V4(v4(1, 2, 3, 4))),
        // 移除 peer ⇒ 其路由 fail-closed，其它 peer 不受影响。
        Op::RemoveByPeer(0),
        Op::Lookup(Ip::V4(v4(8, 8, 8, 8))),
        Op::Lookup(Ip::V4(v4(10, 1, 2, 9))),
        Op::Lookup(Ip::V6(v6_2001db8(1))),
        Op::RemoveByPeer(2),
        Op::Lookup(Ip::V6(mapped)),
        Op::Lookup(Ip::V4(v4(192, 0, 2, 1))),
    ]
}

/// 把操作串写成探针的 ops 文件。
fn write_ops(ops: &[Op]) -> PathBuf {
    let mut text = String::new();
    for op in ops {
        match op {
            Op::Insert(peer, ip, cidr) => {
                let _ = writeln!(text, "I {} {} {cidr}", PEER_NAMES[*peer], ip.text());
            }
            Op::Remove(peer, ip, cidr) => {
                let _ = writeln!(text, "R {} {} {cidr}", PEER_NAMES[*peer], ip.text());
            }
            Op::RemoveByPeer(peer) => {
                let _ = writeln!(text, "D {}", PEER_NAMES[*peer]);
            }
            Op::Lookup(ip) => {
                let _ = writeln!(text, "L {}", ip.text());
            }
        }
    }
    let path = std::env::temp_dir().join(format!(
        "lengsuo-wg-allowedips-oracle-{}-{}.ops",
        std::process::id(),
        OPS_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&path, text).expect("写 ops 文件");
    path
}

/// 跑参考探针，取回它打印的 lookup 归属序列。
fn oracle_owners(ops_path: &Path) -> Vec<Option<usize>> {
    let binary = std::env::var_os("LENGSUO_WG_ALLOWEDIPS_ORACLE")
        .expect("需要参考探针二进制 LENGSUO_WG_ALLOWEDIPS_ORACLE");
    let output = Command::new(binary)
        .arg(ops_path)
        .output()
        .expect("参考探针可启动");
    assert!(
        output.status.success(),
        "参考探针退出码 {:?}：{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("探针输出是 UTF-8");
    stdout
        .lines()
        .filter(|line| line.starts_with("L "))
        .map(|line| {
            let (_, tail) = line.rsplit_once(" -> ").expect("探针输出行含 ' -> '");
            if tail == "-" {
                return None;
            }
            let name = tail.split('(').next().expect("peer 名");
            Some(
                PEER_NAMES
                    .iter()
                    .position(|candidate| *candidate == name)
                    .expect("探针只回 A/B/C 三个 peer"),
            )
        })
        .collect()
}

/// 本仓侧回放同一串操作，取回 lookup 归属序列。
fn local_owners(ops: &[Op]) -> Vec<Option<usize>> {
    let mut table = AllowedIps::new();
    let mut owners = Vec::new();
    for op in ops {
        match op {
            Op::Insert(peer, ip, cidr) => {
                let bytes = ip.bytes();
                assert!(table.insert(*peer, &bytes, *cidr), "插入应被接受");
            }
            Op::Remove(peer, ip, cidr) => {
                let bytes = ip.bytes();
                table.remove(*peer, &bytes, *cidr);
            }
            Op::RemoveByPeer(peer) => table.remove_by_peer(*peer),
            Op::Lookup(ip) => {
                let bytes = ip.bytes();
                owners.push(table.lookup(&bytes));
            }
        }
    }
    owners
}

/// 同一串操作：参考与本仓的 lookup 归属必须逐条相等。
fn assert_matches_reference(ops: &[Op], what: &str) -> usize {
    let path = write_ops(ops);
    let expected = oracle_owners(&path);
    let actual = local_owners(ops);
    let _ = fs::remove_file(&path);
    assert_eq!(
        expected.len(),
        actual.len(),
        "{what}：lookup 次数与参考不一致"
    );
    assert_eq!(expected, actual, "{what}：lookup 归属与参考不一致");
    expected.len()
}

/// 手写边界串的差分回放。
#[test]
#[ignore = "需要参考探针二进制 LENGSUO_WG_ALLOWEDIPS_ORACLE"]
fn boundary_sequence_matches_the_reference() {
    let lookups = assert_matches_reference(&boundary_ops(), "边界操作串");
    assert!(lookups >= 25, "边界串的 lookup 数量偏少：{lookups}");
    println!("边界操作串：{lookups} 次 lookup 与参考逐条相等");
}

/// 随机差分扫描：三个模式各若干种子，0 处不一致才算通过。
#[test]
#[ignore = "需要参考探针二进制 LENGSUO_WG_ALLOWEDIPS_ORACLE"]
fn randomized_differential_scan_matches_the_reference() {
    const SEEDS_PER_MODE: u64 = 200;
    const STEPS: usize = 200;
    let mut lookups = 0usize;
    for mode in Mode::ALL {
        for seed in 0..SEEDS_PER_MODE {
            let ops = random_ops(seed, mode, STEPS);
            lookups += assert_matches_reference(&ops, &format!("模式 {} 种子 {seed}", mode.name()));
        }
    }
    println!(
        "随机差分：{} 个模式 × {} 个种子 = {} 串，{lookups} 次 lookup 全部与参考相等",
        Mode::ALL.len(),
        SEEDS_PER_MODE,
        Mode::ALL.len() * SEEDS_PER_MODE as usize
    );
}
