//! ③ 窗口边界：本仓窗口长度（8192）与参考（8128）的**逐条对照**，以及窗口
//! 推进之后旧 EIH 的出窗语义。
//!
//! 参考 `shadowaead_2022/slidingwindow.go` 的**逐行 Rust 转写**作为对照模型
//! （见 `ReferenceWindow`），判据是「**重放**判定两边必须完全一致」。
//!
//! 归属：`tests/udp_replay_matrix.rs` 的 ③a / ③b 两组用例。

use super::{clock, make_server, now_secs, one_layer_psks, one_layer_users, peer, target};
use lengsuo_ss2022::{
    crypto::Method,
    eih_udp::{EihUdpChain, EihUdpSender},
    Error,
};
use ss_core::replay::{Window, WINDOW_BITS};
use std::collections::BTreeSet;

/// 参考 `shadowaead_2022/slidingwindow.go` 的**逐行 Rust 转写**（对照模型）。
///
/// 常量取自 `slidingwindow.go:3-9`：`swBlockBitLog=6`、`swBlockBits=64`、
/// `swRingBlocks=128`、`swSize=(swRingBlocks-1)*swBlockBits=8128`。
struct ReferenceWindow {
    last: u64,
    ring: [u64; 128],
}

/// 参考窗口长度：`(swRingBlocks - 1) * swBlockBits`。
const REFERENCE_WINDOW_SIZE: u64 = (128 - 1) * 64;

impl ReferenceWindow {
    fn new() -> Self {
        Self {
            last: 0,
            ring: [0; 128],
        }
    }

    /// `slidingwindow.go:25-37` 的 `Check`。
    fn check(&self, counter: u64) -> bool {
        if counter > self.last {
            return true;
        }
        if self.last - counter > REFERENCE_WINDOW_SIZE {
            return false;
        }
        let block = ((counter >> 6) & 127) as usize;
        let bit = counter & 63;
        self.ring[block] >> bit & 1 == 0
    }

    /// `slidingwindow.go:41-63` 的 `Add`。
    fn add(&mut self, counter: u64) {
        if counter > self.last {
            let mut last_block = self.last >> 6;
            let block = counter >> 6;
            let mut diff = (block - last_block) as usize;
            if diff > 128 {
                diff = 128;
            }
            for _ in 0..diff {
                last_block = (last_block + 1) & 127;
                self.ring[last_block as usize] = 0;
            }
            self.last = counter;
        }
        let block = ((counter >> 6) & 127) as usize;
        let bit = counter & 63;
        self.ring[block] |= 1 << bit;
    }

    /// 参考服务端「先 Check，AEAD 成功后才 Add」的组合
    /// （`service_multi.go:324` 与 `:338`）。
    fn accept(&mut self, counter: u64) -> bool {
        if !self.check(counter) {
            return false;
        }
        self.add(counter);
        true
    }
}

/// ③a 窗口边界：本仓窗口长度（8192）与参考（8128）不同，且**只在「从未见过
/// 的旧 id」上**分道扬镳；一切**重放**判定两边完全一致。
///
/// 分歧的精确定义：
/// - 本仓 `ss_core::replay::Window`：`highest - counter >= 8192` 才判过期；
/// - 参考：`last - counter > 8128` 即判过期。
///
/// 于是：
/// - 距最高点 8129..=8191 的**新** id，本仓接受、参考拒绝（窗口长 63 位）；
/// - 距最高点 ≥ 8192 的 id，两边都拒绝；
/// - **任何被收下过的 id（重放），两边都拒绝**（本仓记为 Duplicate/TooOld，
///   参考记为 `ErrPacketIdNotUnique`）——这是用户可见的重放语义，两边一致。
#[test]
fn window_diverges_from_the_reference_only_at_the_old_edge() {
    let mut reference = ReferenceWindow::new();
    let mut repo = Window::new(u64::MAX);
    let mut seen: BTreeSet<u64> = BTreeSet::new();

    // 判定并记录：谁接受、谁拒绝。
    let step = |counter: u64,
                reference: &mut ReferenceWindow,
                repo: &mut Window,
                seen: &mut BTreeSet<u64>| {
        let reference_ok = reference.accept(counter);
        let repo_ok = repo.accept_authenticated(counter).is_ok();
        if reference_ok {
            seen.insert(counter);
        }
        (reference_ok, repo_ok)
    };

    // 起点：id 0（空窗口首包），随后大跨度跳到 100000（把中间都变成「新旧边界」）。
    assert_eq!(step(0, &mut reference, &mut repo, &mut seen), (true, true));
    assert_eq!(
        step(100_000, &mut reference, &mut repo, &mut seen),
        (true, true)
    );

    // 边界扫描：距最高点 delta 的「新」id（100000-delta 从未收下过）。
    let mut divergent = Vec::new();
    for delta in [1u64, 8127, 8128, 8129, 8190, 8191, 8192, 8193] {
        let counter = 100_000 - delta;
        assert!(!seen.contains(&counter), "被测 id 必须是从未见过的新 id");
        let (reference_ok, repo_ok) = step(counter, &mut reference, &mut repo, &mut seen);
        if reference_ok != repo_ok {
            divergent.push((delta, reference_ok, repo_ok));
        }
    }
    assert_eq!(
        divergent,
        vec![
            (8129, false, true),
            (8190, false, true),
            (8191, false, true)
        ],
        "分歧只应出现在距最高点 8129..=8191 的新 id 上（本仓窗口 8192 vs 参考 8128）"
    );

    // 一切**重放**判定两边必须一致：被收下过的 id 再来一次，两边都拒绝。
    for replayed in [0u64, 100_000, 100_000 - 8128, 100_000 - 8129] {
        let reference_ok = reference.accept(replayed);
        let repo_ok = repo.accept_authenticated(replayed).is_ok();
        assert!(!reference_ok, "参考必须拒绝重放 {replayed}");
        assert!(!repo_ok, "本仓必须拒绝重放 {replayed}");
    }
    assert_eq!(WINDOW_BITS as u64, 8192, "本仓窗口位数");
    assert_eq!(REFERENCE_WINDOW_SIZE, 8128, "参考窗口长度");
}

/// ③b 端到端：窗口推进到把旧 EIH 挤出之后，**同一个旧包仍被拒绝**。
///
/// 与参考一致：参考 `Check` 对 `last - counter > 8128` 直接拒绝，
/// 本仓对 `highest - counter >= 8192` 判过期 ⇒ 两边都**不会**让旧包复活。
/// 参考「出窗后新 id 仍可用」是窗口语义本身（`Check` 对 `counter > last`
/// 直接放行），本仓同样放行。
#[test]
fn eih_udp_replay_stays_rejected_after_the_window_advanced() {
    let psks = one_layer_psks(Method::Aes256);
    let chain = EihUdpChain::new(psks.clone()).expect("身份链应可构造");
    let mut sender = EihUdpSender::new(chain).expect("发送端应可构造");
    let mut server = make_server(psks[0].clone(), one_layer_users(Method::Aes256), 1);

    // 首包：id 0。留一份副本，待窗口推进后重放。
    let oldest = sender
        .seal(&target(), b"oldest", now_secs(), 0)
        .expect("封包应成功");
    server
        .receive(&oldest, peer(1), clock())
        .expect("首包应被接受");

    // 把窗口推进到 8192+：此后 id 0 距最高点 ≥ 8192，已被挤出窗口。
    for _ in 0..8192 {
        let packet = sender
            .seal(&target(), b"filler", now_secs(), 0)
            .expect("封包应成功");
        server
            .receive(&packet, peer(1), clock())
            .expect("递增 id 应被接受");
    }
    // 此时最高 packet id = 8192。旧包 id 0 已出窗 ⇒ 仍必须被拒（两边一致）。
    assert!(
        matches!(
            server.receive(&oldest, peer(1), clock()),
            Err(Error::Replay)
        ),
        "出窗后的旧 EIH 仍必须被拒（与参考一致）"
    );
}
