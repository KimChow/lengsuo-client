//! 与 wireguard-go 参考 `calculatePaddingSize` 的**逐向量对齐**回归。
//!
//! 夹具 `tests/fixtures/wg_padding_vectors.txt` 由参考函数
//! （`device/send.go:419`，pin `2631ce99`）对
//! `size ∈ [0,3000] × mtu ∈ {0,1280,1420,1500,16,32}` 全量求值生成，
//! 每行 `size mtu expected`。本测试断言 Rust 实现逐条相等——这是与参考的
//! 对照，不是自家 roundtrip。

use lengsuo_wireguard::packet_pad::calculate_padding_size;

#[test]
fn matches_reference_calculate_padding_size_vectors() {
    let data = include_str!("fixtures/wg_padding_vectors.txt");
    let mut checked = 0usize;
    for (lineno, line) in data.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let size: usize = it.next().unwrap().parse().unwrap();
        let mtu: usize = it.next().unwrap().parse().unwrap();
        let expected: usize = it.next().unwrap().parse().unwrap();
        let got = calculate_padding_size(size, mtu);
        assert_eq!(
            got,
            expected,
            "line {}: calculate_padding_size({size}, {mtu}) = {got}, reference {expected}",
            lineno + 1
        );
        checked += 1;
    }
    assert!(checked >= 18_000, "vector file too small: {checked}");
}
