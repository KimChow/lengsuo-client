//! SS2022 ChaCha（XChaCha20-Poly1305）参考实现的**逐行转写**与固定向量。
//!
//! 转写对象是参考实现实际调用的两个 Go 函数：
//! - `golang.org/x/crypto/chacha20/chacha_generic.go:128` `quarterRound`；
//! - `golang.org/x/crypto/chacha20/chacha_generic.go:352` `hChaCha20`。
//!
//! 为什么自己转写而不是直接调用：`chacha20` crate 虽公开了 `hchacha`，但它只是
//! `chacha20poly1305` 的**传递依赖**，本 crate 没有直接声明；本卡又不得改
//! `Cargo.toml`（共享区由基建卡独占）。转写同时满足「把参考实现转写/对齐到 Rust」
//! 的硬要求，并让切分点可被独立验证。
//!
//! ⚠️ 转写必须与参考**逐字节一致**：`hchacha20_reference` 的输出由
//! `xchacha_nonce_split_matches_reference_vectors` 与 Go 生成的常量比对。

/// ChaCha 状态常量 `"expa" "nd 3" "2-by" "te k"`，小端 u32。
/// 参考 `chacha_generic.go:117-120`。
const CONSTANTS: [u32; 4] = [
    0x6170_7865, // "expa"
    0x3320_646e, // "nd 3"
    0x7962_2d32, // "2-by"
    0x6b20_6574, // "te k"
];

/// ChaCha quarter round。参考 `chacha_generic.go:128-142`。
///
/// Go 用 `bits.RotateLeft32`（无符号循环左移），加法是模 2^32。
fn quarter_round(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
    let a = a.wrapping_add(b);
    let d = (d ^ a).rotate_left(16);
    let c = c.wrapping_add(d);
    let b = (b ^ c).rotate_left(12);
    let a = a.wrapping_add(b);
    let d = (d ^ a).rotate_left(8);
    let c = c.wrapping_add(d);
    let b = (b ^ c).rotate_left(7);
    (a, b, c, d)
}

/// HChaCha20：参考 `chacha_generic.go:352-405`（`hChaCha20`）。
///
/// 与 ChaCha20 核心的差别：计数器段被当作常量（不参与），跑 10 轮，
/// 最后**不加**初始状态、不做 final add。
/// 输出 = `state[0..4] || state[12..16]`（各按小端 u32）。
pub fn hchacha20_reference(key: &[u8; 32], nonce16: &[u8; 16]) -> [u8; 32] {
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&CONSTANTS);
    for (word, chunk) in state[4..12].iter_mut().zip(key.as_chunks::<4>().0.iter()) {
        *word = u32::from_le_bytes(*chunk);
    }
    for (word, chunk) in state[12..16]
        .iter_mut()
        .zip(nonce16.as_chunks::<4>().0.iter())
    {
        *word = u32::from_le_bytes(*chunk);
    }

    // 参考 `chacha_generic.go:377-390`：每轮先对角、后列，共 10 轮。
    // （RustCrypto 内部先列后对角；两条路径产出同一子密钥，由本模块的固定向量
    //   与「切分恒等式」同时钉死，见 `xchacha_nonce_split_matches_reference_vectors`。）
    for _ in 0..10 {
        // Diagonal round.
        let (x0, x4, x8, x12) = quarter_round(state[0], state[4], state[8], state[12]);
        let (x1, x5, x9, x13) = quarter_round(state[1], state[5], state[9], state[13]);
        let (x2, x6, x10, x14) = quarter_round(state[2], state[6], state[10], state[14]);
        let (x3, x7, x11, x15) = quarter_round(state[3], state[7], state[11], state[15]);
        // Column round.
        let (x0, x5, x10, x15) = quarter_round(x0, x5, x10, x15);
        let (x1, x6, x11, x12) = quarter_round(x1, x6, x11, x12);
        let (x2, x7, x8, x13) = quarter_round(x2, x7, x8, x13);
        let (x3, x4, x9, x14) = quarter_round(x3, x4, x9, x14);
        state = [
            x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15,
        ];
    }

    // 参考 `chacha_generic.go:397-404`：输出 state[0..4] 与 state[12..16]。
    let mut out = [0u8; 32];
    for (chunk, word) in out[..16].as_chunks_mut::<4>().0.iter_mut().zip(&state[..4]) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    for (chunk, word) in out[16..]
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(&state[12..])
    {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// 参考向量的 PSK：32 字节，`0x11 0x22 .. 0xff 0x00` 重复两遍。
pub const VECTOR_PSK: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];

/// 解十六进制串（仅测试内使用，输入是本模块里的常量）。
pub fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("常量是合法十六进制"))
        .collect()
}

/// 把字节序列渲染成十六进制（仅用于断言信息，不含密钥内容）。
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// 参考向量的 nonce：24 字节递增序列（起点可变）。
pub fn seq_nonce(start: u8) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    for (index, byte) in nonce.iter_mut().enumerate() {
        *byte = start.wrapping_add(index as u8);
    }
    nonce
}

/// 从 24 字节 nonce 里切出 16 字节窗口：`nonce[start..start+16]`。
///
/// 切分点判据用：`start = 0` 是参考的真实切分（`xchacha20poly1305.go:56`
/// `HChaCha20(x.key[:], nonce[0:16])`），`start = 8` 是**错误**切分，
/// 用来反向证明切分点唯一。
pub fn nonce_window(start: u8, offset: usize) -> [u8; 16] {
    let nonce = seq_nonce(start);
    nonce[offset..offset + 16]
        .try_into()
        .expect("窗口恒为 16 字节")
}

/// 参考向量 A 的明文。
pub const PLAIN_A: &str =
    "1122334455667788000000000000000100000000000003e80003aabbcc017f000001003568656c6c6f";

/// 参考向量 A 的密文（`chacha20poly1305.NewX(psk).Seal(nil, NONCE_A, PLAIN_A, nil)`）。
pub const CT_A: &str = "d6bb5a8de021dfc89294653f104acb38f90f8891540f46f77f7805ab17cd9c4be3f9a207731ec49b47f84deb00045793f7f0eda257f438eab3";

/// 参考向量 A 的 HChaCha20 子密钥（`chacha20.HChaCha20(psk, NONCE_A[0..16])`）。
pub const SUBKEY_A: &str = "c62aabc45803b868c6441edad524e712cf1a5f7542a1c827a03a977cb3eb3e29";

/// 参考向量 A 的**错误切分窗口** `[8..24)` 的 HChaCha20 子密钥。
///
/// 该值只用于**反向**证明切分点唯一：若切分点其实在 `[8..24)`，
/// 则本仓与参考会一致地错、用它做切分恒等式也会成立；用它做恒等式必须**不成立**。
pub const SUBKEY_A_WRONG_WINDOW: &str =
    "c00e2537ce2f51d223c07715b189c147221a03b4497a982f4f9ac01cb8eb12d3";

/// 参考向量 B 的明文。
pub const PLAIN_B: &str =
    "aabbccddeeff0011000000000000000201000000000003e911223344556677880000017f0000010035776f726c64";

/// 参考向量 B 的密文（`chacha20poly1305.NewX(psk).Seal(nil, NONCE_B, PLAIN_B, nil)`）。
pub const CT_B: &str = "231585548e13e550267c081bc324c2717d5b09505a16a9890b90731531aa48c6a7dc8732d3efbf7342010e5f64bc4f24bf16afaa7f3503917910a316ddfa";

/// 参考向量 B 的 HChaCha20 子密钥。
pub const SUBKEY_B: &str = "a3f8b475d43fde8c75a7750df3083874f93ec7d93612f93c6e9fc4e3432a089f";

/// 参考侧 UDP 明文头的**最小**字节数。
///
/// 参考 `shadowaead_2022/protocol.go:42` `PacketMinimalHeaderSize = 30`：
/// `session_id(8) + packet_id(8) + type(1) + timestamp(8) + padding_len(2) + ATYP+addr+port(3)`
/// —— 30 字节是**不载荷**时的最小明文头。响应方向还多 8 字节 client session。
pub const PACKET_MINIMAL_HEADER_SIZE: usize = 30;

/// 参考侧 UDP nonce 长度：`shadowaead_2022/protocol.go:39` `PacketNonceSize = 24`。
pub const PACKET_NONCE_SIZE: usize = 24;

/// AEAD 认证标签长度：参考 `shadowaead/aead.go:22` `Overhead = 16`。
pub const OVERHEAD: usize = 16;
