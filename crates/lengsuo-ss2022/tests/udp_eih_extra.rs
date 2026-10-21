//! SS2022 ChaCha UDP 头（XChaCha 布局）与长度字段的逐字节核对。
//!
//! 固定参考（**不是** Xray 自带的 `proxy/shadowsocks_2022/`，那是账号/路由适配层）：
//! - `sing-shadowsocks/shadowaead_2022` v0.2.7（`33d5391`），线上字节由它生成。
//! - Xray `proxy/shadowsocks_2022/inbound.go:7` 直接 import 该包，
//!   `inbound.go:55` 调 `shadowaead_2022.NewServiceWithPassword`，故 Xray 是它的宿主。
//!
//! 参考要点（`文件:行号`）：
//! - `shadowaead_2022/protocol.go:39` `PacketNonceSize = 24`；
//! - `shadowaead_2022/protocol.go:40` `MaxPacketSize = 65535`；
//! - `shadowaead_2022/protocol.go:42` `PacketMinimalHeaderSize = 30`；
//! - `shadowaead_2022/protocol.go:143` / `service.go:114`
//!   `chacha20poly1305.NewX(psk)` ⇒ **XChaCha20-Poly1305**（24 字节 nonce）；
//! - `shadowaead_2022/protocol.go:494-498` 客户端把 24 字节随机 nonce 明文放在包首；
//! - `shadowaead_2022/protocol.go:541-542` AEAD 覆盖 nonce 之后的全部字节（+16 字节 tag）；
//! - `shadowaead_2022/protocol.go:495-497` ChaCha + 多用户 ⇒ `panic`
//!   （本仓 fail-closed 返回 `Error::Unsupported`）。
//!
//! 固定向量由参考实际使用的 AEAD 构造生成：
//! `golang.org/x/crypto/chacha20poly1305.NewX`（与上面两处 `NewX` 同一调用），
//! 生成器见 `docs/ss2022-udp-eih-extra.md`。
//!
//! 本卡只动测试与文档；生产代码（`crates/lengsuo-ss2022/src/`）不修改。
//!
//! ## 模块划分
//!
//! 按职责拆开，单文件都压在 400 行软目标内：
//! - `reference`（`udp_eih_extra/reference.rs`）：参考实现的**逐行转写**与固定向量。
//! - `header_layout`（`udp_eih_extra/header_layout.rs`）：UDP 头的**字节布局**与长度字段。
//! - `fail_closed`（`udp_eih_extra/fail_closed.rs`）：**拒绝路径**（超长 / 截断 / 组合边界）。
//! - `xray_interop`（`udp_eih_extra/xray_interop.rs`）：与固定 Xray 的**真实互通**（`#[ignore]`）。

#[path = "udp_eih_extra/reference.rs"]
mod reference;

#[path = "udp_eih_extra/header_layout.rs"]
mod header_layout;

#[path = "udp_eih_extra/fail_closed.rs"]
mod fail_closed;

#[path = "udp_eih_extra/xray_common.rs"]
mod xray_common;

#[path = "udp_eih_extra/xray_interop.rs"]
mod xray_interop;

#[path = "udp_eih_extra/xray_field_order.rs"]
mod xray_field_order;

#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;

use std::time::Duration;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use reference::{hchacha20_reference, hex, nonce_window, seq_nonce, unhex, VECTOR_PSK};

/// 每条用例的外层兜底超时。
pub(crate) const CASE_TIMEOUT: Duration = Duration::from_secs(20);

/// XChaCha20-Poly1305：与参考 `chacha20poly1305.NewX` 同一 AEAD。
pub(crate) fn xchacha() -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(&VECTOR_PSK).expect("32 字节是合法的 XChaCha 密钥长度")
}

/// ① XChaCha nonce 布局：24 字节 = 16 字节（HChaCha20 输入）+ 8 字节（big nonce）。
///
/// 逐字节对照表（参考 `protocol.go:39` `PacketNonceSize = 24`，
/// `golang.org/x/crypto/chacha20poly1305/xchacha20poly1305.go:41` 的 `Seal`）：
///
/// | 字节区间 | 语义 | 参考实现 | 本仓 |
/// |---|---|---|---|
/// | `[0..16)` | HChaCha20 的 nonce 输入（**不是**全零） | `xchacha20poly1305.go:56` `chacha20.HChaCha20(x.key[:], nonce[0:16])` | `chacha20::XChaChaCore::new`：`hchacha(key, iv[..16])` |
/// | `[16..24)` | big nonce，落到 ChaCha20 的 nonce 尾 8 字节 | `xchacha20poly1305.go:61` `copy(cNonce[4:12], nonce[16:24])` | `padded_iv[4..].copy_from_slice(&iv[16..])` |
/// | `[24..)` | AEAD 密文 + 16 字节 tag | `Seal(dst, nonce[0:24], plaintext, nil)` | `crypto.rs:155-160` `xchacha::seal` |
///
/// **注意**：任务书里「12 字节小 nonce 全零 + 8 字节大 nonce」的描述与实现不符。
/// XChaCha20-Poly1305 的 24 字节 nonce **不是**「12 全零 + 8」，
/// 而是「16 字节 HChaCha 输入 + 8 字节 big nonce」；
/// 本用例用固定向量把这一点钉死（见 `xchacha_nonce_split_matches_reference_vectors`）。
#[tokio::test]
async fn xchacha_nonce_layout_is_24_bytes_not_twelve_plus_eight() {
    tokio::time::timeout(CASE_TIMEOUT, async {
        // 24 字节 nonce 全部参与 AEAD：改任意 1 字节都必然认证失败。
        let aead = xchacha();
        let plain = b"nonce-layout-probe";
        let nonce = seq_nonce(0x00);
        let sealed = aead
            .encrypt(XNonce::from_slice(&nonce), plain.as_slice())
            .expect("封包应成功");
        // 密文 = 明文 + 16 字节 tag（参考 `shadowaead.Overhead = 16`）。
        assert_eq!(sealed.len(), plain.len() + reference::OVERHEAD);

        for offset in 0..reference::PACKET_NONCE_SIZE {
            let mut broken = nonce;
            broken[offset] ^= 0x01;
            assert!(
                aead.decrypt(XNonce::from_slice(&broken), sealed.as_slice())
                    .is_err(),
                "nonce 第 {offset} 字节被改后仍解密成功，说明该字节未参与认证"
            );
        }
    })
    .await
    .expect("用例不应超时");
}

/// ② XChaCha nonce 切分逐字节对照：HChaCha20(key, nonce[0..16]) 与
/// ChaCha20 尾 8 字节（nonce[16..24]）分别锁定。
///
/// 判据分三层，缺一不可：
/// 1. **HChaCha20 子密钥**逐字节等于参考值（钉死切分点就是 `nonce[0..16]`）；
/// 2. **切分恒等式**：`ChaCha20-Poly1305(subkey, 0000||big_nonce)` 与
///    `XChaCha20-Poly1305(psk, nonce24)` 密文逐字节相同；
/// 3. **反向判据**：换用错误窗口 `[8..24)` 时恒等式**不成立**
///    （证明切分点唯一，不是「随便哪个窗口都行」）。
#[tokio::test]
async fn xchacha_nonce_split_matches_reference_vectors() {
    tokio::time::timeout(CASE_TIMEOUT, async {
        // 第 1 层：本仓转写的 HChaCha20 与 Go 参考逐字节一致。
        let subkey = hchacha20_reference(&VECTOR_PSK, &nonce_window(0x00, 0));
        assert_eq!(
            hex(&subkey),
            reference::SUBKEY_A,
            "HChaCha20 子密钥与参考向量不一致"
        );

        // 第 2 层：完整密文逐字节等于参考 `chacha20poly1305.NewX` 的输出。
        let plain = unhex(reference::PLAIN_A);
        let aead = xchacha();
        let sealed = aead
            .encrypt(XNonce::from_slice(&seq_nonce(0x00)), plain.as_slice())
            .expect("封包应成功");
        assert_eq!(
            hex(&sealed),
            reference::CT_A,
            "XChaCha 密文与参考向量不一致（nonce 布局或 key 派生有偏差）"
        );

        // 第 3 层：切分恒等式成立 —— 用子密钥 + big nonce 走标准 ChaCha20-Poly1305，
        // 密文必须与 XChaCha 路径逐字节相同。
        let big_nonce = {
            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(&seq_nonce(0x00)[16..]);
            nonce
        };
        let sub_aead = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&subkey)
            .expect("32 字节是合法的 ChaCha20 密钥长度");
        let split_sealed = sub_aead
            .encrypt(
                chacha20poly1305::Nonce::from_slice(&big_nonce),
                plain.as_slice(),
            )
            .expect("封包应成功");
        assert_eq!(
            hex(&split_sealed),
            reference::CT_A,
            "切分恒等式不成立：子密钥与 big nonce 的切分位置有偏差"
        );

        // 第 3 层反向：错误窗口 `[8..24)` 的子密钥**不得**满足恒等式。
        let wrong_subkey = hchacha20_reference(&VECTOR_PSK, &nonce_window(0x00, 8));
        assert_eq!(
            hex(&wrong_subkey),
            reference::SUBKEY_A_WRONG_WINDOW,
            "错误窗口的子密钥与参考向量不一致"
        );
        let wrong_aead = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&wrong_subkey)
            .expect("32 字节是合法的 ChaCha20 密钥长度");
        let wrong_nonce = {
            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(&seq_nonce(0x00)[0..8]);
            nonce
        };
        let wrong_sealed = wrong_aead
            .encrypt(
                chacha20poly1305::Nonce::from_slice(&wrong_nonce),
                plain.as_slice(),
            )
            .expect("封包应成功");
        assert_ne!(
            hex(&wrong_sealed),
            reference::CT_A,
            "错误切分窗口竟然也满足恒等式，切分点未被唯一钉死"
        );

        // 第二个参考向量：换 nonce 起点，子密钥与密文都必须跟着变。
        assert_eq!(
            hex(&hchacha20_reference(&VECTOR_PSK, &nonce_window(0x20, 0))),
            reference::SUBKEY_B,
            "参考向量 B 的 HChaCha20 子密钥不一致"
        );
        let sealed_b = xchacha()
            .encrypt(
                XNonce::from_slice(&seq_nonce(0x20)),
                unhex(reference::PLAIN_B).as_slice(),
            )
            .expect("封包应成功");
        assert_eq!(
            hex(&sealed_b),
            reference::CT_B,
            "参考向量 B 的 XChaCha 密文不一致"
        );
    })
    .await
    .expect("用例不应超时");
}
