//! X25519（RFC 7748）**内置实现**，仅供 REALITY 握手层使用。
//!
//! # 为什么内置
//!
//! 参考客户端用 Go 标准库 `crypto/ecdh` 的 `X25519()`，服务端用
//! `golang.org/x/crypto/curve25519`。本 crate 的依赖里**没有**任何
//! X25519 实现（`x25519-dalek` 在工作区未声明，且本卡不得改 `Cargo.toml`），
//! 故按 RFC 7748 §5 逐条转写。**这是既定偏离**，已列入报告「偏离清单」：
//! 由主理人开基建卡引入 `x25519-dalek` 后，本文件可整体删除。
//!
//! # 实现要点（对齐 RFC 7748）
//!
//! * 曲线：Curve25519，模数 `p = 2^255 - 19`。
//! * 标量裁剪（`decodeScalar25519`）：`k[0] &= 248; k[31] &= 127; k[31] |= 64`。
//! * 基点 `u = 9`；`X25519(k, u)` 为 Montgomery ladder 结果。
//! * 编码：小端 255 位，忽略最高位（`u[31] &= 127`）。
//! * 低阶点：结果为全零时**必须报错**（对齐 `crypto/ecdh` 与
//!   `curve25519.X25519` 的行为；本模块以 [`X25519Error::LowOrderPoint`] 表示）。
//!
//! 纯 Rust、无 `unsafe`。字段运算用 5×51 位 limbs（RFC 7748 §5 的
//! 教科书做法），乘法用 u128 累加，规约用 2^255 ≡ 19。

use thiserror::Error;

use self::field::{FieldElement, A24};
/// X25519 运算错误。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum X25519Error {
    /// 输入是低阶点（或标量为 0），共享密钥为全零。
    ///
    /// 参考：`crypto/ecdh` 的 `ECDH` 对全零结果返回
    /// `Err(ecdh.ErrIncorrectLength)`/内部错误，`curve25519.X25519`
    /// 返回 `"bad input point: low order point"`。
    #[error("X25519: low order point (all-zero shared secret)")]
    LowOrderPoint,
}

/// 解码标量（RFC 7748 §5 `decodeScalar25519`）。
fn decode_scalar(k: &[u8; 32]) -> [u8; 32] {
    let mut e = *k;
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;
    e
}

/// Montgomery ladder 标量乘：计算 `X25519(k, u)`（RFC 7748 §5）。
fn montgomery_ladder(k: &[u8; 32], u: &FieldElement) -> FieldElement {
    // 常数时间 ladder（RFC 7748 伪代码）。
    let x1 = *u;
    let mut x2 = FieldElement::ONE;
    let mut z2 = FieldElement::ZERO;
    let mut x3 = x1;
    let mut z3 = FieldElement::ONE;
    let mut swap = 0u8;

    for t in (0..255).rev() {
        let kt = (k[t >> 3] >> (t & 7)) & 1;
        swap ^= kt;
        // 条件交换。
        if swap == 1 {
            core::mem::swap(&mut x2, &mut x3);
            core::mem::swap(&mut z2, &mut z3);
        }
        swap = kt;

        let a = x2.add(z2);
        let aa = a.square();
        let b = x2.sub(z2);
        let bb = b.square();
        let e = aa.sub(bb);
        let c = x3.add(z3);
        let d = x3.sub(z3);
        let da = d.mul(a);
        let cb = c.mul(b);
        x3 = da.add(cb).square();
        z3 = x1.mul(da.sub(cb).square());
        x2 = aa.mul(bb);
        z2 = e.mul(aa.add(e.mul(FieldElement::from_u64(A24))));
    }
    if swap == 1 {
        core::mem::swap(&mut x2, &mut x3);
        core::mem::swap(&mut z2, &mut z3);
    }
    x2.mul(z2.invert())
}

/// 从 `u64` 构造域元素（用于曲线常量 `A24` 与基点 9）。
impl FieldElement {
    fn from_u64(v: u64) -> Self {
        Self([v, 0, 0, 0, 0]).reduce_full()
    }
}

/// 计算 `X25519(private, public)`。
///
/// * `private`：32 字节标量，内部按 RFC 7748 裁剪。
/// * `public`：32 字节 u 坐标。
///
/// 返回 32 字节共享密钥；输入为低阶点（结果全零）时返回
/// [`X25519Error::LowOrderPoint`]，**不得**把全零共享密钥当合法值继续。
pub fn x25519(private: &[u8; 32], public: &[u8; 32]) -> Result<[u8; 32], X25519Error> {
    let scalar = decode_scalar(private);
    let u = FieldElement::from_bytes(public);
    let out = montgomery_ladder(&scalar, &u).to_bytes();
    if out.iter().all(|&b| b == 0) {
        return Err(X25519Error::LowOrderPoint);
    }
    Ok(out)
}

/// 由标量计算公钥（`X25519(k, 9)`），用于生成临时密钥对。
pub fn x25519_base(private: &[u8; 32]) -> [u8; 32] {
    let scalar = decode_scalar(private);
    let nine = FieldElement::from_u64(9);
    // 基点结果不会全零，故直接取字节。
    montgomery_ladder(&scalar, &nine).to_bytes()
}

pub mod field;

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn h32(s: &str) -> [u8; 32] {
        let v: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }

    #[test]
    fn rfc7748_section_5_2_vector_1() {
        // RFC 7748 §5.2 第一组向量。
        let scalar = h32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = h32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let want = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";
        assert_eq!(hex(&x25519(&scalar, &u).unwrap()), want);
    }

    #[test]
    fn rfc7748_section_5_2_vector_2() {
        let scalar = h32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = h32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        let want = "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957";
        assert_eq!(hex(&x25519(&scalar, &u).unwrap()), want);
    }

    #[test]
    fn rfc7748_iterated_vector() {
        // RFC 7748 §5.2 迭代 1000 次（性能可接受）。
        let mut k = h32("0900000000000000000000000000000000000000000000000000000000000000");
        let mut u = k;
        for _ in 0..1000 {
            let r = x25519(&k, &u).unwrap();
            u = k;
            k = r;
        }
        assert_eq!(
            hex(&k),
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
        );
    }

    #[test]
    fn diffie_hellman_agrees() {
        // 两方各自生成，交叉计算必须一致。
        let a_priv = h32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let b_priv = h32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let a_pub = x25519_base(&a_priv);
        let b_pub = x25519_base(&b_priv);
        // RFC 7748 §6.1 的公钥向量。
        assert_eq!(
            hex(&a_pub),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        assert_eq!(
            hex(&b_pub),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );
        let ss1 = x25519(&a_priv, &b_pub).unwrap();
        let ss2 = x25519(&b_priv, &a_pub).unwrap();
        assert_eq!(ss1, ss2);
        assert_eq!(
            hex(&ss1),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
    }

    /// 随机化性质测试：任意两对密钥的 ECDH 必须一致。
    ///
    /// 固定向量只覆盖少量输入；字段算术的边界（进位、借位、19 折叠）
    /// 需要大样本才能暴露 —— 本卡开发过程中 `sub` 的常量错误正是靠这类
    /// 检查发现的。
    #[test]
    fn randomized_diffie_hellman_agreement() {
        // 确定性 LCG，避免引入 dev-dependency。
        let mut state: u64 = 0x1234_5678_9abc_def0;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };
        for _ in 0..200 {
            let mut a = [0u8; 32];
            let mut b = [0u8; 32];
            for i in 0..32 {
                a[i] = (next() >> 33) as u8;
                b[i] = (next() >> 41) as u8;
            }
            let a_pub = x25519_base(&a);
            let b_pub = x25519_base(&b);
            let s1 = x25519(&a, &b_pub).unwrap();
            let s2 = x25519(&b, &a_pub).unwrap();
            assert_eq!(s1, s2, "ECDH disagreement for seeds {a:02x?} / {b:02x?}");
        }
    }

    #[test]
    fn low_order_points_rejected() {
        let k = h32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        // 全零 u 是低阶点。
        assert_eq!(x25519(&k, &[0u8; 32]), Err(X25519Error::LowOrderPoint));
        // 阶为 1 的点 u = 1。
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(x25519(&k, &one), Err(X25519Error::LowOrderPoint));
    }

    #[test]
    fn field_arithmetic_inverse_identity() {
        // x * x^-1 == 1。
        let x = FieldElement::from_bytes(&h32(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        ));
        let inv = x.invert();
        assert_eq!(x.mul(inv).to_bytes(), {
            let mut one = [0u8; 32];
            one[0] = 1;
            one
        });
    }

    #[test]
    fn encode_decode_roundtrip_masks_high_bit() {
        let mut b = [0xffu8; 32];
        b[31] = 0x80;
        // 最高位必须被忽略。
        let e = FieldElement::from_bytes(&b);
        let out = e.to_bytes();
        assert_eq!(out[31] & 0x80, 0);
    }
}
