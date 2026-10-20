//! Ed25519 的曲线与标量算术（RFC 8032 §5.1）。
//!
//! 从 [`super`] 拆出以符合 400 行软目标；除本文件内部使用外**不公开**
//! 任何条目。
//!
//! * [`Point`] —— 扩展坐标下的 Edwards 点（`X`, `Y`, `Z`, `T`）。
//! * [`Scalar`] —— 4×64 位 limbs 的标量，模曲线阶 `L`。
//!
//! 域运算复用 [`crate::reality::x25519::field`] 的 `GF(2^255-19)` 实现
//! （与 Ed25519 的底层域相同）；模 `L` 约减用二进制长除法。

use std::sync::OnceLock;

use crate::reality::x25519::field::FieldElement;

use super::Ed25519Error;

/// 曲线参数 `d = -121665/121666`（RFC 8032 §5.1），小端。
const D_LE: [u8; 32] = [
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
    0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
];

/// `sqrt(-1)`（RFC 8032 §5.1），小端。
const SQRT_M1_LE: [u8; 32] = [
    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
    0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
];

/// 基点 `B` 的 y 坐标（RFC 8032 §5.1），小端。
const BY_LE: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// 基点 `B` 的 x 坐标（RFC 8032 §5.1），小端。
const BX_LE: [u8; 32] = [
    0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69,
    0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21,
];

/// 曲线阶 `L = 2^252 + 27742317777372353535851937790883648493`，4×64 limbs（小端）。
pub(super) const L_LIMBS: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0x0000_0000_0000_0000,
    0x1000_0000_0000_0000,
];

/// 曲线常量 `d`（缓存的域元素）。
fn d_const() -> FieldElement {
    static D: OnceLock<FieldElement> = OnceLock::new();
    *D.get_or_init(|| FieldElement::from_bytes(&D_LE))
}

/// `2*d`（RFC 8032 的加法公式用它）。
fn two_d() -> FieldElement {
    static D2: OnceLock<FieldElement> = OnceLock::new();
    *D2.get_or_init(|| d_const().add(d_const()))
}

/// `sqrt(-1)`。
fn sqrt_m1() -> FieldElement {
    static SQRT: OnceLock<FieldElement> = OnceLock::new();
    *SQRT.get_or_init(|| FieldElement::from_bytes(&SQRT_M1_LE))
}

/// `x^((p-5)/8)`（RFC 8032 §5.1 的开方辅助量）。
///
/// `(p-5)/8 = 2^252 - 3`，小端 32 字节。
fn pow_p58(x: FieldElement) -> FieldElement {
    const EXP: [u8; 32] = {
        let mut e = [0xffu8; 32];
        e[0] = 0xfd;
        e[31] = 0x0f;
        e
    };
    let mut result = FieldElement::ONE;
    for byte in EXP.iter().rev() {
        for bit in (0..8).rev() {
            result = result.square();
            if (byte >> bit) & 1 == 1 {
                result = result.mul(x);
            }
        }
    }
    result
}

/// 扩展坐标下的 Edwards 点（`X`, `Y`, `Z`, `T`）。
#[derive(Clone, Copy)]
pub(super) struct Point {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
    t: FieldElement,
}

impl Point {
    /// 仿射基点 `B`。
    pub(super) fn base() -> Self {
        let mut y_bytes = BY_LE;
        y_bytes[31] &= 0x7f;
        let y = FieldElement::from_bytes(&y_bytes);
        let x = FieldElement::from_bytes(&BX_LE);
        let t = x.mul(y);
        Self {
            x,
            y,
            z: FieldElement::ONE,
            t,
        }
    }

    /// Edwards 加法（RFC 8032 §5.1.4 的 `add-2008-hwcd-3` 公式）。
    ///
    /// 注意 `c = T1·T2·2d`（不是 `d`）：扩展坐标的 `T` 是 `x·y/z`，
    /// 与仿射坐标的乘积因子差一个 `2`。
    pub(super) fn add(self, rhs: &Self) -> Self {
        let a = self.y.sub(self.x).mul(rhs.y.sub(rhs.x));
        let b = self.y.add(self.x).mul(rhs.y.add(rhs.x));
        let c = self.t.mul(rhs.t).mul(two_d());
        let d = self.z.mul(rhs.z);
        let d = d.add(d);
        let e = b.sub(a);
        let f = d.sub(c);
        let g = d.add(c);
        let h = b.add(a);
        Self {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }

    /// 标量倍点（标量为小端字节序）。
    pub(super) fn scalar_mul(self, scalar: &[u8; 32]) -> Self {
        let mut result = Self {
            x: FieldElement::ZERO,
            y: FieldElement::ONE,
            z: FieldElement::ONE,
            t: FieldElement::ZERO,
        };
        let mut base = self;
        for byte in scalar.iter() {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 1 {
                    result = result.add(&base);
                }
                base = base.add(&base);
            }
        }
        result
    }

    /// 压缩编码（32 字节）。
    pub(super) fn compress(&self) -> [u8; 32] {
        let z_inv = self.z.invert();
        let x = self.x.mul(z_inv);
        let y = self.y.mul(z_inv);
        let mut out = y.to_bytes();
        if x.to_bytes()[0] & 1 == 1 {
            out[31] |= 0x80;
        }
        out
    }

    /// 解压（32 字节压缩点）。
    pub(super) fn decompress(bytes: &[u8; 32]) -> Result<Self, Ed25519Error> {
        let sign = bytes[31] >> 7;
        let mut y_bytes = *bytes;
        y_bytes[31] &= 0x7f;
        let y = FieldElement::from_bytes(&y_bytes);
        // x² = (y²-1) / (d·y²+1)
        let y2 = y.square();
        let u = y2.sub(FieldElement::ONE);
        let v = d_const().mul(y2).add(FieldElement::ONE);
        let v3 = v.square().mul(v);
        let v7 = v3.square().mul(v);
        let mut x = u.mul(v3).mul(pow_p58(u.mul(v7)));
        let check = v.mul(x.square());
        if check != u {
            if check == u.negate() {
                x = x.mul(sqrt_m1());
            } else {
                return Err(Ed25519Error::InvalidPublicKey);
            }
        }
        if x.to_bytes()[0] & 1 != sign {
            x = x.negate();
        }
        let t = x.mul(y);
        Ok(Self {
            x,
            y,
            z: FieldElement::ONE,
            t,
        })
    }
}

/// 标量（4×64 位 limbs，小端）。
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Scalar([u64; 4]);

impl Scalar {
    /// 从 4 个 limbs 构造。
    pub(super) fn from_limbs(limbs: [u64; 4]) -> Self {
        Self(limbs)
    }

    /// 转为小端 32 字节。
    pub(super) fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, limb) in self.0.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
        }
        out
    }

    /// 是否 ≥ `L`。
    pub(super) fn ge_l(&self) -> bool {
        for i in (0..4).rev() {
            if self.0[i] != L_LIMBS[i] {
                return self.0[i] > L_LIMBS[i];
            }
        }
        true
    }

    /// 减去 `L`（调用前保证 `self >= L`）。
    fn sub_l(&self) -> Scalar {
        let mut limbs = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (v, b1) = self.0[i].overflowing_sub(L_LIMBS[i]);
            let (v, b2) = v.overflowing_sub(borrow);
            limbs[i] = v;
            borrow = (b1 as u64) | (b2 as u64);
        }
        Scalar(limbs)
    }

    /// 模 `L` 加法（两个操作数均 `< L`）。
    pub(super) fn add_mod_l(&self, rhs: &Scalar) -> Scalar {
        let mut limbs = [0u64; 4];
        let mut carry = 0u128;
        for (i, limb) in limbs.iter_mut().enumerate() {
            let term = (self.0[i] as u128) + (rhs.0[i] as u128) + carry;
            *limb = term as u64;
            carry = term >> 64;
        }
        // `self + rhs < 2^254`，不会溢出 4 个 limbs。
        debug_assert_eq!(carry, 0);
        let mut result = Scalar(limbs);
        while result.ge_l() {
            result = result.sub_l();
        }
        result
    }

    /// 模 `L` 乘法（两个操作数均 `< L`）。
    pub(super) fn mul_mod_l(&self, rhs: &Scalar) -> Scalar {
        // 4×4 的 128 位部分积，得到 8 个 limbs。
        let mut product = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let term =
                    (self.0[i] as u128) * (rhs.0[j] as u128) + (product[i + j] as u128) + carry;
                product[i + j] = term as u64;
                carry = term >> 64;
            }
            product[i + 4] = carry as u64;
        }
        mod_l_512(&product)
    }
}

/// 把 512 位数（8 个 limbs，小端）约减到模 `L`。
///
/// 用二进制长除法：逐位把 `x` 的比特移入余数，余数 ≥ `L` 时减一次 `L`。
/// `L < 2^253`，故移位后余数 `< 2^254`，4 个 limbs 足够。
pub(super) fn mod_l_512(x: &[u64; 8]) -> Scalar {
    let mut rem = [0u64; 4];
    for i in (0..512).rev() {
        let bit = (x[i / 64] >> (i % 64)) & 1;
        let mut carry = bit;
        for limb in rem.iter_mut() {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        debug_assert_eq!(carry, 0);
        if ge_l_limbs(&rem) {
            rem = sub_l_limbs(&rem);
        }
    }
    Scalar::from_limbs(rem)
}

/// 把 512 位哈希（约减到 `< L`）作为标量。
pub(super) fn scalar_from_sha512(hash: &[u8; 64]) -> Scalar {
    let mut limbs = [0u64; 8];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&hash[i * 8..i * 8 + 8]);
        *limb = u64::from_le_bytes(b);
    }
    mod_l_512(&limbs)
}

/// limbs 是否 ≥ `L`。
fn ge_l_limbs(limbs: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if limbs[i] != L_LIMBS[i] {
            return limbs[i] > L_LIMBS[i];
        }
    }
    true
}

/// limbs 减去 `L`。
fn sub_l_limbs(limbs: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (v, b1) = limbs[i].overflowing_sub(L_LIMBS[i]);
        let (v, b2) = v.overflowing_sub(borrow);
        out[i] = v;
        borrow = (b1 as u64) | (b2 as u64);
    }
    out
}

/// 32 字节小端字节序转成 4 个 limbs。
pub(super) fn limbs_from_le(bytes: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
        *limb = u64::from_le_bytes(b);
    }
    limbs
}
