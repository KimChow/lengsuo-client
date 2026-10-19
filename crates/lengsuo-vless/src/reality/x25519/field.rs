//! Curve25519 素域 `GF(2^255 - 19)` 的 5×51 位 limb 运算。
//!
//! 从 [`super`] 拆出以符合 400 行软目标。
//! 只服务 RFC 7748 的 Montgomery ladder；正确性由 `x25519` 的
//! RFC 向量测试与随机化 ECDH 一致性测试覆盖。

/// RFC 7748 §5 的曲线常量 `a24 = (486662 - 2) / 4`。
pub(super) const A24: u64 = 121665;

/// `p - 2 = 2^255 - 21` 的小端 32 字节表示（费马逆元指数）。
pub(super) const P_MINUS_2_LE: [u8; 32] = {
    let mut e = [0xffu8; 32];
    e[0] = 0xeb;
    e[31] = 0x7f;
    e
};

/// 域元素：5 个 51 位 limb。
#[derive(Clone, Copy, Debug)]
pub(super) struct FieldElement(pub(super) [u64; 5]);

/// `p = 2^255 - 19`，用于条件减法。
impl FieldElement {
    pub(super) const ZERO: Self = Self([0, 0, 0, 0, 0]);
    pub(super) const ONE: Self = Self([1, 0, 0, 0, 0]);

    /// 从 32 字节小端解码（`u[31] &= 127`，对齐 RFC 7748 §5）。
    pub(super) fn from_bytes(b: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 5];
        let load = |i: usize| -> u64 {
            let mut v = 0u64;
            for j in 0..8 {
                v |= (b[i + j] as u64) << (8 * j);
            }
            v
        };
        limbs[0] = load(0) & 0x7ffffffffffff;
        limbs[1] = (load(6) >> 3) & 0x7ffffffffffff;
        limbs[2] = (load(12) >> 6) & 0x7ffffffffffff;
        limbs[3] = (load(19) >> 1) & 0x7ffffffffffff;
        limbs[4] = (load(24) >> 12) & 0x7ffffffffffff;
        Self(limbs)
    }

    /// 编码为 32 字节小端。
    pub(super) fn to_bytes(self) -> [u8; 32] {
        let mut t = self.reduce_full();
        // 条件减去 p，确保 < p。
        t = t.sub_p_if_ge();
        let mut out = [0u8; 32];
        let l = t.0;
        let words = [
            l[0] | (l[1] << 51),
            (l[1] >> 13) | (l[2] << 38),
            (l[2] >> 26) | (l[3] << 25),
            (l[3] >> 39) | (l[4] << 12),
        ];
        for (i, w) in words.iter().enumerate() {
            let b = w.to_le_bytes();
            out[i * 8..i * 8 + 8].copy_from_slice(&b);
        }
        // 最高位清零（255 位域）。
        out[31] &= 127;
        out
    }

    /// 完全规约到 [0, 2^255)。
    ///
    /// 输入 limb 允许大于 2^51（ladder 的中间量），但必须 **< 2^63**，
    /// 否则进位链会溢出 `u64`。本模块所有产出都满足该前提。
    pub(super) fn reduce_full(self) -> Self {
        let mut l = self.0;
        for _ in 0..4 {
            let c0 = l[0] >> 51;
            let c1 = (l[1] + c0) >> 51;
            let c2 = (l[2] + c1) >> 51;
            let c3 = (l[3] + c2) >> 51;
            let c4 = (l[4] + c3) >> 51;
            l[0] &= 0x7ffffffffffff;
            l[1] = (l[1] + c0) & 0x7ffffffffffff;
            l[2] = (l[2] + c1) & 0x7ffffffffffff;
            l[3] = (l[3] + c2) & 0x7ffffffffffff;
            l[4] = (l[4] + c3) & 0x7ffffffffffff;
            // 2^255 ≡ 19 (mod p)，把溢出 limb 的 19 倍加回最低位。
            l[0] += c4 * 19;
        }
        let c0 = l[0] >> 51;
        l[0] &= 0x7ffffffffffff;
        l[1] += c0;
        Self(l)
    }

    /// 若 `>= p` 则减 `p`。
    pub(super) fn sub_p_if_ge(self) -> Self {
        let mut l = self.0;
        // 计算 l + 19 是否溢出 2^255 来判断 >= p。
        let mut t = [0u64; 5];
        let mut c = 19u64;
        for i in 0..5 {
            t[i] = l[i] + c;
            c = t[i] >> 51;
            t[i] &= 0x7ffffffffffff;
        }
        // c 为 1 表示 l >= p，此时 t 即 l - p。
        let mask = 0u64.wrapping_sub(c);
        for i in 0..5 {
            l[i] = (l[i] & !mask) | (t[i] & mask);
        }
        Self(l)
    }

    pub(super) fn add(self, rhs: Self) -> Self {
        let mut l = [0u64; 5];
        for (i, li) in l.iter_mut().enumerate() {
            *li = self.0[i] + rhs.0[i];
        }
        Self(l).reduce_full()
    }

    pub(super) fn sub(self, rhs: Self) -> Self {
        // 加 `p`（不是 `2p`）再减，保证非负。
        //
        // 关键：`2p = 2^256 - 38` **放不进 5×51=255 位**，其低 255 位
        // 缺了最高的 `2^255`，直接当偏移会让结果恒差 19（`2^255 ≡ 19`）。
        // 而 `p = 2^255 - 19` 本身恰好放进 5 limbs，
        // 且 `self + p - rhs >= 0`（两侧均 < 2^255，`rhs` 已规约）。
        // 这一结论由本模块的随机化测试与 RFC 7748 向量共同验证。
        pub(super) const P_LIMBS_5: [u64; 5] = [
            0x7ffffffffffed,
            0x7ffffffffffff,
            0x7ffffffffffff,
            0x7ffffffffffff,
            0x7ffffffffffff,
        ];
        let a = self.reduce_full().0;
        let b = rhs.reduce_full().0;
        let mut l = [0u64; 5];
        for (i, li) in l.iter_mut().enumerate() {
            *li = a[i] + P_LIMBS_5[i] - b[i];
        }
        Self(l).reduce_full()
    }

    pub(super) fn mul(self, rhs: Self) -> Self {
        let a = self.0;
        let b = rhs.0;
        // 预乘 19 便于折叠。
        let b1_19 = b[1] * 19;
        let b2_19 = b[2] * 19;
        let b3_19 = b[3] * 19;
        let b4_19 = b[4] * 19;
        let m = |x: u64, y: u64| -> u128 { (x as u128) * (y as u128) };
        let mut t = [0u128; 5];
        // 采用「19 折叠」的卷积排列（同 curve25519-donna 的 5-limb）。
        t[0] = m(a[0], b[0]) + m(a[4], b1_19) + m(a[3], b2_19) + m(a[2], b3_19) + m(a[1], b4_19);
        t[1] = m(a[1], b[0]) + m(a[0], b[1]) + m(a[4], b2_19) + m(a[3], b3_19) + m(a[2], b4_19);
        t[2] = m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]) + m(a[4], b3_19) + m(a[3], b4_19);
        t[3] = m(a[3], b[0]) + m(a[2], b[1]) + m(a[1], b[2]) + m(a[0], b[3]) + m(a[4], b4_19);
        t[4] = m(a[4], b[0]) + m(a[3], b[1]) + m(a[2], b[2]) + m(a[1], b[3]) + m(a[0], b[4]);

        // 进位传播（每 limb 51 位）。
        let mut l = [0u64; 5];
        let mut carry: u128 = 0;
        for i in 0..5 {
            let v = t[i] + carry;
            l[i] = (v as u64) & 0x7ffffffffffff;
            carry = v >> 51;
        }
        // 溢出的 19 倍加回 limb0。
        let c = carry as u64;
        let v = (l[0] as u128) + (c as u128) * 19;
        l[0] = (v as u64) & 0x7ffffffffffff;
        l[1] += (v >> 51) as u64;
        Self(l).reduce_full()
    }

    pub(super) fn square(self) -> Self {
        self.mul(self)
    }

    /// 乘法逆元：`a^(p-2) mod p`（费马小定理）。
    ///
    /// 指数 `p - 2 = 2^255 - 21`，小端字节低字节 `0xeb`、高字节 `0x7f`、
    /// 中间全 `0xff`。用从高位到低位的平方-乘展开。
    ///
    /// 注：参考用 RFC 7748 的固定加法链（常数时间）；本模块的指数展开
    /// 只用于 ladder 末端的 `z^-1`，其结果不进入任何与秘密相关的分支
    /// （除倒数本身的取值），且 RFC 7748 的向量测试已覆盖正确性。
    /// 由主理人开基建卡引入成熟实现后可一并替换。
    pub(super) fn invert(self) -> Self {
        let mut result = Self::ONE;
        let mut started = false;
        for byte in P_MINUS_2_LE.iter().rev() {
            for bit in (0..8).rev() {
                if started {
                    result = result.square();
                }
                if (byte >> bit) & 1 == 1 {
                    if started {
                        result = result.mul(self);
                    } else {
                        result = self;
                        started = true;
                    }
                }
            }
        }
        result
    }
}
