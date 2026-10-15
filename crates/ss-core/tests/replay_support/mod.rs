//! 模型测试使用的确定性序列。
/// 固定种子线性同余发生器：序列完全确定，可重跑复现。
pub struct Lcg {
    state: u64,
}

impl Lcg {
    pub const fn new(seed: u64) -> Self {
        Lcg { state: seed }
    }

    /// 数值类型答案（不含随机数库依赖）。
    pub fn next_u64(&mut self) -> u64 {
        // 常用的 Knuth/MSVC 混合常数，纯算术，跨平台一致。
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.state
    }

    /// 返回 `0..range` 内的确定值；`range` 非零。
    pub fn below(&mut self, range: u64) -> u64 {
        // 取高位避免 LCG 低位周期过短。
        (self.next_u64() >> 11) % range.max(1)
    }
}
