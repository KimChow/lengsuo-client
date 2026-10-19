//! 仅含  子模块的薄壳。
//!
//! 需要「Xray 夹具 + codec」的测试（）直接引 ；
//! 只需要 codec 的测试（）引本文件。两种测试各自独立
//! 编译，后者只用到 codec 的少数几个函数，其余会被判 dead_code —— 这里的
//! allow 只作用于本薄壳， 那条编译单元仍然严格。
#[allow(dead_code)]
pub mod codec;
