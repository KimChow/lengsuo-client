//! FileStore 磁盘存储契约测试（按主题拆分；单文件 700 硬限/400 软目标）。
//! 原单文件 640 行，2026-10-18 按主题机械拆分为六组，断言与顺序未改。

mod basic;
mod fixtures;
mod header;
mod rotation;
mod scope;
mod stderr;
#[path = "../support/mod.rs"]
mod support;
mod tamper;
