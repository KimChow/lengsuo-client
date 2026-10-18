//! 通配模式 API 与语义集成测试（按主题拆分；单文件 700 硬限/400 软目标）。
//! 原单文件 448 行，2026-10-18 按主题机械拆分为四组 + 共享 fixtures，断言与顺序未改。

mod fixtures;

mod boundary;
mod fail_closed;
mod specificity;
mod wildcard_match;
