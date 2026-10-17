# 测试分工

- 卡 A：`engine.rs`（compose/开关/容量/身份读写）
- 卡 B：`daily.rs`（追加/尾部读取/清除/路径安全）
测试文件同名镜像：`engine_tests.rs` / `daily_tests.rs`（AGENTS 规则：测试与被测模块同名镜像）。
