//! 凭据体系的 Native Messaging host 侧**协议层**（纯函数、无 IO、可单测）。
//!
//! 字节布局的唯一真相是浏览器仓的 `docs/credential-wire-contract.md` §5.2 / §5.3；
//! 本 crate 每个模块对应契约的一节，测试逐字节断言。
//!
//! 骨架先落，实现由后续卡补齐。
