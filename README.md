# lengsuo-client

客户端独立开发仓，源码可查看，**不授予开源许可**。

| crate | 职责 | 当前状态 |
|---|---|---|
| `crates/ss-client` | 客户端入站与隧道 | 骨架，尚无可启动服务 |
| `crates/ss-core` | 两端共享地址、KDF、AEAD、TCP chunk | 部分原语实现，未完成 Xray 互通验收 |

服务端位于独立 GitLab 私有仓，本仓构建不需要服务端源码或私有仓权限。
共享协议只在本仓维护；服务端通过固定 Git 提交引用，不复制、不自动抽取同步。

```text
cargo build --workspace --locked
cargo test --workspace --locked
```

先阅读 [AGENTS.md](AGENTS.md)。文件硬上限 700 行、软目标 400 行；行数检查、格式、clippy、测试和构建必须通过。

当前测试不代表客户端/服务端通信已实现，更不代表 Xray 所有协议完全一致。
