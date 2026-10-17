# lengsuo-client

客户端独立开发仓，源码可查看，**不授予开源许可**。

| crate | 职责 | 当前状态 |
|---|---|---|
| `crates/ss-client` | 客户端入站与隧道 | 骨架，尚无可启动服务 |
| `crates/ss-core` | 两端共享地址、KDF、AEAD、TCP chunk | 部分原语实现，未完成 Xray 互通验收 |

服务端位于独立 GitLab 私有仓，本仓构建不需要服务端源码或私有仓权限。
2026-10-15 更新：本批 Rust 网络能力集中在本仓，包括八协议、TUN、环境出口隔离和 VPS 工具；不拆协议仓。平台私有业务仍留在 GitLab。现有私有服务端固定 revision 依赖在明确更新前保持不变。

产品参考 WorkBuddy 的能力与交互，自主实现智能体工作平台，桌面界面采用 GPUI；参考紫鸟的产品设计思路，自主实现指纹浏览器与环境隔离，并结合 Jev 相关能力（具体职责待专项设计）。八协议（含 AnyTLS）与 TUN 专门服务于指定浏览器环境，不默认接管整机流量。

隐私与工具权限由运行时强制检查；浏览器操作、页面读取和向模型发送内容分别授权。规划不代表已实现，详细协作约束见 [AGENTS.md](AGENTS.md)。

```text
cargo build --workspace --locked
cargo test --workspace --locked
```

先阅读 [AGENTS.md](AGENTS.md)。文件硬上限 700 行、软目标 400 行；行数检查、格式、clippy、测试和构建必须通过。

当前测试不代表客户端/服务端通信已实现，更不代表 Xray 所有协议完全一致。

2026-10-16 协议复核：已有参考矩阵覆盖四类协议共17项测试；八协议全能力、
安全路径及 Windows 浏览器 TUN 尚未完成。配置办法、确定缺陷与验收范围见
[协议对等差距矩阵](docs/protocol-parity-gap.md)；自动门禁见
[固定参考互通门禁](docs/reference-validation.md)。

2026-10-17：参考矩阵现含18项，SS2022 TCP反方向及其余协议完整互通仍待验收；
本次门禁修复和证据见 [参考验证记录](docs/reference-validation.md)。

VMess 请求地址编码修复及实际验证范围见 [VMess 状态](docs/vmess-status.md)，
原语修复不代表完整网络互通。
Agent 模块已入仓；能力复核确认网关、策略判定、模块接线和 GPUI 仍有缺口，尚不可作为可运行产品交付。
本批范围、验证与限制见 [Agent 集成状态](docs/agent-integration-status.md)。

网络开发已改为按依赖分批验收，完整范围与启动/交付条件见
[网络开发任务](docs/network-development.md)。WG已补独立KDF及官方核心进程验证，
SS2022非零padding的旧文档限制已按实测纠正，均不代表完整协议/浏览器TUN已完成。

DNS 显式上游 UDP 交换及问题名解析回归已通过研究机 Linux 测试；浏览器 TUN 完整验收仍待完成，详见 [网络开发台账](docs/network-development.md)。

Hysteria2 已具备 UDPMessage 消息层编解码与边界测试；QUIC/HTTP3 运行时和真实互通仍待完成。

SS2022 TCP 新增固定 Xray 客户端到 Rust 接收方的双向载荷互通测试；范围与限制见网络开发台账。
