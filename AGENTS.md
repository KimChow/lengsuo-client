# lengsuo-client AI 与协作规则

## 1. 仓库与边界（已确定）

- 本地独立目录：`D:/OneDrive/project/lengsuo-client`。
- GitHub：`KimChow/lengsuo-client`，源码可查看，不等于开源授权。
- 本仓是客户端真实开发仓，不是私有仓抽取镜像。
- `crates/ss-client`：客户端连接、本地入站与客户端错误处理。
- `crates/ss-core`：双端共享协议的唯一定义处；只容纳协议原语、帧与类型，不依赖客户端/服务端业务。
- 私有服务端位于兄弟目录 `../lengsuo`；通过本公开仓固定 Git revision 引用 `ss-core`。
- 不复制两套协议实现，不引用私有仓路径或凭据；客户独立 clone 后必须能够构建。
- 客户端与服务端独立提交/发版；跨仓修改先发布共享核心，再更新服务端 revision。

## 2. 文件与构建硬限制

- 单文件 **700 行硬上限**，**400 行软目标**，含空行、注释与测试。
- 超 400 行须按职责拆分或在 PR 说明理由；超 700 行必须失败，不得删注释或压缩代码绕过。
- 检查 Git 跟踪文件及未忽略新文件：Rust、TS/JS、Python、Shell、配置、SQL、Markdown。
- 不检查 lockfile、测试 fixture、生成物、依赖和构建目录；不得将手写业务伪装成 fixture。
- `scripts/check_line_limit.py` 执行门禁；两仓各有独立 CI，规则变更须一起核对。
- dev/release profile 显式 `debug = 0`、`strip = "debuginfo"`。
- 禁止生产网络代码使用 `unsafe`，例外必须先说明并取得确认。

## 3. 安全与公开边界

- 禁止提交真实凭据、私钥、签名证书、客户数据、生产配置和未脱敏日志/抓包。
- 使用测试专用假凭据；运行时凭据由配置注入，日志不得输出密码或密钥。
- 认证/解码失败必须 fail-closed，不得静默回退到明文。
- 计费、授权、节点池管理等服务端权威逻辑不进入本仓。
- 不因源码可查看而绕过鉴权；不自动部署、杀进程或改系统安全设置。
- 遵守项目与第三方许可义务；源码可查看不得描述为已授予开源许可。

## 4. AI 工作与测试限制

- 新协议先讨论接口、兼容范围、测试计划，得到确认再实现；本次只调整归属和门禁。
- 修复先复现失败；协议测试须覆盖边界、截断、篡改、错误密码与收尾行为。
- 异步读写测试必须有超时；`read_to_end` 前必须确保写端关闭。
- 不并发对同一 target 执行 cargo；长任务等待完成通知，不反复轮询或 sleep。
- 卡住先依据测试/进程证据定位；未经确认不得终止用户进程。
- 自家 roundtrip 和 Python 向量只证明有限原语，不证明与 Xray 完全兼容。
- Xray 基线锁定 tag 和完整 commit；实际互通需 Rust↔Rust、Rust 客户端↔Xray 服务端、Xray 客户端↔Rust 服务端。
- 固定随机参数/时钟/分块的确定性用例逐字节比对；真实连接比较重组后的协议语义与载荷。
- 原生 TCP/UDP、外层传输、安全层、异常行为分别验收；不把不同网络分段误判为协议差异。
- 全协议是长期兼容目标，未实现项标记待实现；未经实测不得声称完全一致。
- 远程测试优先研究机 47，测试专用目录/端口/假凭据；只抓测试流量，不抓生产或用户业务。
- 拿到真实服务程序后再进行抓包验收；目前 client/server 是桩，不能冒充已具备服务。
- 保留基线 commit、配置摘要、命令、退出码、断言与脱敏证据；测试失败不能报全绿。

## 5. 交付门禁

```text
python scripts/check_line_limit.py
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo build --workspace --locked
```

- 本机使用隔离 target 验证，不触碰旧构建锁；远程完整互通另行验收。
- 功能分组 commit/push，不强推、不跳过 hooks；push 后核对远端 SHA。
- 协议兼容改动同时核对服务端固定 revision；不默认自动更新所有消费者。
- 用户明确的 700/400 行数及双目录归属已生效；严格 TDD 强度与细化兼容矩阵仍可讨论。
