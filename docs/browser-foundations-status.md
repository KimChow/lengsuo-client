# 浏览器基础组件验收（2026-10-17）

本批补齐原本未纳入主工作区的 profile/signature/package/lifecycle 四个
crate，并加入 installer/state 两个前置组件。常规工作区 CI 现在覆盖六者，
另设 Linux/Windows 浏览器组件 job，避免“仓内有代码但 CI 漏测”。
不代表浏览器运行器、安装器和恢复流程已经交付。

## 两个新模块的精确范围

### lengsuo-browser-installer：归档计划校验

`ArchivePlan` 只校验声明的路径、类型与资源预算，不读取/提取任何归档，
不认证清单或发布者，不安装或启动内核。后续安装器必须复用既有
package/signature 组件的来源证明，不能拿此校验替代认证。

- ASCII ZIP 路径子集，规范路径不超过 240 字节、32 个分段。
- 拒绝绝对路径、盘符、UNC、反斜杠、空段、dot/dotdot、Windows 非法/
  保留设备名、尾点/空格、符号链接、非空目录载荷。
- 拒绝大小写折叠碰撞和文件/后代路径碰撞；条目、单项、总字节受限，
  加法检查溢出，失败不修改计划状态。
- 5 项契约测试包含多组负例；初始 stub 真实失败，实现后转绿。

这些规则尚未证明文件系统暂存、reparse/符号链接竞态、ZIP 解码/压缩比、
下载、占用排空、原子发布、回滚或 Windows 签名。预算由可信调用方给出。

### lengsuo-browser-state：有界恢复元数据编解码

`encode/decode` 只处理非秘密的环境 ID、generation 与 was_running。
LBST v1 格式：4 字节魔数、u8 版本、u8 环境长度、环境字节、BE u64
generation、u8 running。环境 1..64 ASCII 字母数字/-/_，generation 非零，
编码总长最多 79 字节；严格拒绝截断、未知版本、额外字节与无效字段。

- 解码核对预期环境与调用方给出的 generation 下界。
- 无论 was_running 的值，结果都为 NeedsReconciliation。
- 不认证本地数据，不授予权限/租约/进程所有权，不按 PID 收养进程。
- 4 项测试覆盖独立字节断言、所有截断前缀、边界、环境和代际隔离。

状态落盘、原子更新、断电持久性、OS/Job Object 回收、崩溃恢复与应用
运行器接线仍待实现；原有 lifecycle 继续是状态机，不被此 codec 替代。

## 已执行验证

研究机 1.47 的最终合并快照基于 `af30038c38b42541a109de9b68dd8cafa8604c85`。
全工作区行数、fmt、clippy、test、build 门禁均退出 0，使用独立 target：

```text
python scripts/check_line_limit.py
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --locked
```

实际执行额外使用 `--offline`；不扩展测试覆盖范围。
Linux 最终全工作区合计 1034 项通过、24 项忽略；忽略项不计互通通过。
Windows 六个浏览器 crate 合计 206 项通过（含 doc-tests）、无忽略，
同六 crate 的 all-targets clippy 与全工作区 fmt 通过。发现并修复了既有
manifest_diagnostics 测试的 nonminimal_bool lint，未放宽断言。
Windows 其余网络/智能体模块未由本批重新完整验收。

Linux 回执：`/home/ubuntu/lengsuo-browser-dev/reviews/client-foundation-final-merge/`。
Windows 日志：`D:/lengsuo-build/client-browser-six-tests.log`、
`client-browser-six-clippy-final.log`。原始日志不入库。
workspace 中被忽略的专项测试仍不计作互通通过，网络范围继续以
[网络开发台账](network-development.md) 为准。
