# 记忆安全修复（2026-10-17）

原始回归复现：paths_guard_tests 3通过/5失败；memory_write_policy 1通过/4失败。

修复：用户/项目/身份/日志路径共用真实路径边界校验，拒绝外部及悬空symlink；
运行时写入记忆前脱敏，compose摘要在进入会话前脱敏；关闭记忆时拒绝append_daily，
身份层仍按MEMORY-SPEC不受跨会话开关限制。

新增8项路径回归与5项运行时写策略回归，既有断言保留。
agent-core + agent-memory：84 passed，0 failed；两crate all-targets clippy -D warnings及fmt通过。
先失败再修复记录在continue-20261017/logs/runtime-memory.jsonl；最终日志agent-next-memory-tests.log。

限制：路径检查与IO之间仍有TOCTOU窗口；不宣称原子文件系统防护。
用户/租户授权、路径根信任与记忆工具审批仍需宿主强制，不能以执行体测试代表完整权限链。
