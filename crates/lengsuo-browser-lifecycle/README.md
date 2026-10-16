# 浏览器环境生命周期核心

该 crate 实现单个环境的状态机、代次、注入时钟期限和资源清理记账。
它不启动进程，不拥有 Windows Job Object，也不建立网络隔离、授权或持久化。
集成层必须提供真实资源及可信观察；状态机不是鉴权边界。

## 接口与兼容范围

启动顺序固定：

```text
Stopped -> Authorizing -> Installing -> PreparingNetwork
        -> StartingProcess -> Probing -> Running
```

- `begin_start` 只接受已保存代次的下一个值；检查失败不消耗代次。
- `complete` 完成当前步骤；进程启动只能用 `report_identity` 报告。
- 进程身份为非零 PID 与非零创建标识；同 PID 不同创建标识不可混用。
- `stage_failed`、网络丢失、授权撤销或确切进程退出转入 Failed，返回清理需求。
- `stop_with_budget` 进入 Stopping，要求正数清理期限；`stop` 默认 30 秒。
  默认值是可配置的实现选择，不代表已经验收的停止性能指标。
- 超时保留资源记账，不能将超时当作进程已终止或资源已释放。
- 只有可信资源所有者调用 `cleanup_completed` 后，才允许回到 Stopped 并重启。
- 异步计时回调应调用带代次的 `deadline_expired_for` / `timeout_for`。
  不带代次的方法用于当前监督器的集中时钟观察，不能接收旧任务的计时回调。

时钟由调用者注入；相等可接受，倒退、零预算、期限加法溢出均拒绝。
期限在 `now >= expiry` 时失效。守卫拒绝不修改状态；已接受的运行失败会保留
`pending_cleanup`，即使操作返回错误，调用者也必须处理该需求。
迟到的进程身份或网络就绪报告会在失败时保留对应资源，避免清理遗漏。

运行代次必须在创建外部资源前可靠持久化。清理确认必须等待真实进程树、
安装暂存与网络资源收尾；不能仅凭 `identity=None` 就声称清理完成。
本模块不实现上述存储与操作系统行为，也不把画像字符串 ID 转换为网络数字 ID。

## 验证

Linux 使用研究机 1.47 隔离 target，Windows 使用本机 OneDrive 外的 target：

```text
cargo test -p lengsuo-browser-lifecycle --offline --locked
cargo clippy -p lengsuo-browser-lifecycle --all-targets --offline --locked -- -D warnings
```

测试覆盖顺序、重复步骤、代次溢出、迟到回调、PID 复用、时钟边界、启动各阶段
取消、清理期限、撤销、网络丢失以及清理确认前禁止重启。
47 的证据保存在开发目录 `reviews/lifecycle-primary-*.log`；本机证据位于
`D:/lengsuo-build/logs/lifecycle-windows-test.*`，不将原始日志作为发行产物。

本次纠正的旧测试问题：

- 原测试引用不存在的身份辅助函数和错误枚举；改为实际构造器及既有运行守卫。
- 一项测试给 begin 的期限多加了辅助驱动的后续 STEP，与另一项断言冲突；
  期限按 begin 收到的真实注入时刻计算。
- 两项超时测试在期限前期待超时；改为观察确切期限。
- 驱动在接受未来时刻的观察后未推进自己的时钟，导致后续清理倒退；驱动现与
  已接受的观察一致。没有放宽运行时代码的时钟守卫。

尚缺真实 Windows 进程树/Job Object、进程创建时间核验、网络租约接入、
凭据 IPC、崩溃恢复日志及 GPUI 状态显示；单元测试通过不代表这些已实现。
