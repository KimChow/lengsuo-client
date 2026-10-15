# 浏览器环境出口路由实现状态

本模块（`crates/lengsuo-environment`）提供「浏览器环境身份 -> 出口设备」的纯内存权威路由核心，
不是平台 TUN，不接触真实设备、不读系统进程、不做域名全局路由。

## 已实现

- 类型：`EnvironmentId(u64)`、`DeviceId(u64)`、`Binding { device, epoch }`、
  `Lease { environment, device, epoch }`，字段公开便于上层组合。
- `Router::bind(env, device) -> Result<Lease, RouterError>`：只有目标设备已显式上线才成功；
  离线目标返回 `DeviceOffline` 且不改动原绑定、不消耗代次。
- `Router::set_online(device, bool) -> usize`：设备离线时其在途绑定全部失效并被移除，
  返回失效条数；重新上线不恢复任何旧 lease，必须显式重绑。
- `Router::remove(env) -> Option<Binding>`：撤销绑定，幂等；已分配代次永不复用。
- `Router::resolve(env) -> Result<Lease, RouterError>`：无映射返回 `UnknownEnvironment`，
  绑定设备当前离线返回 `DeviceOffline`，两者都拒绝且不回退到默认出口。
- `Router::validate(lease) -> Result<(), RouterError>`：要求环境、设备、代次与当前权威状态
  逐项匹配且设备在线；任何不符返回 `StaleLease` 或 `UnknownEnvironment`。
- 代次由 `Router` 内部全局计数器用 `checked_add` 分配，严格递增；到达 `u64::MAX` 时
  返回 `EpochExhausted`，状态保持不变。
- 仅使用 `std::collections::BTreeMap`，无新增依赖；`#![forbid(unsafe_code)]`。

## 域名与身份

`resolve` 与 `validate` 的入参里没有域名字段：域名不参与出口身份判定。
同一个站点域名下的三个浏览器环境（测试中的 A/B/C）凭各自的 `EnvironmentId`
解析到三台互不相同的出口设备，互不串扰。域名到环境的选择属于上层策略与
平台 TUN 分流，本 crate 只保证身份到设备的权威映射与失效语义。

## 验证

`cargo test -p lengsuo-environment --offline`：原始会话的 11 个测试通过；集成复核后为 12 个（9 个集成 + 3 个单元）。

- 同域名 A/B/C 三个环境得到三个独立出口设备，撤销其一不影响其余，且不给出默认出口。
- 未知环境身份的 `resolve`/`validate` 均拒绝。
- 绑定离线设备失败且原绑定逐字不变；失败不消耗代次。
- 重绑或换设备后旧 lease 立即失效，「新设备 + 旧代次」的混搭凭据同样被拒。
- 删除后以同一 id 重建一定拿到更大的代次，旧 lease 永久不可用。
- 设备离线使其全部绑定失效，重新上线后旧 lease 仍失效，需显式重绑。
- 单元用例直接构造内部状态覆盖代次耗尽与「绑定指向离线设备」的防御分支。

`cargo fmt --all -- --check`、`cargo clippy -p lengsuo-environment --all-targets -- -D warnings`、
`python3 scripts/check_line_limit.py` 均通过；`src/router.rs` 238 行、
`tests/router.rs` 271 行、`src/lib.rs` 20 行，均在 400 行软目标内。

## 未实现 / 待独立验收

- 与平台 TUN、DNS、IPv6、UDP、MTU、断线与休眠恢复的分流集成尚未实现，需单独验收。
- 设备在线状态的真实来源（出口运行时心跳）未接入，目前由调用方显式上报。
- lease 的持久化、跨进程传递与并发（锁/异步）未实现，本核心为单所有者同步模型。
- 未做与任何第三方实现的互通验证；以上结论只来自本仓自有测试。

## 集成复核修正

额外复现测试发现：新建 Router 时 epoch 从 1 开始，上一 Router 的旧租约
可能匹配新绑定。现每个 Router 用操作系统安全随机源生成 128 位实例命名空间，
所有租约同时校验实例、环境、设备和代次。系统随机源失败时构造函数返回错误，
不会使用固定值回退。移除 Router 的 Clone/Default，避免复制权威表或绕过构造。
`Router::new()` 现返回 Result；实例标识不是凭据，租约必须留在可信运行时内部，
不能将外部请求中的结构体直接视为已认证身份。新增重建实例回归测试。
新增直接依赖 getrandom 0.2 为 MIT/Apache-2.0；许可证自动门禁仍未落地。
