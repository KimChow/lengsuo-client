# 网关 v0 实现与验收（2026-10-17）

## 接口与边界

`GatewayHandle::start(Runtime, GatewayConfig::new(handshake_path, isolation))`异步启动；
`port()`供本机客户端连接，`token()`只供宿主传递，不记录日志；`shutdown()`有界关闭并清理握手文件。
仅绑定127.0.0.1随机端口；256bit启动token，所有HTTP/WS请求以X-Gateway-Token鉴权。
握手文件create_new创建，拒绝覆盖其他进程文件；Unix权限0600，需宿主提供已有私有父目录。
非Unix平台因ACL尚未验证明确返回Unsupported，不宣称Windows已验收。

实现冻结动作：sys:ping、config:get/set、session:list/create/get/send/stop、tool:list、approval:respond。
信封code/msg/data；未知动作404，鉴权HTTP403，非法载荷400，RPC超时408。
会话动作以payload.id指定session；create支持title/workspaceRoot/mode/permissionMode。
身份和环境由宿主绑定，禁止客户端覆盖；操作外部隔离会话拒绝。
审批应答需id（会话）、approvalId与approved；只允许当前隔离范围的挂起审批。
WS发送蛇形事件字段seq/session_id/kind/payload/ts_ms，与shell wire约定一致；过滤隔离身份及环境。

## 实际验证

先写真实HTTP回环测试，空lib基线因GatewayConfig/GatewayHandle缺失编译失败；再实现转绿。
7个有界集成测试通过：RPC往返/配置、错误token/404、隔离、旧握手保护、
WS鉴权/事件顺序、50会话并发、慢provider的408与ping响应、0600与token轮换。
`cargo test -p agent-gateway --locked --offline`、all-targets clippy -D warnings与fmt通过。
源码日志gateway-red.log/gateway-green.log/gateway-clippy.log保存在研究机lengsuo-client-dev外部目录。

## 明确限制

Runtime现有Provider只有Echo/Unsupported，本测试不代表真实模型或工具执行链完成。
RPC超时只终止等待；已进入spawn_blocking的同步回合可能继续完成，不保证副作用回滚。
session:stop沿用现有Runtime停止状态语义，不宣称中断正在阻塞的Provider。
WS慢客户端有发送超时；底层有界总线丢弃语义不变，客户端可通过seq识别缺口。
记忆工具/策略/MCP完整编排与GPUI联调仍需另卡，网关不新增未冻结动作伪装接通。
