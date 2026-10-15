# AnyTLS 实现与验收状态

协议参考基线：anytls-go 完整 commit
`fd6167acd6d73b9fa3e607659951847fbc9e6c50` 中的 `docs/protocol.md`、
`proxy/session/frame.go` 与 `proxy/session/session.go` 客户端分支，协议版本 2。
参考目录只读，仅用于核对语义，未复制其实现。

## 已实现（纯内存原语与状态机）

认证原语：SHA256 密码摘要、两字节 padding 长度、容量限制内完整读取
padding 后常量时间认证。调用方必须先建立经过服务器身份验证的 TLS。
所有异步读写具备正数截止时间，无认证失败明文回退。

帧原语：11 个命令的编解码，四字节大端 Stream ID、两字节大端数据长度；
禁止不允许载荷的 SYN、FIN 和心跳帧携带数据。异步读取先检查容量上限。
认证对象与数据帧均不派生 Debug，避免凭据或应用载荷意外进入日志。
任何流操作失败后调用方必须丢弃该连接，不得在未对齐的流上继续读取。

服务端入站会话 `server_state::ServerState`：帧方向、Settings 先行及一次性、
Stream ID 非零且严格递增、活跃流容量、数据与关闭的流归属、v2 心跳。
首个非法帧永久失效（fail-closed），之后全部拒绝。

客户端出站会话 `client_state::ClientState`：只解释服务器方向帧。

- `new(max_streams)` 拒绝零容量；`mark_settings_sent()` 只调用一次，
  未标记前仅容忍 Waste，其余远端帧使会话 poison。
- Stream ID 由本端从 1 严格连续分配（`checked_add`，先查容量后取号，
  因此容量或编号空间耗尽都不消耗 ID），已关闭 ID 永不复用。
- 活跃流表是 `BTreeMap<u32, bool>`（编号 → 是否已收到成功 SYNACK），
  不保存任何载荷或错误文本；事件只带流编号，字节由调用方持有的原帧提供。
- 对端版本默认 1，收到合法 ServerSettings 后升级为 2。ServerSettings 须
  stream id 为 0、只出现一次、UTF-8 `key=value` 文本、禁止重复键、
  必须含 `v=1|2`，未知键忽略；本实现自设 4096 字节上限（参考实现无此上限）。
- `is_ready`：v1 活跃即就绪；v2 须已收到空载荷 SYNACK。带错误文本的
  SYNACK 只删除该流并产出 `Rejected`，不毒化其他流；v1 收到 SYNACK 视为违规。
- 关闭竞态：ID 由本端连续分配，故 `0 < id <= 已分配上限` 而不在活跃表内
  唯一含义是“本端已关闭”，这类迟到 Push/Fin/SynAck 一律 `Ignore`，
  不影响其他活跃流；`id == 0` 的流帧或超出已分配上限（从未创建）的引用
  是协议违规，poison 整条会话。
- Push 须活跃且就绪；空载荷 Push 不产生事件。FIN 无载荷并关闭流。
- UpdatePadding 在 v1/v2 均可、须 stream id 为 0，只上报 `PaddingUpdate`
  事件交由上层解析，本模块不宣称 padding 策略已生效。
- HeartRequest/HeartResponse 仅已知 v2 且无载荷；任意 u32 关联值都合法，
  前者以 `Heartbeat(id)` 交上层原样回包，后者 `Ignore`（不当作完整健康验证）。
  心跳的关联值不是流编号，也不用于映射浏览器环境。
- Alert 产出终止事件并终止会话，之后 `accept`/`open_stream`/`close_stream`
  全部拒绝；Syn/Settings 等客户端方向帧由服务端发送即 poison。
- 异常路径 fail-closed：远端违规永久 poison；本地 API 参数错误仅返回错误，
  不破坏既有流，也不改写已协商版本。

## 已验证（真实断言，仅本 crate）

- 5 项帧与认证原语测试；15 项服务端状态测试；30 项客户端状态测试。
- 客户端用例覆盖 Settings 先行与版本协商、重复/非法 UTF-8/重复键/超上限、
  容量拒绝不消耗 ID、关闭不复用 ID、v2 ACK 成功与错误仅影响单流、
  跨流隔离、关闭后迟到数据/FIN/ACK 安全忽略、从未创建流与零编号拒绝、
  方向违规 poison、心跳保留 37 等非零关联值、Alert 终止、零容量、
  以及事件不复制载荷（帧可原样编解码回比对）。
- 门禁：`cargo fmt --all`、`cargo test -p lengsuo-anytls --locked`、
  `cargo clippy -p lengsuo-anytls --all-targets -- -D warnings`、
  `python scripts/check_line_limit.py` 全绿；各文件均在 400 行目标内。

## 未实现 / 未验证（不得据此认为可用）

`client_state` 不是完整的 AnyTLS 网络服务。缺口包括：

- TLS 连接与服务器身份验证、`Credential::send` 的实际调用与握手时序；
- 帧的读写循环、`Command`/`Frame` 到真实 socket 的绑定、超时与半关闭；
- 客户端 Settings 文本与 `padding-md5` 的生成（本模块只标记“已发送”）；
- padding 方案解析、`stop`/分包/`c` 检查符号及 Waste 填充的写出策略；
- SYNACK 等待超时与卡住隧道恢复、主动心跳计时与健康判定；
- 空闲会话复用池（`Seq`、`idleSessionCheckInterval` 等）与 UDP-over-TCP v2；
- 与 anytls-go 或 Xray 的任何双向参考互通——目前未互通。

上述原语与状态机测试不能代表网络服务、复用或参考互通通过，
不得作为可用代理发布。
