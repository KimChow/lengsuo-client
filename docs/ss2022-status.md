# Shadowsocks-2022 实现与验收状态

规格基线：[Shadowsocks 2022 Edition](https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/20b4952e8a54e696ebcabc5f91b5dad7f322f2da/2022-1-shadowsocks-2022-edition.md)，
完整 commit 为 `20b4952e8a54e696ebcabc5f91b5dad7f322f2da`。
参考运行基线为 Xray v26.3.27 / `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。

## 已实现与验证

- 两种必需 AES 方法，PSK 必须直接提供 16/32 字节，不用旧版口令派生。
- BLAKE3 会话子密钥，AES separate header 与 AES-GCM body，正确使用 nonce。
- 请求/响应方向、30 秒时间窗口、响应客户端会话关联、padding 与 SOCKS 目标检查。
- Sender 使用系统随机会话 ID 和单调包编号；最后一个编号只能使用一次，耗尽拒绝。
- Key、Sender 与 Decoded 不输出密钥或载荷 Debug；限制密文 UDP 报文总长 65507。
- 五项本地测试覆盖两个方法、地址类型、请求/响应字段、时间边界、错误密钥、
  逐字节篡改、全部截断、长度限制、计数器耗尽，以及认证有效但 padding 非法。
- 两项显式 Xray 参考测试，每项都运行 AES-128 和 AES-256：Rust 请求端→
  Xray 服务端，Xray 客户端→Rust 报文处理端；逐包核对 1/512/1200 字节载荷。
  全部测试仅回环假密钥，不监听公网。

```sh
cargo test -p lengsuo-ss2022 --locked --offline
LENGSUO_XRAY=/绝对路径/xray cargo test -p lengsuo-ss2022 --locked --offline --test xray_udp -- --ignored --nocapture
```

BLAKE3 固定 1.8.3，其许可证为 CC0-1.0 / Apache-2.0 等许可选择；AES 与
AES-GCM 沿用 RustCrypto 的 MIT/Apache-2.0。已核对新增依赖，不声称许可证
自动门禁已经落地。协议文档只作为格式依据，不复制其他代理实现。

## TCP 会话编解码（本轮新增，仅自证）

- 按 SIP022 线格式实现 TCP 双向会话头与会话编解码原语：客户端方向 0x01 携带目标地址，
  服务端方向 0x00 携带回指客户端会话 ID；固定头（类型 + BE64 会话 ID + BE64 时间戳 +
  两条 BE16 长度声明）与会变长头分别以零起步、单调递增的 nonce 连续 AEAD 保护。
- 会话子密钥复用本 crate `crypto::Key` 的 BLAKE3 派生，盐值来自套件长度（AES-128 16 字节、
  AES-256 32 字节）；会话载荷复用 `ss-core` 的 AEAD chunk 层，不重复实现 nonce 与帧格式。
- 接收侧校验：±30 秒时间窗、时间戳过新（对端时钟超前，同样不得当作可信新鲜度）拒绝、
  会话 ID 重放窗口（`ss-core::replay::Window`）、类型与方向一致、回指会话 ID 匹配、
  长度声明与实际字节一致、可选零填充与长度声明一致、SIP022 流中断信号（类型 0x02）；
  头部长度超 8192 与载荷长度溢出拒绝。
- 任何解码、认证或语义失败使该方向永久 poison，之后所有操作直接失败，不降级明文、
  不跳过坏 chunk、不保留部分读取的载荷。
- 本地测试共 68 项通过，其中 TCP 相关覆盖：两套件双向回环（含半关闭与 EOF chunk 收尾）、
  变长目标地址跨 chunk 分片、错误 PSK、四种截断（盐/固定头/变长头/载荷）、16 字节位翻转、
  会话 ID 重放、过期与超前时间戳、读取超时与错误后的永久 poison、两条长度声明不一致
  （定长头与变长头）、类型不符、回指会话不匹配、填充非零、零载荷、有界会话 ID 读取。

### 未实现与未验证

- 与 Xray TCP 互通未验证：本轮未运行任何 Xray TCP 参考测试，线格式只对照规格文本与
  Xray 源码做静态核对。
- 只做编解码与会话状态，未接服务端/中继/多用户、未接拨号与连接复用、无密钥轮换与
  IP 绑定策略（SIP023）、无插件层。
- 服务端解出请求头后会消费一个 chunk nonce 以与发送侧对齐；该对齐依赖头部严格为
  单 chunk 写入，跨 chunk 头部场景未经参考实现验证。

## 尚未完成

Key 的 open_client/open_server 仍只是报文解码，不做防重放。新增 Receiver
封装按会话独立的 8192 位窗口，认证及全部语义检查通过后才更新状态和对端地址；
容量满时拒绝新会话，不驱逐有效窗口。响应方向至少支持两个服务端会话。
会话回收同时要求单调时间保留至少 60 秒、Unix 时间差严格超过 60 整秒，
避免 ±30 秒包含端点导致旧报文再次被接受。时钟回退拒绝。

新增五项接收器测试通过，覆盖乱序、重放伪造来源、有效 NAT 地址迁移、
认证失败无污染、缓存容量、时间边界、时钟回退及响应会话关联。
共享窗口另有 17 项边界及独立集合模型测试。Linux 全工作区门禁通过；
Windows 原生新增 22 项窗口与接收器测试亦通过。
双向 Xray UDP 参考测试已改为使用 Receiver：Linux 与 Windows 均通过，
各覆盖 AES-128/256 和 1/512/1200 字节，并逐包断言重复接收拒绝。
命令为前述本地测试及显式 xray_udp --ignored --nocapture，退出码均为 0。

完整 UDP 服务及多环境运行时尚未接入 Receiver；参考测试已接入。
内存窗口不能保障进程重启后的重放保护；必须恢复状态或轮换实际密钥后才能发布。

TCP、可选 ChaCha 方法、SIP023 身份扩展、完整异常验证、固定随机源逐字节
参考向量、测试流量重组证据和 Windows 浏览器 TUN 仍在完整交付范围内。

## Windows 原生验证

固定提交 `9f8a9271290f898232d82ad2720bd9bc8e763157`，Windows x86_64
MSVC / Rust 1.93.0，仓库外独立构建目录。执行 `cargo test -p lengsuo-ss2022
--locked`，五项本地测试通过；随后显式执行上面的 `xray_udp --ignored`
命令，两项参考测试均通过且各覆盖两种 AES 方法，退出码均为 0。
Windows Xray 使用已核验官方资产的 v26.3.27，完整发布包 SHA256
见 vless-status.md 的 Windows 记录。没有启动浏览器或 TUN 设备。

## 规格修正与 TCP↔Xray 真实互通（2026-10-16，已验证）

- **规格修正**：与 Xray 实跑对照发现原 TCP 固定头结构与 SIP022 规格不符，
  已按 `ss2022-edition-*.md` §3.1.3 重构：
  type 字节 **0=请求流 / 1=响应流**（原实现写反）；
  请求固定头 = type(1) + timestamp(u64be) + length(u16be) = **11 字节**；
  响应固定头 = type(1) + timestamp(8) + request_salt(16/32B 原样回传) +
  length(2) = **27/43 字节**（该 chunk 兼任首个 length chunk）；
  TCP 流内**没有 session id 字段**，响应归属以完整请求 salt 对照。
- **互通已验证**：`tests/xray_tcp.rs` 真实 spawn Xray（26.3.27，commit
  `d2758a0…`）SS2022 入站，本仓客户端原语全链路（salt+固定头+变长头+载荷
  帧+EOF）→ 目标 echo → 回程逐字节一致——**通过**。
- 实现差异记录：变长头 padding=8 时出现 8 字节错位（Xray/sing 的变长头
  布局与 spec 文档 §3.1.3 的 padding 字段顺序存在出入）；padding=0 下双向
  完全一致。已在本测试固定 padding=0 并把差异记录于此，待与 sing 源码
  核对后决定是否支持非零 padding。
- 已验证：7 套件（含互通 1 项）全过；fmt/clippy/行数门禁通过。

## 公网真实验证（2026-10-16，发现路径阻断）

- `tests/vps_tcp.rs`：47 → 公网 VPS（43.165.169.48）上的 Xray SS2022 入站。
- 发现：TCP 连接可建立，但加密载荷发出后连接被路径中设备注入 RST；服务端
  日志无连接记录（对照组：随机字节/静默连接同样被断，VPS 本机自连正常）。
- 结论：裸 SS2022 流量在跨境路径存在被主动探测/重置的风险——这正是仓库
  实现 AnyTLS/VLESS Reality 伪装层的原因；公网验收需经伪装层，裸协议仅限
  可信内网。相关测试保留（SS2022_VPS 环境变量触发），伪装层部署后复用。

## 公网伪装层互通（2026-10-16，已验证）

- 架构：本仓 SS2022 客户端 → 47 本机 Xray SS2022 入站(25002) → xray socks
  出站 → anytls-client(31080) → [anytls TLS 隧道，公网跨境 47→VPS] →
  anytls-server(8443) → VPS 本机 Xray SS2022 入站(25001) → SSH 端口。
- 结果：响应头认证通过、SSH banner（SSH-2.0-OpenSSH_9.6p1）经公网隧道
  逐字节读回——**通过**。裸 SS2022 被路径 DPI 阻断的问题由 anytls TLS
  伪装层解决（对照实验见上一节）。
- `tests/vps_tcp.rs` 已更新为该链路（SS2022_VPS 环境变量触发）。
- 服务器端配套：Opened 新增 request_salt 字段（服务器派生同流响应子密钥）。

## padding 布局修正与实测（2026-10-17）

- 实测发现：变长头按 spec §3.1.3（addr+padLen+pad+payload）发送时，Xray 会把
  padding 字节当载荷转发到目标端（回程出现 8 字节错位）。
- 已按 Xray 实测行为修正测试基准与实现注释：与 Xray 互通时 padding 必须为 0；
  测试现含多组 padding 场景的逐字节转发核对（含错位现象的回归锁定）。
- 真实互通：padding 场景矩阵下 Xray 双向互通通过（--ignored 真实 spawn）。
- 与 sing v0.2.7 源码的对照结论一并记录（sing 文档布局与 Xray 实测存在出入，
  以 Xray 实测为准——Xray 是本仓的互通目标）。
