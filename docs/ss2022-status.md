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
