# 协议对等差距矩阵（本仓 vs 原生参考实现）

生成方式：只读静态盘点。参考侧按目录逐文件 `wc -l` + 命名/头部注释判职责；本仓侧按 crate 文件清单 + `pub fn|struct|enum` API 面提取。未做运行时互通验证。

## 0. 范围原则（先读这一节）

本仓定位是**客户端协议原语层**：分帧（frame/header/chunk）、AEAD/KDF、握手与认证、会话/流状态机、重放窗口、目标地址编解码、UDP associate 帧、心跳/空闲、错误处理与 fail-closed。

参考实现（Xray-core / anytls-go / hysteria）是**完整代理服务端 + 客户端 + 平台栈**，其中以下内容属于**范围外**，不计入缺失（集中列在第 10 节）：配置解析与 protobuf、policy/路由/分发器、监听器与多用户管理、UDP NAT 会话表与端口分配、度量统计/日志/OCSP、进程级 TLS 证书加载、TUN 设备内核交互、QUIC/HTTP3 栈本身、VMess/VLESS 服务端用户校验与时间窗缓存。

因此"参考几十个文件、我们没那么多"这句话需要拆开看：**文件数差距中约一半是 config/pb/inbound/server/平台层**；但另一半（协议原语）确实存在真实缺口，尤其是 **VMess（本仓为空壳）**、**Hysteria（空壳）**、**VLESS XEL 加密层（缺失）**、**WireGuard 只解不封**、**AnyTLS 只有服务端状态机没有客户端**、**Shadowsocks TCP 流端到端未收尾**。

---

## 1. 总览表

参考行数量级按"协议相关文件"统计（含参考自带测试；protobuf 生成文件标注在明细中）。本仓行数为该 crate 全部 `.rs`（含 tests）。

| 协议 | 参考协议相关文件数 | 本仓文件数 | 参考行数量级 | 本仓行数量级 | 差距级别 |
|---|---|---|---|---|---|
| Shadowsocks（传统/AEAD） | 9（proxy/shadowsocks）+ 8（common/crypto）+ 2（common/protocol/address）= 19 | 5（lengsuo-shadowsocks）+ 12（ss-core）= 17 | ~2.4K + ~1.2K | 774 + 1606 ≈ 2.4K | **中** |
| Shadowsocks 2022 | 7（proxy/shadowsocks_2022，其中 542 行为 pb） | 7（lengsuo-ss2022） | ~1.4K | 817 | **中** |
| Trojan | 8（proxy/trojan，其中 324 行为 pb） | 10（lengsuo-trojan） | ~1.5K | 1810 | **小** |
| VLESS | 18（proxy/vless）+ 2（common/xudp）= 20 | 11（lengsuo-vless） | ~3.8K | 1363 | **大** |
| VMess | 24（proxy/vmess） | 1（lengsuo-vmess 空壳） | ~3.0K | 2 | **大（几乎全缺）** |
| WireGuard | 11（proxy/wireguard，不含 wireguard-go 依赖） | 5（lengsuo-wireguard）+ 6（lengsuo-tun） | ~2.3K（其中 ~890 行为 tun/bind 平台层） | 610 + 1271 | **大（消息只解不封）** |
| AnyTLS | 22（anytls-go 全部 `.go`，其中 cmd/ 工具层 6 个） | 8（lengsuo-anytls）+ 2（lengsuo-tls） | ~2.0K | 1123 + 231 | **中偏大** |
| Hysteria（仅 protocol 层） | 4（core/internal/protocol）+ 2（speedtest/protocol） | 1（lengsuo-hysteria 空壳） | ~1.3K（含测试 763） | 2 | **大（几乎全缺）** |
| TUN / IP 包解析 | 6（wireguard tun*.go + gvisortun） | 6（lengsuo-tun） | ~1.2K（多为平台代码） | 1271 | **中** |
| 共享原语（buf/net/mux/drain/antireplay/cache） | 约 60 文件 / ~7K 行 | ss-core replay/target + lengsuo-environment | ~7K | 416（replay+target）+ 816 | 多数**范围外**，见 §10 |

---

## 2. Shadowsocks（传统 + AEAD，SIP002/003/004/007/010）

### 2.1 映射表

| 参考文件 | 一行职责 | 本仓对应 | 状态 |
|---|---|---|---|
| `proxy/shadowsocks/protocol.go` | UDP 请求/响应分帧：salt + 目标地址 + payload 的 seal/open，地址长度上限校验 | `lengsuo-shadowsocks/src/udp.rs`（`UdpCodec::seal/open`、`MAX_PACKET_LEN=65507`） | 已实现（UDP 双向） |
| `proxy/shadowsocks/protocol_test.go` | 地址编解码/坏地址/往返测试 | `tests/udp.rs`、`tests/xray_udp.rs`、`src/udp/vectors.rs` | 已实现（含 Xray 互通） |
| `proxy/shadowsocks/client.go` | TCP 出站：salt+chunk 流写入、读取循环、半关闭 | `ss-core/src/chunk.rs`（异步 chunk reader/writer）+ 无上层流装配 | **部分**：chunk 层有，端到端 TCP 会话流未收尾（`ss-core/src/lib.rs` 文档明示"完整流收尾…尚未完成"） |
| `proxy/shadowsocks/server.go` | 入站：多用户、UDP NAT 会话表、lastPeer 回包 | — | 范围外（除回包绑定语义） |
| `proxy/shadowsocks/config.go` + `config.pb.go` | 套件名解析（`getCipher`）、protobuf 配置 | `ss-core/src/crypto.rs::CipherSuite::from_name` | 已实现（4 套件）；pb 范围外 |
| `proxy/shadowsocks/validator.go` | 服务端多密码校验 | — | 范围外 |
| `common/crypto/auth.go` | `CreateAuthenticator`：TCP AEAD 流封装（salt→HKDF→CK/MS/MK、2 字节长度头 + tag）、legacy 分支 | `ss-core/src/kdf.rs`（`evp_bytes_to_key`、`hkdf_sha1_subkey`）+ `crypto.rs`（`SessionAead`、`NonceCounter`）+ `chunk.rs` | **部分**：拆解件齐，未按 `auth.go` 的完整流顺序（含 size 头 tag 覆盖规则、`Next` 读满语义）串成可互通的读写器 |
| `common/crypto/chunk.go` | 分块读写（`ChunkWriter/ChunkReader`，最大块 8192，`ErrChunkSizeTooLarge`） | `ss-core/src/chunk.rs`（`MAX_CHUNK_PAYLOAD=8192`、`SIZE_WIRE_LEN`） | 已实现 |
| `common/crypto/io.go`、`crypto.go`、`aes.go`、`chacha20*.go` | Buffer 池、`AEAD` 接口、内部 chacha 实现 | 依赖 `ring`/RustCrypto（`SessionAead`） | 范围外（性能层） |
| `common/protocol/address.go`（+ test） | SS 地址 ATY 编解码、域名/端口校验、`AddrFromStr` | `ss-core/src/target.rs`（`encode_checked/decode/encoded_len`） | 已实现 |
| `references/ss2022-edition-*.md`、`shadowsocks-spec` 站点文本 | SIP004/SIP007 规范文本 | 注释已引用 | 已实现（依据文档） |

### 2.2 缺失能力清单（待实现）

1. **TCP AEAD 端到端流（salt→子密钥→chunk 循环→失败即断）** — 待实现。依据：`proxy/shadowsocks/client.go`、`common/crypto/auth.go`。风险：TCP 互通目前无证据，只有 UDP 有 Xray 互通测试。建议落点 `ss-core`（新增 `stream.rs`）或 `lengsuo-shadowsocks`（`tcp.rs`）。
2. **nonce 溢出/回绕的 fail-closed 语义** — 待实现。依据：`common/crypto/auth.go` 中 `NonceCounter` 达上限后必须拒绝继续写；本仓 `NonceCounter::next`（`ss-core/src/crypto.rs:112`）需明确并测试溢出行为（当前 lib 文档仅注明"nonce 为小端递增"）。
3. **AES-128-CCM / 其它 Xray `CipherType` 变体覆盖** — 待评估。依据：`proxy/shadowsocks/config.go` 的 `CipherType` 枚举（本仓仅 4 套：aes-128/256-gcm、chacha20-ietf-poly1305、xchacha20-ietf-poly1305）。若目标环境存在非 GCM/Poly1305 服务器，需补；否则记为刻意不做（建议文档化决策）。
4. **legacy 流密码（SIP003，aes-256-cfb 等）+ `authDataLength`** — 刻意不做（规范已废弃、Xray 亦默认拒绝），但需在 §10 明示为"安全理由排除"，并在错误路径返回明确变体（当前 `CipherSuite::from_name` 只返回 `None`）。
5. **UDP 重放/去重（同一 salt 会话内 payload 重复）** — 待实现（可选增强）。依据：SS 经典 UDP 无内建重放保护，而本仓已有 `ss-core::replay::Window` 可复用；参考侧无对应代码，属本仓主动加固项。

### 2.3 测试覆盖对照

| 场景 | 参考测试 | 本仓测试 | 缺口 |
|---|---|---|---|
| 地址边界（域名长度、端口 0、ATY 非法） | `protocol_test.go`、`address_test.go` | `ss-core/tests/address_validation.rs`、`tests/udp.rs` | 基本覆盖；建议补 IPv4-mapped/超长地址 |
| 截断包 | `protocol_test.go`（部分） | `tests/udp.rs` 有短包用例 | **TCP chunk 截断无测试**（随缺口 1 补） |
| 篡改（tag 失败） | — | `tests/udp.rs` 翻转位 | 覆盖 |
| 错误密码 | — | `tests/udp.rs`/`vectors.rs` | 覆盖；需断言"不 panic、不泄露明文" |
| 真实 Xray 互通 | 无自动化（Xray 需实跑） | `lengsuo-shadowsocks/tests/xray_udp.rs` | **TCP 互通完全缺失** |

---

## 3. Shadowsocks 2022（SIP022 / Edition 3 草案）

### 3.1 映射表

| 参考文件 | 一行职责 | 本仓对应 | 状态 |
|---|---|---|---|
| `proxy/shadowsocks_2022/outbound.go` | 出站：把 2022 密码派生为子密钥并接入 transport（UDP/TCP） | `lengsuo-ss2022/src/crypto.rs`（`Method`、`Key::subkey`）+ `packet.rs::Sender` | 部分（UDP 齐，TCP 无） |
| `proxy/shadowsocks_2022/inbound.go` | 入站：解 UDP 包、时间窗与重放过滤、回包到 lastPeer | `src/receiver.rs`（`Receiver::receive`、`Clock`、`last_peer`、`gc`） | 已实现（最小必要子集） |
| `proxy/shadowsocks_2022/inbound_relay.go` |  relay 语义：客户端会话绑定、转发方向固定 | `packet.rs::Sender::new(key, Some(client_session))`（响应方向绑定） | 已实现（单会话） |
| `proxy/shadowsocks_2022/inbound_multi.go` | 多用户（多 PSK）分流、按 session id 选择 | — | 范围外（服务端多用户） |
| `proxy/shadowsocks_2022/config.go` + `config.pb.go`（542 行） | 配置与 protobuf | — | 范围外 |
| `references/ss2022-edition-*.md` | 报文格式、时间容忍、padding 规则 | `packet.rs` 头注释 + `seal` 参数 `padding: u16` | 部分 |
| 共享重放（本仓） | — | `ss-core/src/replay.rs`（`WINDOW_BITS=8192`、`accept_authenticated`）+ `tests/replay*.rs`（含 model/invariants） | 已实现（比参考更严格的形式化测试） |

### 3.2 缺失能力清单（待实现）

1. **2022 TCP 会话（握手包 + 子密钥 + 重放窗口）** — 待实现。依据：`outbound.go` 接入的是通用 transport（TCP 路径复用 2022 密码的流封装），本仓 `packet.rs` 只做 UDP 报文；`lengsuo-ss2022/src/crypto.rs` 只有 `Method::key_len`/`subkey`。这是 2022 互通最大风险。
2. **握手期时间容忍与拒绝策略参数化** — 部分。依据：`inbound.go`（时间窗）与本仓 `Receiver::receive(..., now)`；缺窗宽/漂移上限的配置点与错误变体区分（`Error` 在 `lib.rs:8`，需确认覆盖 clock-skew vs replay vs tag）。
3. **padding 策略模块** — 待实现（本仓 `packet.rs` 注释自证："UDP 填充可为零；本实现使用零字节填充，尚无 padding 策略模块"）。依据：ss2022 规范文本 + `inbound.go`/`inbound_relay.go` 对长度敏感性的处理。风险：流量分析对端可观测，属"能力有但策略缺失"。
4. **packet id（计数器）上限与 Exhausted 后的连接终止** — 部分。依据：`Sender::next: Option<u64>` 与 `Error::Exhausted`；需与规范的重放窗口/上限对齐并测试（参考 `inbound_multi.go` 的计数器过滤）。
5. **多 PSK / session id 路由的服务端侧** — 范围外（`inbound_multi.go`），客户端仅需按 PSK 单会话。

### 3.3 测试覆盖对照

| 场景 | 参考测试 | 本仓测试 | 缺口 |
|---|---|---|---|
| 报文往返、双向（client→server→server→client） | 无（该包无 `_test.go`） | `tests/packet.rs`（89 行）、`tests/xray_udp.rs`（146 行，双平台参考互通） | 覆盖 |
| 重放（旧 counter / 重复 packet id） | 无 | `ss-core/tests/replay.rs`、`replay_model.rs`、`replay_invariants.rs` | 覆盖，且比参考强 |
| 时间窗越界 / 时钟漂移 | 无 | `tests/receiver.rs`（含 `gc`） | 建议补"未来时间戳"与"边界恰好窗宽"用例 |
| 截断 / 篡改 | 无 | `tests/packet.rs` 部分 | **头 32 字节截断矩阵不足**；缺"padding 长度与 total 不一致"用例 |
| 错误 PSK | 无 | `tests/receiver.rs`/`packet.rs` | 覆盖（需确认失败后 session 表不被污染） |
| TCP 互通 | 参考 TCP 走通用路径 | 无 | **完全缺失**（对应缺口 1） |

---

## 4. Trojan

### 4.1 映射表

| 参考文件 | 一行职责 | 本仓对应 | 状态 |
|---|---|---|---|
| `proxy/trojan/protocol.go` | 头部 `password\r\naddr\r\n` 编解码、`Command`（CONNECT / UDP）、UDP 分帧（2 字节长度 + 地址 + payload） | `src/codec.rs`（`Request`、`Command`、`encode/decode`、`header_len`） | 已实现 |
| `proxy/trojan/protocol_test.go` | 地址解析、头不匹配测试 | `tests/codec.rs`（327 行） | 已实现 |
| `proxy/trojan/client.go` | 出站流：写头、读响应（首字节 0x00/0x0A？）、TCP 转发 | `src/stream.rs`（212 行） | 已实现（含 `tests/stream.rs`、`stream_datagram.rs`） |
| `proxy/trojan/server.go`（550 行） | 入站、UDP associate 会话、TLS 记录、心跳处理 | 客户端侧仅需响应与 UDP 帧；`tests/xray_tls.rs`、`tests/xray_udp.rs` | 大部分范围外 |
| `proxy/trojan/validator.go`、`config*.go` | 多密码校验、配置 | `src/credential.rs`（`HASH_LEN=56`、`verify` 常量时间比较） | 客户端部分已实现；服务端范围外 |
| `common/drain/` | 关闭前读取残留避免 RST | — | 待实现 |

### 4.2 缺失能力清单（待实现）

1. **心跳/应答命令（`protocol.go` 中除 CONNECT/UDP 外的命令分支）** — 待实现（若参考侧存在 `DoHeartbeat`/应答码分支，本仓 `Command` 枚举未覆盖全部值）。风险：对端在空闲期发心跳时本仓可能当作非法帧 → 断连。参考依据：`proxy/trojan/protocol.go`、`server.go`。
2. **服务端响应首字节校验（成功/失败码）与 fail-closed** — 部分/待实现。依据：`proxy/trojan/client.go` 在读到响应字节后才开始转发；本仓 `stream.rs` 需明确"未收到成功响应前不转发载荷"，并测试错误密码路径。
3. **UDP 分帧最大长度与 MTU 处理** — 部分。依据：`protocol.go` 的 UDP 长度字段（2 字节）；本仓 `tests/stream_datagram.rs` 已覆盖往返，需补 65535 边界与截断。
4. **drain（优雅关闭）** — 待实现。依据：`common/drain/drainer.go`（虽属 common，但为互通所需：TLS 关闭前收发残留）。

### 4.3 测试覆盖对照

| 场景 | 参考测试 | 本仓测试 | 缺口 |
|---|---|---|---|
| 头编解码 / 错误密码 | `protocol_test.go`（92 行） | `tests/codec.rs`（327 行，含篡改） | 覆盖优于参考 |
| 截断头 | 无 | `tests/codec.rs` | 覆盖 |
| TCP 数据段往返 | 无 | `tests/stream.rs`（334） | 覆盖 |
| UDP associate 往返 | 无 | `tests/stream_datagram.rs`（317） | 覆盖；缺超长/分片边界 |
| 真实 Xray（TLS）互通 | 无 | `tests/xray_tls.rs`（172）、`tests/xray_udp.rs`（143） | 覆盖 |
| 心跳 / 空闲 | 无 | 无 | **缺**（对应缺口 1） |

整体：**Trojan 是最接近对等的协议**，差距集中在空闲/关闭语义。

---

## 5. VLESS

### 5.1 映射表

| 参考文件 | 一行职责 | 本仓对应 | 状态 |
|---|---|---|---|
| `proxy/vless/encoding/encoding.go` | 请求头（version/UUID/target/command/addons）与响应头编解码 | `lengsuo-vless/src/header.rs`（`encode/decode`、`Request`、`Command`） | 部分：**响应头解析未见独立 API** |
| `proxy/vless/encoding/encoding_test.go`（133 行） | 头往返、addons、边界 | `tests/stream.rs`（150）、`tests/xray_tcp.rs`（148） | 部分 |
| `proxy/vless/encoding/addons.go` + `addons.pb.go` | protobuf addons（flow/UA/路径） | `header.rs` 以原始字节承载 addons；`xudp.rs` 需要 inner flow | 部分 |
| `proxy/vless/encryption/common.go`（280）、`client.go`（210）、`server.go`（328）、`xor.go`（93） | **XEL（Xray Encryption Layer）**：`encryption=128`/`xor`/`none` 的记录封装、密钥轮转、内部重放保护 | 本仓完全无对应模块 | **待实现（最大缺口）** |
| `proxy/vless/account.go`、`validator.go`、`inbound/`、`outbound/`、`*.pb.go` | 账户、UUID+时间窗校验、in/out 服务、配置 | — | 范围外 |
| `common/xudp/xudp.go`（192）+ `xudp_test.go` | XUDP 内层地址/会话混淆头（Base/Seed/Suffix） | `lengsuo-vless/src/xudp.rs`（`Session::client/server`） | 已实现 |
| `proxy/vless/encryption/xor.go` | 轻量 XOR 记录层（反协议识别） | 无 | 待实现 |
| `common/protocol/id.go`、`time.go`、`headers.go` | UUID 生成/校验、认证时间戳计算 | `header.rs` 接收 `[u8;16]` UUID | 部分（无 UUID 字符串校验） |
| `transport/`（含 REALITY/TLS） | TLS 记录、REALITY 握手 | `lengsuo-tls`（`TlsClient/TlsServer`，231 行） | 部分：**REALITY 完全缺失**（是否范围外需产品决策） |

### 5.2 缺失能力清单（待实现）

1. **XEL 加密层（`encryption=128` / `xor`）** — 待实现。依据：`proxy/vless/encryption/{common,client,server,xor}.go` 共 ~711 行。现代 Xray 服务器可强制要求 XEL，缺失即无法互通。落点建议：`lengsuo-vless/src/xel/`。
2. **VLESS 响应头（服务端 → 客户端）解析与错误分支** — 待实现。依据：`encoding/encoding.go` 的 `WriteResponseHeader` 对应读取路径。
3. **addons protobuf 字段解码（flow 等）** — 部分。依据：`encoding/addons.go`、`addons.pb.go`；客户端需要至少读 `flow`（XUDP 依赖）。
4. **XUDP 序列/回绕与多流复用策略** — 部分。依据：`common/xudp/xudp.go` + `encryption/server.go` 对序号的处理；本仓 `xudp.rs`（128 行）只有会话基元。
5. **REALITY / TLS 记录层对接** — 待评估（若客户端目标环境包含 REALITY 服务器，则是硬性缺口；依据 `proxy/vless/inbound/inbound.go` 中 TLS/XEL 组合路径 + `lengsuo-tls` 现状仅 231 行）。
6. **UUID 文本校验/规范化** — 待实现（小）。依据：`common/protocol/id.go`。

### 5.3 测试覆盖对照

| 场景 | 参考测试 | 本仓测试 | 缺口 |
|---|---|---|---|
| 请求头往返/截断/篡改 | `encoding_test.go` | `tests/stream.rs`、`tests/xray_tcp.rs` | 覆盖；缺 addons 畸形 protobuf |
| XUDP 头 | `xudp_test.go`（36 行） | `tests/xudp.rs`（130） | 覆盖优于参考 |
| TLS 互通 | 无 | `tests/xray_tls.rs`（143）、`tests/tls_stream.rs`（60） | 覆盖 |
| UDP associate | 无 | `tests/xray_udp.rs`（152） | 覆盖 |
| **XEL（xor / 128）往返、密钥轮转、重放** | `encryption/` 无独立测试文件（依赖 in/out 集成） | 无 | **完全缺失**（对应缺口 1） |
| 错误 UUID / 时间窗 | `validator` 层 | 无 | 范围外偏多，但客户端需"错误即断"用例 |

---

## 6. VMess

本仓 `crates/lengsuo-vmess/src/lib.rs` 为 2 行占位（`#![forbid(unsafe_code)]` + "Network component under development"）。参考 `proxy/vmess` 有 24 个 `.go` / ~3001 行（含 pb 与测试）。**差距级别：大（近乎全缺）。**

### 6.1 映射表（参考 → 建议本仓文件）

| 参考文件 | 职责 | 本仓 | 状态 |
|---|---|---|---|
| `vmess/aead/kdf.go`（33） | KDF: MD5(uuid) → key/iv 派生 | 无 | 待实现 |
| `vmess/aead/authid.go`（121）+ `authid_test.go`（127） | AuthID 生成（时间窗 + 随机 valid 字节）、服务端有效性校验（含 ±2 窗） | 无 | 待实现（客户端只需生成） |
| `vmess/aead/encrypt.go`（135）+ `encrypt_test.go`（104） | `AuthResponseEncrypt/AuthResponseDecrypt`、LongConn 的 ShortID AEAD 封装 | 无 | 待实现 |
| `vmess/aead/consts.go`（14） | AEAD 常量 | 无 | 待实现 |
| `vmess/encoding/auth.go`（99） | VMess 认证请求（timestamp + request ID + cid 的 AEAD 头） | 无 | 待实现 |
| `vmess/encoding/client.go`（340） | 客户端请求头 + 响应解密 + 加密层选择（none / aes-128-gcm / chacha20-poly1305 / autocipher） | 无 | 待实现 |
| `vmess/encoding/server.go`（447） | 服务端对应路径 | 范围外（可作互通对端） | 范围外 |
| `vmess/encoding/commands.go`（73）+ `outbound/command.go`（14） | VMessOverTCP 命令（隧道/探测） | 无 | 待实现（可选） |
| `vmess/account.go` + `account.pb.go`、`validator.go`、`inbound/`、`outbound/` | 账户、alterID 配置、用户校验、服务装配 | 无 | 范围外 |
| `common/crypto/auth.go`（legacy `aes-128-cfb` 等） | VMess legacy 加密层 | 无 | 刻意不做（应拒绝） |

### 6.2 缺失能力清单（待实现，全部）

1. KDF + AuthID（`aead/kdf.go`、`aead/authid.go`）；
2. AEAD 请求/响应封装（`aead/encrypt.go`、`encoding/auth.go`）；
3. 客户端会话与加密层选择（`encoding/client.go`）；
4. 目标地址编码复用（`ss-core/src/target.rs` 可直接共享，避免第二套实现）；
5. 空闲/心跳（`aead/consts.go` 的 `Command` + `encoding/commands.go`）；
6. fail-closed：解密失败/响应校验失败一律断链（`encoding/client.go`）。

### 6.3 测试覆盖对照

| 场景 | 参考测试 | 本仓测试 | 缺口 |
|---|---|---|---|
| AuthID 时间窗（前后 2 分钟有效、过期拒绝） | `aead/authid_test.go` | 无 | **全缺** |
| ShortID/请求头往返、篡改 | `aead/encrypt_test.go`、`encoding/encoding_test.go` | 无 | **全缺** |
| KDF 黄金值 | 无 | 无 | **全缺**（建议自造固定向量） |
| Xray VMess 互通 | 无 | 无 | **全缺** |

---

## 7. WireGuard

### 7.1 映射表

| 参考文件 | 一行职责 | 本仓对应 | 状态 |
|---|---|---|---|
| `proxy/wireguard/client.go`（375） | 客户端：静态密钥握手、transport 消息封装/解封装、keepalive、pseudo-header（16 字节） | `src/wire.rs`（`parse`、`HandshakeKind::exact_len`、`TransportMessage`、`Message::counter`） | **部分：只解不封** |
| `proxy/wireguard/server.go`（172）+ `server_test.go`（52） | 入站 peer 表、握手应答 | 无（对端仅用于互通） | 范围外 |
| `proxy/wireguard/bind.go`（262） | bind/queue 与 device 对接 | `lengsuo-tun`（部分） | 范围外 |
| `proxy/wireguard/tun.go`、`tun_linux.go`、`tun_default.go`、`gvisortun/tun.go`（~890 行） | 内核 TUN 设备/平台差异/gvisor 栈 | `lengsuo-tun/src/{packet,checksum}.rs` | 部分（见 §9） |
| `proxy/wireguard/config.go`、`config.pb.go`（352） | pb 配置、密钥编解码 | — | 范围外 |
| `wireguard-go`（外部依赖，不在参考目录内） | 真正的 handshake 消息构造、noise 状态机、mac1/mac2/cookie | 本仓无 | **待实现（依赖决策）** |
| 重放 | — | `ss-core/src/replay.rs` 共享窗口 + `lengsuo-wireguard/src/replay.rs`（2 行复用 shim） | 已实现（窗口语义；缺 counter 回绕与"单调不回退"细则测试） |

### 7.2 缺失能力清单（待实现）

1. **握手消息构造（initiate/response 编码、X25519 + blake2s + AEAD）** — 待实现。依据：`proxy/wireguard/client.go` 走 `conn.Begin/Handshake`（wireguard-go）。本仓 `wire.rs` 仅有 `HandshakeMessage::unverified_bytes` 与长度校验，**无 seal**。这是 WireGuard 互通的阻塞项。需决策：引入 `x25519-dalek`/`blake2` 自研，或声明依赖外部协议库。
2. **transport 消息封装（`seal`：receiver index / counter / AEAD / 上限 1420）** — 待实现。依据：`client.go` 的数据发送路径。
3. **mac1/mac2 与 cookie 轮换校验** — 待实现。依据：`client.go`/`bind.go` 中对 cookie-reply 的处理；本仓 `COOKIE_LEN=64` 常量已在，但无校验函数。
4. **pseudo-header（16 字节：0x01000000 + 源/目的端口）** — 待实现。依据：`client.go`/`server.go` 的 `pseudoHeader`，无 TUN 场景（如 SS/VLESS 承载 WG）必需。
5. **keepalive / 空闲保活计时** — 待实现。依据：`client.go` 的 `Keepalive` 配置路径；原语层可只提供注入式时钟的计时器。
6. **重放窗口与 counter 单调性（不回退、超出窗即拒）** — 部分。依据：wireguard-go `channel.go` 语义 + 本仓 `Window::accept_authenticated`；需补 WG 专用测试（当前 WG 测试仅报文结构）。
7. **载荷上限/分片** — 待实现。依据：`tun.go` 的 MTU 处理与 `client.go` 的最大包长度。

### 7.3 测试覆盖对照

| 场景 | 参考测试 | 本仓测试 | 缺口 |
|---|---|---|---|
| 报文类型长度精确匹配（截断/超长拒绝） | `server_test.go` 仅配置级 | `tests/wire.rs`（297 行，含 `exact_len`） | 覆盖较好 |
| 握手往返（initiate→response） | 依赖 wireguard-go，本目录无 | 无 | **全缺** |
| transport AEAD 篡改/重放 | 无 | 无（`tests/support/mod.rs` 51 行为构造辅助） | **缺** |
| cookie 轮换 | 无 | 无 | **缺** |
| 与真实 WG 对端互通 | 无 | 无 | **缺** |

---

## 8. AnyTLS

### 8.1 映射表

| 参考文件 | 一行职责 | 本仓对应 | 状态 |
|---|---|---|---|
| `proxy/session/frame.go`（49） | 帧格式（命令 + 流 ID + 长度 + 载荷） | `lengsuo-anytls/src/frame.rs`（`Command`、`Frame::encode/decode`） | 已实现 |
| `proxy/session/session.go`（493） | 会话状态机：认证、版本协商、ping/pong、错误码、流表上限、poison | `src/server_state.rs`（`accept`、`Event`、`StateError`、`peer_version`、`is_poisoned`、`max_streams`） | **部分：仅服务端状态机** |
| `proxy/session/client.go`（242） | 客户端：拨号、TLS 建立、认证、TCP/UDP 关联 | `src/auth.rs`（`Credential`，70 行） | **待实现：客户端状态机缺失** |
| `proxy/session/stream.go`（164） | 流对象：FIN/RST、窗口/缓冲、读写关闭 | 无独立流表 API（`server_state` 内含最小） | 待实现 |
| `proxy/pipe/io_pipe.go`（232）、`pipe/deadline.go`（74） | 管道缓冲、超时 | 无 | 待实现（原语：带背压的流管道） |
| `proxy/padding/padding.go`（96） | 帧填充策略 | 无 | 待实现 |
| `cmd/server/inbound_tcp.go`、`outbound_tcp.go`、`main.go`、`cmd/client/*`、`util/*` | 参考自带的可运行服务端/客户端工具与工具函数 | — | 范围外（但**是最方便的互通夹具**，见 `references/binaries`） |
| `proxy/system_dialer.go`（10） | 系统 dial 选项（fwmark 等） | — | 范围外 |
| TLS 层 | anytls 依赖 TLS 记录 | `lengsuo-tls`（`TlsClient/TlsServer`） | 部分 |

### 8.2 缺失能力清单（待实现）

1. **客户端会话状态机（认证→流打开→FIN/RST→错误处理）** — 待实现。依据：`proxy/session/client.go`、`session.go`。当前本仓只有 `server_state.rs`，客户端方向无对等实现，互通只能靠手写胶水。
2. **认证算法核对** — 部分。依据：`session.go` 的认证信息构造（密码哈希 + 时间/随机 + 服务端校验）。本仓 `auth.rs` 仅 70 行 `Credential([u8;32])`；需与参考逐字节对齐（**具体哈希输入顺序待补充**，需读 `session.go` 认证段确认）。
3. **UDP associate（报文 over stream 的帧类型）** — 部分。依据：`client.go`/`session.go` 的 UDP 路径；`frame.rs::Command` 是否含 packet 类命令需确认（**待补充**），本仓无 anytls UDP 互通测试。
4. **padding 策略** — 待实现。依据：`proxy/padding/padding.go`（本仓无任何填充代码）。
5. **ping/pong 与空闲超时** — 待实现。依据：`session.go` 的 ping 处理 + `pipe/deadline.go`。
6. **流窗口/背压与超限拒绝** — 部分。依据：`stream.go` 与 `io_pipe.go`；本仓 `ServerState::new(max_streams)` 有上限，缺窗口/缓冲语义。
7. **版本协商失败/降级路径** — 部分。依据：`session.go` 的版本字段（本仓已暴露 `peer_version`，缺"版本不支持即 fail-closed"的用例）。

### 8.3 测试覆盖对照

| 场景 | 参考测试 | 本仓测试 | 缺口 |
|---|---|---|---|
| 帧编解码/截断/畸形长度 | **anytls-go 无任何 `_test.go`** | `tests/primitives.rs`（155） | 本仓优于参考 |
| 服务端状态机（流上限、poison、版本） | 无 | `tests/server_state.rs`（62）、`tests/server_state/streams.rs`（250）、`settings.rs`（180） | 覆盖 |
| 与真实 anytls-go 二进制互通 | 有 `cmd/` 可执行 | **无** | **缺**（建议用 `references/binaries` 建立互通门） |
| 客户端认证 + 真实流量 | 无 | 无 | **缺**（对应缺口 1、2） |
| 错误密码 | 无 | 无 | **缺** |
| TLS 记录 + ALPN | 无 | `lengsuo-tls` 覆盖基础 | 部分 |

---

## 9. Hysteria（仅 core/internal/protocol 层）

范围声明：**QUIC/HTTP3 栈本身（quiche、拥塞控制、maskprobe、带宽测速调度）明确范围外**；本节只看协议消息层。本仓 `crates/lengsuo-hysteria/src/lib.rs` 为 2 行空壳。

### 9.1 映射表

| 参考文件 | 一行职责 | 本仓对应 | 状态 |
|---|---|---|---|
| `core/internal/protocol/proxy.go`（256）+ `proxy_test.go`（317） | CONNECT-UDP / Extended CONNECT 的伪方法与目标地址编解码、UDP 代理协议帧 | 无 | 待实现 |
| `core/internal/protocol/padding.go`（31） | 填充策略 | 无 | 待实现 |
| `core/internal/protocol/http.go`（68） | HTTP/3 层辅助（方法/头约定） | 无 | 待实现（原语级） |
| `extras/outbounds/speedtest/protocol.go`（152）+ `protocol_test.go`（446） | 测速帧（request/response 结构） | 无 | 待实现（客户端"速度测试"是对端能力探测的一部分） |
| `extras/sniff/quic.go`（194） | 内层 QUIC 嗅探 | 无 | 范围外 |
| hysteria2 认证（QUIC TLS  transcript + HMAC token，参考实现在 `internal/` 与 quic 配置处，**具体文件本轮未逐一确认，待补充**） | 认证 cookie/token 计算 | 无 | 待实现 |

### 9.2 缺失能力清单（待实现）

1. CONNECT-UDP 帧与目标地址编解码 — 待实现（依据 `protocol/proxy.go`）。
2. 认证 token（含 QUIC TLS transcript 派生的 HMAC，具体参考文件位置待补充）— 待实现。
3. speedtest 测速帧 — 待实现（客户端能力探测用，优先级低）。
4. padding 策略（`protocol/padding.go`）— 待实现。

（§9 测试对照：本仓在快照后已落 TCP 帧测试，见文末勘误。）

---

## 10. 范围外清单（不计入缺失）

- 参考实现中的 config/protobuf、policy/路由/分发器、监听器与多用户管理。
- UDP NAT 会话表、端口分配、服务端用户校验与时间窗缓存。
- 度量统计、日志、OCSP、进程级证书加载。
- QUIC/HTTP3/拥塞控制栈本身（hysteria）、gvisor 网络栈、内核 TUN 平台层。
- legacy 流密码（aes-128-cfb 等）：规范已废弃，按安全理由刻意拒绝，
  错误路径需返回明确变体而非 `None`。
- 性能层（Buffer 池、自研 chacha）：本仓直接用 `ring`/RustCrypto。

---

## 11. 建议开发顺序（按互通风险排序）

1. **SS 传统 TCP AEAD 端到端流**（`lengsuo-shadowsocks/src/tcp.rs`，~2 文件）
   —— TCP 互通目前零证据， UDP 已过 Xray 双向。
2. **SS2022 TCP 会话**（握手包 + 子密钥 + 重放窗口，~2 文件）—— 2022 互通最大风险。
3. **VMess 全套**（KDF/AuthID/AEAD 封装/客户端编码，~5 文件）—— 本仓空壳，近乎全缺。
4. **VLESS XEL 加密层**（`encryption=128`/`xor`，~3 文件）—— 现代 Xray 服务器可强制要求。
5. **WireGuard 握手与 transport 封装**（seal 方向，~3 文件）—— 目前只解不封，需先决策
   密码学依赖（x25519-dalek/blake2）。
6. **AnyTLS 客户端会话装配**（TLS 拨号 + 认证逐字节对齐 + UDP associate + padding，~3 文件）
   —— 帧解释层已落地，缺会话与策略。
7. **Hysteria CONNECT-UDP 帧与认证 token**（~2 文件）—— TCP 帧原语已落地。
8. **Trojan 心跳/应答命令与 drain 优雅关闭**（~2 文件）—— 差距集中在空闲/关闭语义。
9. **nonce 溢出 fail-closed、SS2022 padding 策略、时间窗边界用例**（~3 文件）—— 加固项。
10. **互通验收门**：anytls-go 二进制（`references/binaries` 现成可用）、Xray TCP 双向、
    WG 真实对端——按 AGENTS 规则 Rust↔Rust 先行，再 Rust↔参考双向。

---

## 12. 勘误（快照后已落地的差距）

本矩阵基于 main 快照 `c1d16d0` 静态盘点。其后两批提交已部分收窄差距：

- `5edae57`：Hysteria2 TCPRequest/TCPResponse 帧与 QUIC varint 原语
  （§9 中"空壳"已过时；CONNECT-UDP、认证 token、speedtest 仍待实现）。
- `8f9b6d3`：AnyTLS 客户端出站会话状态机 `ClientState`
  （§8 缺口 1 部分收窄：帧解释层已落地；TLS 拨号装配、UDP associate、
  padding、认证逐字节对齐仍待实现）。

其余结论不受影响：VMess、VLESS XEL、WireGuard 封装方向仍是最大缺口。
