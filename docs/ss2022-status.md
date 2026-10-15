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

## 尚未完成

这里是报文原语，不是完整 UDP 服务：open_client/open_server 返回后，调用方
仍必须执行按会话隔离的滑动窗口过滤，禁止直接将返回值作为允许转发的决定。
UDP 会话至少 60 秒保留、地址更新、服务器会话切换、多环境运行时与防重放
尚未接入；目前同一报文重复解码会成功，因此不得发布为可用代理。

TCP、可选 ChaCha 方法、SIP023 身份扩展、完整异常验证、固定随机源逐字节
参考向量、测试流量重组证据和 Windows 浏览器 TUN 仍在完整交付范围内。
