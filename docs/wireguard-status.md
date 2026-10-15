# WireGuard 实现与验收状态

报文格式参考官方 https://www.wireguard.com/protocol/ 。本次仅实现类型及长度解析，
不是完整 WireGuard 连接，也没有参考端互通证据。

- 初始化 148 字节、响应 92 字节、Cookie 64 字节，类型为小端且保留位必须为零。
- 运输报文至少 32 字节，读取小端接收者与计数器，借用密文切片，不宣称已认证。
- 结构层不要求运输报文总长是 16 的倍数；认证及内层报文检查由后续实现完成。
- 复用 ss-core::replay 共享窗口，不复制第二套实现；必须认证后才更新窗口。
- 12 项解析测试涵盖固定字段、全部握手截断、保留位、长度、借用及 Debug 脱敏。

待实现：Noise 握手、密钥协商、MAC/Cookie、AEAD、密钥轮换、计时和 UDP 运行时，
Rust 双端与固定参考端双向互通、异常验证、Windows 浏览器环境接入及 TUN 验收。
本次测试不得作为上述待实现能力的完成证据。

## Transport 数据面封装（2026-10-16 新增）

- 已实现 `src/transport.rs`：type 0x04 seal/open——LE32 receiver index +
  LE64 counter + chacha20poly1305（nonce 为零前缀 + LE64 计数，复用
  ss-core AEAD 语义）；零长载荷（keepalive）合法；1420 上限写入前拒绝；
  counter 接入共享重放窗口；任何错误 fail-closed。
- 已验证：24 项新增测试通过（seal→既有解析器 roundtrip、counter 递增、
  keepalive、上限、错钥、篡改、重放、乱序、回绕）；fmt/clippy/行数门禁。
- 未实现（待实现）：noise IK 握手消息构造（references 缺 wireguard-go
  源码，待参考入库后另开任务）、mac1/mac2 与 cookie、keepalive 计时器、
  与真实 WG 对端互通（未互通，不宣称兼容）。
