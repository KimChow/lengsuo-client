# ss-core 加密原语状态

## Nonce 计数器取尽语义（2026-10-16 加固）

- 已实现：NonceCounter 到达容量上限后返回明确的 Error::NonceExhausted，
  不得回绕复用、不得 panic；取尽后对象进入不可逆的 exhausted 状态，
  seal/open 均继续报错；拒绝步不改动内部计数值。
- 边界语义（与 Xray common/crypto/auth.go 对齐并测试固化）：全 FF 计数器
  的下一步是全 0 nonce（唯一允许的整串进位），它是合法 nonce 而非取尽——
  误判会破坏线格式互通；全 FF 用尽后才进入 NonceExhausted。nonce_len=0 
  构造即取尽。capacity(n) = 2^(8n)（0 长度容量为 0）。
- 已验证：ss-core 47 项测试通过（其中 nonce 相关新增 10+ 项：边界、取尽、
  不可逆、拒绝不改状态、错误消息无密钥材料）；**全 workspace 285 项测试
  0 失败**（共享核心无回归）；fmt/clippy/行数门禁通过。
- 影响面：所有 AEAD 消费者（shadowsocks/ss2022/trojan 等）在 nonce 取尽时
  现在得到明确的 NonceExhausted 并按既有 poison 语义处置，不再可能静默复用。
