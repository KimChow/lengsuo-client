# Shadowsocks-2022 实现与验收状态

## 固定参考

- 规格：Shadowsocks 2022 Edition 完整commit
  `20b4952e8a54e696ebcabc5f91b5dad7f322f2da`。
- Xray v26.3.27 / `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。
- 本轮核对客户端源码基线：`5ee593b3c2f3b138ba0877f1de491119adddf07b`。

## 已实现

AES-128/256，原始16/32字节PSK、固定BLAKE3子密钥派生、UDP separate header与AEAD body、
方向/时间/目标/客户端会话关联校验；Sender随机会话和单调包计数，耗尽拒绝。
Receiver按环境/密钥epoch独占会话表与8192位重放窗口，认证及语义验证后才更新地址。
缓存满拒绝新会话，不驱逐有效窗口；回收同时检查单调时间与严格超过60秒的Unix差值。
Key.open_client/open_server只是原始解码，不提供防重放，禁止绕过Receiver直接转发。

TCP已有固定头/变长头/载荷编解码、会话关联、超时与错误后poison；
不等于完整可运行中继服务。凭据、明文及密钥不输出Debug。

## 实测与非零padding纠正

已有UDP Rust→Xray、Xray→Rust两方向参考用例，覆盖AES-128/256与多种载荷，
接收器验证重复包拒绝；历史Windows UDP验证不等于浏览器/TUN验收。

本轮从干净worktree重新执行：

```sh
LENGSUO_XRAY=<固定参考程序> cargo test -p lengsuo-ss2022 --test xray_tcp --locked -- --ignored --nocapture
```

1项参考测试exit0，函数内部覆盖AES-128/256以及padding=1/8/17/900，
并包含首批载荷为空的场景；逐字节核对回程和目标端实收载荷，padding不得泄漏。
证据：研究机47 results/recovery-ss2022-padding.log。
旧文档“与Xray必须padding=0”与当前实现不一致，已撤销。
**这次只证明Rust客户端→Xray服务端方向，不能称TCP两方向全部验收。**

此前公网链路验证记录不能替代上述固定配置的可重复回环测试；本轮未连接公网VPS。

## 尚未完成

- TCP参考客户端→Rust服务端、多算法/分块/半关闭/异常的完整矩阵。
- 多环境完整UDP/TCP运行时、密钥轮换、SIP023、可选ChaCha方法。
- 内存重放窗口不能跨进程重启保障安全；必须恢复状态或轮换实际密钥。
- 固定随机源逐字节完整参考向量、测试流量重组证据、Windows最新TCP验证。
- Windows浏览器TUN完整验收，不能用协议测试代替。

新增依赖许可按独立核验记录；不声称许可证自动化门禁已落地。
