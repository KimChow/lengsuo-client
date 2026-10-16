# 协议对等差距与验收矩阵

## 验收范围

目标是八协议双向互通、异常验证及 Windows 浏览器 TUN 完整验收。
协议原语、自家 roundtrip、配置语法通过都不能替代完整服务互通。
QUIC、TLS、入站/出站运行时、UDP 会话、平台接入与 TUN 均保留在交付范围内。
私有权限、计费、节点池权威逻辑仍归私有产品仓。本表不调整产品冻结范围。
旧版按文件数及行数估算兼容程度、把运行时等列为范围外的口径撤销。

## 固定参考及本轮实测

- Xray v26.3.27，完整 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。
- 官方 Linux ZIP SHA256：`23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae`。
- 本轮从客户端基线 `e9f5b52de8bb1711281299b98844858368ca9150` 隔离 worktree 验证。
- 基线 `--locked` 最初失败：公开 WG 握手所需依赖未完整写入锁文件。
  在隔离树补齐八项传递/直接依赖，保留已有依赖版本后才继续测试。
- 原 15 项参考矩阵重跑通过；纳入现有 SS TCP 双向用例后 17 项通过。
- 命令：`python3 scripts/run_reference_tests.py --work-dir <仓库外证据目录> --archive <固定官方ZIP>`。
  47 本轮证据目录：`/home/ubuntu/lengsuo-dev/results/audit-20261016-reference`。
  report.json 记录参考完整 commit、包哈希、源码基线、dirty 状态、命令、退出码和测试数量。
- 另在 `audit-config-20261016` 运行固定 Xray `run -test -config <文件>`：
  下述七协议各 inbound/outbound 两份配置均 exit 0；AnyTLS 两方向均 exit 23。
  这些是配置校验，**不是运行时连接或安全验证**。临时证书/假密钥均不入库。

## 八协议现状

| 协议 | 已有真实参考证据 | 本轮发现与尚未验收 |
|---|---|---|
| VLESS | TCP/TLS/UDP，有限 XUDP，共 7 项 | Vision、REALITY、XEL、通用复用及全部外层传输未完整验收 |
| VMess | 无网络参考互通 | 请求地址误用 SS 顺序，固定 Xray 要求 port→type→address；客户端原语不等于服务 |
| Trojan | TLS TCP/UDP，共 4 项 | 完整运行时、全部外层与异常矩阵待补；不得凭推测添加成功响应首字节或心跳 |
| Shadowsocks | 四 AEAD 的 TCP/UDP 双向，共 4 项函数 | 盐重放与跨重启策略、运行时/全部异常待补；函数内部覆盖多算法与长度 |
| SS2022 | AES UDP 双向，共 2 项 | TCP 修正草稿无法编译，尚未合并；完整运行时、重启重放保护、可选算法待补 |
| Hysteria2 | 无 Rust 网络参考互通 | 旧 CONNECT-UDP 0x402 是自造扩展，不能计入 Hysteria2；真实 UDP、QUIC/HTTP3/auth 待补 |
| WireGuard | 无真实参考互通 | 公开握手的 HMAC block、KDF3、端序及响应处理存在实质错误，修复与完整握手向量进行中 |
| AnyTLS | 现有单向帧测试通过 Python TLS 桥 | 桥跳过证书验证，不能证明 Rust TLS 安全互通；参考哈希未强校验，日志认证前缀需移除；反向待补 |

WireGuard 和 VMess 的现有自家向量不足以覆盖上述错误，不能再作为协议兼容证明。
SS2022 草稿出现 `</content>` 编译残留；worker 达轮次上限不是任务完成通知。
未经重现、修复、测试和文档对齐的产物不得合并。

## 对应配置办法

全部测试只用回环地址、临时端口、假凭据。TLS 必须有明确 CA 与名称验证；
配置语法可接受不等于证书正确、认证正确或安全策略达标。

| 协议 | Xray 入站 settings 要点 | Xray 出站 settings 要点 |
|---|---|---|
| VLESS | clients/id、decryption=none | vnext/address/port/users/id/encryption=none |
| VMess | clients/id、alterId=0 | vnext/address/port/users/id/security，先测 AEAD AES |
| Trojan | clients/password，TLS 证书 | servers/address/port/password，TLS 信任根与 serverName |
| SS | method/password/network=tcp,udp | servers/address/port/method/password |
| SS2022 | method=2022-blake3-aes-128-gcm 或 aes-256-gcm，Base64 PSK | servers 同套件，PSK 必须为 16/32 字节 |
| Hysteria2 | version=2、clients/auth | version=2、address、port |
| WireGuard | secretKey、address、peers，测试用 noKernelTun=true | 同一设备配置模型，peer endpoint/publicKey/allowedIPs |
| AnyTLS | 本基线不注册该协议 | 本基线不注册该协议，改用固定 anytls-go |

Hysteria2 另设 streamSettings.network=hysteria、security=tls、
hysteriaSettings.version=2 与 auth，TLS ALPN=h3。配置来源为固定 Xray
`infra/conf/hysteria.go` 和 `infra/conf/transport_internet.go`；本轮已做语法验证。

## 完整交付门禁

1. 每个声明支持的算法/命令/传输分别验证 Rust↔Rust、Rust→参考、参考→Rust。
2. 错密码、截断、篡改、重放、边界、半关闭、超时与清理分别出证据。
3. 固定随机源/时钟/分块的参考向量逐字节核对，真实连接核对重组载荷与语义。
4. Linux 与 Windows 分开记录；Linux 协议通过不证明 Windows 设备可用。
5. Windows 浏览器同域名/同 IP 多环境分别出口，DNS/IPv6/UDP/MTU、断线、
   休眠恢复、身份复用及非受管流量独立验收；网络失败不得直连。
6. 代码、文档、台账及参考测试清单一致后才可宣称对应范围已验收。

本矩阵结论：当前未达到完全兼容及完整 TUN 验收，持续开发与验证。
