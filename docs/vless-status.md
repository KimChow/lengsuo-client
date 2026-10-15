# VLESS 实现与验收状态

参考基线为 Xray v26.3.27，完整 commit：
`d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。

## 已实现

- v0 TCP/UDP/Mux 请求头编码及增量解析，共用目标地址内存模型。
- XUDP 单连接单会话帧，固定会话 ID=0，不跨连接复用 global ID。
  拒绝 TCP Mux 帧、其他会话 ID、不支持状态及异常标志。
- 地址使用 VLESS 自身的端口在前格式，IPv4=1、域名=2、IPv6=3。
- 明确返回头部消耗长度，保留后续应用载荷；用户标识不放入 Debug 请求对象。
- 拒绝不支持的版本、命令和非空附加字段；域名拒绝空值、NUL 和超长值。
- 异步请求发送、常量时间用户标识校验、响应头及长度前缀 UDP 帧。
- 每次协议操作均使用正数截止时间；请求和响应操作分离，允许先发应用载荷。
- 数据帧先检查调用方容量上限再分配；截断、认证失败和不支持字段不会回退。

## 已验证

- 四项请求头测试：固定字节向量、地址编号、全部截断位置和非法输入。
- 七项异步测试：逐字节分片、错误用户标识、半关闭后回复、超时、
  截断、响应拒绝，以及数据报边界和长度限制。
- 一项真实 Rust 双端 TLS 测试：验证服务器证书，发送 VLESS 请求与载荷，
  客户端关闭写端后服务端回复，最终读取 EOF。
- 两项显式参考测试：Rust 客户端→Xray 服务端、Xray 客户端→Rust 服务端。
  IPv4 TCP 二进制载荷逐字节一致；前者还验证客户端半关闭后收取回复，
  错误用户标识导致参考端断开，测试目标在观察窗口内未收到连接。
- 两项认证 TLS 参考测试：Rust TLS 客户端→Xray 服务端，以及 Xray TLS
  客户端→Rust 服务端，二进制载荷一致。临时自签名证书运行时生成并显式信任，
  不关闭证书验证；Rust 对参考端的错误主机名和不可信证书均拒绝。
- 参考测试启动日志仅输出版本、端口、入站协议和安全层，不输出带私钥的配置。
- 三项 UDP 参考测试：Rust 基础 UDP 客户端→Xray 服务端、Rust XUDP
  客户端→Xray 服务端，以及默认 Xray XUDP 客户端→Rust 服务端。
  每项逐个核对 1、512、1200 字节数据报，不将不同数据报合并。
- 五项 XUDP 测试：固定字节及收发状态、全部截断、其他会话/状态/标志拒绝、
  长度限制与静默对端超时，以及 Mux 请求头载荷边界。
- 初次反向 UDP 测试真实失败：Xray 默认将目标端口 18001 的 UDP 转成
  XUDP/Mux，旧解码器拒绝命令。保留默认参考配置补齐该路径后测试通过，
  没有通过禁用参考端 XUDP 绕开差异。
- 参考测试仅回环地址，使用公开的假用户标识，不启动公网测试服务。

```sh
cargo test -p lengsuo-vless --locked --offline
LENGSUO_XRAY=/绝对路径/xray cargo test -p lengsuo-vless --locked --offline --test xray_tcp --test xray_udp --test xray_tls -- --ignored --nocapture
```

参考测试检查版本与 commit 前缀，输出基线及配置摘要；普通测试默认忽略这七项，
不能将默认测试成功说成执行过参考互通。完整基线来源为研究机 references 中的
固定源码、已核验官方发布包和二进制清单。测试进程只在当前测试期间存活。

## 尚未完成

- 当前库尚未接入产品出口运行时；调用方必须在认证安全传输上使用。
- 参考测试目前证明基础 IPv4 TCP、UDP、单会话 XUDP 及 TCP/TLS；
  UDP/TLS、域名、IPv6、全部异常路径和真实测试流量重组对比尚未完成。
- 零长度、超大 UDP 数据报及拥塞/丢包场景仍需比较；XUDP 当前拒绝空数据报。
- Vision、通用多会话 Mux、XUDP 跨连接会话恢复、反向代理及其他外层传输尚未实现。
- Windows 浏览器环境隔离与 TUN 完整验收仍属于最终交付要求。

核验依据为参考源码 `proxy/vless/encoding/encoding.go`、
`proxy/vless/encoding/addons.go`、`common/protocol/payload.go` 与本仓测试。

## Windows 原生验证记录

2026-10-15 使用 Windows x86_64 MSVC、Rust 1.93.0，独立干净工作区
固定在 `128159c4cfa8edf3b3c85ce120dbcae359bb81b3`，构建目录放仓库外。

```powershell
cargo test -p lengsuo-vless -p lengsuo-tls --locked
cargo test -p lengsuo-vless --locked --test xray_tcp --test xray_udp --test xray_tls -- --ignored --nocapture
```

两个命令退出码均为 0。第一项执行 TLS 五项与 VLESS 十七项本地测试；
七项参考测试在第一项中明确忽略，第二项才显式执行并通过。
第二项使用官方 `Xray-windows-64.zip` v26.3.27 发布包，SHA256 与
GitHub 发布资产 digest 核对一致：
`d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad`。
运行时版本显示 `26.3.27 d2758a0 windows/amd64`。

这些证据证明协议库原生 Windows 构建及该测试矩阵，未启动浏览器或 TUN
设备，不能用来声明 Windows 浏览器 TUN 完整验收通过。
