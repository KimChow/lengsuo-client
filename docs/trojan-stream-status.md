# Trojan 异步接口与限定互通状态

沿用 Xray v26.3.27 / `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。

请求发送/接收复用 codec；增量读取不吞应用载荷，每次操作一个正数截止时间，
密码错误在 56 字节认证前缀到齐后立即失败。Trojan 没有成功响应头。
UDP 帧为 SOCKS 目标、两字节大端长度、CRLF、载荷；先检查容量再分配载荷。
失败后调用方必须关闭连接，不得在失去对齐的流上重试或静默直连。

九项请求测试与七项 UDP 测试已实际通过，包括逐字节分片、截断、错误密码、
整体截止时间、坏 CRLF、地址类型、容量、内存及真实 TCP 半关闭后回复。
原十一项同步 codec 测试也通过，共二十七项本地测试。

四项显式参考测试已接入真实 stream API，不再使用测试内的替代握手实现：
Rust→Xray、Xray→Rust 的 TCP/TLS 和 UDP/TLS。UDP 每项逐包核对
1/512/1200 字节，均使用运行时生成证书并验证服务器身份，仅回环假凭据。
TCP 参考测试额外检查写端关闭后收取回复，以及错误密码断开且不拨号目标。

```sh
LENGSUO_XRAY=/绝对路径/xray cargo test -p lengsuo-trojan --locked --test xray_tls --test xray_udp -- --ignored --nocapture
```

这不代表产品服务已可部署：可信浏览器入口、出口运行时、目标策略、DNS、
域名/IPv6 真实参考链路、所有异常路径及其他 Xray 外层传输仍需单独验证。
Windows 浏览器 TUN 完整验收仍未完成。基本 TLS 互通也不证明 Chrome 指纹。
