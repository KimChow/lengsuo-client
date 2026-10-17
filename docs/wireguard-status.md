# WireGuard 实现与验收状态

## 固定参考与实现边界

官方 wireguard-go 完整commit：`2631ce99a06f27120d581611cf125d68bc6aa565`。
本轮参考工具链：Go1.23.8 linux/amd64。源码只作参考，产品Rust不链接Go/GPL协议实现。

已有：四类消息结构解析、发起方Noise IK握手、MAC1、零/显式PSK、
ChaCha20-Poly1305运输报文封装/打开、计数器及共享重放窗口。
消息type/index采用little endian，TAI64N内部采用big endian。
结构解析不代表认证成功；只有握手/AEAD验证通过后才处理可信数据。

## 2026-10-17 已复现与修复

- HMAC-BLAKE2s block从错误32修正为64；长密钥摘要只拷前32字节并保留零填充。
- KDF3第三输出补入0x03。主会话用Python hashlib/hmac实际生成独立预期，
  tests/kdf_reference.rs完整比对三项派生输出；不是自家函数生成断言。
- 测试内响应方此前把MAC1留零，修复为正确MAC1并移除密钥/哈希前缀打印。
- 旧“RFC4231锁定BLAKE2s HMAC”表述撤销，RFC4231不能充当该算法的向量来源。

## 已实跑参考进程验证

`tools/reference/wireguard_go_udp_test.go` 是独立测试适配器，调用固定官方
Noise/keypair核心，用ChannelTUN与loopback UDP交换报文，不碰系统设备/路由。
参考侧真实执行ConsumeMessageInitiation/CreateMessageResponse/BeginSymmetricSession、
官方AEAD与replayFilter；Rust侧实际发送握手、打开响应、收发与验证载荷。

复现步骤：

1. 将固定commit的官方源码检出到仓库外副本，确认tracked源码无diff。
2. 将适配器复制为device/lengsuo_wg_udp_test.go，执行
   `go test -c -o <参考二进制> ./device`。Go测试程序不进入产品发布包。
3. 设置 `LENGSUO_WG_REFERENCE_BIN=<参考二进制>`，执行
   `cargo test -p lengsuo-wireguard --test wireguard_go --locked -- --ignored --nocapture`。

本轮重新从该固定源码构建，两个进程用例通过（无PSK/显式PSK），
Rust→Go与Go→Rust载荷一致，重复包被拒绝。独立KDF一项通过，crate全测试与Clippy通过。
研究机47证据：results/recovery-wg-go-build.log、recovery-wg-real-peer-rebuilt.log、
recovery-wg-kdf.log、recovery-wg-tests.log、recovery-wg-clippy.log。

## 仍未完成

当前参考进程调用真实官方密码学核心，但不是完整wireguard-go设备的常驻网络运行时。
完整Rust响应方、Cookie/MAC2、keepalive/重试、密钥轮换、IP包填充/路由与设备生命周期、
完整参考客户端→Rust响应方、Windows设备及浏览器TUN仍待开发和验收。
不得以两项参考核心测试推导上述能力完成；完整范围见network-development.md。
