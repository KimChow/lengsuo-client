# VMess 实现与验收状态

固定对照：Xray v26.3.27，完整 commit
`d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，
`proxy/vmess/encoding/encoding.go` 的 PortThenAddress 配置与 client.go 请求编码。

## 本批地址修复

请求头此前误用 SOCKS5 地址线格式，已改为 VMess 自有线格式：
port BE16 → type（IPv4=1/domain=2/IPv6=3）→ 地址（域名前有一字节长度）。
仍复用 ss-core::TargetAddr 模型，不修改其他协议的 SOCKS5 编码。
非法域名在写入前拒绝，不留下部分字节。

新增三项完整请求明文字节测试及五项地址测试；独立 Python 标准库生成器
`tools/gen_vmess_request_vectors.py` 实际执行，重新计算 FNV 尾。
同时修正旧向量中缺失字节、错误 FNV，以及错误使用 SOCKS5 解码器的断言。
已复现未接线编译失败及旧断言失败，再修复并执行该 crate 全测试与 Clippy，均 exit 0。

## 尚未完成

本次只确认请求明文地址布局修复；既有 KDF/AuthID/头部/分帧原语的完整
线格式、会话与服务端仍需逐项参考端验证。
尚无完整 Rust↔Rust、Rust→Xray、Xray→Rust VMess 网络互通证据。
不宣称全部 VMess、外层传输、异常矩阵或 Windows 浏览器 TUN 验收完成。
