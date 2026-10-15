# 传统 Shadowsocks AEAD UDP 状态

基线为 Xray v26.3.27 / `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。
支持 AES-128-GCM、AES-256-GCM、ChaCha20-IETF-Poly1305 与 XChaCha20-IETF-Poly1305。
主密钥、HKDF-SHA1、一次性零 nonce AEAD 和 SOCKS 地址均复用 ss-core。
生产 seal 只能通过系统随机源取得新 salt，固定 salt 入口仅在模块内测试使用。
认证通过后才解析目标，空口令配置拒绝（参考 conf/shadowsocks.go 同样拒绝）。

## 已执行验证

- 五项模块与十项集成测试通过，覆盖四套件、三种地址、随机 salt、错误密码、
  全部截断、逐字节篡改、尾部垃圾、地址限制及数据报长度边界。
- 初始草稿的固定向量实际失败，未按其注释认定为正确。用
  tools/gen_ss_udp_vectors.py 独立执行 MD5、HKDF-SHA1、cryptography AEAD，
  重新生成十二个向量后与 Rust 逐字节一致。HChaCha 使用
  [XChaCha-03 §2.2.1](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#section-2.2.1)
  的公开固定向量自检；它不是 RFC 8439 中的 HChaCha 向量。
- 两项显式 Xray UDP 测试均通过，每项覆盖四套件；Rust→Xray 与 Xray→Rust
  逐包核对 1/512/1200 字节，限定 IPv4 回环、假口令，不监听公网。
- 编码在追加载荷前检查总长，避免超长输入先产生完整载荷缓冲。

```sh
cargo test -p lengsuo-shadowsocks --locked --offline
LENGSUO_XRAY=/绝对路径/xray cargo test -p lengsuo-shadowsocks --locked --offline --test xray_udp -- --ignored --nocapture
python3 tools/gen_ss_udp_vectors.py
```

Python 生成器仅是可选测试工具，需要 cryptography，不参与 Rust 产品构建；
它的输出不能替代真实参考互通。新增 getrandom 为 MIT/Apache-2.0，未新增 GPL
链接依赖，也不宣称许可证自动门禁已经完成。

## 未完成

当前是单包 codec，不是可部署 UDP 服务。重复 salt 过滤、密钥轮换、会话与
环境隔离的入口、真实域名/IPv6、UDP 零载荷及极大报文参考场景仍需补齐。
传统 SS TCP、完整异常矩阵、真实测试流量重组证据、浏览器 TUN 仍未完成。
