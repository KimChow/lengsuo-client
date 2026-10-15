# Hysteria2 状态

## 已实现（`crates/lengsuo-hysteria`）

- QUIC varint（RFC 9000 变长整数）：规范最短编码、接受非最短解码、
  2^62-1 上限与越界拒绝（`src/varint.rs`，`tests/varint.rs` 6 项）。
- TCPRequest / TCPResponse 帧编解码：帧类型 0x401、地址 ≤2048、
  消息 ≤2048、padding ≤4096、精确消耗长度（帧后字节保留给载荷，
  不吞数据）。所有失败 fail-closed：截断、超长、非法状态字节、
  非 UTF-8、NUL 一律报错（`src/tcp.rs`，`tests/tcp_request.rs` 14 项、
  `tests/tcp_response.rs` 10 项）。

## 已验证

- 2026-10-15 研究机 47（Linux）：`cargo test -p lengsuo-hysteria
  --locked` 30 项全部通过；`cargo fmt --check`、
  `cargo clippy --all-targets -- -D warnings`、
  `scripts/check_line_limit.py` 均通过。
- `tests/tcp_request.rs` 406 行略超 400 行软目标（含独立测试辅助
  函数），700 行硬限内；后续按编解码/错误路径拆分。

## 未实现（待实现）

- QUIC 连接与流、HTTP/3 伪装与 `POST /auth` 认证。
- UDP 中继报文与分片、Salamander 混淆。
- 与 apernet/hysteria 参考实现（固定 commit
  `ca8fbd874fd6ca82413948de6dc5924405e103e1`）的真实互通验收：
  **未互通，不宣称兼容**。
- Windows 原生验证证据（与既有组件同格式补录）。

本 crate 是协议原语层，不能作为可用 Hysteria2 客户端或服务端发布。
