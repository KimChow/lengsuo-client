//! XEL 记录层接成出站原语：把「已建立的字节流」包装成「xel 加密/分帧后的字节流」。
//!
//! # 本模块只做接线
//!
//! 加密、分帧、序号锁定、头部掩蔽全部委托给 [`crate::xel`] 的既有原语，本模块
//! **不复制第二份实现**：
//!
//! | 环节 | 既有原语 | 位置 |
//! |---|---|---|
//! | 发送方向的记录封装（AEAD + 头部作 AAD） | [`crate::xel::record::RecordWriter::seal`] | `src/xel/record.rs:46` |
//! | 接收方向的分帧 + 锁定步序号 + 解封 | [`crate::xel::record::RecordReader`] | `src/xel/record.rs:58` |
//! | XOR 头部掩蔽（可选） | [`crate::xel::xor::XorMask`] | `src/xel/xor.rs:149` |
//!
//! 本模块新增的只有**编排**：上下行密钥分离、8192 字节分块（参考 `common.go`
//! `CommonConn.Write` 的循环）、掩蔽层与 AEAD 层的先后顺序，以及把记录层包装成
//! `AsyncRead`/`AsyncWrite` 字节流的管道。
//!
//! # 分层顺序（与参考一致）
//!
//! 参考把 AEAD 记录层（`common.go` 的 `CommonConn`）放在**外层**、XOR 头部掩蔽
//! （`xor.go` 的 `XorConn`）放在**内层**（贴近 TCP）：客户端先 AEAD 封记录，再由
//! `XorConn.Write` 掩蔽 5 字节头；接收端先 `XorConn.Read` 去掩蔽，再
//! `CommonConn.Read` 解封。因此线上顺序是
//! `明文 → AEAD 记录(头+体) → XOR 掩蔽头 → TCP`。
//!
//! # 参考基线与偏离
//!
//! 基线：Xray v26.3.27 `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。
//!
//! - `proxy/vless/encryption/common.go:47` `CommonConn.Write`：**每 8192 字节明文
//!   一条记录**（`common.go:55` 的 `if len(b) > 8192 { b = b[:8192] }`）。本模块按
//!   同一上限分块。
//! - `proxy/vless/encryption/common.go:80` `CommonConn.Read`：记录体先整体读满再解封。
//! - `proxy/vless/encryption/xor.go:41`/`:69` `XorConn.Write`/`Read`：只掩蔽 5 字节
//!   头，记录体原样透传；跳过量由解码出的头部长度决定（`xor.go:58`/`:88`）。
//! - **偏离**：`common.go:212` `DecodeHeader` 在魔数不符时把长度置 0 后继续运行；
//!   本仓 `src/xel/frame.rs:68` 视为 `InvalidHeader` 并 poison（更严格，已在
//!   `src/xel/mod.rs:15` 记录）。本模块沿用本仓的严格语义。
//! - **范围外**：XEL 的密钥协商（ML-KEM-768 × X25519、票据、0-RTT、`PreWrite`、
//!   `PeerPadding`）属握手层，不在本模块；本模块从「会话密钥与 IV 已就绪」开始。
//!
//! # fail-closed
//!
//! 认证失败、序号失步、头部非法、长度越界、截断——任一发生即由既有原语 poison
//! 该方向，之后所有调用返回 `Error::Record(Poisoned)`，绝不产出明文或静默降级。
//!
//! [`XelStream`] 的读方向失败**在读操作本身**报出：管道（`tokio::io::duplex`）
//! 只能表达 EOF，表达不了失败原因，所以读任务把失败原因放进独立失败槽，
//! 应用侧在「本轮没有交付任何字节」时把该原因作为 `io::Error` 抛出来。
//! ⇒ 「认证失败的流」不会被误读成「对端正常结束」（干净的 EOF）。
//!
//! # 用法
//!
//! ```no_run
//! use lengsuo_vless::xel::aead::XelCipher;
//! use lengsuo_vless::xel::XelKey;
//! use lengsuo_vless::xel_wire::{XelStream, XelWireConfig};
//! use tokio::{io::AsyncWriteExt, net::TcpStream};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let transport = TcpStream::connect("example.invalid:443").await?;
//! let config = XelWireConfig {
//!     cipher: XelCipher::Aes256Gcm,
//!     uplink_key: XelKey::new(&[0x11; 32])?,
//!     downlink_key: XelKey::new(&[0x22; 32])?,
//!     xor: None,
//! };
//! // 之后 `stream` 就是一条「xel 加密/分帧后」的字节流。
//! let mut stream = XelStream::new(transport, config)?;
//! stream.write_all(b"hello").await?;
//! # Ok(())
//! # }
//! ```
//!
//! # 目录结构
//!
//! （拆分自原单文件 `xel_wire.rs`，行为逐字节等价）：
//! - `config`：配置与错误类型（`XelWireConfig` / `XorLayer` / `Error`）；
//! - `endpoint`：发送 / 接收方向原语（`XelSender` / `XelReceiver`）；
//! - `stream`：把字节流包装成 `AsyncRead`/`AsyncWrite`（`XelStream`）；
//! - `pump`：记录层与管道之间的搬运任务。

mod config;
mod endpoint;
mod pump;
mod stream;

pub use config::{Error, XelWireConfig, XorLayer, MAX_PLAINTEXT_PER_RECORD, XOR_IV_LEN};
pub use endpoint::{XelReceiver, XelSender};
pub use stream::XelStream;
