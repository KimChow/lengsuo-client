//! 外层传输矩阵的 **Rust↔Rust 回环**部分（非忽略）。
//!
//! 目的：证明同一组 trojan 语义在三种外层（`tcp` / `ws` / `httpupgrade`）上
//! 判定**一致** —— 正常往返逐字节一致、错密码与截断都 fail-closed、半关闭后
//! 回程仍完整。这不是与参考的互通（对端是本仓自己的服务端），真实互通见
//! `transport_matrix/xray_matrix.rs`（`#[ignore]`，必须 `--ignored` 实跑）。
//!
//! 逐外层的**唯一**差异在两处，本文件把它们显式写出来：
//!
//! 1. 建流：TLS 之后套 `ws` / `httpupgrade` 升级，或直接用裸 TLS 流；
//! 2. 关写端：WS 走 `Close` 帧，其余走底层 FIN。
//!
//! 判定纪律：拒绝类用例**不以“我方读操作超时”**为证据。要求
//! （a）本仓服务端的处理任务返回**可判别的错误变体**（不是 panic、不是挂起），
//! （b）业务目标的 accept 计数**不增长**。
//!
//! 结构：本文件是**入口**，只留共享的导入；**跑腿助手**（本仓服务端夹具、
//! 单连接处理、客户端建流）在 `rust_matrix/helpers.rs`，用例在
//! `rust_matrix/cases.rs`。两者都以 `include!` 拼回**本模块**，
//! 因此用例的全限定名（`rust_matrix::rust_matrix_*`）与拆分前完全一致。

use std::time::Duration;

use lengsuo_trojan::transport::{httpupgrade, server as transport_server, ws};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use super::harness::{
    bounded_shutdown, client_action, header_bytes, tcp_request, Action, Identity, Outcome, Outer,
    ReplyWhen, Target, Verdict, BAD_PASSWORD, CLOSE_BOUND, HANDSHAKE, PASSWORD, PATH, PAYLOAD,
    REPLY, REPLY_BULK_LEN, TOTAL, TRUNCATION_CUTS, WAIT,
};

include!("rust_matrix/helpers.rs");
include!("rust_matrix/cases.rs");
