//! reader 侧：从子进程 stdout 切帧、分类 JSON-RPC、分发响应/通知/服务端请求。
//!
//! 分两条循环（按 [`Framing`] 选择），共同点是：退出即连接结束，标记 closed
//! 并撤下全部在途请求。
//!
//! fail-closed 边界（与 `docs` / result.md 一致）：
//! - 帧级损坏（非法 UTF-8、非法头、超长帧、EOF 截断）→ poison 并停止读；
//! - 形状非法但分帧仍对齐（JSON 合法但非 JSON-RPC 2.0 消息）→ 只计数忽略。

use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::ChildStdout;

use super::state::{Inner, READ_CHUNK_BYTES};
use crate::codec::{Framing, FrameDecoder};
use crate::error::Error;
use crate::protocol::{
    parse_wire_message, JsonRpcErrorObject, ServerRequest, WireMessage, METHOD_NOT_FOUND,
};

/// reader 主循环：按分帧方式取帧、解析 JSON-RPC、分发。
pub(super) async fn reader_loop(mut reader: BufReader<ChildStdout>, inner: Arc<Inner>) {
    match inner.framing {
        Framing::NewlineDelimited => newline_loop(&mut reader, &inner).await,
        Framing::ContentLength => length_prefixed_loop(&mut reader, &inner).await,
    }
    // 循环退出即连接结束：撤下全部在途请求。
    inner.closed.store(true, Ordering::Release);
    inner.fail_all(&inner.failure_reason());
}

/// 去掉行尾 `\n` 与可选的 `\r`。
fn trim_newline(line: &mut Vec<u8>) {
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
}

async fn newline_loop(reader: &mut BufReader<ChildStdout>, inner: &Arc<Inner>) {
    let mut line: Vec<u8> = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line).await {
            Ok(0) => return,
            Ok(n) => {
                // read_until 在 EOF 时也会把没有分隔符的残留交给我们：
                // 末尾不是 `\n` 就是截断帧，必须 fail-closed，不能当完整帧解析。
                if line.last() != Some(&b'\n') {
                    inner.poison(format!("子进程在帧中途结束输出，残留 {n} 字节（无行终止符）"));
                    return;
                }
                trim_newline(&mut line);
                if line.is_empty() {
                    continue;
                }
                if line.len() > inner.max_frame_bytes {
                    inner.poison(format!(
                        "行分隔帧长度 {} 超过上限 {}",
                        line.len(),
                        inner.max_frame_bytes
                    ));
                    return;
                }
                if !handle_body(inner, &line) {
                    return;
                }
            }
            Err(e) => {
                inner.poison(format!("读取子进程 stdout 失败：{e}"));
                return;
            }
        }
    }
}

async fn length_prefixed_loop(reader: &mut BufReader<ChildStdout>, inner: &Arc<Inner>) {
    let mut decoder: FrameDecoder = inner
        .framing
        .decoder_with_limit(inner.max_frame_bytes);
    let mut chunk = vec![0_u8; READ_CHUNK_BYTES];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => {
                if let Err(e) = decoder.finish() {
                    inner.poison(e.to_string());
                }
                return;
            }
            Ok(n) => {
                decoder.push(&chunk[..n]);
                loop {
                    match decoder.next_frame() {
                        Ok(Some(body)) => {
                            if !handle_body(inner, &body) {
                                return;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            inner.poison(e.to_string());
                            return;
                        }
                    }
                }
            }
            Err(e) => {
                inner.poison(format!("读取子进程 stdout 失败：{e}"));
                return;
            }
        }
    }
}

/// 处理一帧。返回 `false` 表示 reader 必须停止（帧级损坏）。
fn handle_body(inner: &Arc<Inner>, body: &[u8]) -> bool {
    match parse_wire_message(body) {
        Ok(WireMessage::Response(resp)) => {
            inner.deliver(resp);
            true
        }
        Ok(WireMessage::Notification(note)) => {
            inner.broadcast_notification(note);
            true
        }
        Ok(WireMessage::ServerRequest(req)) => reject_server_request(inner, req),
        Err(Error::MalformedMessage { .. }) => {
            // JSON 合法但消息形状非法：分帧仍对齐，忽略并计数，不 poison。
            inner.ignored_messages.fetch_add(1, Ordering::AcqRel);
            true
        }
        Err(e) => {
            inner.poison(e.to_string());
            false
        }
    }
}

/// v0 策略：记录服务端请求（供上层观测），并异步回一条 `METHOD_NOT_FOUND`。
/// 不静默丢弃（静默丢弃会让对端一直等待），也不擅自伪造业务结果。
///
/// 写侧交给 detached 任务：reader 循环内不能 `await` 写锁（会与自己的请求
/// 路径互相等待），也不能阻塞写管道。补写失败只会让对端继续等待，不影响
/// 本端状态一致性，因此丢弃 JoinHandle。
fn reject_server_request(inner: &Arc<Inner>, req: ServerRequest) -> bool {
    inner.record_server_request(req.clone());
    let mut err = JsonRpcErrorObject::method_not_found("client does not handle server requests");
    err.data = Some(serde_json::Value::String(req.method.clone()));
    debug_assert_eq!(err.code, METHOD_NOT_FOUND);
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": req.id, "error": err });
    let frame = match inner.framing.encode(&body) {
        Ok(f) => f,
        Err(e) => {
            // 序列化失败说明 id 之类的内部状态被破坏：连接不再可信。
            inner.poison(e.to_string());
            return false;
        }
    };
    let task_inner = Arc::clone(inner);
    tokio::spawn(async move {
        let _ = task_inner.send_raw_frame(&frame).await;
    });
    true
}
