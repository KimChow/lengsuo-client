//! 装配层：配置预检、建流与握手。

use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use lengsuo_vless::header::{self, Flow, Request};
use lengsuo_vless::vision_wire::{
    RecordStream, ResponseHeaderStream, VisionStream, VisionWireError,
};
use tokio::io::{AsyncRead, ReadBuf};

use crate::config::NodeConfig;
use crate::outbound::DialError;

use super::config::{record_config, record_enabled, vision_wire_config};
use super::stream::VisionInner;
use super::{BoxedCarrier, VisionConfigError, VlessVisionStream, FLOW_XTLS_RPRX_VISION};

/// 建流前的配置预检（fail-closed）。
///
/// - 未知 `flow` 名 ⇒ **显式报错**，绝不静默退回「无流量层」路径。
/// - 记录层配置非法（未知 cipher / 非法十六进制 / 空 key）⇒ 在**建任何连接之前**
///   失败（参考在拨号前就已完成 `encryption` 的装配，不会带着坏配置去连对端）。
pub fn precheck(config: &NodeConfig) -> Result<(), VisionConfigError> {
    if let Some(vision) = &config.vision {
        if vision.flow != FLOW_XTLS_RPRX_VISION {
            return Err(VisionConfigError::UnknownFlow(vision.flow.clone()));
        }
    }
    if record_enabled(config) {
        record_config(config)?;
    }
    Ok(())
}

/// 建 Vision 承载。
///
/// 记录层开启 ⇒ `VisionStream<ResponseHeaderStream<RecordStream<S>>>`；
/// 关闭 ⇒ `VisionStream<ResponseHeaderStream<S>>`。
pub fn build(
    carrier: BoxedCarrier,
    config: &NodeConfig,
    uuid: [u8; 16],
) -> Result<VlessVisionStream, VisionConfigError> {
    let wire = vision_wire_config(config, uuid);
    if record_enabled(config) {
        let record = RecordStream::new(carrier, &record_config(config)?)?;
        let header = ResponseHeaderStream::new(record);
        let response = header.header_handle();
        Ok(VlessVisionStream {
            inner: VisionInner::Record(Box::new(VisionStream::new(header, wire))),
            response,
            pending: Vec::new(),
        })
    } else {
        let header = ResponseHeaderStream::new(carrier);
        let response = header.header_handle();
        Ok(VlessVisionStream {
            inner: VisionInner::Plain(Box::new(VisionStream::new(header, wire))),
            response,
            pending: Vec::new(),
        })
    }
}

/// Vision 握手：写请求头（带 `flow=xtls-rprx-vision` addons）+ 首个 vision 块，
/// 再确认下行的 VLESS 成功响应头。
///
/// 参考 `postRequest` + `getResponse`：
/// - 请求头由 `encoding.EncodeRequestHeader` 写，`flow` 走 addons（参考
///   `EncodeHeaderAddons`：长度字节 0x12 + `[0x0A, 0x10]` + `"xtls-rprx-vision"`）。
/// - 首包决策：node 拨号阶段没有业务载荷 ⇒ 插入 0 内容 `Continue` 长 padding 块
///   （参考 `postRequest` 中 500ms 内无首包的分支）。
/// - 响应头由 `DecodeResponseHeader` 读并校验（版本 / addons 长度）。
///
/// **正向证据**：响应头被成功解出 ⇒ 服务端已认证本连接（参考入站只在目标连接
/// 建立成功后才写响应头）。读不到 ⇒ 失败（fail-closed，不回落明文路径）。
///
/// # 为什么用 `poll_fn` 而不是「读满 2 字节即返回」
///
/// 参考是**直读 conn** 拿响应头（`outbound.go:384`：`DecodeResponseHeader(conn, …)`
/// 在包 vision 读者**之前**），所以参考**不等**目标数据就能确认认证。
///
/// 本仓的 `ResponseHeaderStream` 是**惰性**解头的：它在被 poll 时读齐头字节、解出
/// 并写进共享单元格，但**同一次 poll 会继续**去读后续字节（那已经是 vision 流量）。
/// 若把握手写成「`read()` 返回即算握手完成」，就会一直等到 vision 层**吐出明文**
/// —— 服务端此时可能还没收到客户端载荷 ⇒ **死锁**。
///
/// ⇒ 这里用 `poll_fn`：**每次 poll 之后检查共享单元格**，响应头一旦解出就立刻
/// 握手完成，不等明文（与参考的「直读响应头」语义等价）。
///
/// 顺带读到的东西**不丢**：poll 返回 `Ready` 时读到的明文进 `pending`，下次读
/// 先交付它。
pub async fn handshake(
    stream: &mut VlessVisionStream,
    request: &Request,
    uuid: [u8; 16],
    wait: Duration,
) -> Result<(), DialError> {
    let bytes = header::encode_with_flow(request, &uuid, Flow::XtlsRprxVision)
        .map_err(DialError::VlessHeader)?;
    stream.set_preamble(&bytes);
    // 请求头与首个 vision 块**同一次**写出（参考 `postRequest` 的同一个
    // `buf.BufferedWriter`）。
    stream.write_first(None).await.map_err(vision_error)?;

    let deadline = tokio::time::Instant::now() + wait;
    let mut scratch = [0u8; 4096];
    tokio::time::timeout_at(
        deadline,
        std::future::poll_fn(|cx| -> Poll<Result<(), DialError>> {
            // 响应头已解出 ⇒ 握手完成（不等载荷，与参考一致）。
            if stream.response_header().is_some() {
                return Poll::Ready(Ok(()));
            }
            let mut buf = ReadBuf::new(&mut scratch);
            match Pin::new(&mut *stream).poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) => {
                    let read = buf.filled().len();
                    if read > 0 {
                        // 顺带读到的明文不能丢（响应头可能与它同批到达）。
                        stream.pending.extend_from_slice(buf.filled());
                    }
                    if stream.response_header().is_some() {
                        Poll::Ready(Ok(()))
                    } else {
                        // EOF 且没有响应头 ⇒ 对端拒绝（fail-closed）。
                        Poll::Ready(Err(DialError::Rejected(
                            "vision 未收到成功响应头".to_owned(),
                        )))
                    }
                }
                Poll::Ready(Err(error)) => {
                    // 错误也可能发生在「**响应头已解出之后**」：响应头与后续字节
                    // 同批到达时，vision 层解析后续字节失败会让同一次 poll 返回
                    // 错误。响应头才是认证证据 ⇒ 已解出就握手成功，错误留给
                    // 后续读暴露（与参考「先直读响应头、再包 vision 读者」一致）。
                    if stream.response_header().is_some() {
                        Poll::Ready(Ok(()))
                    } else {
                        // 响应头没读到 ⇒ 对端拒绝或线路失败；错误点名 Vision 层
                        // （参考 `failed to decode response header` 的定位方式）。
                        Poll::Ready(Err(DialError::Rejected(format!(
                            "vision 未收到成功响应头：{error}"
                        ))))
                    }
                }
                Poll::Pending => {
                    // 读挂起时响应头可能**已经**解出（响应头与后续字节同批到达）。
                    if stream.response_header().is_some() {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    }
                }
            }
        }),
    )
    .await
    .map_err(|_| DialError::Timeout)?
}

/// Vision 线路错误 → 拨号错误（fail-closed；消息不含密钥材料）。
fn vision_error(error: VisionWireError) -> DialError {
    match error {
        VisionWireError::Io(io) => vision_io_error(io),
        other => DialError::Rejected(format!("vision 线路失败：{other}")),
    }
}

/// 承载流 I/O 错误 → 拨号错误。
fn vision_io_error(error: std::io::Error) -> DialError {
    DialError::Vless(lengsuo_vless::stream::Error::Io(error))
}
