//! 注入点：设备收包来源、五元组分类器与出口投递端。

use std::fmt::Display;
use std::time::Duration;

use crate::packet::PacketInfo;

/// 一次设备收包的结果。把「超时」与「错误」显式分开，避免按错误文本猜语义。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Receipt {
    /// 收到一个完整 IP 报文。
    Packet(Vec<u8>),
    /// 在超时窗口内没有报文，属于正常空闲。
    Timeout,
}

/// 设备收包来源。生产实现见 [`crate::device::Device`]（Windows）。
pub trait PacketSource {
    /// 收包失败的类型；必须可读，便于统计与排障。
    type Error: Display;

    /// 在 `timeout` 内尝试收一个报文。超时必须返回 [`Receipt::Timeout`]。
    fn receive(&mut self, timeout: Duration) -> Result<Receipt, Self::Error>;
}

/// 五元组分类器。实现方负责把环境归属策略（例如 `lengsuo-environment`）接进来。
///
/// 返回 `Ok(None)` 表示「没有归属」，`Err` 表示分类过程失败；两者都会被丢弃，
/// 但按不同原因计数。
pub trait Classifier {
    /// 归属标识。本模块不解释其内容，只原样交给出口。
    type Attribution;
    /// 分类失败的错误类型。
    type Error: Display;

    /// 对已解析的报文元数据给出归属。
    fn classify(&mut self, info: &PacketInfo) -> Result<Option<Self::Attribution>, Self::Error>;
}

/// 出口投递端。实现方负责实际转发，本模块只做投递与计数。
pub trait EgressSink<A> {
    /// 投递失败的错误类型。
    type Error: Display;

    /// 投递原包、元数据与归属。失败表示本包未被送出。
    fn deliver(
        &mut self,
        packet: &[u8],
        info: &PacketInfo,
        attribution: A,
    ) -> Result<(), Self::Error>;
}
