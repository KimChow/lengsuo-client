//! 把 [`WireMask`] 装配成 quinn 端点，并驱动跳跃循环。
//!
//! 参考 `dialer.go:206-217`：先 `udphop`（内层）、再 `udpmaskManager`（外层）；
//! 服务端 `hub.go:379-386` 只有 mask。本模块用 `psk`/`hop` 两个独立输入表达。

use std::net::SocketAddr;
use std::sync::Arc;

use crate::transport::socket::MaskedUdpSocket;
use crate::transport::wire::{WireError, WireMask};
use crate::transport::{HopSpec, OsRng};

/// 端点装配错误。
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    #[error("本机 UDP 端口绑定失败: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Wire(#[from] WireError),
}

/// 绑定本地端口并按 `psk`/`hop` 包装。
///
/// 无混淆也无跳跃时**不**套包装层（保持改动前的 socket 路径）。
/// `remote` 是远端规范地址：跳跃时线上目标端口按 `hop` 轮换，但 quinn 视角
/// 的远端地址固定为它（见 [`WireMask::normalize_peer`]）。
pub fn bind(
    local: SocketAddr,
    remote: SocketAddr,
    psk: Option<Vec<u8>>,
    hop: Option<HopSpec>,
) -> Result<(quinn::Endpoint, Option<Arc<WireMask>>), EndpointError> {
    let mask = match (psk, hop) {
        (None, None) => None,
        (psk, hop) => Some(Arc::new(WireMask::new(remote, psk, hop, Arc::new(OsRng))?)),
    };
    let socket = std::net::UdpSocket::bind(local)?;
    let runtime =
        quinn::default_runtime().ok_or_else(|| std::io::Error::other("无可用异步运行时"))?;
    let endpoint = match &mask {
        Some(mask) => {
            let inner = runtime.wrap_udp_socket(socket)?;
            quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                Arc::new(MaskedUdpSocket::new(inner, Arc::clone(mask))),
                runtime,
            )
            .map_err(std::io::Error::other)?
        }
        None => quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)?,
    };
    Ok((endpoint, mask))
}

/// 跳跃循环（对照 `hopLoop`：每跳后按新抽的间隔重新计时）。
///
/// 当前只轮换远端端口、本地 socket 不变；参考 `hop()` 每跳新建一个已
/// `connect` 的 socket（本地 4 元组随之改变）。见 docs 偏离清单。
///
/// 任务只持 `Weak`：端点（连带 socket 与 mask）释放后循环自动退出，
/// 对照参考 `closeChan` 的效果。
pub fn spawn_hop_loop(mask: &Arc<WireMask>) {
    if !mask.hopping() {
        return;
    }
    let weak = Arc::downgrade(mask);
    tokio::spawn(async move {
        loop {
            let Some(mask) = weak.upgrade() else {
                return;
            };
            tokio::time::sleep(mask.hop_interval()).await;
            let Some(mask) = weak.upgrade() else {
                return;
            };
            if mask.next_hop().is_none() {
                return;
            }
        }
    });
}
