//! AnyTLS 出口：TLS → 认证块 → 客户端 Settings(v=2) → 等服务端 ServerSettings。
//!
//! 语义来源（只读参考）：anytls-go `proxy/session/session.go` 的客户端分支
//! （仓内基线 commit `fd6167acd6d73b9fa3e607659951847fbc9e6c50`；参考树可用
//! 版本 v0.0.13 = `9666872946857b50a74fdb692896d77b53773cb2`，二者在本卡引用的
//! 路径上逐字节相同）。**收到服务端 ServerSettings 即认证完成的正向证据**；
//! 断连或 Alert 即拒绝——anytls 没有同步响应头，这与 trojan 的「负向排除」
//! 不同。拆分前该判据写在 `outbound` 模块注释里，本卡只是把它连同实现一起
//! 搬到协议专属文件，**判据本身未改**。
//!
//! 注：Xray（固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）**没有**
//! anytls 实现（其 `proxy/` 下无 `anytls` 目录），故 anytls 的对齐对象是
//! anytls-go 而非 Xray——详见 `docs/node-anytls-outbound.md` §6.1。
//!
//! 帧与状态机语义由 `lengsuo_anytls` 承担（`auth` 认证块、`frame` 帧原语、
//! `client_state` 客户端状态机），本模块只做「配置 → 建流 → 认证 → 等待
//! ServerSettings」的编排，不复制协议实现。
//!
//! 共享部分留在 `outbound`：`NodeTlsStream`（trojan 与 anytls 共用的 TLS 流
//! 类型）、`tls_client`（证书加载与信任锚校验，trojan 也在用）与 `resolve`
//! （异步解析，trojan 与其余六个协议都在用）——按「迁走前先 grep 确认引用方」
//! 的判据，这三个符号的引用方**不止** anytls，故不迁。

use std::time::Duration;

use lengsuo_anytls::auth::Credential as AnyTlsCredential;
use lengsuo_anytls::client_state::ClientState;
use lengsuo_anytls::frame::{Command as AnyTlsCommand, Frame};

use crate::config::NodeConfig;
use crate::outbound::{resolve, tls_client, DialError, NodeTlsStream};

/// anytls 客户端单会话活跃流上限（对齐参考默认，见 interop 客户端组装）。
pub const ANYTLS_MAX_STREAMS: usize = 16;
/// anytls 客户端标识；服务端不校验该键，如实上报自身。
pub const ANYTLS_CLIENT_IDENT: &str = "lengsuo-node";
/// 默认 padding 方案的 md5（anytls-go v0.0.13 `pad/padding.go` 逐字节算出），
/// 上报它使服务端不必先下发 UpdatePadding 即完成 v2 协商。
/// 与 `lengsuo-anytls/tests/interop_client/session.rs` 同源同值
/// （亦即 `lengsuo_anytls::padding::DEFAULT_PADDING_MD5`）。
pub const ANYTLS_DEFAULT_SCHEME_MD5: &str = "75cff2ad89aadf5e257059ee571ebe11";
/// 认证块 padding：参考客户端按默认方案 `0=30-30` 生成，0 号记录恒 30 字节零值。
pub const ANYTLS_AUTH_PADDING: [u8; 30] = [0; 30];

/// anytls 出站会话：已认证、已协商版本，可继续开流（SYN/PUSH）转发业务。
pub struct AnyTlsOutbound {
    pub stream: NodeTlsStream,
    pub state: ClientState,
}

/// anytls 专属的拨号失败原因。
///
/// 拆分前这两个变体直接挂在 `outbound::DialError` 上（`AnyTls` /
/// `AnyTlsState`）；变体随协议实现一起迁到本文件后，`DialError::AnyTls`
/// 改用 `#[error(transparent)]` 承载本类型 ⇒ **对外 `Display` 逐字不变**：
/// - 协议原语错误仍是「anytls 协议错误：{err}」；
/// - 状态机拒绝仍是「anytls 客户端状态机拒绝：{err}」。
#[derive(Debug, thiserror::Error)]
pub enum AnyTlsError {
    /// anytls 协议原语错误（认证块、帧编解码、I/O 等）。
    #[error("anytls 协议错误：{0}")]
    Protocol(#[from] lengsuo_anytls::Error),
    /// 客户端状态机拒绝（远端帧违反协议，或版本/设置协商失败）。
    #[error("anytls 客户端状态机拒绝：{0}")]
    State(String),
}

/// anytls 协议原语错误 ⇒ node 拨号错误。
///
/// 拆分前该转换由 `DialError::AnyTls(#[from] lengsuo_anytls::Error)` 直接提供；
/// 变体迁到 `AnyTlsError` 后在此补上等价转换，`?` 的行为与错误文案不变。
impl From<lengsuo_anytls::Error> for DialError {
    fn from(err: lengsuo_anytls::Error) -> Self {
        DialError::AnyTls(AnyTlsError::Protocol(err))
    }
}

/// anytls 出站：TLS → 认证块 → 客户端 Settings(v=2) → 等服务端 ServerSettings。
pub async fn dial_anytls(config: &NodeConfig, wait: Duration) -> Result<AnyTlsOutbound, DialError> {
    let client = tls_client(config, wait)?;
    let addr = resolve(&config.endpoint.host, config.endpoint.port, wait).await?;
    let mut stream = client.connect(addr).await?;

    AnyTlsCredential::new(config.auth.password.as_bytes())
        .send(&mut stream, &ANYTLS_AUTH_PADDING, wait)
        .await?;
    let mut state = ClientState::new(ANYTLS_MAX_STREAMS)
        .map_err(|err| DialError::AnyTls(AnyTlsError::State(err.to_string())))?;
    state
        .mark_settings_sent()
        .map_err(|err| DialError::AnyTls(AnyTlsError::State(err.to_string())))?;
    let settings =
        format!("v=2\nclient={ANYTLS_CLIENT_IDENT}\npadding-md5={ANYTLS_DEFAULT_SCHEME_MD5}");
    Frame {
        command: AnyTlsCommand::Settings,
        stream_id: 0,
        data: settings.into_bytes(),
    }
    .write(&mut stream, wait)
    .await?;

    // 等认证完成的正向证据：ServerSettings。断连/Alert = 拒绝；其他帧按状态机处理。
    loop {
        let frame = Frame::read(&mut stream, u16::MAX, wait).await?;
        let event = state.accept(&frame).map_err(|err| {
            DialError::AnyTls(AnyTlsError::State(format!(
                "cmd={}: {err}",
                frame.command as u8
            )))
        })?;
        match frame.command {
            AnyTlsCommand::ServerSettings => {
                let _ = event;
                return Ok(AnyTlsOutbound { stream, state });
            }
            AnyTlsCommand::Alert => {
                return Err(DialError::Rejected("服务端 Alert".to_owned()));
            }
            // Waste/心跳/padding 更新/迟到帧：状态机已归类，继续等待。
            _ => continue,
        }
    }
}
