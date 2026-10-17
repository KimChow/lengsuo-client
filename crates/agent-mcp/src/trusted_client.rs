//! TrustedClient：把 [`TrustGate`] 接到真实 [`crate::McpClient`] 上的受控门面。
//!
//! 门面独占持有私有的 `McpClient` 与 `TrustGate`，只暴露「先过门、再动连接」的
//! 少数方法：
//! - [`TrustedClient::connect`]：spawn 之前先要求 `is_trusted` 且 server 已启用，
//!   任一条件不成立即拒绝，**不会启动子进程**，也不会留下半成品会话。
//! - [`TrustedClient::call_tool`]：发出 `tools/call` 之前要求 `can_call(name)`，
//!   拒绝时**不发送任何请求**，连接不受影响（不 poison、不产生在途请求）。
//! - 授权变更（`set_trusted`/`set_server_enabled`/`set_tool_enabled`）与调用都
//!   通过 `&mut self` 序列化：同一门面内不可能出现「判定与调用交叉」。
//! - [`TrustedClient::shutdown`]：转发底层收尾并回收子进程，之后门面进入 closed，
//!   即使门仍放行也不再走调用路径。
//!
//! 刻意不提供 `request`/`notify`/`list_tools` 等逃生口：门面只保证「被门覆盖的
//! 调用面」，需要更多协议面时应另卡扩展并同样接门。原始 [`crate::McpClient`]
//! 的兼容 API 保持不变，本门面**尚未**成为 Runtime 的唯一入口。

use std::time::Duration;

use serde_json::Value;

use crate::client::{ClientConfig, McpClient};
use crate::error::Error;
use crate::protocol::{InitializeResult, ServerCapabilities, ToolCallResult};
use crate::trust::TrustGate;

/// 门面本地错误：门拒绝（不触碰连接）或底层 [`Error`]（透传，不改变原类型）。
///
/// 刻意不回写全局 `error::Error`：门拒绝不是协议错误，混进全局枚举会让既有
/// 匹配点被迫处理与连接无关的分支。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustedClientError {
    /// 连接前 gate 未处于 trusted 状态：**未 spawn 子进程**。
    #[error("server 未被信任（is_trusted=false），拒绝连接，未启动子进程")]
    NotTrusted,

    /// 连接前 gate 的 server 总开关关闭：**未 spawn 子进程**。
    #[error("server 总开关未启用（set_server_enabled(false)），拒绝连接，未启动子进程")]
    ServerDisabled,

    /// `call_tool` 前 `can_call` 为假（trust/server/工具登记任一缺失）：
    /// **未发送请求**。
    #[error("工具 {tool} 未被允许（can_call=false），请求未发出")]
    ToolNotAllowed {
        /// 被拒绝的工具名（工具标识不是用户数据，可安全出现在错误文本里）。
        tool: String,
    },

    /// 门面已 shutdown/disconnect，不再接受调用。
    #[error("门面已关闭，拒绝调用")]
    Closed,

    /// 门已放行、请求已走底层路径后发生的错误：原样透传 [`Error`]，
    /// 保留错误种类（`JsonRpc`/`Timeout`/`Transport`/…）供上层判定。
    #[error(transparent)]
    Client(#[from] Error),
}

/// 独占持有 `McpClient` + `TrustGate` 的受控客户端。
///
/// 非 `Sync`（继承 `TrustGate` 的纯数据性质）；一个实例只归一个所有者使用，
/// 授权变更与调用由 `&mut self` 天然串行。
#[derive(Debug)]
pub struct TrustedClient {
    client: McpClient,
    gate: TrustGate,
    /// 本门面是否已主动收尾过（`shutdown`/`disconnect`）。
    closed: bool,
}

impl TrustedClient {
    /// 过门后再握手：`is_trusted` 与 `is_server_enabled` 缺一不可，
    /// 拒绝时不 spawn；通过后转发 [`McpClient::connect`]。
    ///
    /// # Errors
    /// [`TrustedClientError::NotTrusted`] / [`TrustedClientError::ServerDisabled`]：
    /// 门拒绝，未启动子进程；[`TrustedClientError::Client`]：门放行后的握手/spawn 失败。
    pub async fn connect(
        config: ClientConfig,
        gate: TrustGate,
    ) -> Result<Self, TrustedClientError> {
        // 判定顺序固定：先 trust 再 server 开关，两者都在 spawn 之前完成。
        if !gate.is_trusted() {
            return Err(TrustedClientError::NotTrusted);
        }
        if !gate.is_server_enabled() {
            return Err(TrustedClientError::ServerDisabled);
        }
        let client = McpClient::connect(config).await?;
        Ok(Self {
            client,
            gate,
            closed: false,
        })
    }

    /// 授权变更：授予/撤销 trust。撤销后所有调用立即被拒（不擦除其他状态）。
    pub fn set_trusted(&mut self, trusted: bool) {
        self.gate.set_trusted(trusted);
    }

    /// 授权变更：server 总开关。停用只切断通路，不撤销 trust 与登记。
    pub fn set_server_enabled(&mut self, enabled: bool) {
        self.gate.set_server_enabled(enabled);
    }

    /// 授权变更：显式登记某工具的启用状态；以 `false` 登记不构成启用。
    pub fn set_tool_enabled(&mut self, name: &str, enabled: bool) {
        self.gate.set_tool_enabled(name, enabled);
    }

    /// 当前判定：是否允许调用该工具（trust + server 启用 + 工具显式启用）。
    #[must_use]
    pub fn can_call(&self, name: &str) -> bool {
        self.gate.can_call(name)
    }

    /// 当前是否 trusted（不改变状态的只读查询）。
    #[must_use]
    pub fn is_trusted(&self) -> bool {
        self.gate.is_trusted()
    }

    /// 当前 server 总开关状态。
    #[must_use]
    pub fn is_server_enabled(&self) -> bool {
        self.gate.is_server_enabled()
    }

    /// 某工具是否被显式登记为启用（不含 trust 与 server 开关）。
    #[must_use]
    pub fn is_tool_enabled(&self, name: &str) -> bool {
        self.gate.is_tool_enabled(name)
    }

    /// 门面持有的门（只读）。需要按状态做展示或断言时用；变更必须走本门面的
    /// `set_*`，否则会绕开 `&mut self` 的序列化。
    #[must_use]
    pub fn gate(&self) -> &TrustGate {
        &self.gate
    }

    /// 受控 `tools/call`：先 `can_call(name)`，拒绝时不发送请求；放行后透传底层
    /// 结果（工具自身失败仍走 `result.is_error`，不映射为错误）。
    ///
    /// # Errors
    /// [`TrustedClientError::Closed`]：门面已关闭；
    /// [`TrustedClientError::ToolNotAllowed`]：门拒绝，请求未发出；
    /// [`TrustedClientError::Client`]：门放行后的超时/poisoned/传输中断/JSON-RPC 错误。
    pub async fn call_tool(
        &mut self,
        name: &str,
        arguments: Option<Value>,
    ) -> Result<ToolCallResult, TrustedClientError> {
        if self.closed {
            return Err(TrustedClientError::Closed);
        }
        if !self.gate.can_call(name) {
            // fail-closed：判定为假即返回，不构造请求、不触碰写侧。
            return Err(TrustedClientError::ToolNotAllowed {
                tool: name.to_string(),
            });
        }
        Ok(self.client.call_tool(name, arguments).await?)
    }

    /// 门面是否已关闭：主动收尾过，或底层会话已 EOF/结束。
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed || self.client.is_closed()
    }

    /// `shutdown` 并回收子进程（转发 [`McpClient::shutdown`]），随后门面标记关闭。
    ///
    /// 幂等：第二次调用直接 `Ok(())`，不再发送报文。第一次调用即使底层报错，
    /// 门面同样进入 closed（底层已尽力 `exit` + 回收）。
    ///
    /// # Errors
    /// 第一次调用时底层返回的错误（对端未响应 `shutdown` 等）。
    pub async fn shutdown(&mut self) -> Result<(), TrustedClientError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        Ok(self.client.shutdown().await?)
    }

    /// 不强求对端配合的直接断开：不发送报文，直接回收子进程，门面进入 closed。
    pub async fn disconnect(&mut self) {
        self.closed = true;
        self.client.disconnect().await;
    }

    /// 底层连接是否已被标记 poisoned（超时/帧损坏后需重建门面）。
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.client.is_poisoned()
    }

    /// poisoned 原因（若有）。
    #[must_use]
    pub fn poison_reason(&self) -> Option<String> {
        self.client.poison_reason()
    }

    /// 无法匹配到在途请求的响应数量。拒绝路径不发送请求，因此该计数只由
    /// 真实调用产生，可用来佐证「拒绝时未发请求」。
    #[must_use]
    pub fn unmatched_responses(&self) -> u64 {
        self.client.unmatched_responses()
    }

    /// 握手协商出的协议版本。
    #[must_use]
    pub fn protocol_version(&self) -> &str {
        self.client.protocol_version()
    }

    /// 握手返回的服务端能力（只读元数据，不涉及调用授权）。
    #[must_use]
    pub fn server_capabilities(&self) -> &ServerCapabilities {
        self.client.server_capabilities()
    }

    /// 握手 `initialize` 结果（版本、能力、serverInfo）。
    #[must_use]
    pub fn initialize_result(&self) -> &InitializeResult {
        self.client.initialize_result()
    }

    /// 当前使用的每请求超时。
    #[must_use]
    pub fn request_timeout(&self) -> Duration {
        self.client.request_timeout()
    }
}
