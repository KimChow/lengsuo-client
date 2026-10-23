//! DNS 查询的环境分流决策层：环境 → 登记上游 → 协议出口。
//!
//! 本模块补上 [`super::upstream`]（一发一收原语与绑定表）与 [`crate::egress`]
//! （出口选择层）之间缺的那一段：给定环境号，用该环境登记的 DNS 上游作为**目的
//! 地址**，经 [`EgressSelector`] 选一条协议出口把查询送出去；环境换绑、撤绑或
//! 设备代次变化时回收旧会话，下一次查询自然重拨到新出口（即「迁移」）。
//!
//! ## 不变量（全部 fail-closed，任一不满足即拒绝）
//!
//! - **任何 `Err` 路径都不调用 `forward`**：不把查询发给错误出口，也不发一半。
//! - **目的地址恒等于该环境登记的上游**：`PacketInfo` 的目的地址/端口只从
//!   [`Table::upstream_of`] 取值，调用方传入的会话键不能把 DNS 改指向别处。
//! - **同一 [`SessionKey`] 不能被两个环境共用**：冲突直接拒绝，既不复用别的
//!   环境的会话，也不悄悄覆盖。
//! - **换绑/撤绑/陈旧租约都释放旧出口**：不等 TTL，不泄漏。
//! - 纯内存决策层：不建真实 socket、不碰网卡、不需要 root。
//!
//! ## 与直连路径的分工
//!
//! [`super::upstream::exchange`] 直接 bind 一个独立 UDP socket、走宿主 OS 路由，
//! **绕过协议出口**；本模块不改变它的语义，也不隐式改用它。何时走决策层、何时
//! 走直连由上层显式选择。
//!
//! 错误只描述失败种类，绝不携带查询内容、名字或上游明文。

use std::collections::HashMap;
use std::net::SocketAddr;

use crate::egress::{
    Attribution, BindingAuthority, DenyReason, EgressHandle, EgressSelector, OutboundRuntime,
    RuntimeError,
};
use crate::packet::{PacketInfo, Transport};
use crate::session::{Clock, SessionKey};

use super::upstream::Table;

/// DNS 分流决策的失败种类。Display 只说明类型，不含报文内容或上游明文。
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    /// 环境没有登记 DNS 上游：一条查询都不外发。
    #[error("环境没有绑定的 DNS 上游，拒绝发送")]
    UnboundEnvironment,
    /// 调用方给的归因环境与本次分流的环境不一致。
    #[error("归因环境与分流环境不一致")]
    EnvironmentMismatch,
    /// 同一会话键已被另一个环境占用：拒绝复用。
    #[error("会话键已被其它环境占用")]
    KeyConflict,
    /// 出口选择层拒绝（透传原因）。
    #[error("出口拒绝：{0}")]
    Denied(DenyReason),
    /// 出口转发失败。
    #[error("出口转发失败")]
    Forward(#[source] RuntimeError),
}

/// DNS 环境分流决策层：环境绑定表 + 出口选择层 + 会话键归属。
///
/// `env_by_key` 只记录「这个会话键归哪个环境所有」，用于隔离与换绑回收；它不
/// 参与出口选择本身（那由 [`EgressSelector`] 负责）。
pub struct DnsDispatcher<A, R> {
    selector: EgressSelector<A, R>,
    table: Table,
    env_by_key: HashMap<SessionKey, u64>,
}

impl<A, R> DnsDispatcher<A, R>
where
    A: BindingAuthority,
    R: OutboundRuntime,
{
    /// 组装决策层：已有的出口选择层 + 环境→上游绑定表。
    pub fn new(selector: EgressSelector<A, R>, table: Table) -> Self {
        Self {
            selector,
            table,
            env_by_key: HashMap::new(),
        }
    }

    /// 只读出口选择层（测试/诊断用）。
    #[must_use]
    pub fn selector(&self) -> &EgressSelector<A, R> {
        &self.selector
    }

    /// 当前持有的出口会话数（与 [`EgressSelector::session_count`] 一致）。
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.selector.session_count()
    }

    /// `environment` 登记的上游；未登记即 [`DispatchError::UnboundEnvironment`]。
    pub fn upstream_of(&self, environment: u64) -> Result<SocketAddr, DispatchError> {
        self.table
            .upstream_of(environment)
            .map_err(|_| DispatchError::UnboundEnvironment)
    }

    /// 把一份 DNS 查询按 `environment` 分流到该环境的协议出口。
    ///
    /// 顺序即 fail-closed 语义：
    /// 1. 归因环境必须与入参一致，否则 [`DispatchError::EnvironmentMismatch`]；
    ///    在此之前不查表、不建会话。
    /// 2. 环境必须已登记上游，否则 [`DispatchError::UnboundEnvironment`]；
    ///    此时一个 socket 都没建、一条字节都没发。
    /// 3. 会话键若已归别的环境，拒绝（[`DispatchError::KeyConflict`]），不复用。
    /// 4. 目的地址/端口**只**取自登记的上游；调用方的键只贡献源地址与源端口。
    /// 5. 出口选择层拒绝时透传原因；陈旧归因/租约先回收旧会话再返回。
    /// 6. 转发失败时回收会话并返回 [`DispatchError::Forward`]。
    pub fn dispatch(
        &mut self,
        environment: u64,
        key: SessionKey,
        attribution: Attribution,
        query: &[u8],
        now: Clock,
    ) -> Result<EgressHandle, DispatchError> {
        if attribution.environment.0 != environment {
            return Err(DispatchError::EnvironmentMismatch);
        }
        let upstream = self.upstream_of(environment)?;
        if let Some(&owner) = self.env_by_key.get(&key) {
            if owner != environment {
                return Err(DispatchError::KeyConflict);
            }
        }

        // 目的地址只能来自登记的上游：调用方的键无法把 DNS 改指向别的服务器。
        let info = PacketInfo {
            source: key.source(),
            source_port: key.source_port(),
            destination: upstream.ip(),
            destination_port: upstream.port(),
            protocol: Transport::Udp,
            payload_offset: 0,
        };

        let decision = self.selector.select(&info, key, attribution, now);
        let Some(handle) = decision.handle() else {
            let reason = decision.deny_reason().unwrap_or(DenyReason::NoAttribution);
            if matches!(
                reason,
                DenyReason::StaleAttribution | DenyReason::StaleLease
            ) {
                // 陈旧会话不许留：关掉后下次重拨即迁移到新出口。
                self.close_key(key);
            }
            return Err(DispatchError::Denied(reason));
        };

        match self.selector.forward(&handle, query) {
            Ok(()) => {
                self.env_by_key.insert(key, environment);
                Ok(handle)
            }
            Err(error) => {
                // 关会话 + 释放出口，不泄漏；不把坏会话留到下一次。
                self.close_key(key);
                Err(DispatchError::Forward(error))
            }
        }
    }

    /// 换绑 `environment` 的上游，并回收该环境名下的全部会话，返回关闭数。
    ///
    /// 只影响该环境：别的环境的会话原样保留。
    pub fn rebind(&mut self, environment: u64, upstream: SocketAddr) -> usize {
        self.table.bind(environment, upstream);
        self.close_environment(environment)
    }

    /// 撤销 `environment` 的上游绑定，并回收该环境名下的全部会话，返回关闭数。
    pub fn unbind(&mut self, environment: u64) -> usize {
        self.table.unbind(environment);
        self.close_environment(environment)
    }

    /// 关闭一个会话键对应的出口（若有），返回是否真的关闭。
    fn close_key(&mut self, key: SessionKey) -> bool {
        let closed = self.selector.close(key).is_some();
        self.env_by_key.remove(&key);
        closed
    }

    /// 回收属于 `environment` 的全部会话，返回实际关闭数。
    fn close_environment(&mut self, environment: u64) -> usize {
        let keys: Vec<SessionKey> = self
            .env_by_key
            .iter()
            .filter(|(_, &owner)| owner == environment)
            .map(|(&key, _)| key)
            .collect();
        keys.into_iter().filter(|&key| self.close_key(key)).count()
    }
}
