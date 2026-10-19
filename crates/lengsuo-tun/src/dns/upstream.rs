//! DNS 载荷到**显式上游**的异步 UDP 请求-响应原语，以及 environment id → 上游
//! 端点的绑定表。
//!
//! 入口分两层：环境无关的孤立动作 [`exchange`]（把一份已编码的 DNS 查询发到调用
//! 方指定的上游端点，等待与之匹配的那份响应，并原样返回响应字节）；环境绑定的
//! [`Table`]（按 environment id 登记每环境唯一的上游，A 环境的响应绝不回给 B）。
//! 二者都是「一发一收」，不构成整个 TUN/DNS 转发链路：不建设备、不查系统默认
//! DNS、不做缓存、不重写报文、不并发多路复用，也不理解资源记录语义。
//!
//! 可信边界由调用方负责：`exchange` 假定「这份查询可以发往这个上游」是上层已经
//! 做出的授权决定；`Table` 把它具象化为登记动作——任何 environment 没有登记过的
//! 查询被拒绝，已登记的查询只发往登记的那个端点，上游不可信或未授权时唯一正确的
//! 做法是不调用本函数。两个入口都绝不静默回退到系统 DNS 或别的出口。
//!
//! fail-closed 清单（任一不满足都返回 [`Error`]，没有任何宽松回退）：
//! - `deadline` 为零：直接 [`Error::InvalidDeadline`]，不绑定、不发送。
//! - `query` 未通过 [`super::parse_query`]：[`Error::BadQuery`]，**在发包之前**
//!   拒绝，绝不把非法载荷送往上游。
//! - 响应必须通过 [`super::parse_response`]（QR=1、结构完整、单问题、非 TC），
//!   且头部 ID 与 qtype/qclass 逐字段精确一致、问题名字按 RFC 1035 2.3.1 的大小写
//!   不敏感语义一致，才接受回注。
//! - 不匹配或非法的报文一律丢弃并继续等待合法响应；丢弃次数受 [`MAX_REJECTS`]
//!   上限约束，整个交换又被单一 `deadline` 覆盖（send 与 recv 都在其内），
//!   因此非法洪泛既不能无限占用 CPU，也不能把总期限拖长。
//!
//! 独占性：每次调用都新绑一个 UDP socket（按上游地址族绑定零端口）并 `connect`
//! 固定 peer。连接式 socket 只收来自该 peer 的报文，伪造来源（别的地址发来的
//! 合法响应）进不来，因此天然拒绝来源伪装；不同调用各用各的 socket，互不串扰。
//!
//! 错误只描述失败种类，绝不携带查询内容、名字、token 或响应字节。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::dns;

/// 单次交换允许丢弃的最大「非预期」报文数：超过即放弃等待，给非法/洪泛输入
/// 一个硬性收敛上界，防止无限循环消耗 CPU。合法远达不到此数。
const MAX_REJECTS: usize = 32;
/// 接收缓冲区覆盖 UDP 长度字段的完整范围；一次接收一个数据报，不重组。
const MAX_DATAGRAM: usize = 65_535;

/// [`exchange`] 的全部失败种类。Display 只说明失败类型，不含任何报文内容。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `deadline` 为零：整个操作必须有正的总期限，零期限无法覆盖任何收发。
    #[error("DNS 交换期限必须为正")]
    InvalidDeadline,
    /// 查询载荷未通过 [`super::parse_query`]：拒绝，且发生在发送之前。
    /// 仅转述解析失败的类型，不回显查询字节。
    #[error("DNS 查询报文非法，拒绝发送")]
    BadQuery(#[source] dns::Error),
    /// 在 `deadline` 内没有收到与查询匹配的合法响应（含 send 或 recv 阶段）。
    #[error("DNS 上游交换未在期限内完成")]
    Timeout,
    /// 丢弃的非预期报文达到 [`MAX_REJECTS`]：放弃继续等待，避免无界消耗。
    #[error("DNS 上游丢弃报文超过上限，放弃等待")]
    TooManyRejects,
    /// 该 environment 没有登记过 DNS 上游：拒绝，且一条查询都不外发。
    #[error("环境没有绑定的 DNS 上游，拒绝发送")]
    UnboundEnvironment,
    /// 绑定、连接或收发底层的 socket 错误（OS 层面，不含查询内容）。
    #[error("DNS 上游 UDP socket 操作失败")]
    Io(#[source] std::io::Error),
}

/// 把一份 DNS 查询发往 `upstream` 并返回与之匹配的响应字节。
///
/// 语义与时限：
/// 1. `deadline` 必须为正，否则 [`Error::InvalidDeadline`]（不绑定、不发送）。
/// 2. `query` 必须先通过 [`super::parse_query`]，否则 [`Error::BadQuery`]——
///    校验在发包前完成，非法查询绝不外发。
/// 3. 独占绑定：按 `upstream` 地址族选定未指定地址（V4→`0.0.0.0`，
///    V6→`::`）与零端口 bind，再 `connect` 固定 `upstream` 作为唯一 peer。
/// 4. 用单一 `timeout` 覆盖 send 与整个 recv 循环；期限内反复接收，丢弃任何
///    解析失败或 ID/问题区不符的报文，直到匹配响应到手或触及 [`MAX_REJECTS`]。
/// 5. 成功返回**原样响应字节**（不重新编码、不改写），供上层自行回注。
///
/// 本函数不查系统默认 DNS、不回退到其它上游；上游由调用方给定并视为已授权。
pub async fn exchange(
    query: &[u8],
    upstream: SocketAddr,
    deadline: Duration,
) -> Result<Vec<u8>, Error> {
    if deadline.is_zero() {
        return Err(Error::InvalidDeadline);
    }
    // 发包前完成查询校验：拿到期望的 ID 与问题区，用于逐字段比对响应。
    let expected = dns::parse_query(query).map_err(Error::BadQuery)?;

    // 绑定、连接与收发均受同一个总期限约束。
    timeout(deadline, async {
        let socket = bind_socket(upstream).await?;
        request_and_await(&socket, query, &expected).await
    })
    .await
    .map_err(|_| Error::Timeout)?
}

/// 按上游地址族绑定一个独占 UDP socket 并连接固定 peer。
///
/// 地址族必须与 `connect` 目标一致（V4 socket 不能连 V6 地址），否则链路错误；
/// 绑定零端口把源端口选择交给内核，同时保证本调用独享这一 socket。
async fn bind_socket(upstream: SocketAddr) -> Result<UdpSocket, Error> {
    let any: SocketAddr = match upstream.ip() {
        IpAddr::V4(_) => (IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0).into(),
        IpAddr::V6(_) => (IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0).into(),
    };
    let socket = UdpSocket::bind(any).await.map_err(Error::Io)?;
    socket.connect(upstream).await.map_err(Error::Io)?;
    Ok(socket)
}

/// 发出查询后在 socket 上等待匹配的响应；不匹配/非法报文丢弃并计入拒绝上限。
///
/// 被 [`exchange`] 的 `timeout` 包裹，因此循环自身只需在每次 `recv` 就绪时判断
/// 「是否匹配」，无需自己数时间：期限到点由外层取消整段收发。返回 `Err` 代表
/// 触及拒绝上限或底层 socket 错误；正常匹配则带回响应字节。
async fn request_and_await(
    socket: &UdpSocket,
    query: &[u8],
    expected: &dns::Message,
) -> Result<Vec<u8>, Error> {
    socket.send(query).await.map_err(Error::Io)?;

    let mut buffer = vec![0u8; MAX_DATAGRAM];
    let mut rejected = 0usize;
    loop {
        let read = socket.recv(&mut buffer).await.map_err(Error::Io)?;
        let payload = &buffer[..read];
        // 结构/方向不合格，或 ID 与问题区不与查询一致：判为非预期，丢弃续等。
        if matches_response(payload, expected) {
            // 原样返回收到的响应字节（含其自身问题区与资源记录）。
            buffer.truncate(read);
            buffer.shrink_to_fit();
            return Ok(buffer);
        }
        rejected += 1;
        if rejected >= MAX_REJECTS {
            return Err(Error::TooManyRejects);
        }
    }
}

/// environment id → 上游端点的绑定表：每环境唯一上游，查询只发往登记端点。
///
/// 环境身份来自可信入口的显式登记（`bind`），绝不从地址、端口或域名猜测；未登记
/// 的环境一律 [`Error::UnboundEnvironment`]，不查系统 DNS、不挑别的上游。登记即
/// 覆盖：换绑后旧端点立即失权，存量会话按新端点重发。条目不可枚举（无迭代器），
/// 上游地址不落日志、不进错误文本。
#[derive(Default)]
pub struct Table {
    /// 环境 → 该环境唯一授权的 DNS 上游端点。
    upstreams: HashMap<u64, SocketAddr>,
}

impl Table {
    /// 登记 `environment` 的 DNS 上游；重复登记视为换绑，覆盖旧端点。
    pub fn bind(&mut self, environment: u64, upstream: SocketAddr) {
        self.upstreams.insert(environment, upstream);
    }

    /// 撤销 `environment` 的绑定；撤销后其查询一律 [`Error::UnboundEnvironment`]。
    pub fn unbind(&mut self, environment: u64) {
        self.upstreams.remove(&environment);
    }

    /// `environment` 当前绑定的上游；未登记即 [`Error::UnboundEnvironment`]。
    pub fn upstream_of(&self, environment: u64) -> Result<SocketAddr, Error> {
        self.upstreams
            .get(&environment)
            .copied()
            .ok_or(Error::UnboundEnvironment)
    }

    /// 把 `query` 发往 `environment` 绑定的上游并返回匹配的响应字节。
    ///
    /// 绑定查找发生在发送之前：环境未登记时一条查询都不会外发。失败路径（超时、
    /// 报文被拒、底层错误）一律以错误结束，绝不改发其它环境的上游或系统 DNS；
    /// 时间预算由 `deadline` 单一覆盖（见 [`exchange`]）。
    pub async fn resolve(
        &self,
        environment: u64,
        query: &[u8],
        deadline: Duration,
    ) -> Result<Vec<u8>, Error> {
        let upstream = self.upstream_of(environment)?;
        exchange(query, upstream, deadline).await
    }
}

/// 判断一份数据报是否是 `expected` 查询的合法匹配响应。
///
/// 复用 [`super::parse_response`] 做结构与方向校验（不重新解析 DNS 语义），随后比对：
/// - 查询 ID 必须逐字节相同：ID 是事务标识，漂移一位就说明这份报文不属于本次交换。
/// - 名字按 [`dns::QuestionName::matches`] 逐标签、ASCII 大小写不敏感比较（RFC 1035
///   2.3.1）：上游把回显名字规范化为小写是合法行为，按字节比较会把真实响应误判为
///   非预期，进而让整条交换无谓超时。与 `super::rewrite::match_response` 同源。
/// - qtype 与 qclass 必须精确相同：它们定义了被回答的是哪个问题，没有等价形式。
///
/// 任一不符即视为非预期，交由调用方丢弃并计入拒绝上限。
fn matches_response(payload: &[u8], expected: &dns::Message) -> bool {
    match dns::parse_response(payload) {
        Ok(response) => {
            response.header.id == expected.header.id
                && response.question.name.matches(&expected.question.name)
                && response.question.qtype == expected.question.qtype
                && response.question.qclass == expected.question.qclass
        }
        Err(_) => false,
    }
}
