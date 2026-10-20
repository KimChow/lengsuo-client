//! Hysteria2 服务端侧：HTTP/3 认证应答 + 每条连接的服务例程
//! （对齐 Xray `transport/internet/hysteria/hub.go` 的
//! `httpHandler.ServeHTTP` / `StreamDispatcher` / `udpSessionManagerServer`
//! 与 `proxy/hysteria/server.go` 的 `Process`）。
//!
//! 本模块手写 HTTP/3 帧与 QPACK 头部块（与客户端侧 `h3_auth` 同一理由：
//! 依赖冻结拿不到 `http`/`bytes` crate，见 `qpack` 模块文档），语义对齐
//! quic-go 的 http3 服务端：
//! - 建立本端控制流（SETTINGS）与 QPACK 编码器流；
//! - 逐条接受客户端双向流：首个帧类型为 `0x401`（TCPRequest）且已认证则
//!   交给 `proxy::serve_tcp_stream`；否则按 HTTP/3 请求处理；
//! - `POST https://hysteria/auth`：校验 `Hysteria-Auth`（常量时间、fail-closed），
//!   成功回 233 + `Hysteria-UDP` / `Hysteria-CC-RX` / `Hysteria-Padding`，
//!   失败按参考回 masquerade 缺省 404；
//! - 认证成功且客户端要求 datagram 时启动 UDP 会话管理器。

use crate::h3_auth::{
    random_padding, AuthError, ServerHeaderField as HeaderField, ServerPaddingRange as Range,
    COMMON_HEADER_CC_RX, COMMON_HEADER_PADDING, FRAME_HEADERS, FRAME_SETTINGS, MAX_RESPONSE_BYTES,
    REQUEST_HEADER_AUTH, RESPONSE_HEADER_UDP_ENABLED, STATUS_AUTH_OK, STATUS_NOT_FOUND,
    STREAM_TYPE_QPACK_ENCODER, URL_HOST, URL_PATH,
};
use crate::qpack;
use crate::varint;
use quinn::{Connection, RecvStream, SendStream};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use crate::quic::server::{ServerSessionCtx, UdpManager};

/// 服务端处理一条已握手 QUIC 连接（对齐 `handleClient` → `http3.Server.ServeQUICConn`）。
///
/// 本实现手写 HTTP/3 控制流与请求分派（依赖冻结拿不到 `h3` 的 `http` 类型，
/// 见 `qpack` 模块文档），语义对齐 quic-go 的 http3 服务端：
/// - 先建立/接受控制流（本端发 SETTINGS，收对端 SETTINGS）；
/// - 逐条接受客户端双向流，解析首个帧类型：
///   `0x401`（TCPRequest）分派为 TCP 承载（`StreamDispatcher`），
///   其余按 HTTP/3 请求处理（`POST https://hysteria/auth` 认证）；
/// - 认证一旦成功即开启 UDP 会话管理器（仅当客户端要求 datagram）。
///
/// 认证失败：非 233 一律回 masquerade 404（fail-closed，不建立任何承载）。
/// 服务端处理一条已握手 QUIC 连接（对齐 `handleClient` → `http3.Server.ServeQUICConn`）。
pub async fn serve_connection(conn: Connection, ctx: ServerSessionCtx) -> Result<(), AuthError> {
    ServerState::new(conn, ctx).run().await
}

/// 从接收流读满 `len` 字节；EOF 提前结束（或因流错误）时返回已读部分。
///
/// `len` 很小（拥塞通告长度）且此时流数据已基本在本地，读超时 5s 兜底。
async fn read_exact_or_eof(recv: &mut RecvStream, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while out.len() < len {
        let left = len - out.len();
        match tokio::time::timeout_at(deadline, recv.read_chunk(left, true)).await {
            Ok(Ok(Some(chunk))) => out.extend_from_slice(&chunk.bytes),
            _ => break,
        }
    }
    out
}

/// 每连接服务端状态（等价 `hub.go` `httpHandler`）。
pub struct ServerState {
    conn: Connection,
    ctx: ServerSessionCtx,
    /// `h.auth`：认证成功后置真（同一连接只认证一次，参考用 `h.mutex` 串行化）。
    auth: bool,
    /// 拥塞协商是否已按客户端 `Hysteria-CC-RX` 做过一次（`hub.go` 每连接一次）。
    negotiated: bool,
    /// 每连接的服务端发送速率（字节/秒；`0` = 不限速 / 未协商）。
    tcp_rate: u64,
    /// 需要保持打开的 H3 单向流（本端 SETTINGS + QPACK 编码器）。
    h3: Option<H3ServerStreams>,
    /// 服务端 UDP 会话表（认证成功且客户端要求 datagram 时才有值）。
    udp: Option<Arc<Mutex<UdpManager>>>,
    /// 从接收流 chunk 顺路取得的一次性发送种子（Bytes 桥，见
    /// `h3_auth::seed_filler_from_chunk`）；认证成功时交给 UDP 管理器。
    seeds: Vec<crate::h3_auth::SeedFiller>,
}

/// 服务端须保活的 H3 单向流：控制流（已发 SETTINGS）与 QPACK 编码器流。
struct H3ServerStreams {
    #[allow(dead_code)]
    control: quinn::SendStream,
    #[allow(dead_code)]
    qpack_encoder: quinn::SendStream,
}

impl ServerState {
    fn new(conn: Connection, ctx: ServerSessionCtx) -> Self {
        Self {
            conn,
            ctx,
            auth: false,
            negotiated: false,
            tcp_rate: 0,
            h3: None,
            udp: None,
            seeds: Vec::new(),
        }
    }

    async fn run(mut self) -> Result<(), AuthError> {
        // 本端控制流：首帧 SETTINGS（空）。QPACK 编码器流同时建立，
        // 但本实现对响应头块只使用静态表/字面量，故编码器流不发插入指令。
        let mut control = self.conn.open_uni().await?;
        let mut head = Vec::with_capacity(4);
        varint::append(0x0u64, &mut head)?;
        varint::append(FRAME_SETTINGS, &mut head)?;
        varint::append(0u64, &mut head)?;
        control.write_all(&head).await?;
        let mut qpack_encoder = self.conn.open_uni().await?;
        let mut enc = Vec::with_capacity(1);
        varint::append(STREAM_TYPE_QPACK_ENCODER, &mut enc)?;
        qpack_encoder.write_all(&enc).await?;
        self.h3 = Some(H3ServerStreams {
            control,
            qpack_encoder,
        });

        // 接受客户端双向流；连接关闭即结束。
        while let Ok((mut send, mut recv)) = self.conn.accept_bi().await {
            let first = read_first_varint(&mut recv).await?;
            if first == crate::tcp::FRAME_TYPE_TCP_REQUEST {
                // 对齐 hub.go StreamDispatcher：已认证才交给承载层，
                // 否则回落到 HTTP/3 请求处理（= masquerade 404）。
                if !self.auth {
                    let _ = respond_not_found(&mut send).await;
                    continue;
                }
                // 帧类型已被读走；首个 varint 之后若为拥塞通告（不带数据的
                // TCPRequest，见 `congestion::wire`），只供逐连接协商，不建承载。
                let head = read_exact_or_eof(&mut recv, crate::congestion::ANNOUNCE_LEN).await;
                if crate::congestion::parse_announce(&head).is_some() {
                    let _ = send.finish();
                    continue;
                }
                // TCPRequest 的其余部分由承载层解析；预读字节原样交还。
                let conn = self.conn.clone();
                let rate = self.tcp_rate;
                tokio::spawn(async move {
                    let _ =
                        crate::proxy::serve_tcp_stream_paced(conn, send, recv, rate, head).await;
                });
            } else {
                // HTTP/3 请求：`first` 是 HEADERS 帧类型（0x1）或未知帧。
                self.handle_http3_request(first, &mut send, &mut recv)
                    .await?;
            }
        }
        Ok(())
    }

    /// 处理一条 HTTP/3 请求流（对齐 `httpHandler.ServeHTTP`）。
    ///
    /// `first_frame` 已从流上读到的首帧类型。认证请求为
    /// `POST https://hysteria/auth`；成功回 233 + UDP/CC-RX/padding 响应头，
    /// 否则（含已认证后的重复认证）直接回 233（对齐参考 `h.auth` 早退分支；
    /// 拥塞协商只在首次认证通过时做一次），其余请求一律走 masquerade 404。
    async fn handle_http3_request(
        &mut self,
        first_frame: u64,
        send: &mut quinn::SendStream,
        recv: &mut quinn::RecvStream,
    ) -> Result<(), AuthError> {
        if first_frame != FRAME_HEADERS {
            // 非 HEADERS 起始的流按参考忽略（不属认证请求）。
            return Ok(());
        }
        let block = read_frame_payload(recv, &mut self.seeds).await?;
        let mut decoder = qpack::Decoder::default();
        let fields = match decoder.decode_field_section(&block) {
            Ok(f) => f,
            Err(e) => {
                // 解码失败：按参考落到 masquerade，不建立承载。
                let _ = respond_not_found(send).await;
                return Err(e.into());
            }
        };
        let request = RequestHead::from_fields(&fields);
        if !request.is_auth_request() {
            let _ = respond_not_found(send).await;
            return Ok(());
        }
        let authorized = self.auth || self.check_auth(request.auth.as_deref());
        if !authorized {
            let _ = respond_not_found(send).await;
            return Ok(());
        }
        self.auth = true;
        if !self.negotiated {
            // 对齐 hub.go:187-205：认证通过后按客户端 `Hysteria-CC-RX` 与本端
            // `BrutalUp` 协商服务端发送速率（`min`，任一为 0 ⇒ 回落分支）。
            self.negotiated = true;
            match crate::congestion::server_send_rate(&self.ctx.congestion, request.cc_rx) {
                Ok(0) => eprintln!(
                    "[lengsuo-hysteria] 服务端未协商出 Brutal 速率（参考回落分支），TCP 端口不限速"
                ),
                Ok(rate) => {
                    self.tcp_rate = rate;
                    eprintln!(
                        "[lengsuo-hysteria] 服务端 TCP 端口限速 {rate} 字节/秒（min(BrutalUp, clientDown)）"
                    );
                }
                // 非法速率 fail-closed：`serve_connection` 收尾以协议错误关闭连接。
                Err(e) => return Err(AuthError::Protocol(format!("拥塞控制配置非法: {e}"))),
            }
        }
        // `Hysteria-UDP` 由服务端配置决定（对齐 `RequireDatagramFromContext`
        // 的服务端语义），不由客户端请求头决定。
        let udp_enabled = self.ctx.udp_enabled;
        if udp_enabled && self.udp.is_none() {
            self.spawn_udp_manager();
        }
        respond_auth_ok(send, udp_enabled, self.ctx.brutal_down).await
    }

    /// 常量时间比较口令（fail-closed）；空口令配置一律拒绝。
    fn check_auth(&self, presented: Option<&str>) -> bool {
        let expected = self.ctx.auth.as_bytes();
        if expected.is_empty() {
            return false;
        }
        let Some(presented) = presented else {
            return false;
        };
        let presented = presented.as_bytes();
        if presented.len() != expected.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in presented.iter().zip(expected.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    /// 认证成功后启动服务端 UDP 会话管理器（对齐 `go udpSM.clean()` +
    /// `go udpSM.run()`：run 分发 + 每条新建会话交给应用层承载）。
    fn spawn_udp_manager(&mut self) {
        let conn = self.conn.clone();
        let idle = self.ctx.udp_idle_timeout_secs;
        let (session_tx, session_rx) = mpsc::channel(64);
        let mut manager_state = UdpManager::new(session_tx);
        for seed in std::mem::take(&mut self.seeds) {
            manager_state.push_seed(seed);
        }
        let manager = Arc::new(Mutex::new(manager_state));
        self.udp = Some(Arc::clone(&manager));
        let mgr = Arc::clone(&manager);
        // 会话交付（`addConn(udpConn)` → Xray 为每条连接起 Process 协程）：
        // 每条新建会话起一个承载循环（`proxy::serve_udp_session`）。
        let max_dgram = conn.max_datagram_size().unwrap_or(1200);
        tokio::spawn(async move {
            crate::quic::server::run_udp_manager(&conn, idle, &mgr, session_rx, max_dgram).await;
        });
    }
}

/// 已解析的认证请求头（只保留参考用到的字段）。
struct RequestHead {
    method: Option<String>,
    host: Option<String>,
    path: Option<String>,
    /// `Hysteria-Auth` 请求头值（机密，不进入任何错误文本）。
    auth: Option<String>,
    /// `Hysteria-CC-RX`（客户端下行带宽；解析失败按 0，对齐参考
    /// `strconv.ParseUint` 忽略错误）。
    cc_rx: u64,
}

impl RequestHead {
    fn from_fields(fields: &[HeaderField]) -> Self {
        let take = |name: &[u8]| -> Option<String> {
            fields
                .iter()
                .find(|f| f.name.as_slice() == name)
                .map(|f| String::from_utf8_lossy(&f.value).into_owned())
        };
        let cc_rx = take(COMMON_HEADER_CC_RX.as_bytes())
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        Self {
            method: take(b":method"),
            host: take(b":authority").or_else(|| take(b"host")),
            path: take(b":path"),
            auth: take(REQUEST_HEADER_AUTH.as_bytes()),
            cc_rx,
        }
    }

    /// 对齐 `r.Method == POST && r.Host == URLHost && r.URL.Path == URLPath`。
    fn is_auth_request(&self) -> bool {
        self.method.as_deref() == Some("POST")
            && self.host.as_deref() == Some(URL_HOST)
            && self.path.as_deref() == Some(URL_PATH)
    }
}

/// 读对端流首个 varint（接受非最短编码，对齐 `quicvarint.Read`）。
async fn read_first_varint(recv: &mut RecvStream) -> Result<u64, AuthError> {
    let mut probe = Vec::with_capacity(8);
    loop {
        let mut byte = [0u8; 1];
        recv.read_exact(&mut byte)
            .await
            .map_err(|e| AuthError::Protocol(format!("读取流首字节失败: {e}")))?;
        probe.push(byte[0]);
        if let Ok((value, _)) = varint::decode(&probe) {
            return Ok(value);
        }
        if probe.len() == 8 {
            return Err(AuthError::Protocol("帧类型 varint 非法".into()));
        }
    }
}

/// 从请求流上读一帧，返回其载荷（对齐 quic-go `http3` 的 HEADERS 帧读取：
/// 未知帧跳过载荷，只认 HEADERS）。
///
/// 读载荷时用 `read_chunk`（而非 `read_exact`）：顺路把独占的接收缓冲
/// 转成一次性发送种子交给 `seeds`（Bytes 桥，见 `h3_auth` 模块文档），
/// 供服务端 UDP 回程发送使用。
async fn read_frame_payload(
    recv: &mut RecvStream,
    seeds: &mut Vec<crate::h3_auth::SeedFiller>,
) -> Result<Vec<u8>, AuthError> {
    // 调用方已读走 HEADERS 帧类型，这里只读长度与载荷。
    let len = read_first_varint(recv).await?;
    let len = usize::try_from(len).map_err(|_| AuthError::Protocol("帧长度超出 usize".into()))?;
    if len > MAX_RESPONSE_BYTES {
        return Err(AuthError::Protocol("请求帧超出大小上限".into()));
    }
    let mut payload = Vec::with_capacity(len);
    while payload.len() < len {
        let Some(chunk) = recv
            .read_chunk(usize::MAX, true)
            .await
            .map_err(|e| AuthError::Protocol(format!("读取帧载荷失败: {e}")))?
        else {
            return Err(AuthError::Protocol(
                "读取帧载荷失败: stream finished early".into(),
            ));
        };
        payload.extend_from_slice(&chunk.bytes);
        if let Some(seed) = crate::h3_auth::seed_filler_from_chunk(chunk) {
            seeds.push(seed);
        }
    }
    Ok(payload)
}

/// 写一条响应：HEADERS 帧（单个字段区块）。
async fn write_headers(send: &mut SendStream, fields: &[HeaderField]) -> Result<(), AuthError> {
    let block = qpack::encode_field_block(fields);
    let mut frame = Vec::with_capacity(block.len() + 9);
    varint::append(FRAME_HEADERS, &mut frame)?;
    varint::append(block.len() as u64, &mut frame)?;
    frame.extend_from_slice(&block);
    send.write_all(&frame).await?;
    send.finish()?;
    Ok(())
}

/// 服务端 `HeaderField` 便捷构造。
fn field(name: &str, value: &str) -> HeaderField {
    HeaderField {
        name: name.as_bytes().to_vec(),
        value: value.as_bytes().to_vec(),
    }
}

/// 认证成功响应（对齐 hub.go）：233 + `Hysteria-UDP` / `Hysteria-CC-RX` /
/// `Hysteria-Padding`。
async fn respond_auth_ok(
    send: &mut SendStream,
    udp_enabled: bool,
    brutal_down: u64,
) -> Result<(), AuthError> {
    let padding = random_padding(Range::AUTH_RESPONSE);
    let fields = vec![
        field(":status", &STATUS_AUTH_OK.to_string()),
        field(RESPONSE_HEADER_UDP_ENABLED, &udp_enabled.to_string()),
        field(COMMON_HEADER_CC_RX, &brutal_down.to_string()),
        field(COMMON_HEADER_PADDING, &padding),
    ];
    write_headers(send, &fields).await
}

/// masquerade 缺省处理器：`http.NotFoundHandler()` 的 404（对齐 hub.go
/// `case "", "404"`）。认证失败一律走此路径（fail-closed）。
async fn respond_not_found(send: &mut SendStream) -> Result<(), AuthError> {
    let fields = vec![field(":status", &STATUS_NOT_FOUND.to_string())];
    write_headers(send, &fields).await
}
