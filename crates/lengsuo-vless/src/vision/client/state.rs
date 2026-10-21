//! 流量状态模型：`InboundState` / `OutboundState` / [`TrafficState`]。
//!
//! 从父模块拆出以保持单文件 ≤400 行（软约束）。状态字段逐条对齐参考
//! `proxy.go` 的 `InboundState` / `OutboundState` / `TrafficState`。

/// 参考 `InboundState`（本客户端不使用，保留完整状态模型以便将来做入站侧）。
#[derive(Debug, Clone, Copy)]
pub struct InboundState {
    pub within_padding_buffers: bool,
    pub uplink_reader_direct_copy: bool,
    pub remaining_command: i32,
    pub remaining_content: i32,
    pub remaining_padding: i32,
    pub current_command: i32,
    pub is_padding: bool,
    pub downlink_writer_direct_copy: bool,
}

impl Default for InboundState {
    fn default() -> Self {
        Self {
            within_padding_buffers: true,
            uplink_reader_direct_copy: false,
            remaining_command: -1,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
            is_padding: true,
            downlink_writer_direct_copy: false,
        }
    }
}

/// 参考 `OutboundState`；客户端上行写 / 下行读都落在这里。
#[derive(Debug, Clone, Copy)]
pub struct OutboundState {
    pub within_padding_buffers: bool,
    pub downlink_reader_direct_copy: bool,
    pub remaining_command: i32,
    pub remaining_content: i32,
    pub remaining_padding: i32,
    pub current_command: i32,
    pub is_padding: bool,
    pub uplink_writer_direct_copy: bool,
}

impl Default for OutboundState {
    fn default() -> Self {
        Self {
            within_padding_buffers: true,
            downlink_reader_direct_copy: false,
            remaining_command: -1,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
            is_padding: true,
            uplink_writer_direct_copy: false,
        }
    }
}

/// 参考 `NewTrafficState`：单连接上下行共享的流量状态。
#[derive(Debug, Clone, Copy)]
pub struct TrafficState {
    pub user_uuid: [u8; 16],
    pub number_of_packet_to_filter: i32,
    pub enable_xtls: bool,
    pub is_tls12_or_above: bool,
    pub is_tls: bool,
    pub cipher: u16,
    pub remaining_server_hello: i32,
    pub inbound: InboundState,
    pub outbound: OutboundState,
}

impl TrafficState {
    pub fn new(user_uuid: [u8; 16]) -> Self {
        Self {
            user_uuid,
            number_of_packet_to_filter: 8,
            enable_xtls: false,
            is_tls12_or_above: false,
            is_tls: false,
            cipher: 0,
            remaining_server_hello: -1,
            inbound: InboundState::default(),
            outbound: OutboundState::default(),
        }
    }
}
