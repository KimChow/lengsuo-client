//! Hysteria2 UDP 中继报文 `UDPMessage` 的字节层编解码（不是完整协议服务）。
//!
//! 线上格式与参考实现逐字节一致（apernet/hysteria 完整 commit
//! `ca8fbd874fd6ca82413948de6dc5924405e103e1`，`core/internal/protocol/proxy.go`
//! 第 151-225 行的 `UDPMessage.Serialize` / `ParseUDPMessage`）：
//!
//! ```text
//! Session ID     (uint32, 大端定宽)
//! Packet ID      (uint16, 大端定宽)
//! Fragment ID    (uint8)
//! Fragment count (uint8)
//! Address length (QUIC varint，编码用规范最短形式)
//! Address        (原字节，长度 1..=2048)
//! Data...        (至少 1 字节，贪心取完剩余输入)
//! ```
//!
//! 头前 8 字节是定宽大端整数，不是 varint，因此 `0xFF`/`0xC0` 之类的值不会
//! 改变字段宽度。地址长度上限沿用参考实现的 `MaxMessageLength = 2048`
//! （与本 crate `tcp::MAX_MESSAGE_LENGTH` 同源同值）。地址按**原字节**保留：
//! Go 侧只把地址当字符串切片，不做 UTF-8 或 NUL 校验，本 codec 同样不校验，
//! 解析出的 `address` 直接借用输入缓冲，不复制也不改写。
//!
//! `fragID` / `fragCount` 也不由本 codec 判定合法性（例如 `fragID >= fragCount`、
//! `fragCount == 0` 之类只由分片重组层负责），这里只透传 0..=255，
//! 保证重组层能看到原始字段。
//!
//! 报文不是自定界的：`Data` 吃掉地址之后的全部剩余字节，因此 `decode` 消费整个
//! 输入切片、不返回消耗长度（与 `tcp.rs` / `connect_udp.rs` 的帧不同，那两个格式
//! 帧后还要留字节给载荷）。参考实现的 `len(bs) <= int(lAddr)`（要求地址之后至少
//! 1 字节数据）在这里归一为 [`Error::Truncated`]，`need` 给出「地址末端 + 1 字节
//! 数据」这个最小可完成长度。
//!
//! 所有失败 fail-closed：截断、varint 不足、空地址、地址超长、空数据一律报错，
//! 调用方必须丢弃该报文，不得继续复用未对齐的字节。错误只携带长度与取值元数据，
//! 不输出地址或数据内容；`Debug` 同样只输出长度（地址是用户连接元数据）。
//!
//! 本模块只是消息层：QUIC 连接与 datagram 中继、HTTP/3 伪装与认证、分片重组、
//! Salamander 混淆都不在这里。与原生 apernet/hysteria 服务端的真实互通尚未验收，
//! 因此不宣称兼容；测试见 `tests/udp_go_vectors.rs`（黄金字节由参考 Go 代码
//! 逐字抄录实现后**实跑**生成，覆盖 IPv4/IPv6/域名与长度边界）与
//! `tests/udp_reference.rs`（结构、错误与边界用例）。
//!
//! 另注：本 crate 的 `connect_udp.rs`（CONNECT-UDP capsule，帧类型 0x402）是本仓
//! 自造的消息层，与本模块的官方 `UDPMessage` 是两种不同格式，不能互相替代，
//! 也不计入 Hysteria2 官方兼容范围。

use crate::frame::{check_len, read_varint};
use crate::tcp::MAX_MESSAGE_LENGTH;
use crate::varint;
use crate::Error;

/// UDP 报文编解码错误：与本 crate 其它模块共用同一 fail-closed 错误枚举。
pub type UdpError = Error;

/// 地址长度上限，等于参考实现的 `MaxMessageLength`（`proxy.go` 第 20 行）。
pub const MAX_ADDRESS_LENGTH: u64 = MAX_MESSAGE_LENGTH;

/// 头部固定字节数：4 (session) + 2 (packet) + 1 (fragID) + 1 (fragCount)。
pub const HEADER_LEN: usize = 8;

/// Hysteria2 UDP 中继报文。字段全部借用输入切片，codec 不复制地址与数据。
///
/// 不派生 `Debug`（改用下方手写脱敏实现）：地址与数据是用户流量内容，
/// 受隐私策略约束，只输出长度元数据。
#[derive(Clone, PartialEq, Eq)]
pub struct UdpMessage<'a> {
    /// 会话 ID，同一 QUIC 连接内区分 UDP 会话。
    pub session_id: u32,
    /// 报文 ID，用于分片归组与去重。
    pub packet_id: u16,
    /// 本片序号；语义由分片重组层判定，本 codec 只透传。
    pub fragment_id: u8,
    /// 总分片数；语义由分片重组层判定，本 codec 只透传。
    pub fragment_count: u8,
    /// 目标地址的原始字节（`host:port`，可能不是合法 UTF-8），1..=2048 字节。
    pub address: &'a [u8],
    /// UDP 载荷，至少 1 字节，占满地址之后的剩余输入。
    pub data: &'a [u8],
}

/// 手写 `Debug`：只输出长度与整数字段，不输出地址或数据内容。
impl std::fmt::Debug for UdpMessage<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpMessage")
            .field("session_id", &self.session_id)
            .field("packet_id", &self.packet_id)
            .field("fragment_id", &self.fragment_id)
            .field("fragment_count", &self.fragment_count)
            .field("address_len", &self.address.len())
            .field("data_len", &self.data.len())
            .finish()
    }
}

impl<'a> UdpMessage<'a> {
    /// 解析整条 UDP 报文。输入必须正好是一完整报文（数据字段贪心取完尾部字节）。
    ///
    /// 检查顺序与参考实现相同：头字段 → 地址长度 varint → 长度区间 →
    /// 「地址之后至少 1 字节」。地址按原字节返回，不做 UTF-8/NUL 校验；
    /// `fragID` / `fragCount` 不做语义校验。
    pub fn decode(input: &'a [u8]) -> Result<Self, UdpError> {
        let header = input.get(..HEADER_LEN).ok_or(Error::Truncated {
            need: HEADER_LEN,
            got: input.len(),
        })?;
        let session_id =
            u32::from_be_bytes(header[..4].try_into().expect("切片长度已由 get(..4) 确认"));
        let packet_id =
            u16::from_be_bytes(header[4..6].try_into().expect("切片长度已由 get(..6) 确认"));
        let fragment_id = header[6];
        let fragment_count = header[7];

        let (addr_len, offset) = read_varint(input, HEADER_LEN)?;
        check_len("address", addr_len, 1, MAX_ADDRESS_LENGTH)?;
        let addr_len_usize = usize::try_from(addr_len).expect("上游已限制 <= 2048");
        let addr_end = offset.saturating_add(addr_len_usize);
        // 参考实现用 `len(bs) <= int(lAddr)`：地址之后必须还有至少 1 字节数据。
        if input.len() <= addr_end {
            return Err(Error::Truncated {
                need: addr_end.saturating_add(1),
                got: input.len(),
            });
        }
        let address = input.get(offset..addr_end).ok_or(Error::Truncated {
            need: addr_end,
            got: input.len(),
        })?;
        Ok(UdpMessage {
            session_id,
            packet_id,
            fragment_id,
            fragment_count,
            address,
            data: &input[addr_end..],
        })
    }

    /// 校验字段并返回完整报文字节数；超限或空字段在写入任何字节前失败。
    pub fn encoded_len(&self) -> Result<usize, UdpError> {
        check_len("address", self.address.len() as u64, 1, MAX_ADDRESS_LENGTH)?;
        check_len("data", self.data.len() as u64, 1, u64::MAX)?;
        Ok(HEADER_LEN
            + varint::size(self.address.len() as u64)?
            + self.address.len()
            + self.data.len())
    }

    /// 编码完整报文；地址长度使用规范最短 varint（不保留非最短形式）。
    pub fn encode(&self) -> Result<Vec<u8>, UdpError> {
        let total = self.encoded_len()?;
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(&self.session_id.to_be_bytes());
        bytes.extend_from_slice(&self.packet_id.to_be_bytes());
        bytes.push(self.fragment_id);
        bytes.push(self.fragment_count);
        varint::append(self.address.len() as u64, &mut bytes)?;
        bytes.extend_from_slice(self.address);
        bytes.extend_from_slice(self.data);
        Ok(bytes)
    }
}
