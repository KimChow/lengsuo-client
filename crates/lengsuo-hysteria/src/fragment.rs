//! Hysteria2 UDP 分片**重组**（defrag）状态机。
//!
//! 语义逐条对齐 apernet/hysteria 完整 commit
//! `ca8fbd874fd6ca82413948de6dc5924405e103e1` 的
//! `core/internal/frag/frag.go` 第 36-80 行 `Defragger.Feed`（字段布局见同 commit
//! `core/internal/protocol/proxy.go` 的 `UDPMessage`）。本模块**不复制第二套
//! codec**，也不重新解释线上字节：分片描述符一律取自 [`crate::udp::UdpMessage`]。
//!
//! 与参考实现逐条对应的 `Feed` 语义（行号指参考 `frag.go`）：
//! 1. `FragCount <= 1` ⇒ 原样交回该消息，**不进缓冲、不改写字段**（第 48-50 行）。
//!    参考用的是 `<=` 而不是 `==`，所以 `FragCount == 0` 也走这条直通路径，
//!    且 `FragID >= FragCount` 的非法组合在直通时不会被判非法；本实现同样如此。
//! 2. `FragID >= FragCount` ⇒ 丢弃本片（参考注释 `// wtf is this?`，第 51-54 行）。
//! 3. `PacketID` 变化**或** `FragCount` 与当前缓冲的片数不等 ⇒ 丢弃旧状态、以本片
//!    重开（第 55-61 行）。因此同一时刻只维持**一个**报文的半截状态；
//!    未收齐的半截会被后来者直接顶掉。
//! 4. 同一报文内 `FragID` 槽位已占用（重复片）⇒ 不覆盖内容、不增加计数（第 62 行）。
//! 5. 计数达到 `FragCount` ⇒ 按 `FragID` 升序拼接各片载荷，交回一条
//!    `FragID = 0 / FragCount = 1` 的完整消息；会话 ID、报文 ID 与地址取自
//!    **最后到达**的那一片（第 66-77 行：参考改写并返回入参 `m`，字段即 `m` 的）。
//! 6. 其余情况交回「未产生完整报文」，对应参考的 `return nil`（第 79 行）。
//! 7. 交付完整报文后缓冲**不清空**，因此同一分片集的任何再到达都按第 4 条被忽略，
//!    不会重复交付。
//!
//! 内存是天然有界的：缓冲只有一格，槽数 `FragCount ∈ [2, 255]`（wire 上是
//! `uint8`），所以无需策略上限或期限。非法输入一律 fail-closed：本片被丢弃，
//! 调用方不得凭半截数据继续；没有「按明文继续处理」之类的回退。
//!
//! 借用寿命：参考在槽位里保留 `*protocol.UDPMessage` 指针，载荷不复制。Rust 侧
//! 同样保留输入借用，因此 [`Defragger<'a>`] 的寿命参数绑定到喂入分片的字节缓冲：
//! 调用方必须让这些字节活到该报文收齐或状态被替换。这是同一事实的类型化表达，
//! 不是额外限制。
//!
//! 与参考的差异只在**表示层**，不改改变换语义（如实记录）：
//! - 参考在直通与收齐两条路径都返回**同一个入参指针**，收齐时还**就地改写**最后
//!   一片的 `Data`/`FragID`/`FragCount`。Rust 侧 `feed` 借用入参、不改写它，改为
//!   返回新建的 [`CompleteMessage`]：字段值与参考改写后的入参逐一相同（载荷是
//!   新分配的拼接副本，参考也是 `make` 新切片），但调用方不能依赖指针同一性。
//!   参考 `frag_test.go` 用 `reflect.DeepEqual` 比对内容，不涉及指针，因此该差异
//!   不影响与参考用例表的逐项一致。
//! - 状态判据写作 `m.packet_id != self.packet_id || count != self.slots.len()`，
//!   与参考第 55 行同形；空态（`slots.len() == 0`）由第二个条件天然覆盖
//!   （进入该判断时 `count >= 2`），因此首片总是走重开分支，与参考一致。
//! - 参考第 66-77 行的 `for _, frag := range d.frags` 在槽位齐全前不会执行，故
//!   参考不存在 `frag` 为 `nil` 的解引用路径；本实现同样只在 `received == count`
//!   时拼接，此时所有槽位必为非空（`.flatten()` 只是把这一不变量转成 Rust 写法，
//!   不掩盖任何半截状态）。
//!
//! 本模块还含发送侧 [`frag_udp_message`]（参考 `FragUDPMessage`，判据同上），
//! 以及它依赖的分片条数上限 [`MAX_FRAGMENTS`]。
//!
//! 除状态机与切片函数之外的部分仍未实现／未验收：QUIC 连接与 datagram 中继、
//! HTTP/3 伪装与认证、UDP 中继调度、Salamander 混淆、以及与原生
//! apernet/hysteria 服务端的真实互通。测试见 `tests/fragment_reference.rs`
//! （参考 `frag_test.go` 用例表的逐条移植，含 `FragUDPMessage` 三例）与
//! `tests/fragment_reassembly.rs`（乱序、重复、丢弃、`uint8` 上限与防御分支、
//! 以及切片→重组的往返一致性）。

use crate::udp::UdpMessage;
use std::borrow::Cow;

/// 分片产出条数的硬上限：wire 上 `fragCount` 是 `uint8`（见 `udp.rs` 的字段布局），
/// 因此单报文最多 255 片；`fragID` 同样只有 8 位。
pub const MAX_FRAGMENTS: usize = u8::MAX as usize;

/// 分片（发送侧）失败。与 [`crate::Error`]（字节层解析失败）分开：这里是
/// 「按给定上限无法合法分片」的策略判断，文本只携带长度与计数元数据。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FragmentError {
    #[error("单片长度上限 {max_size} 不足以容纳 {header_len} 字节头部再加 1 字节载荷")]
    MaxSizeTooSmall { max_size: usize, header_len: usize },

    #[error("载荷需要 {needed} 片，超过 uint8 分片计数的上限 {max}: 报文过长")]
    TooManyFragments { needed: usize, max: usize },

    #[error("消息长度检查失败：{0}")]
    Message(#[from] crate::Error),
}

/// 按参考 `frag.go` 第 7-34 行 `FragUDPMessage` 的判据把一条报文切成分片序列。
///
/// 与参考逐条对应：
/// 1. `Size() <= max_size` ⇒ 返回**只含原报文本身**的单元素序列，不改写
///    `fragID` / `fragCount`（参考第 8-10 行；`Size()` 在本 crate 等于
///    [`UdpMessage::encoded_len`]，头部长度等于 `Size() - data.len()`）。
/// 2. 否则 `max_payload = max_size - header_size`；`max_payload <= 0` ⇒ 失败
///    （参考返回 `nil`，本实现返回 [`FragmentError::MaxSizeTooSmall`]）。
/// 3. 条数按**向上取整** `(len(data) + max_payload - 1) / max_payload` 得出
///    （参考第 18 行的 round-up 判据）；每片 `fragID` 从 0 递增、`fragCount`
///    全部等于该条数，载荷是原 `data` 的连续切片，最后一片取剩余字节。
/// 4. 条数 `> MAX_FRAGMENTS` ⇒ 失败（见下方偏差说明）。
///
/// 分片只借用原载荷，不复制字节；返回的每个元素其余字段与会话报文一致，因此
/// 各片地址相同 —— 参考也是如此（`frag := *m` 的浅拷贝）。
///
/// 与参考的偏差：Go 用 `uint8(...)` 把向上取整的结果**静默截断**，条数一旦超过
/// 255，`frags[fragID]` 越界直接 panic。本实现改为在写入任何字节前 fail-closed
/// 返回 [`FragmentError::TooManyFragments`]：既消除 panic 路径，也不产出
/// `fragCount` 与实际片数不一致的畸形报文。其余行为与参考一致。
pub fn frag_udp_message<'a>(
    m: &UdpMessage<'a>,
    max_size: usize,
) -> Result<Vec<UdpMessage<'a>>, FragmentError> {
    let total = m.encoded_len()?;
    if total <= max_size {
        return Ok(vec![m.clone()]);
    }
    let header_len = total - m.data.len();
    let max_payload = max_size.saturating_sub(header_len);
    if max_payload == 0 {
        return Err(FragmentError::MaxSizeTooSmall {
            max_size,
            header_len,
        });
    }
    let needed = m.data.len().div_ceil(max_payload);
    if needed > MAX_FRAGMENTS {
        return Err(FragmentError::TooManyFragments {
            needed,
            max: MAX_FRAGMENTS,
        });
    }
    let count = u8::try_from(needed).expect("上游已确认 <= MAX_FRAGMENTS");
    let mut frags = Vec::with_capacity(needed);
    let mut offset = 0;
    let mut frag_id = 0u8;
    while offset < m.data.len() {
        let end = offset.saturating_add(max_payload).min(m.data.len());
        frags.push(UdpMessage {
            session_id: m.session_id,
            packet_id: m.packet_id,
            fragment_id: frag_id,
            fragment_count: count,
            address: m.address,
            data: &m.data[offset..end],
        });
        offset = end;
        frag_id += 1;
    }
    Ok(frags)
}

/// 一次 [`Defragger::feed`] 的结果，与参考 `Feed` 的两种出口一一对应。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefragOutput<'a> {
    /// 参考 `Feed` 返回非 `nil`：一条完整、可直接上抛的报文。包含两种来路——
    /// 未分片消息原样直通，以及分片收齐后的拼装结果。
    Complete(CompleteMessage<'a>),

    /// 参考 `Feed` 返回 `nil`：本次输入没有产生完整报文。三种来路在参考里
    /// 不可区分（本片已登记等待其余分片／`fragID >= fragCount` 非法片被丢弃／
    /// 重复片被忽略），本实现同样不区分。
    Pending,
}

/// [`DefragOutput::Complete`] 携带的完整报文。
///
/// 分片描述符一律按原值保留，只在收齐时才归一为 `0 / 1`；载荷在直通时借用输入、
/// 在收齐时是拼接副本。不派生 `Debug`（见下方手写脱敏实现）。
#[derive(Clone, PartialEq, Eq)]
pub struct CompleteMessage<'a> {
    /// 会话 ID，取自交付的那一片（参考行为：最后到达的片）。
    pub session_id: u32,
    /// 报文 ID，取自交付的那一片。
    pub packet_id: u16,
    /// 分片序号：直通时保留输入原值，收齐拼装后为 `0`。
    pub fragment_id: u8,
    /// 分片总数：直通时保留输入原值（`<= 1`），收齐拼装后为 `1`。
    pub fragment_count: u8,
    /// 目标地址原始字节，取自交付的那一片（参考行为：最后到达的片）。
    /// 与 `udp.rs` 同策略：不校验 UTF-8／NUL，各片地址是否一致由上层负责。
    pub address: &'a [u8],
    /// 载荷：直通时是原切片的借用，收齐时是按 `fragID` 升序拼接的副本。
    pub data: Cow<'a, [u8]>,
}

/// 手写 `Debug`：只输出整数与长度元数据，不输出地址或载荷内容。
impl std::fmt::Debug for CompleteMessage<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompleteMessage")
            .field("session_id", &self.session_id)
            .field("packet_id", &self.packet_id)
            .field("fragment_id", &self.fragment_id)
            .field("fragment_count", &self.fragment_count)
            .field("address_len", &self.address.len())
            .field("data_len", &self.data.len())
            .finish()
    }
}

impl<'a> CompleteMessage<'a> {
    /// 借用本结果构造 `UdpMessage`，分片描述符按本结果的原值透传（收齐拼装是
    /// `0 / 1`；直通则保留输入的描述符，可能是 `<= 1` 的任意组合）。
    ///
    /// 重组层与消息层共用同一份字段定义，不另立类型。
    #[must_use]
    pub fn to_udp_message(&self) -> UdpMessage<'_> {
        UdpMessage {
            session_id: self.session_id,
            packet_id: self.packet_id,
            fragment_id: self.fragment_id,
            fragment_count: self.fragment_count,
            address: self.address,
            data: self.data.as_ref(),
        }
    }

    /// 完整报文的线上字节，等价于 `to_udp_message().encode()`。
    pub fn encode(&self) -> Result<Vec<u8>, crate::Error> {
        self.to_udp_message().encode()
    }
}

/// UDP 分片重组器：只维持**一个**报文的半截状态，与参考 `Defragger` 同形。
///
/// 寿命参数 `'a` 是槽位对输入字节的借用寿命（参考保留指针的等价表达）。
pub struct Defragger<'a> {
    /// 参考 `d.pktID`：当前缓冲所属报文的 ID。
    packet_id: u16,
    /// 参考 `d.frags`：长度等于当前报文的 `fragCount`，下标即 `fragID`。
    slots: Vec<Option<UdpMessage<'a>>>,
    /// 参考 `d.count`：已登记的分片数。
    received: usize,
    /// 参考 `d.size`：已登记分片的载荷字节总数。
    bytes: usize,
}

/// 手写 `Debug`：只输出状态元数据，不输出任何分片内容。
impl std::fmt::Debug for Defragger<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Defragger")
            .field("packet_id", &self.packet_id)
            .field("fragment_count", &self.slots.len())
            .field("received", &self.received)
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl Default for Defragger<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Defragger<'a> {
    /// 新建空状态，等价于参考的 `&Defragger{}` 零值。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            packet_id: 0,
            slots: Vec::new(),
            received: 0,
            bytes: 0,
        }
    }

    /// 喂入一片报文，语义与参考 `frag.go` 的 `Feed` 逐条对应（见模块头）。
    #[must_use]
    pub fn feed(&mut self, m: &UdpMessage<'a>) -> DefragOutput<'a> {
        // 1. 未分片（含 `fragCount == 0` 怪癖）：原样交回，不进缓冲、不改写字段。
        if m.fragment_count <= 1 {
            return DefragOutput::Complete(CompleteMessage {
                session_id: m.session_id,
                packet_id: m.packet_id,
                fragment_id: m.fragment_id,
                fragment_count: m.fragment_count,
                address: m.address,
                data: Cow::Borrowed(m.data),
            });
        }
        // 2. `fragID >= fragCount` 的非法片丢弃。本条同时保证后续按 `fragID` 索引
        //    槽位必然在界内（进入下方分支时 `slots.len() == fragCount`），
        //    与参考在同一处获得的不变量相同。
        let count = usize::from(m.fragment_count);
        let id = usize::from(m.fragment_id);
        if id >= count {
            return DefragOutput::Pending;
        }
        // 3. `packetID` 变化或 `fragCount` 与缓冲片数不等：丢弃旧状态，以本片重开。
        //    空态（`slots.len() == 0`）由第二个条件天然覆盖，因为此处 `count >= 2`。
        if m.packet_id != self.packet_id || count != self.slots.len() {
            self.packet_id = m.packet_id;
            self.slots = vec![None; count];
            self.slots[id] = Some(m.clone());
            self.received = 1;
            self.bytes = m.data.len();
            return DefragOutput::Pending;
        }
        // 4. 槽位已占用 ⇒ 重复片：不覆盖、不计数，直接落空。
        if self.slots[id].is_none() {
            self.slots[id] = Some(m.clone());
            self.received += 1;
            self.bytes += m.data.len();
            // 5. 分片收齐 ⇒ 按 `fragID` 升序拼接，交回 `0 / 1` 的完整报文。
            if self.received == count {
                let mut data = Vec::with_capacity(self.bytes);
                for frag in self.slots.iter().flatten() {
                    data.extend_from_slice(frag.data);
                }
                return DefragOutput::Complete(CompleteMessage {
                    session_id: m.session_id,
                    packet_id: m.packet_id,
                    fragment_id: 0,
                    fragment_count: 1,
                    address: m.address,
                    data: Cow::Owned(data),
                });
            }
        }
        // 6. 参考的 `return nil`。缓冲保持不动（第 7 条：交付后也不清空）。
        DefragOutput::Pending
    }

    /// 参考 `d.pktID` 的只读视图：当前缓冲所属报文 ID。空态为 `0`。
    #[must_use]
    pub const fn current_packet_id(&self) -> u16 {
        self.packet_id
    }

    /// 参考 `len(d.frags)` 的只读视图：当前缓冲期望的分片条数。空态为 `0`。
    #[must_use]
    pub fn current_fragment_count(&self) -> usize {
        self.slots.len()
    }

    /// 参考 `d.count` 的只读视图：已登记的分片条数。
    #[must_use]
    pub const fn current_fragments_received(&self) -> usize {
        self.received
    }

    /// 参考 `d.size` 的只读视图：已登记分片的载荷字节数。
    #[must_use]
    pub const fn current_bytes(&self) -> usize {
        self.bytes
    }

    /// 缓冲是否为空态（未登记任何半截报文）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
}
