//! VLESS Vision 上行解包原语：`XtlsUnpadding` 的逐点对齐实现。
//!
//! 从 [`super::server`] 拆出以保持单文件 ≤400 行（软约束）。直接作用于
//! [`InboundState`] 的 `remaining_*` / `current_command` 字段（参考把 `s.Inbound`
//! 指针传进 `XtlsUnpadding`，避免状态副本不同步）。
//!
//! 本模块不含 `unsafe`。

use super::client::InboundState;
use super::framing::PADDING_OVERHEAD;

/// 参考 `XtlsUnpadding`：一次解包后读到的命令（诊断用，不含密钥）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// `CommandPaddingContinue`：padding 未结束。
    Continue,
    /// `CommandPaddingEnd`：最后一帧 padding 块。
    End,
    /// `CommandPaddingDirect`：`EnableXtls` 下最后一次 padding，随后直拷贝。
    Direct,
    /// 参考未知命令（`currentCommand` 既非 0/1/2）。
    Unknown(i32),
}

impl Command {
    /// 由 `current_command` 字节映射（0/1/2，其余为 [`Command::Unknown`]）。
    pub fn from_raw(raw: i32) -> Self {
        match raw {
            0 => Command::Continue,
            1 => Command::End,
            2 => Command::Direct,
            other => Command::Unknown(other),
        }
    }
}

/// 参考 `XtlsUnpadding`：只暴露服务端上行所需的 `isUplink=true` 分支；客户端下行读在
/// [`super::client::VisionClient::decode_downlink`] 内走 `Outbound` 状态组。
pub trait Unpad {
    /// 初始态判据：三个 `remaining_*` 均为 -1。
    fn is_initial(&self) -> bool;

    /// 参考 `XtlsUnpadding` 的逐点对齐实现：从 `wire` 里按块切出明文。
    ///
    /// - 初始态且 `wire.len() >= 21` 且前 16 字节等于 `uuid` → 吃掉 16 字节 UUID 头，
    ///   `remaining_command = 5`；否则**原样返回整段**（不进 padding 解析）。
    /// - 命令头 5 字节（命令 + BE16 内容长 + BE16 padding 长）按 `remaining_command`
    ///   5→1 逐字节消费。
    /// - 内容 / padding 按剩余量切分，块结束（三个剩余量均 ≤ 0）后：`current_command == 0`
    ///   则继续读下一块头（`remaining_command = 5`），否则回到初始态并在有剩余字节时
    ///   原样吐出（参考注释「shouldn't happen」）。
    fn unpad(&mut self, wire: &[u8], uuid: &[u8; 16], out: &mut Vec<u8>);
}

impl Unpad for InboundState {
    fn is_initial(&self) -> bool {
        self.remaining_command == -1 && self.remaining_content == -1 && self.remaining_padding == -1
    }

    fn unpad(&mut self, wire: &[u8], uuid: &[u8; 16], out: &mut Vec<u8>) {
        let mut pos = 0usize;
        if self.is_initial() {
            if wire.len() >= PADDING_OVERHEAD && wire[..16] == uuid[..] {
                pos += 16;
                self.remaining_command = 5;
            } else {
                out.extend_from_slice(wire);
                return;
            }
        }
        while pos < wire.len() {
            if self.remaining_command > 0 {
                let data = wire[pos];
                pos += 1;
                match self.remaining_command {
                    5 => self.current_command = i32::from(data),
                    4 => self.remaining_content = i32::from(data) << 8,
                    3 => self.remaining_content |= i32::from(data),
                    2 => self.remaining_padding = i32::from(data) << 8,
                    1 => self.remaining_padding |= i32::from(data),
                    _ => {}
                }
                self.remaining_command -= 1;
            } else if self.remaining_content > 0 {
                let mut len = self.remaining_content as usize;
                if wire.len() - pos < len {
                    len = wire.len() - pos;
                }
                out.extend_from_slice(&wire[pos..pos + len]);
                pos += len;
                self.remaining_content -= len as i32;
            } else {
                let mut len = self.remaining_padding as usize;
                if wire.len() - pos < len {
                    len = wire.len() - pos;
                }
                pos += len;
                self.remaining_padding -= len as i32;
            }
            if self.remaining_command <= 0
                && self.remaining_content <= 0
                && self.remaining_padding <= 0
            {
                if self.current_command == 0 {
                    self.remaining_command = 5;
                } else {
                    self.remaining_command = -1;
                    self.remaining_content = -1;
                    self.remaining_padding = -1;
                    if pos < wire.len() {
                        out.extend_from_slice(&wire[pos..]);
                    }
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: [u8; 16] = [0x33; 16];

    #[test]
    fn unpad_roundtrips_single_continue_block_with_uuid() {
        let mut block = UUID.to_vec();
        block.push(0);
        block.extend_from_slice(&5u16.to_be_bytes());
        block.extend_from_slice(&0u16.to_be_bytes());
        block.extend_from_slice(b"hello");
        let mut state = InboundState::default();
        let mut out = Vec::new();
        state.unpad(&block, &UUID, &mut out);
        assert_eq!(out, b"hello");
        assert_eq!(state.remaining_command, 5);
        assert_eq!(state.current_command, 0);
    }

    #[test]
    fn unpad_returns_raw_when_first_block_lacks_uuid() {
        let wire = b"not a vision block at all";
        let mut state = InboundState::default();
        let mut out = Vec::new();
        state.unpad(wire, &UUID, &mut out);
        assert_eq!(out, wire);
        assert!(state.is_initial());
    }

    #[test]
    fn unpad_strips_padding_and_ends_on_end_command() {
        let mut wire = UUID.to_vec();
        wire.push(0);
        wire.extend_from_slice(&3u16.to_be_bytes());
        wire.extend_from_slice(&4u16.to_be_bytes());
        wire.extend_from_slice(b"abc");
        wire.extend_from_slice(&[0u8; 4]);
        wire.push(1);
        wire.extend_from_slice(&0u16.to_be_bytes());
        wire.extend_from_slice(&2u16.to_be_bytes());
        wire.extend_from_slice(&[0u8; 2]);
        let mut state = InboundState::default();
        let mut out = Vec::new();
        state.unpad(&wire, &UUID, &mut out);
        assert_eq!(out, b"abc");
        assert!(state.is_initial());
        assert_eq!(state.current_command, 1);
    }

    #[test]
    fn command_maps_raw_bytes() {
        assert_eq!(Command::from_raw(0), Command::Continue);
        assert_eq!(Command::from_raw(1), Command::End);
        assert_eq!(Command::from_raw(2), Command::Direct);
        assert_eq!(Command::from_raw(9), Command::Unknown(9));
    }
}
