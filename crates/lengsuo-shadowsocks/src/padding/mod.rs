//! Chunked padding codec, transcribed from the reference's padding format.
//!
//! # Provenance (read before changing anything here)
//!
//! The task brief listed `common/protocol/padding/` as a required reference path.
//! **That package does not exist in Xray v26.3.27.** There is no padding code
//! anywhere under `proxy/shadowsocks/` either — classic Shadowsocks in this
//! reference version is unpadded. Rather than invent an SS padding format (which
//! the brief explicitly forbids), this module transcribes the padding that the
//! reference *actually* implements: the VMess header padding codec in
//! `proxy/vmess/encoding/{client,server}.go`.
//!
//! That format is a single length-prefixed padding block, not a multi-block
//! scheme:
//!
//! ```text
//! client.go  EncodeRequestHeader:
//!     paddingLen := dice.Roll(16)                       // 0..=15
//!     security   := byte(paddingLen<<4) | byte(security) // high nibble
//!     ...
//!     if paddingLen > 0 { buffer.ReadFullFrom(rand.Reader, int32(paddingLen)) }
//!
//! server.go  header decode:
//!     paddingLen := int(buffer.Byte(35) >> 4)            // high nibble
//!     ...
//!     if paddingLen > 0 { buffer.ReadFullFrom(decryptor, int32(paddingLen)) }
//! ```
//!
//! So: the length lives in the *high nibble* of an existing header byte (max 15,
//! because the low nibble carries the security type), the padding bytes are
//! random and carry no marker, and the receiver strips exactly `paddingLen`
//! bytes. Nothing here is self-describing beyond that nibble — which is exactly
//! why the decoder below must be told the length rather than discovering it.
//!
//! # Scope
//!
//! This is the *codec only*: [`PaddingPolicy`] rolls a length, [`encode_padded`]
//! appends the block, [`dechunk_padded`] strips and validates it. Wiring it into
//! `tcp.rs`'s send/receive path is deliberately **not** done, because classic
//! Shadowsocks has no header byte to steal a nibble from and the reference adds
//! no padding there. Doing so would change the on-wire SS format and break
//! interoperability with the reference binary. See `docs/shadowsocks-status.md`.
//!
//! 模块按职责拆成子文件：帧编解码在 [`codec`]，长度决策策略在 [`policy`]。

mod codec;
mod policy;

pub use codec::{
    dechunk_padded, decode_flags, encode_padded, PaddedChunk, PaddingError, MAX_PADDING_LEN,
};
pub use policy::PaddingPolicy;

#[cfg(test)]
mod tests;
