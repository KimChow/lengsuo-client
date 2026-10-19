//! TCP 流上的目标地址读取（`protocol.go` 的 `ReadTCPSession` 语义）。
//!
//! 为什么 UDP 与 TCP 不共用一段解析代码：参考实现的地址字节虽然由同一个
//! `addrParser` 产出，但读端入口不同——UDP 是**整包在内存里**（`DecodeUDPPacket`
//! 直接把 buffer 当 `io.Reader`，`net.Address`/`net.Port` 的错误分支各只有一条
//! `io.ErrUnexpectedEOF`），TCP 是**跨 chunk 的流**（`ReadTCPSession` 拿
//! `buf.BufferedReader`，需要区分「地址族字节读到一半」与「域名体读到一半」）。
//! `TargetAddr::decode` 只接受完整切片，无法表达行程中的部分状态，因此在 TCP 侧
//! 新增本模块做行程式读取；两者最终都产出同一个 `TargetAddr`。
//!
//! 与参考 `common/protocol/address.go` 的 `addressParser.readAddress` 逐条对应：
//!
//! - 地址族字节先 `& 0x0F`（`WithAddressTypeParser`），再按
//!   `AddressFamilyByte` 建立的映射查表；映射表外的值一律拒绝，**不猜**。
//! - ATYP 0x03 的域名允许 `[0-9A-Za-z.\-_]`（`isValidDomain`），空域名、含 NUL、
//!   非法字符、长度超过 `u8::MAX` 都拒绝。参考在此处对 `maybeIPPrefix`（首字符是
//!   `[` 或数字）的输入会尝试 `net.ParseAddress` 并**改写地址族**；本实现的
//!   `TargetAddr` 是纯类型化模型，没有「能解析成 IP 的域名字符串」这一态，
//!   因此只按域名处理，该差异记在 `docs/shadowsocks-status.md` 的偏离清单。
//! - **不做 DNS 解析**：返回 `Domain` 原样，由中继的拨号阶段决定是否解析。

use ss_core::target::TargetAddr;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::tcp::Error;

/// 地址族字节：与 `protocol.go` 的 `addrParser` 完全一致（0x01/0x04/0x03）。
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;

/// 一次地址读取的读端：流 + 本连接已缓冲的字节。
///
/// 参考实现把「已读入但未交付」的字节放在 `buf.BufferedReader` 里，本类型承担同一
/// 角色，同时给读端一个唯一的错误类型（地址读失败一律让连接永久失效，不重试）。
/// 无底层流的占位读端：读到即 EOF。中继路径用它构造
/// [`AddressReader::from_pending`]，所有地址字节改由 [`AddressReader::push`] 喂入。
#[derive(Debug, Default)]
pub struct NoStream;

impl AsyncRead for NoStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // 缓冲已空 ⇒ 直接 EOF（地址字节不足时呈现为 Truncated，调用方喂下一个 chunk）。
        std::task::Poll::Ready(Ok(()))
    }
}

pub struct AddressReader<R> {
    inner: R,
    /// 已认证 chunk 中尚未消费的明文（可能包含地址前几字节与载荷开头）。
    pending: Vec<u8>,
    /// 已成功消费的前缀长度。用游标而非 `drain`：地址可能跨 chunk，读到一半失败时
    /// 必须保留进度，等下一个 chunk 到达后从断点续读（否则重试会丢字节）。
    cursor: usize,
}

impl<R: AsyncRead + Unpin> AddressReader<R> {
    /// 由底层流构造。`pending` 由调用方在构造后按需追加（例如首个 chunk 的明文）。
    #[must_use]
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            cursor: 0,
        }
    }

    /// 把一段已认证的明文追加到缓冲区末尾（chunk 顺序即需要保证）。
    pub fn push(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
    }

    /// 缓冲区内尚未消费的字节数。
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.pending.len() - self.cursor
    }

    /// 取出并清空缓冲区（中继把读到的字节转交上游时使用）。游标一并复位。
    pub fn take_pending(&mut self) -> Vec<u8> {
        self.cursor = 0;
        std::mem::take(&mut self.pending)
    }

    /// 按 SOCKS5 地址格式读出一个目标地址。
    ///
    /// **非破坏性**：内部用游标推进，读取成功才提交（`commit`），中途字节不足时
    /// 返回 `Err(Error::Truncated)` 且**回滚游标**，调用方可在 `push` 新 chunk 后
    /// 重试（地址跨 chunk 的关键）。`Err(Error::InvalidFrame)` 表示地址族/域名非法，
    /// 属于永久错误，调用方必须关连接（fail-closed）。
    pub async fn read_target(&mut self) -> Result<TargetAddr, Error> {
        let saved = self.cursor;
        match self.try_read_target().await {
            Ok(target) => {
                // 提交：丢弃已消费的前缀（含地址与可能的载荷开头留在 pending 里）。
                self.pending.drain(..self.cursor);
                self.cursor = 0;
                Ok(target)
            }
            Err(err) => {
                // 字节不足：回滚，等更多 chunk；协议错误：不可恢复，同样回滚（调用方关连接）。
                self.cursor = saved;
                Err(err)
            }
        }
    }

    /// 在游标处尝试解析一个完整地址；成功时把游标推进到地址末尾。
    async fn try_read_target(&mut self) -> Result<TargetAddr, Error> {
        let atyp = self.take_atyp().await?;
        match atyp {
            ATYP_V4 => {
                let mut ip = [0u8; 4];
                self.fill(&mut ip, "地址").await?;
                let port = self.take_port().await?;
                Ok(TargetAddr::V4(ip, port))
            }
            ATYP_V6 => {
                let mut ip = [0u8; 16];
                self.fill(&mut ip, "地址").await?;
                let port = self.take_port().await?;
                Ok(TargetAddr::V6(ip, port))
            }
            ATYP_DOMAIN => {
                let len = usize::from(self.take_u8("域名长度").await?);
                // 参考：domainLength 为 0 时后续 `domain[0]` 会 panic；本端显式拒绝。
                if len == 0 {
                    return Err(Error::InvalidFrame(0));
                }
                let mut raw = vec![0u8; len];
                self.fill(&mut raw, "域名").await?;
                let host = std::str::from_utf8(&raw)
                    .map_err(|_| Error::InvalidFrame(len))?
                    .to_string();
                check_domain(&host)?;
                let port = self.take_port().await?;
                Ok(TargetAddr::Domain(host, port))
            }
            // 参考按 `addrType & 0x0F` 查表，表外（含 0x02/0x05..0x0F 与掩码后越界者）
            // 一律 `unknown address type` 拒绝。
            other => Err(Error::InvalidFrame(usize::from(other))),
        }
    }

    /// 读地址族字节并套用 `& 0x0F` 掩码（参考 `WithAddressTypeParser`）。
    async fn take_atyp(&mut self) -> Result<u8, Error> {
        let raw = self.take_u8("地址族").await?;
        Ok(raw & 0x0F)
    }

    /// 取一个字节；缓冲不足时从底层流续读，EOF 视为截断。
    async fn take_u8(&mut self, expect: &'static str) -> Result<u8, Error> {
        let mut one = [0u8; 1];
        self.fill(&mut one, expect).await?;
        Ok(one[0])
    }

    /// 取大端 16 位端口。
    async fn take_port(&mut self) -> Result<u16, Error> {
        let mut raw = [0u8; 2];
        self.fill(&mut raw, "端口").await?;
        Ok(u16::from_be_bytes(raw))
    }

    /// 从游标处填充 `out`：先消费缓冲区剩余字节，不足时读底层流（正是参考
    /// `buf.Buffer.ReadFullFrom` 的行为）。游标随成功读取推进；任何一步字节不足
    /// 都返回 `Truncated`（调用方回滚游标重试），底层 EOF 亦视为截断。
    async fn fill(&mut self, out: &mut [u8], expect: &'static str) -> Result<(), Error> {
        let take = out.len().min(self.pending.len() - self.cursor);
        if take > 0 {
            out[..take].copy_from_slice(&self.pending[self.cursor..self.cursor + take]);
            self.cursor += take;
        }
        if take == out.len() {
            return Ok(());
        }
        self.inner
            .read_exact(&mut out[take..])
            .await
            .map(|_| ())
            .map_err(|err| {
                if err.kind() == std::io::ErrorKind::UnexpectedEof {
                    Error::Truncated { expect }
                } else {
                    Error::Io(err)
                }
            })
    }
}

impl AddressReader<NoStream> {
    /// 只有已缓冲字节、没有底层流的构造（中继路径：chunk 由调用方 `push` 驱动，
    /// 地址所需字节全部来自已认证 chunk，`inner` 不被读取）。
    #[must_use]
    pub fn from_pending() -> Self {
        AddressReader {
            inner: NoStream,
            pending: Vec::new(),
            cursor: 0,
        }
    }
}

/// 参考 `isValidDomain` 的同构检查，另外拒绝空域名（参考在空域名上会数组越界）。
fn check_domain(domain: &str) -> Result<(), Error> {
    if domain.is_empty() {
        return Err(Error::InvalidFrame(0));
    }
    if domain
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.' || c == b'_')
    {
        Ok(())
    } else {
        Err(Error::InvalidFrame(domain.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reader(bytes: &[u8]) -> AddressReader<&[u8]> {
        AddressReader::new(bytes)
    }

    #[tokio::test]
    async fn reads_v4_from_stream() {
        let mut r = reader(&[0x01, 127, 0, 0, 1, 0x1F, 0x90]);
        assert_eq!(
            r.read_target().await.unwrap(),
            TargetAddr::V4([127, 0, 0, 1], 8080)
        );
        assert_eq!(r.buffered(), 0);
    }

    #[tokio::test]
    async fn reads_v6_from_stream() {
        let mut raw = vec![0x04];
        raw.extend_from_slice(&[0u8; 15]);
        raw.push(1);
        raw.extend_from_slice(&[0x00, 0x35]);
        let mut r = reader(&raw);
        let mut ip = [0u8; 16];
        ip[15] = 1;
        assert_eq!(r.read_target().await.unwrap(), TargetAddr::V6(ip, 53));
    }

    #[tokio::test]
    async fn reads_domain_from_stream() {
        let mut raw = vec![0x03, 9];
        raw.extend_from_slice(b"a.invalid");
        raw.extend_from_slice(&[0x01, 0xBB]);
        let mut r = reader(&raw);
        assert_eq!(
            r.read_target().await.unwrap(),
            TargetAddr::Domain("a.invalid".into(), 443)
        );
    }

    #[tokio::test]
    async fn atyp_masked_before_dispatch() {
        // 参考对地址族字节做 & 0x0F：0x11 → 0x01（IPv4）。
        let mut r = reader(&[0x11, 8, 8, 8, 8, 0, 53]);
        assert_eq!(
            r.read_target().await.unwrap(),
            TargetAddr::V4([8, 8, 8, 8], 53)
        );
    }

    #[tokio::test]
    async fn buffered_bytes_are_consumed_first() {
        let mut r = reader(&[]);
        r.push(&[0x01, 127, 0, 0, 1, 0x00, 0x50, b'x', b'y']);
        assert_eq!(
            r.read_target().await.unwrap(),
            TargetAddr::V4([127, 0, 0, 1], 80)
        );
        assert_eq!(r.take_pending(), b"xy".to_vec());
    }

    #[tokio::test]
    async fn truncated_domain_is_error_not_eof() {
        let mut raw = vec![0x03, 9];
        raw.extend_from_slice(b"short");
        let mut r = reader(&raw);
        assert!(matches!(
            r.read_target().await.unwrap_err(),
            Error::Truncated { .. }
        ));
    }

    #[tokio::test]
    async fn invalid_atyp_rejected() {
        let mut r = reader(&[0x05, 0, 0, 0, 0, 0, 0]);
        assert!(matches!(
            r.read_target().await.unwrap_err(),
            Error::InvalidFrame(5)
        ));
    }

    #[tokio::test]
    async fn empty_and_illegal_domain_rejected() {
        let mut r = reader(&[0x03, 0, 0, 0]);
        assert!(r.read_target().await.is_err());
        let mut raw = vec![0x03, 3];
        raw.extend_from_slice(b"a\x00b");
        raw.extend_from_slice(&[0, 80]);
        let mut r = reader(&raw);
        assert!(r.read_target().await.is_err());
    }
}
