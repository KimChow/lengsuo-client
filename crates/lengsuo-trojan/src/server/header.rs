//! 服务端侧请求头解析，字节语义以 `proxy/trojan/{server,protocol}.go` 为准。
//!
//! 差异对照（如实记录，不让读者误以为本文件是 `codec::decode` 的搬家）：
//!
//! - **多用户校验**：`codec::decode` 只针对单个 `Credential`，服务端必须面向
//!   整个 `Validator`；这里在读完 56 字节哈希后立即用 `Validator::get` 常量时间
//!   选中用户，认证失败先于地址解析暴露（与 `codec::decode` 的顺序一致）。
//! - **命令分支**：参考 `ConnReader.ParseHeader` 把「非 3」一律按 TCP 处理，
//!   本仓沿用既有 `codec` 严格语义——只有 `1`/`3` 合法，其余 `InvalidCommand`
//!   拒绝（本卡验收明确要求“非法命令字节必须拒绝”）。
//! - **CRLF**：参考 `ParseHeader` 只把两处 CRLF **读走**、不校验内容；唯一内容
//!   校验是 `server.go` 首块守卫里的 `first.Byte(56) != '\r'`（第 57 字节必须
//!   是 CR）。本文件同步只消费不比对；守卫由 `server::process` 完成。
//!   客户端侧的 `codec::decode` 仍保持严格 CRLF 校验，两者不冲突。
//!
//! `PrefixedReader` 对齐参考的 `buf.BufferedReader`：把首块读取到的字节留在缓冲
//! 前端，头部解析完成后未消费的应用载荷由**同一个** reader 继续交给中继，不会丢。

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use ss_core::target::TargetAddr;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio::time::timeout;

use crate::codec::{Command, Request};
use crate::credential::HASH_LEN;
use crate::server::validator::{User, Validator};
use crate::server::Error;

/// SOCKS 地址最大长度：ATYP 1 + 域名长度 1 + 域名 255 + 端口 2。
const MAX_TARGET_LEN: usize = 1 + 1 + 255 + 2;

/// 先回放 `prefix`、再读 `inner` 的读取器；等价参考的 `buf.BufferedReader`。
pub struct PrefixedReader<R> {
    prefix: Vec<u8>,
    pos: usize,
    inner: R,
}

impl<R> PrefixedReader<R> {
    pub fn new(prefix: Vec<u8>, inner: R) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PrefixedReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let available = &this.prefix[this.pos..];
            let take = available.len().min(buf.remaining());
            buf.put_slice(&available[..take]);
            this.pos += take;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

/// 读取并校验请求头，返回（请求、命中的用户）。头部之后的字节留在 `reader` 上。
///
/// 哈希校验在一处 `wait` 截止时间内完成；认证通过后才解析命令与地址，因此认证
/// 失败不会先暴露地址解析结果。命令只接受 `1`/`3`。
pub async fn accept<R: AsyncRead + Unpin>(
    reader: &mut R,
    validator: &Validator,
    wait: Duration,
) -> Result<(Request, Arc<User>), Error> {
    if wait.is_zero() {
        return Err(Error::InvalidDeadline);
    }
    timeout(wait, async {
        let mut hash = [0u8; HASH_LEN];
        reader.read_exact(&mut hash).await?;
        let user = validator.get(&hash).ok_or(Error::Authentication)?;

        // 参考 ParseHeader 只消费 CRLF、不校验内容；`server::process` 已做过
        // `initial[56] == b'\r'` 的首块守卫，这里保持“读走”即可。
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await?;

        let command = reader.read_u8().await?;
        let command = match command {
            1 => Command::Tcp,
            3 => Command::Udp,
            other => return Err(Error::InvalidCommand(other)),
        };

        let target = read_target(reader).await?;

        // 尾 CRLF 同样只消费不校验（对齐参考 ParseHeader）。
        reader.read_exact(&mut crlf).await?;
        Ok((Request { command, target }, user))
    })
    .await
    .map_err(|_| Error::Timeout)?
}

/// 逐字节增量解析 SOCKS 地址，读完地址即停手（长度字段等后续内容不被吞）。
async fn read_target<R: AsyncRead + Unpin>(reader: &mut R) -> Result<TargetAddr, Error> {
    let mut buf = Vec::with_capacity(MAX_TARGET_LEN);
    loop {
        match TargetAddr::decode(&buf) {
            Ok((target, used)) => {
                debug_assert_eq!(used, buf.len());
                return Ok(target);
            }
            Err(ss_core::Error::TooShort { .. }) => {
                if buf.len() >= MAX_TARGET_LEN {
                    return Err(Error::HeaderTooLarge);
                }
                buf.push(reader.read_u8().await?);
            }
            Err(other) => return Err(Error::Address(other)),
        }
    }
}
