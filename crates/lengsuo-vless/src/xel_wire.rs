//! XEL 记录层接成出站原语：把「已建立的字节流」包装成「xel 加密/分帧后的字节流」。
//!
//! # 本模块只做接线
//!
//! 加密、分帧、序号锁定、头部掩蔽全部委托给 [`crate::xel`] 的既有原语，本模块
//! **不复制第二份实现**：
//!
//! | 环节 | 既有原语 | 位置 |
//! |---|---|---|
//! | 发送方向的记录封装（AEAD + 头部作 AAD） | [`crate::xel::record::RecordWriter::seal`] | `src/xel/record.rs:46` |
//! | 接收方向的分帧 + 锁定步序号 + 解封 | [`crate::xel::record::Reader`] | `src/xel/record.rs:63` |
//! | XOR 头部掩蔽（可选） | [`crate::xel::xor::XorMask`] | `src/xel/xor.rs:149` |
//!
//! 本模块新增的只有**编排**：上下行密钥分离、8192 字节分块（参考 `common.go`
//! `CommonConn.Write` 的循环）、掩蔽层与 AEAD 层的先后顺序，以及把记录层包装成
//! `AsyncRead`/`AsyncWrite` 字节流的管道。
//!
//! # 分层顺序（与参考一致）
//!
//! 参考把 AEAD 记录层（`common.go` 的 `CommonConn`）放在**外层**、XOR 头部掩蔽
//! （`xor.go` 的 `XorConn`）放在**内层**（贴近 TCP）：客户端先 AEAD 封记录，再由
//! `XorConn.Write` 掩蔽 5 字节头；接收端先 `XorConn.Read` 去掩蔽，再
//! `CommonConn.Read` 解封。因此线上顺序是
//! `明文 → AEAD 记录(头+体) → XOR 掩蔽头 → TCP`。
//!
//! # 参考基线与偏离
//!
//! 基线：Xray v26.3.27 `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。
//!
//! - `proxy/vless/encryption/common.go:47` `CommonConn.Write`：**每 8192 字节明文
//!   一条记录**（`if len(b) > 8192 { b = b[:8192] }`）。本模块按同一上限分块。
//! - `proxy/vless/encryption/common.go:80` `CommonConn.Read`：记录体先整体读满再解封。
//! - `proxy/vless/encryption/xor.go:41`/`:69` `XorConn.Write`/`Read`：只掩蔽 5 字节
//!   头，记录体原样透传；跳过量由解码出的头部长度决定。
//! - **偏离**：`common.go:212` `DecodeHeader` 在魔数不符时把长度置 0 后继续运行；
//!   本仓 `src/xel/frame.rs:68` 视为 `InvalidHeader` 并 poison（更严格，已在
//!   `src/xel/mod.rs:15` 记录）。本模块沿用本仓的严格语义。
//! - **范围外**：XEL 的密钥协商（ML-KEM-768 × X25519、票据、0-RTT、`PreWrite`、
//!   `PeerPadding`）属握手层，不在本模块；本模块从「会话密钥与 IV 已就绪」开始。
//!
//! # fail-closed
//!
//! 认证失败、序号失步、头部非法、长度越界、截断——任一发生即由既有原语 poison
//! 该方向，之后所有调用返回 `Error::Record(Poisoned)`，绝不产出明文或静默降级。
//!
//! # 用法
//!
//! ```no_run
//! use lengsuo_vless::xel::aead::XelCipher;
//! use lengsuo_vless::xel::XelKey;
//! use lengsuo_vless::xel_wire::{XelStream, XelWireConfig};
//! use tokio::{io::AsyncWriteExt, net::TcpStream};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let transport = TcpStream::connect("example.invalid:443").await?;
//! let config = XelWireConfig {
//!     cipher: XelCipher::Aes256Gcm,
//!     uplink_key: XelKey::new(&[0x11; 32])?,
//!     downlink_key: XelKey::new(&[0x22; 32])?,
//!     xor: None,
//! };
//! // 之后 `stream` 就是一条「xel 加密/分帧后」的字节流。
//! let mut stream = XelStream::new(transport, config)?;
//! stream.write_all(b"hello").await?;
//! # Ok(())
//! # }
//! ```

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{
        duplex, split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
    },
    task::{spawn, JoinHandle},
    time::timeout,
};

use crate::xel::{
    aead::XelCipher,
    record::{RecordReader, RecordWriter},
    xor::XorMask,
    Error as XelError, XelKey,
};

/// 单条记录的明文上限（参考 `common.go:53` `CommonConn.Write` 的
/// `if len(b) > 8192 { b = b[:8192] }`）。
pub const MAX_PLAINTEXT_PER_RECORD: usize = 8192;

/// XOR 掩蔽层 CTR IV 长度（AES 块长，参考 `xor.go:12` `NewCTR` 的 IV）。
pub const XOR_IV_LEN: usize = 16;

/// 单次底层 I/O 的截止时间（所有网络操作必须有界）。
const IO_DEADLINE: Duration = Duration::from_secs(10);

/// 管道容量（一条记录的最大明文量的量级）。
const PIPE: usize = MAX_PLAINTEXT_PER_RECORD + 256;

/// XEL 记录层出站原语的错误。全部 fail-closed。
///
/// 消息只含长度／序号／状态，不含密钥、明文或密文字节（与
/// [`crate::xel::Error`] 的脱敏纪律一致）。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// 记录层失败（认证、序号、头部、长度、截断、poison）。
    #[error("XEL 记录层失败：{0}")]
    Record(#[from] XelError),
    /// 底层 I/O 失败。
    #[error("XEL: I/O 失败")]
    Io(#[from] io::Error),
    /// I/O 超时。
    #[error("XEL: 操作超时")]
    Timeout,
}

/// XOR 头部掩蔽层配置（参考 `xor.go` `NewCTR` + `NewXorConn`）。
///
/// **命名以端点为基准**（`send` = 本端发出，`recv` = 本端收到）：客户端的
/// `send` 是上行、服务端的 `send` 是下行，两端因此可以对调同一份配置。
///
/// **密钥材料与 AEAD 密钥不是同一份**：参考用 `blake3.DeriveKey("VLESS", UnitedKey)`
/// 作 AES-256-CTR 密钥（`xor.go:12`），而 AEAD 侧用 `blake3.DeriveKey(ctx, UnitedKey)`
/// （`common.go:157`）。本仓把派生结果与 IV 都交给调用方注入，因此这里给的是
/// **未派生的 UnitedKey 材料**，掩蔽层内部再派生一次（`src/xel/xor.rs:34`）。
#[derive(Debug)]
pub struct XorLayer {
    /// 本端**发送**方向的掩蔽密钥材料。
    pub send_key: XelKey,
    /// 本端发送方向的 CTR IV。
    pub send_iv: [u8; XOR_IV_LEN],
    /// 本端**接收**方向的掩蔽密钥材料。
    pub recv_key: XelKey,
    /// 本端接收方向的 CTR IV。
    pub recv_iv: [u8; XOR_IV_LEN],
}

impl XorLayer {
    /// 构造掩蔽层配置；IV 长度必须恰为 [`XOR_IV_LEN`]，否则 fail-closed 拒绝。
    pub fn new(
        send_key: XelKey,
        send_iv: &[u8],
        recv_key: XelKey,
        recv_iv: &[u8],
    ) -> Result<Self, Error> {
        let send_iv = fixed_iv(send_iv)?;
        let recv_iv = fixed_iv(recv_iv)?;
        Ok(Self {
            send_key,
            send_iv,
            recv_key,
            recv_iv,
        })
    }
}

/// 定长 IV 的 fail-closed 校验（错误只报长度）。
fn fixed_iv(iv: &[u8]) -> Result<[u8; XOR_IV_LEN], Error> {
    if iv.len() != XOR_IV_LEN {
        return Err(Error::Record(XelError::InvalidIvLength {
            got: iv.len(),
            want: XOR_IV_LEN,
        }));
    }
    let mut out = [0u8; XOR_IV_LEN];
    out.copy_from_slice(iv);
    Ok(out)
}

/// XEL 记录层配置。密钥与 IV 全部由调用方注入（握手/KEM 不在本模块范围）。
///
/// **命名以端点为基准**：`uplink_key` = 本端**发送**方向的 AEAD 记录密钥，
/// `downlink_key` = 本端**接收**方向的 AEAD 记录密钥。客户端与服务端因此可以
/// 对调同一份配置（客户端的 `uplink` = 服务端的 `downlink`）。
#[derive(Debug)]
pub struct XelWireConfig {
    /// AEAD 套件（两个方向相同；参考 `common.go:157` 的 `useAES` 二选一）。
    pub cipher: XelCipher,
    /// 本端**发送**方向的 AEAD 记录密钥（客户端视角 = 上行）。
    pub uplink_key: XelKey,
    /// 本端**接收**方向的 AEAD 记录密钥（客户端视角 = 下行）。
    pub downlink_key: XelKey,
    /// 可选的 XOR 头部掩蔽层（参考 `client.go:123` / `server.go:231` 的
    /// `XorMode == 2`；`XorMode == 1` 时置 `None`）。
    pub xor: Option<XorLayer>,
}

impl XelWireConfig {
    /// 拆成发送端与接收端（同步调用方与 [`XelStream`] 共用）。
    pub fn split(self) -> Result<(XelSender, XelReceiver), Error> {
        let XelWireConfig {
            cipher,
            uplink_key,
            downlink_key,
            xor,
        } = self;
        // 掩蔽器分两个实例：发送端只用 `mask_outgoing`（掩蔽本端发出的头），
        // 接收端只用 `unmask_incoming`（还原本端收到的头）。方向状态不能共用。
        // 逻辑全在既有 `XorMask` 内，本模块不重复实现。
        let (out_mask, in_mask) = match xor {
            Some(layer) => {
                let out = XorMask::new(
                    &layer.send_key,
                    &layer.send_iv,
                    &layer.recv_key,
                    &layer.recv_iv,
                )?;
                let inbound = XorMask::new(
                    &layer.send_key,
                    &layer.send_iv,
                    &layer.recv_key,
                    &layer.recv_iv,
                )?;
                (Some(out), Some(inbound))
            }
            None => (None, None),
        };
        Ok((
            XelSender {
                writer: RecordWriter::new(cipher, uplink_key),
                mask: out_mask,
            },
            XelReceiver {
                reader: RecordReader::new(cipher, downlink_key),
                mask: in_mask,
            },
        ))
    }
}

/// 发送方向原语：明文 → 线上字节。
///
/// 语义全部来自 [`crate::xel::record::RecordWriter`]（记录封装、nonce 序号、
/// 头部作 AAD）与可选的 [`crate::xel::xor::XorMask`]（只掩蔽 5 字节头）。
pub struct XelSender {
    writer: RecordWriter,
    mask: Option<XorMask>,
}

impl XelSender {
    /// 把明文封成线上字节（可能含多条记录）。
    ///
    /// 分块上限 [`MAX_PLAINTEXT_PER_RECORD`]，与参考 `common.go:53` 一致：
    /// 每 8192 字节明文一条记录，空明文产出空输出（参考 `common.go:49`）。
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut wire = Vec::with_capacity(plaintext.len() + 5);
        for chunk in plaintext.chunks(MAX_PLAINTEXT_PER_RECORD) {
            let mut record = self.writer.seal(chunk)?;
            // 掩蔽层作用在「头 + 体」整条线上记录上（参考 `xor.go:41`）。
            if let Some(mask) = &mut self.mask {
                mask.mask_outgoing(&mut record)?;
            }
            wire.extend_from_slice(&record);
        }
        Ok(wire)
    }

    /// 已发送的记录数（= 已消耗的 nonce 序号）。
    pub fn sequence(&self) -> u64 {
        self.writer.sequence()
    }

    /// 方向是否已 poison（认证失败或序号耗尽后为真）。
    pub fn is_poisoned(&self) -> bool {
        self.writer.is_poisoned() || self.mask.as_ref().is_some_and(XorMask::is_poisoned)
    }
}

impl std::fmt::Debug for XelSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XelSender")
            .field("sequence", &self.writer.sequence())
            .field("poisoned", &self.is_poisoned())
            .finish_non_exhaustive()
    }
}

/// 接收方向原语：线上字节 → 明文。
///
/// 语义全部来自 [`crate::xel::record::RecordReader`]（分帧、锁定步序号、解封）
/// 与可选的 [`crate::xel::xor::XorMask`]（只去掩蔽 5 字节头）。
pub struct XelReceiver {
    reader: RecordReader,
    mask: Option<XorMask>,
}

impl XelReceiver {
    /// 喂入线上字节，返回解出的明文（不足一条记录时返回空）。
    ///
    /// 顺序与参考一致：先去掩蔽（`xor.go:69`），再分帧解封（`common.go:80`）。
    pub fn open(&mut self, wire: &[u8]) -> Result<Vec<u8>, Error> {
        let mut plaintext = Vec::new();
        if let Some(mask) = &mut self.mask {
            // 掩蔽是**原地**的，必须先复制再改（调用方的缓冲不能被篡改）。
            let mut unmasked = wire.to_vec();
            mask.unmask_incoming(&mut unmasked)?;
            self.reader.push(&unmasked)?;
        } else {
            self.reader.push(wire)?;
        }
        while let Some(chunk) = self.reader.next_plaintext()? {
            plaintext.extend_from_slice(&chunk);
        }
        Ok(plaintext)
    }

    /// 流结束检查：残字节即截断（fail-closed）。
    pub fn finish(&mut self) -> Result<(), Error> {
        Ok(self.reader.finish()?)
    }

    /// 方向是否已 poison。
    pub fn is_poisoned(&self) -> bool {
        self.reader.is_poisoned() || self.mask.as_ref().is_some_and(XorMask::is_poisoned)
    }
}

impl std::fmt::Debug for XelReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XelReceiver")
            .field("poisoned", &self.is_poisoned())
            .finish_non_exhaustive()
    }
}

/// XEL 记录层出站原语：把「已建立的字节流」包装成「xel 加密/分帧后的字节流」。
///
/// 结构照搬 [`crate::reality_link::RealityStream`] 的既有做法：记录层两个方向各
/// 起一个后台任务，在「底层传输」与「内存管道（`tokio::io::duplex`）」之间搬运
/// 记录；调用方拿到的是管道的应用侧，因此 `AsyncRead`/`AsyncWrite` 就是普通
/// 字节流，可直接交给 [`crate::stream::send_request`] 等主链路函数。
pub struct XelStream {
    /// 应用侧（管道本端）：VLESS 头与载荷都从这里读写。
    app: DuplexStream,
    /// 读方向失败槽：读任务失败时把错误放进来，应用侧读到 EOF 前先取它
    /// （管道本身只能表达 EOF，不能表达失败原因）。用 `Arc` 是因为
    /// `io::Error` 不实现 `Clone`。
    read_error: Arc<Mutex<Option<Arc<Error>>>>,
    /// 写方向失败槽：写任务失败时把错误放进来，应用侧写入前先取它。
    write_error: Arc<Mutex<Option<Arc<Error>>>>,
    /// 读任务：传输 → 管道。
    reader_task: Option<JoinHandle<Result<(), Error>>>,
    /// 写任务：管道 → 传输。
    writer_task: Option<JoinHandle<Result<(), Error>>>,
    /// 写任务的结果（`shutdown()` 先等过写任务时存在这里，`close()` 取用）。
    writer_result: Option<Result<(), Error>>,
}

impl XelStream {
    /// 用已建立的传输（通常是已握好 TLS 的字节流）构造 XEL 记录层字节流。
    pub fn new<T>(transport: T, config: XelWireConfig) -> Result<Self, Error>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, mut receiver) = config.split()?;
        let (read_half, write_half) = split(transport);
        let (app, inner) = duplex(PIPE);
        let (inner_read, inner_write) = split(inner);
        let read_error = Arc::new(Mutex::new(None));
        let sink_error = Arc::clone(&read_error);
        let reader_task = spawn(async move {
            // 失败槽必须在**管道写端关闭之前**填好：否则应用侧可能先看到
            // 一个「干净的 EOF」而误以为流是正常结束的（fail-closed 被绕过）。
            // 因此写端由本闭包持有，`pump_reads` 只借用它。
            let mut sink = inner_write;
            let outcome = pump_reads(&mut receiver, read_half, &mut sink).await;
            if let Err(error) = &outcome {
                // 失败原因只放进槽里（不写进管道字节流），应用侧读到时取出。
                if let Ok(mut slot) = sink_error.lock() {
                    *slot = Some(Arc::new(clone_error(error)));
                }
            }
            // 无论成功还是失败都关闭管道写半：`tokio::io::split` 出来的半边
            // drop **不会**关闭管道（底层 `Arc` 还活着），不显式 shutdown 的话
            // 应用侧会永远等在一个「不会到来的 EOF」上。
            let _ = sink.shutdown().await;
            outcome
        });
        let write_error = Arc::new(Mutex::new(None));
        let sink_error = Arc::clone(&write_error);
        let writer_task = spawn(async move {
            let mut source = inner_read;
            let outcome = pump_writes(&mut sender, &mut source, write_half).await;
            if let Err(error) = &outcome {
                // 写方向失败同样要让应用侧看见（否则应用侧会写进一个没人读的
                // 管道，直到管道满才挂死）。
                if let Ok(mut slot) = sink_error.lock() {
                    *slot = Some(Arc::new(clone_error(error)));
                }
            }
            outcome
        });
        Ok(Self {
            app,
            read_error,
            write_error,
            reader_task: Some(reader_task),
            writer_task: Some(writer_task),
            writer_result: None,
        })
    }

    /// 关闭写方向（应用侧 → 传输的写任务随之结束），返回前等写任务收尾。
    ///
    /// 写任务的失败**不在这里**报错（写方向的失败通常在读取方向失败之后才被
    /// 观察到），由 [`XelStream::close`] 统一报。
    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.app.shutdown().await?;
        self.join_writer().await;
        Ok(())
    }

    /// 等写任务收尾并把结果存进 `writer_result`（只等一次，避免重复 poll）。
    async fn join_writer(&mut self) {
        if let Some(task) = self.writer_task.take() {
            self.writer_result = Some(flatten(task.await));
        }
    }

    /// 收尾：关闭写方向并等两个后台任务结束。
    ///
    /// 读取方向在传输 EOF 时做截断检查（残字节 ⇒ 失败），任何一方向失败都原样
    /// 返回（fail-closed 的可见出口）；读任务在截止时间内未结束则中止它。
    pub async fn close(mut self) -> Result<(), Error> {
        let _ = self.app.shutdown().await;
        self.join_writer().await;
        let writer = self.writer_result.take();
        let mut reader_task = self.reader_task.take();
        let reader = match reader_task.as_mut() {
            Some(task) => match timeout(IO_DEADLINE, &mut *task).await {
                Ok(joined) => flatten(joined),
                Err(_) => {
                    task.abort();
                    Err(Error::Timeout)
                }
            },
            None => Ok(()),
        };
        // 先报读取方向（对端数据的真实性校验在这里），再报写入方向。
        reader?;
        writer.unwrap_or(Ok(()))?;
        Ok(())
    }
}

impl std::fmt::Debug for XelStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XelStream").finish_non_exhaustive()
    }
}

impl Drop for XelStream {
    fn drop(&mut self) {
        if let Some(task) = self.reader_task.take() {
            task.abort();
        }
        if let Some(task) = self.writer_task.take() {
            task.abort();
        }
    }
}

/// `JoinHandle` 的两层结果拍平（`JoinError` → `io::Error`）。
fn flatten(outcome: Result<Result<(), Error>, tokio::task::JoinError>) -> Result<(), Error> {
    match outcome {
        Ok(inner) => inner,
        Err(join) => Err(Error::Io(io::Error::other(join.to_string()))),
    }
}

/// 复制一份错误（`io::Error` 不实现 `Clone`，按 kind 重建，不回显原始字节）。
///
/// 复制只保留错误**种类**与静态文案：I/O 错误用 `other` 重建（不带原始
/// 路径/内容），记录层错误本身是可 `Copy` 的。
fn clone_error(error: &Error) -> Error {
    match error {
        Error::Record(inner) => Error::Record(*inner),
        Error::Io(_) => Error::Io(io::Error::other("XEL: I/O 失败")),
        Error::Timeout => Error::Timeout,
    }
}

/// 读任务：传输 → 管道。按记录解封，把明文写进管道。
async fn pump_reads<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    receiver: &mut XelReceiver,
    mut transport: R,
    mut sink: W,
) -> Result<(), Error> {
    let mut buffer = vec![0u8; MAX_PLAINTEXT_PER_RECORD];
    loop {
        let read = timeout(IO_DEADLINE, transport.read(&mut buffer))
            .await
            .map_err(|_| Error::Timeout)??;
        if read == 0 {
            // 对端关闭写半：残字节即截断（fail-closed），随后关闭应用侧写端。
            receiver.finish()?;
            let _ = sink.shutdown().await;
            return Ok(());
        }
        let plaintext = receiver.open(&buffer[..read])?;
        if !plaintext.is_empty() {
            timeout(IO_DEADLINE, sink.write_all(&plaintext))
                .await
                .map_err(|_| Error::Timeout)??;
        }
    }
}

/// 写任务：管道 → 传输。把应用字节封成记录写出。
async fn pump_writes<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    sender: &mut XelSender,
    mut source: R,
    mut transport: W,
) -> Result<(), Error> {
    let mut buffer = vec![0u8; MAX_PLAINTEXT_PER_RECORD];
    loop {
        let read = timeout(IO_DEADLINE, source.read(&mut buffer))
            .await
            .map_err(|_| Error::Timeout)??;
        if read == 0 {
            transport.shutdown().await?;
            return Ok(());
        }
        let wire = sender.seal(&buffer[..read])?;
        timeout(IO_DEADLINE, transport.write_all(&wire))
            .await
            .map_err(|_| Error::Timeout)??;
    }
}

impl AsyncRead for XelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 先把管道里**已认证的明文**交给应用侧（记录层失败可能发生在同一批
        // 字节的后半段；前半段的明文是有效的，不该被丢弃）。
        // 三态：None = 管道读侧仍 pending（等更多数据）；
        // Some(Ok(())) = 本轮读到数据；错误直接向上抛（不吞）。
        let read: Option<io::Result<()>> = match Pin::new(&mut self.app).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => Some(Ok(())),
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => None,
        };
        // 管道读空了（EOF）且读方向有失败 ⇒ 报出失败原因（管道只能表达 EOF）。
        if read.is_none() {
            if let Ok(slot) = self.read_error.lock() {
                if let Some(error) = slot.as_ref() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        error.to_string(),
                    )));
                }
            }
        }
        match read {
            Some(result) => Poll::Ready(result),
            // 管道侧 pending：本层没有更多数据可给，但**读方向可能已有失败**
            // （上面已检查并返回）。这里返回 Pending 让调用方等管道唤醒。
            None => Poll::Pending,
        }
    }
}

impl AsyncWrite for XelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // 写方向失败必须让应用侧看见（否则应用侧会一直写进一个没人读的管道）。
        if let Ok(slot) = self.write_error.lock() {
            if let Some(error) = slot.as_ref() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    error.to_string(),
                )));
            }
        }
        Pin::new(&mut self.app).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.app).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.app).poll_shutdown(cx)
    }
}
