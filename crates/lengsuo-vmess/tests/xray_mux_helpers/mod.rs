//! `xray_mux.rs` 的共享夹具（不注册为独立测试目标：位于子目录）。
//!
//! 只做测试侧连线与断言辅助：Mux 请求头封装、`v1.mux.cool` 字节流
//! 分帧/重组、回显后端。生产语义（帧编解码、会话状态机）仍由
//! `lengsuo_vmess::muxframe` / `muxsession` 提供。

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lengsuo_vmess::aead;
use lengsuo_vmess::chunkframe::{self, DataCipher};
use lengsuo_vmess::consts::{SECURITY_AES_128_GCM, VMESS_VERSION};
use lengsuo_vmess::muxframe::{FrameMetadata, TargetNetwork, MAX_META_LEN, SESSION_CHUNK_SIZE};
use lengsuo_vmess::muxsession::{ClientSession, StreamSink};
use lengsuo_vmess::request::{fnv1a32, KeySource, CMD_MUX};
use ss_core::target::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::support::codec;
use crate::support::XrayFixture;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
/// `RequestOptionChunkStream`（`common/protocol/headers.go:34`）。
const OPTION_CHUNK_STREAM: u8 = 0x01;
/// 每个 VMess 体的 chunk 明文上限（参考 `buf.Size`，`common/buf/buffer.go:13`）。
const VMESS_CHUNK_SIZE: usize = 8192;

/// 一个完整 mux 帧：元数据 + 可选数据段。
type ParsedFrame = (FrameMetadata, Option<Vec<u8>>);
/// 单帧解析结果：`Ok(None)` 表示已缓存的字节流还不足一帧。
type ParseResult = Result<Option<ParsedFrame>, String>;

pub fn xray_bin() -> Option<PathBuf> {
    match std::env::var_os("LENGSUO_XRAY") {
        Some(path) => Some(PathBuf::from(path)),
        None => {
            eprintln!(
                "SKIP: 环境变量 LENGSUO_XRAY 未设置，跳过依赖真实 Xray 的 Mux 互通用例。\
                 原因：没有参考二进制可拉起，无法证明 Rust↔Xray 的 v1.mux.cool 互通。"
            );
            None
        }
    }
}

pub fn start_fixture(bin: &Path, uuid: &str) -> XrayFixture {
    match XrayFixture::start(bin, uuid) {
        Ok(fixture) => fixture,
        Err(report) => {
            eprintln!("{report}");
            panic!("启动 Xray 失败（UUID 已打码）");
        }
    }
}

/// 握手失败时带夹具诊断。
pub fn fail(fixture: &XrayFixture, label: &str, error: String) -> ! {
    panic!("{label}: {error}\n{}", fixture.report())
}

/// `EncodeRequestHeader` 的 Mux 分支（`encoding/client.go:63-94`）：
/// 38 字节定长段 + 无地址 + FNV1a 尾。命令字节固定 3。
fn mux_request_plaintext(keys: &KeySource, option: u8) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(38 + 4);
    buffer.push(VMESS_VERSION);
    buffer.extend_from_slice(&keys.body_iv);
    buffer.extend_from_slice(&keys.body_key);
    buffer.push(keys.response_header);
    buffer.push(option);
    // security 字节：paddingLen << 4 | Security；paddingLen = 0。
    buffer.push(SECURITY_AES_128_GCM & 0x0F);
    buffer.push(0x00);
    buffer.push(CMD_MUX);
    // Mux 命令不写地址：`if header.Command != protocol.RequestCommandMux`。
    let hash = fnv1a32(&buffer);
    buffer.extend_from_slice(&hash.to_be_bytes());
    buffer
}

/// 一条已建立 VMess 请求头的 Mux 连接：发/收各自独立的 chunk 序列。
pub struct MuxConn {
    stream: TcpStream,
    send_cipher: DataCipher,
    recv_cipher: DataCipher,
    pending: Vec<u8>,
}

impl MuxConn {
    /// 连接 Xray 并写出 Mux 请求头（**不**读响应头：参考
    /// `proxy/vmess/inbound/inbound.go:187-223` 要等首个回程数据才刷响应头）。
    pub async fn connect(
        fixture: &XrayFixture,
        cmd_key: &[u8; 16],
        keys: &KeySource,
    ) -> Result<Self, String> {
        let mut stream =
            tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(fixture.address()))
                .await
                .map_err(|_| "连接 Xray 超时".to_string())?
                .map_err(|e| format!("连接 Xray 失败: {e:?}"))?;

        let plaintext = mux_request_plaintext(keys, OPTION_CHUNK_STREAM);
        let header = aead::seal_vmess_aead_header(cmd_key, &plaintext)
            .map_err(|e| format!("封装 Mux 请求头失败: {e}"))?;
        stream
            .write_all(&header)
            .await
            .map_err(|e| format!("写 Mux 请求头失败: {e:?}"))?;

        let (resp_key, resp_iv) = codec::response_key_iv(&keys.body_key, &keys.body_iv);
        Ok(MuxConn {
            stream,
            send_cipher: DataCipher::new(SECURITY_AES_128_GCM, &keys.body_key, &keys.body_iv),
            recv_cipher: DataCipher::new(SECURITY_AES_128_GCM, &resp_key, &resp_iv),
            pending: Vec::new(),
        })
    }

    /// 把任意长度的 mux 字节流切成 VMess chunk 写出
    /// （参考 `AuthenticationWriter.writeStream`）。
    pub async fn send_wire(&mut self, bytes: &[u8]) -> Result<(), String> {
        for piece in bytes.chunks(VMESS_CHUNK_SIZE) {
            chunkframe::write_data_chunk(&mut self.send_cipher, None, &mut self.stream, piece)
                .await
                .map_err(|e| format!("写 mux 帧失败: {e}"))?;
        }
        self.stream
            .flush()
            .await
            .map_err(|e| format!("flush 失败: {e:?}"))
    }

    /// 读 VMess 响应头并校验 `responseHeader` 种子字节。
    pub async fn read_response_header(&mut self, keys: &KeySource) -> Result<(), String> {
        let header = tokio::time::timeout(
            RESPONSE_TIMEOUT,
            codec::read_response_header(&mut self.stream, &keys.body_key, &keys.body_iv),
        )
        .await
        .map_err(|_| "读 VMess 响应头超时".to_string())?
        .map_err(|e| format!("读 VMess 响应头失败: {e}"))?;
        if header.first() != Some(&keys.response_header) {
            return Err(format!("响应头种子字节不匹配（明文长度 {}）", header.len()));
        }
        Ok(())
    }

    /// 从解密后的字节流里切出一个完整 mux 帧；不足一帧返回 `None`。
    fn try_parse(&mut self) -> ParseResult {
        if self.pending.len() < 2 {
            return Ok(None);
        }
        let meta_len = usize::from(u16::from_be_bytes([self.pending[0], self.pending[1]]));
        if meta_len > MAX_META_LEN {
            return Err(format!("帧 metaLen 超限: {meta_len} > {MAX_META_LEN}"));
        }
        let meta_end = 2 + meta_len;
        if self.pending.len() < meta_end {
            return Ok(None);
        }
        let meta = FrameMetadata::decode_meta(&self.pending[2..meta_end], false)
            .map_err(|e| format!("解析 mux 元数据失败: {e}"))?;
        let mut consumed = meta_end;
        let payload = if meta.has_data() {
            if self.pending.len() < consumed + 2 {
                return Ok(None);
            }
            let size = usize::from(u16::from_be_bytes([
                self.pending[consumed],
                self.pending[consumed + 1],
            ]));
            if size > SESSION_CHUNK_SIZE {
                return Err(format!("帧数据段超限: {size} > {SESSION_CHUNK_SIZE}"));
            }
            if self.pending.len() < consumed + 2 + size {
                return Ok(None);
            }
            let data = self.pending[consumed + 2..consumed + 2 + size].to_vec();
            consumed += 2 + size;
            Some(data)
        } else {
            None
        };
        self.pending.drain(..consumed);
        Ok(Some((meta, payload)))
    }

    /// 读下一个完整帧（跨 VMess chunk 重组）。
    pub async fn next_frame(&mut self) -> Result<ParsedFrame, String> {
        loop {
            if let Some(frame) = self.try_parse()? {
                return Ok(frame);
            }
            let chunk = chunkframe::read_data_chunk(&mut self.recv_cipher, None, &mut self.stream)
                .await
                .map_err(|e| format!("读回程 chunk 失败: {e}"))?;
            match chunk {
                Some(bytes) => self.pending.extend_from_slice(&bytes),
                None => return Err("服务端发送了 VMess EOF 帧".to_string()),
            }
        }
    }

    /// 关闭写方向（用例 D③ 的「写半个帧后关流」）。
    pub async fn shutdown_write(&mut self) {
        let _ = self.stream.shutdown().await;
    }

    /// 读侧必须观察到 EOF/RST 才算关闭；超时不算通过。
    pub async fn expect_peer_close(&mut self, label: &str) -> Result<(), String> {
        let outcome = tokio::time::timeout(RESPONSE_TIMEOUT, async {
            let mut buffer = [0u8; 2048];
            loop {
                match self.stream.read(&mut buffer).await {
                    Ok(0) => return Ok(()),
                    Ok(_) => continue,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::BrokenPipe
                                | std::io::ErrorKind::UnexpectedEof
                        ) =>
                    {
                        return Ok(())
                    }
                    Err(error) => return Err(format!("读侧非关闭错误: {:?}", error.kind())),
                }
            }
        })
        .await;

        match outcome {
            Err(_) => Err(format!(
                "{label}: {RESPONSE_TIMEOUT:?} 内未观察到 EOF/RST（超时不算关闭）"
            )),
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(format!("{label}: {error}")),
        }
    }
}

/// 下行捕获器：把 `ClientSession` 收到的字节留存供断言。
#[derive(Clone, Default)]
pub struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    pub fn snapshot(&self) -> Vec<u8> {
        self.0.lock().expect("capture 锁").clone()
    }

    pub fn len(&self) -> usize {
        self.0.lock().expect("capture 锁").len()
    }
}

impl StreamSink for Capture {
    fn write(&mut self, payload: &[u8]) -> Result<(), String> {
        self.0
            .lock()
            .expect("capture 锁")
            .extend_from_slice(payload);
        Ok(())
    }

    fn close_remote(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn close_local(&mut self) -> Result<(), String> {
        Ok(())
    }
}

/// 分配一条会话并挂上捕获器。
pub fn open_session(
    client: &mut ClientSession,
    network: TargetNetwork,
    target: TargetAddr,
) -> (u16, Capture) {
    let state = client.open(network, target).expect("会话表应能分配 id");
    let capture = Capture::default();
    client.attach(state.id, Box::new(capture.clone()));
    (state.id, capture)
}

/// 反复读帧并交给 `ClientSession`，直到 `done()` 为真；超时即失败。
pub async fn pump_until<F>(
    conn: &mut MuxConn,
    client: &mut ClientSession,
    mut done: F,
    label: &str,
) -> Result<(), String>
where
    F: FnMut() -> bool,
{
    let deadline = Instant::now() + RESPONSE_TIMEOUT;
    while !done() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| format!("{label}: {RESPONSE_TIMEOUT:?} 内未满足判据"))?;
        let (meta, payload) = tokio::time::timeout(remaining, conn.next_frame())
            .await
            .map_err(|_| format!("{label}: 读帧超时"))??;
        client
            .handle_frame(&meta, payload.as_deref())
            .map_err(|e| format!("{label}: 处理帧失败: {e}"))?;
    }
    Ok(())
}

/// 回环 UDP 回显后端：每个数据报原样送回来源地址。
pub async fn spawn_udp_echo() -> std::net::SocketAddr {
    let socket = UdpSocket::bind(("127.0.0.1", 0))
        .await
        .expect("回显后端绑定 127.0.0.1:0");
    let addr = socket.local_addr().expect("回显后端地址");
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65536];
        while let Ok((n, from)) = socket.recv_from(&mut buffer).await {
            if socket.send_to(&buffer[..n], from).await.is_err() {
                break;
            }
        }
    });
    addr
}

/// 记录监听器：返回（地址, 拨号次数, 收到的字节数）。
///
/// 截断用例的判据是「无残留数据」而不是「零拨号」：参考
/// `server.go:165-298` 在解析完 New 元数据后立即 dispatch，数据段随后才读；
/// 若截断点落在数据段，服务端会合法地拨号，但不得把半截载荷写出去。
pub async fn spawn_counting_listener() -> (
    std::net::SocketAddr,
    Arc<std::sync::atomic::AtomicUsize>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("监听器绑定 127.0.0.1:0");
    let addr = listener.local_addr().expect("监听器地址");
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let dials = Arc::clone(&accepted);
    let bytes = Arc::clone(&received);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            dials.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut buffer = [0u8; 4096];
            loop {
                match socket.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        bytes.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
            let _ = socket.shutdown().await;
        }
    });
    (addr, accepted, received)
}
