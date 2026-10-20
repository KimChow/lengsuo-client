//! REALITY 的 Rust↔Rust 端到端夹具：本仓客户端 ↔ 本仓服务端。
//!
//! 服务端与客户端在 `127.0.0.1` 的临时端口上建立一条 TCP 连接：
//!
//! 1. 客户端构造带 REALITY 认证载荷的 ClientHello 并发出；
//! 2. 服务端用 `accept_hello` 做 REALITY 认证（**失败即拒**，不回落）；
//! 3. 双方跑完整的 TLS 1.3 握手（`session::client_handshake` /
//!    `session::server_handshake`）；
//! 4. 应用数据阶段双向转发载荷，**逐字节**比对。
//!
//! **硬约束**：只用回环地址与临时端口；凭据全是假值；错误消息里不含密钥。

use std::time::Duration;

use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use lengsuo_vless::reality::client::{build_reality_client_hello, BuiltClientHello, RealityClient};
use lengsuo_vless::reality::server::{accept_hello, RealityReject, RealityServerConfig};
use lengsuo_vless::reality::session::{client_handshake, server_handshake};
use lengsuo_vless::reality::tls13::io::{
    HandshakeCollector, Inbound, Outbound, RecordReader, RecordWriter,
};
use lengsuo_vless::reality::tls13::server::ServerHandshake;
use lengsuo_vless::reality::ClientVersion;

use super::{ClientIdentity, SeededRng, ServerIdentity, DEADLINE};

/// 客户端侧造好的 ClientHello（服务端要用它的原始字节做认证）。
pub struct ClientHelloFixture {
    /// ClientHello 握手消息的完整字节（含 4 字节头）。
    pub raw: Vec<u8>,
    /// 客户端 X25519 临时公钥。
    pub ephemeral_public: [u8; 32],
    /// 客户端 `client_random`。
    pub random: [u8; 32],
    /// ClientHello 产物（交给客户端状态机）。
    pub built: BuiltClientHello,
}

/// 服务端配置（全部假值）。
pub fn server_config(identity: &ServerIdentity) -> RealityServerConfig {
    RealityServerConfig {
        private_key: identity.private_key,
        short_ids: vec![identity.short_id],
        server_names: vec![identity.server_name.clone()],
        max_time_diff: Duration::from_secs(60),
    }
}

/// 用固定种子构造 ClientHello。
pub fn build_hello(
    identity: &ServerIdentity,
    client: &ClientIdentity,
    short_id: [u8; 8],
    server_name: &str,
    unix_time: u32,
) -> ClientHelloFixture {
    let mut rng = SeededRng::new(client.seed);
    let built = build_reality_client_hello(
        &identity.public_key,
        server_name,
        &short_id,
        ClientVersion { x: 26, y: 3, z: 27 },
        unix_time,
        &mut rng,
    )
    .expect("ClientHello 构造不应失败");
    ClientHelloFixture {
        raw: built.raw.clone(),
        ephemeral_public: built.ephemeral_public,
        random: built.random,
        built,
    }
}

/// 服务端状态机（固定种子，握手过程完全可复现）。
fn server_state(auth_key: [u8; 32]) -> ServerHandshake {
    let mut rng = SeededRng::from_label("server-handshake");
    ServerHandshake::new(auth_key, [0x31; 32], [0x32; 32], &mut rng)
        .expect("服务端状态机建立不应失败")
}

/// 一次端到端握手后的应用数据收发结果。
pub struct E2eResult {
    /// 客户端收到的服务端载荷。
    pub client_received: Vec<u8>,
    /// 服务端收到的客户端载荷。
    pub server_received: Vec<u8>,
    /// 客户端拿到的服务端叶子证书 DER。
    pub peer_certificate: Vec<u8>,
}

/// 端到端跑一次握手，并交换两段载荷。
///
/// `client_payload` 由客户端发出，`server_payload` 由服务端回发；
/// 两段都必须被对端**逐字节**取回。
#[allow(clippy::too_many_arguments)]
pub async fn run_handshake(
    identity: &ServerIdentity,
    client: &ClientIdentity,
    short_id: [u8; 8],
    server_name: &str,
    now_unix: u32,
    client_payload: &[u8],
    server_payload: &[u8],
) -> Result<E2eResult, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("监听失败: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("读取端口失败: {e}"))?
        .port();

    let hello = build_hello(identity, client, short_id, server_name, now_unix);
    let auth_key = identity
        .auth_key(&hello.ephemeral_public, &hello.random)
        .ok_or_else(|| "服务端派生 auth_key 失败".to_owned())?;
    let config = server_config(identity);
    let client_built = hello.built.clone();

    let server_payload = server_payload.to_vec();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
        server_side(
            &mut stream,
            &config,
            &auth_key,
            &hello,
            now_unix,
            &server_payload,
        )
        .await
    });

    let mut client_stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| format!("连接失败: {e}"))?;
    let mut client_built = client_built;
    // **必须用 `join!` 而不是先 `await` 客户端再 `await` 服务端**：
    // `#[tokio::test]` 默认是 current-thread 运行时，客户端握手会一直等
    // 服务端的飞行；若先把客户端 `await` 到底，服务端任务根本没有被轮询的
    // 机会，直接死锁。`join!` 让两个 future 在同一个任务里交替推进。
    let client_fut = client_side(&mut client_stream, &mut client_built, client_payload);
    let server_fut = async {
        // 服务端任务必须有截止时间：客户端若提前失败，服务端会一直等对端的
        // `Finished`，没有超时就会挂死整个门禁。
        match tokio::time::timeout(DEADLINE, server_task).await {
            Ok(joined) => joined.map_err(|e| format!("服务端任务异常: {e}"))?,
            Err(_) => Err("服务端握手超时".to_owned()),
        }
    };
    let (client_result, server_result) = tokio::join!(client_fut, server_fut);

    // 两侧的错误**都**要报出来：握手是双向的，只报一侧会把「谁先失败」
    // 搞反（例如客户端报 `malformed message`，其实是服务端先写坏了）。
    let (client_received, peer_certificate) = client_result.map_err(|e| {
        let peer = server_result
            .as_ref()
            .err()
            .cloned()
            .unwrap_or_else(|| "无（已成功）".to_owned());
        format!("客户端侧失败: {e}; 服务端侧: {peer}")
    })?;
    let server_received = server_result.map_err(|e| format!("服务端侧失败: {e}"))?;
    Ok(E2eResult {
        client_received,
        server_received,
        peer_certificate,
    })
}

/// 服务端：REALITY 认证 + TLS 1.3 服务端飞行 + 回发载荷。
async fn server_side(
    stream: &mut TcpStream,
    config: &RealityServerConfig,
    auth_key: &[u8; 32],
    hello: &ClientHelloFixture,
    now_unix: u32,
    server_payload: &[u8],
) -> Result<Vec<u8>, String> {
    // 1. 读 ClientHello（明文握手记录）。
    let mut reader = RecordReader::new();
    let mut collector = HandshakeCollector::new();
    let raw = loop {
        match reader
            .next_record(stream)
            .await
            .map_err(|e| format!("服务端读记录失败: {e}"))?
        {
            Some(Inbound::PlainHandshake(payload)) => {
                collector.push(&payload);
                if let Some(message) = collector.take().map_err(|e| e.to_string())? {
                    break message;
                }
            }
            Some(_) => continue,
            None => return Err("服务端在 ClientHello 前遇到 EOF".to_owned()),
        }
    };

    // 2. REALITY 认证：失败即拒（不回落、不放行）。
    accept_hello(config, &raw, now_unix).map_err(|e| format!("REALITY 认证被拒: {e}"))?;

    // 3. TLS 1.3 服务端飞行。
    let mut state = server_state(*auth_key);
    state
        .process_client_hello(&raw, &hello.ephemeral_public)
        .map_err(|e| format!("服务端处理 ClientHello 失败: {e}"))?;
    let outcome = server_handshake(&mut state, stream, &hello.random)
        .await
        .map_err(|e| format!("服务端握手失败: {e}"))?;

    // 4. 应用数据：读客户端载荷，回发服务端载荷。
    let (mut read_half, mut write_half) = split(stream);
    let mut server_reader = RecordReader::new();
    server_reader.enable_cipher(outcome.reader);
    let mut server_writer = RecordWriter::new();
    server_writer.enable_cipher(outcome.writer);

    let received = read_application(&mut server_reader, &mut read_half).await?;
    server_writer
        .write(
            &mut write_half,
            &Outbound::EncryptedApplication(server_payload.to_vec()),
        )
        .await
        .map_err(|e| format!("服务端写载荷失败: {e}"))?;
    Ok(received)
}

/// 客户端：发 ClientHello + TLS 1.3 客户端飞行 + 收发载荷。
async fn client_side(
    stream: &mut TcpStream,
    built: &mut BuiltClientHello,
    client_payload: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let raw = built.raw.clone();
    let mut state =
        RealityClient::from_built(built).map_err(|e| format!("客户端状态机建立失败: {e}"))?;
    // ClientHello 必须先于握手状态机发出（明文飞行）。
    let mut writer = RecordWriter::new();
    writer
        .write(stream, &Outbound::PlainHandshake(raw))
        .await
        .map_err(|e| format!("客户端发 ClientHello 失败: {e}"))?;
    let outcome = client_handshake(&mut state, stream, DEADLINE)
        .await
        .map_err(|e| format!("客户端握手失败: {e}"))?;

    let (mut read_half, mut write_half) = split(stream);
    let mut client_reader = RecordReader::new();
    client_reader.enable_cipher(outcome.reader);
    let mut client_writer = RecordWriter::new();
    client_writer.enable_cipher(outcome.writer);

    client_writer
        .write(
            &mut write_half,
            &Outbound::EncryptedApplication(client_payload.to_vec()),
        )
        .await
        .map_err(|e| format!("客户端写载荷失败: {e}"))?;
    let received = read_application(&mut client_reader, &mut read_half).await?;
    Ok((received, outcome.peer_certificate))
}

/// 读一条应用数据记录并返回明文载荷。
async fn read_application<R: AsyncRead + Unpin>(
    reader: &mut RecordReader,
    stream: &mut R,
) -> Result<Vec<u8>, String> {
    loop {
        match reader
            .next_record(stream)
            .await
            .map_err(|e| format!("读应用数据失败: {e}"))?
        {
            Some(Inbound::Encrypted(framed)) => {
                // `framed[0]` 是内容类型，其余是明文载荷。
                return Ok(framed[1..].to_vec());
            }
            Some(_) => continue,
            None => return Err("应用数据阶段遇到 EOF".to_owned()),
        }
    }
}

/// 只跑 REALITY 认证（不跑 TLS），返回认证结果。
///
/// 用于负例：错短 ID / 错 SNI / 错口令 / 重放（时间窗外）。
pub fn authenticate(
    identity: &ServerIdentity,
    hello: &ClientHelloFixture,
    now_unix: u32,
) -> Result<(), RealityReject> {
    let config = server_config(identity);
    accept_hello(&config, &hello.raw, now_unix).map(|_| ())
}

/// 预留一个回环端口（供需要显式端口的用例使用）。
#[allow(dead_code)]
pub async fn reserve_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("监听失败: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("读取端口失败: {e}"))?
        .port();
    drop(listener);
    Ok(port)
}

/// 写一段字节到连接（用于篡改/截断注入）。
#[allow(dead_code)]
pub async fn write_raw<W: AsyncWrite + Unpin>(stream: &mut W, bytes: &[u8]) -> Result<(), String> {
    stream
        .write_all(bytes)
        .await
        .map_err(|e| format!("写原始字节失败: {e}"))
}

/// 读一段字节（用于篡改/截断注入）。
#[allow(dead_code)]
pub async fn read_raw<R: AsyncRead + Unpin>(stream: &mut R, len: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| format!("读原始字节失败: {e}"))?;
    Ok(buf)
}
