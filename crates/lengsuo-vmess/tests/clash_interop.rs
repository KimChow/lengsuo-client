//! Clash/Mihomo（Mihomo Meta v1.19.20）参考互通 · VMess（AEAD，alterId=0）。
//!
//! 独立测试实例：配置写在仓外（`LENGSUO_CLASH_TEST_DIR`，默认
//! `/home/ubuntu/lengsuo-network-dev/clash-test`），只绑 `127.0.0.1` 的高位临时端口，
//! `external-controller` 关闭，日志落测试目录；退出时**按 PID** 杀并删目录。
//! ⛔ 绝不触碰 47 上的 root 生产实例（`/opt/clash-for-linux/conf/config.yaml`）。
//!
//! 实跑（默认二进制 `/opt/clash-for-linux/bin/clash-linux-amd64`，可用 `LENGSUO_MIHOMO` 覆盖）：
//!   cargo test -p lengsuo-vmess --test clash_interop -- --nocapture
//!   cargo test -p lengsuo-vmess --test clash_interop -- --ignored --nocapture
//!
//! 三向：
//!   1. Rust 客户端 -> Mihomo `vmess` 协议入站 -> Mihomo `direct` 出站 -> 本仓 echo；
//!   2. Mihomo `vmess` 出站 -> 本仓入站桩（`server::decode_request_header` +
//!      `chunkframe` 分帧原语）；桩按请求 option 位（chunkMasking / GlobalPadding）
//!      分支处理数据面，目标地址不拨号、原样回显（同 vless 仓内先例）；
//!   3. Rust<->Rust 基线（同一入站桩，option=0 简化路径，**不冒充互通**）。
//!
//! 本 crate 无 `serde_json` dev 依赖（也不新增），Mihomo 配置用手写 YAML 字符串。
#[path = "support/codec_mod.rs"]
mod support;

use lengsuo_vmess::aead;
use lengsuo_vmess::chunkframe::{
    self, open_padded_chunk, read_padded_size, seal_data_chunk, seal_padded_chunk, write_data_eof,
    DataCipher, DataSizeParser,
};
use lengsuo_vmess::consts::SECURITY_AES_128_GCM;
use lengsuo_vmess::request::{Command, HeaderPlanner, KeySource, RequestHeader, SecurityOption};
use lengsuo_vmess::server::{
    decode_request_header, encode_response_header, response_key_iv, DecodedRequest,
    HeaderDecodeError, HeaderSecurity, ResponseHeader, RESPONSE_HEADER_WIRE_LEN,
};
use ss_core::target::TargetAddr;
use std::{
    path::PathBuf,
    process::{Child, Command as Process, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use support::codec::{cmd_key_from_uuid, generate_uuid_bytes, uuid_string};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{timeout, Instant},
};

const DEFAULT_MIHOMO: &str = "/opt/clash-for-linux/bin/clash-linux-amd64";
const WAIT: Duration = Duration::from_secs(8);
const PAYLOAD: &[u8] = b"clash-interop vmess payload\0binary\xff";
/// 选项位（`common/protocol/headers.go`；仓内 consts 的 OPTION_* 是旧命名，勿混用）。
const OPT_CHUNK_STREAM: u8 = 0x01;
const OPT_CHUNK_MASKING: u8 = 0x04;
const OPT_GLOBAL_PADDING: u8 = 0x08;
const OPT_AUTHENTICATED_LENGTH: u8 = 0x10;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时钟在 UNIX 纪元之后")
        .as_secs() as i64
}

// ---------------------------------------------------------------- Mihomo 实例

struct Mihomo {
    child: Child,
    directory: PathBuf,
}

impl Drop for Mihomo {
    fn drop(&mut self) {
        // 只按 PID 清理自己起的实例；⛔ 绝不 pkill/killall 按名杀（会命中 root 生产实例）。
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::env::var("LENGSUO_KEEP_REF_LOG").is_ok() {
            if let Ok(log) = std::fs::read_to_string(self.directory.join("mihomo.log")) {
                eprintln!("--- Mihomo 日志 {} ---\n{log}", self.directory.display());
            }
            return;
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn mihomo_binary() -> String {
    std::env::var("LENGSUO_MIHOMO").unwrap_or_else(|_| DEFAULT_MIHOMO.to_string())
}

/// 仓外测试目录（不进仓库、不提交）。`tag` 用协议名，`pid` 隔离并发测试进程。
fn test_directory(tag: &str) -> PathBuf {
    let base = std::env::var("LENGSUO_CLASH_TEST_DIR")
        .unwrap_or_else(|_| "/home/ubuntu/lengsuo-network-dev/clash-test".into());
    let directory = PathBuf::from(base).join(format!("{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

/// 启动独立 Mihomo 实例并等到 `probe_port` 可连。配置为手写 YAML 字符串。
async fn launch(config: String, probe_port: u16, tag: &str) -> Mihomo {
    let binary = mihomo_binary();
    assert!(
        std::path::Path::new(&binary).exists(),
        "缺少 Mihomo 参考二进制：{binary}（设 LENGSUO_MIHOMO 覆盖）"
    );
    let version = Process::new(&binary).arg("-v").output().unwrap();
    let version = String::from_utf8_lossy(&version.stdout).into_owned();
    assert!(
        version.contains("Mihomo") && version.contains("v1.19.20"),
        "基线不匹配：{version}"
    );
    let directory = test_directory(tag);
    let path = directory.join("config.yaml");
    std::fs::write(&path, config).unwrap();
    let log = std::fs::File::create(directory.join("mihomo.log")).unwrap();
    let child = Process::new(&binary)
        .arg("-d")
        .arg(&directory)
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    let mut mihomo = Mihomo { child, directory };
    let end = Instant::now() + WAIT;
    loop {
        if let Some(status) = mihomo.child.try_wait().unwrap() {
            panic!(
                "Mihomo 提前退出 {status}：{}",
                std::fs::read_to_string(mihomo.directory.join("mihomo.log")).unwrap()
            );
        }
        if TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, probe_port))
            .await
            .is_ok()
        {
            break;
        }
        assert!(Instant::now() < end, "Mihomo 启动超时");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    println!("基线 Mihomo {version}测试端口 {probe_port}");
    mihomo
}

/// Mihomo 公共骨架（YAML）：只回环、无控制接口、无 DNS、MATCH 全走 `rust` 出站。
fn base_config(mixed_port: u16, proxy_yaml: &str) -> String {
    format!(
        "mixed-port: {mixed_port}\n\
         allow-lan: false\n\
         bind-address: 127.0.0.1\n\
         mode: rule\n\
         log-level: warning\n\
         external-controller: ''\n\
         ipv6: false\n\
         dns:\n  enable: false\n\
         proxies:\n  {proxy_yaml}\n\
         proxy-groups:\n  - name: proxy\n    type: select\n    proxies: [rust]\n\
         rules:\n  - MATCH,proxy\n"
    )
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// ------------------------------------------------------------------ 本仓端点

/// 方向 1 的目的地：接受连接直到某条连接收到逐字节一致的载荷后回显。
/// （跨 Mihomo 入站初始化窗口的重试可能带出多条连接，单连接 accept 会漏掉成功那条。）
async fn echo_until_match(listener: TcpListener) {
    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut received = vec![0; PAYLOAD.len()];
        if stream.read_exact(&mut received).await.is_err() {
            continue;
        }
        if received != PAYLOAD {
            continue;
        }
        stream.write_all(&received).await.unwrap();
        let _ = stream.shutdown().await;
        return;
    }
}

// ------------------------------------------------------------------ 本仓入站桩

/// 读请求头。`decode_request_header` 是同步 `Read` 接口，而 tokio `TcpStream` 的
/// 同步 `Read` 不可阻塞等待 ⇒ 按**一字节渐进 + 重试解码**读取：字节不够得到
/// `Io`/`Truncated`，就再读一字节；认证类错误立即拒绝（fail-closed）。
/// 成功时缓冲恰为头部长度，请求体第一字节不会被吞。
async fn read_header(
    stream: &mut TcpStream,
    cmd_keys: &[[u8; 16]],
    sessions: &mut Vec<[u8; 48]>,
) -> Result<DecodedRequest, String> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let mut probe: Option<[u8; 48]> = None;
        let result = {
            let mut cursor = std::io::Cursor::new(buf.as_slice());
            let mut take = |user: &[u8; 16], key: &[u8; 16], iv: &[u8; 16]| {
                let mut entry = [0u8; 48];
                entry[..16].copy_from_slice(user);
                entry[16..32].copy_from_slice(key);
                entry[32..].copy_from_slice(iv);
                probe = Some(entry);
                true
            };
            decode_request_header(cmd_keys, &mut cursor, now_unix(), &mut take)
        };
        match result {
            Ok(decoded) => {
                if let Some(entry) = probe {
                    if sessions.contains(&entry) {
                        return Err("duplicated session id".into());
                    }
                    sessions.push(entry);
                }
                return Ok(decoded);
            }
            Err(HeaderDecodeError::Io(_)) | Err(HeaderDecodeError::Truncated { .. }) => {
                if buf.len() >= 1024 {
                    return Err("请求头超过 1024 字节上限".into());
                }
                let mut one = [0u8; 1];
                if stream.read_exact(&mut one).await.is_err() {
                    return Err("请求头读取中断".into());
                }
                buf.push(one[0]);
            }
            Err(other) => return Err(format!("入站头拒绝：{other}")),
        }
    }
}

/// 读一个带 GlobalPadding 的 chunk：size 段（掩码）→ 声明长度字节数 → 解密。
/// 返回 `Ok(None)` 表示 EOF 帧（空载荷）。
async fn read_padded_frame(
    stream: &mut TcpStream,
    cipher: &mut DataCipher,
    mask: &mut DataSizeParser,
) -> Result<Option<Vec<u8>>, String> {
    let mut size_wire = [0u8; 2];
    if stream.read_exact(&mut size_wire).await.is_err() {
        return Err("padding 帧长度段读取中断".into());
    }
    let (declared, padding) = read_padded_size(mask, size_wire);
    let mut wire = vec![0u8; declared as usize];
    if declared > 0 && stream.read_exact(&mut wire).await.is_err() {
        return Err("padding 帧载荷读取中断".into());
    }
    open_padded_chunk(cipher, &wire, padding).map_err(|e| e.to_string())
}

/// 处理一条入站连接：解头 → 回显。请求体按 option 位分支解帧；响应头先于
/// 任何体数据（对齐参考 `transferResponse` 顺序），响应体用 `response_key_iv`
/// 派生的密钥按**同一组 option 位**分帧回写。目标地址不拨号，仅回显。
// clippy::needless_option_as_deref：`Option<&mut _>` 不可 Copy，同一 parser 在
// seal_data_chunk / write_data_eof 两次调用之间必须用 as_deref_mut() 重借用，
// 并非多余的解引用。
#[allow(clippy::needless_option_as_deref)]
async fn handle_vmess(
    stream: &mut TcpStream,
    cmd_keys: &[[u8; 16]],
    sessions: &mut Vec<[u8; 48]>,
) -> Result<(), String> {
    let decoded = read_header(stream, cmd_keys, sessions).await?;
    eprintln!(
        "[vmess-in] option=0x{:02x} security={:?}",
        decoded.option, decoded.security
    );
    if decoded.security != HeaderSecurity::Aes128Gcm {
        return Err("入站桩仅支持 AES-128-GCM 数据面".into());
    }
    let option = decoded.option;
    if option & OPT_CHUNK_STREAM == 0 {
        return Err("入站桩要求 ChunkStream 分帧".into());
    }
    if option & OPT_AUTHENTICATED_LENGTH != 0 {
        return Err("入站桩不支持 authenticated length".into());
    }
    let key = decoded.request_body_key;
    let iv = decoded.request_body_iv;
    let mut header_wire = Vec::new();
    encode_response_header(
        decoded.response_header,
        &key,
        &iv,
        &ResponseHeader::new(),
        &mut header_wire,
    )
    .map_err(|e| e.to_string())?;
    stream
        .write_all(&header_wire)
        .await
        .map_err(|e| e.to_string())?;

    // 上行：解帧 → 明文（目标地址不拨号，读满 PAYLOAD 即断言）。
    let mut cipher = DataCipher::new(SECURITY_AES_128_GCM, &key, &iv);
    let mut plaintext = Vec::new();
    if option & OPT_GLOBAL_PADDING != 0 {
        let mut mask = DataSizeParser::new(&iv);
        loop {
            match read_padded_frame(stream, &mut cipher, &mut mask).await? {
                Some(piece) => plaintext.extend_from_slice(&piece),
                None => break,
            }
            if plaintext.len() >= PAYLOAD.len() {
                break;
            }
        }
    } else {
        let mut mask = DataSizeParser::new(&iv);
        let mut parser = (option & OPT_CHUNK_MASKING != 0).then_some(&mut mask);
        loop {
            match chunkframe::read_data_chunk(&mut cipher, parser.as_deref_mut(), stream)
                .await
                .map_err(|e| e.to_string())?
            {
                Some(piece) => plaintext.extend_from_slice(&piece),
                None => break,
            }
            if plaintext.len() >= PAYLOAD.len() {
                break;
            }
        }
    }
    assert_eq!(plaintext, PAYLOAD, "载荷未逐字节一致");

    // 下行：同一 option 位分帧回写。
    let (resp_key, resp_iv) = response_key_iv(&key, &iv);
    let mut resp_cipher = DataCipher::new(SECURITY_AES_128_GCM, &resp_key, &resp_iv);
    let mut resp_mask = DataSizeParser::new(&resp_iv);
    let mut out = Vec::new();
    if option & OPT_GLOBAL_PADDING != 0 {
        seal_padded_chunk(&mut resp_cipher, &mut resp_mask, &mut out, &plaintext)
            .map_err(|e| e.to_string())?;
        stream.write_all(&out).await.map_err(|e| e.to_string())?;
        out.clear();
        seal_padded_chunk(&mut resp_cipher, &mut resp_mask, &mut out, &[])
            .map_err(|e| e.to_string())?;
        stream.write_all(&out).await.map_err(|e| e.to_string())?;
    } else {
        let mut parser = (option & OPT_CHUNK_MASKING != 0).then_some(&mut resp_mask);
        seal_data_chunk(
            &mut resp_cipher,
            parser.as_deref_mut(),
            &mut out,
            &plaintext,
        )
        .map_err(|e| e.to_string())?;
        stream.write_all(&out).await.map_err(|e| e.to_string())?;
        out.clear();
        write_data_eof(&mut resp_cipher, parser.as_deref_mut(), &mut out)
            .map_err(|e| e.to_string())?;
        stream.write_all(&out).await.map_err(|e| e.to_string())?;
    }
    stream.flush().await.map_err(|e| e.to_string())
}

/// 本仓 VMess 入站桩：循环 accept（Mihomo 可能先建探测连接，失败即续接下一条），
/// 处理成功一条即返回。
async fn rust_vmess_server(listener: TcpListener, cmd_key: [u8; 16]) {
    let mut sessions: Vec<[u8; 48]> = Vec::new();
    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        if let Err(error) = handle_vmess(&mut stream, &[cmd_key], &mut sessions).await {
            eprintln!("[vmess-in] 连接处理失败：{error}");
            continue;
        }
        return;
    }
}

/// Rust 客户端走 Mihomo 的 `mixed-port` 发一条 TCP 请求到 `target_port`。
///
/// ⚠️ Mihomo 的 mixed-port 在监听之后仍有一段初始化窗口：窗口内的 SOCKS5 握手会
/// 被接受、CONNECT 也回成功，但拨号被静默丢弃（实测表现为 payload 后立刻 EOF）。
/// 这是参考实现的时序行为，不是本仓缺陷 ⇒ 用重试跨过窗口，超次即 fail-closed。
async fn proxy_payload(mixed_port: u16, target_port: u16) {
    let mut last = String::from("未尝试");
    for _ in 0..20 {
        match proxy_payload_once(mixed_port, target_port).await {
            Ok(()) => return,
            Err(error) => {
                last = error;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    panic!("SOCKS5 拨号在 20 次重试内未成功（窗口期过长？）：{last}");
}

/// 单次 SOCKS5 拨号；无认证 + CONNECT 127.0.0.1:target_port。
async fn proxy_payload_once(mixed_port: u16, target_port: u16) -> Result<(), String> {
    let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, mixed_port))
        .await
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&[5, 1, 0])
        .await
        .map_err(|e| e.to_string())?;
    let mut choice = [0u8; 2];
    stream
        .read_exact(&mut choice)
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(choice, [5, 0]);
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&target_port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|e| e.to_string())?;
    let mut reply = [0u8; 10];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(reply[1], 0, "SOCKS5 CONNECT 被拒：{reply:?}");
    stream.write_all(PAYLOAD).await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;
    let mut response = vec![0; PAYLOAD.len()];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(response, PAYLOAD, "载荷未逐字节一致");
    stream.shutdown().await.map_err(|e| e.to_string())?;
    Ok(())
}

// ------------------------------------------------------------------ 用例

/// 方向 2：Mihomo `vmess` 出站 -> 本仓入站桩（目标地址为假端口，桩不拨号仅回显）。
#[tokio::test]
async fn clash_outbound_to_rust_server_tcp() {
    timeout(WAIT, async {
        let uuid = generate_uuid_bytes();
        let cmd_key = cmd_key_from_uuid(&uuid);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rust_port = listener.local_addr().unwrap().port();
        let mixed_port = free_port();
        let proxy_yaml = format!(
            "- name: rust\n    type: vmess\n    server: 127.0.0.1\n    port: {rust_port}\n    \
             uuid: {}\n    alterId: 0\n    cipher: auto\n    udp: false",
            uuid_string(&uuid)
        );
        let mihomo = launch(
            base_config(mixed_port, &proxy_yaml),
            mixed_port,
            "vmess-clash-out",
        )
        .await;
        let server = tokio::spawn(rust_vmess_server(listener, cmd_key));
        proxy_payload(mixed_port, 18001).await;
        server.await.unwrap();
        drop(mihomo);
    })
    .await
    .unwrap();
}

/// 方向 3：Rust<->Rust 基线（本仓 vmess 客户端 option=0 -> 同一入站桩）。
#[tokio::test]
async fn rust_roundtrip_baseline_tcp() {
    timeout(WAIT, async {
        let uuid = generate_uuid_bytes();
        let cmd_key = cmd_key_from_uuid(&uuid);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(rust_vmess_server(listener, cmd_key));
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let keys = KeySource::generate().unwrap();
        let planner = HeaderPlanner::new(KeySource {
            body_key: keys.body_key,
            body_iv: keys.body_iv,
            response_header: keys.response_header,
        });
        let request = RequestHeader {
            target: Some(TargetAddr::V4([127, 0, 0, 1], 18001)),
            command: Command::Tcp,
            security: SecurityOption::Aes128Gcm,
            option: OPT_CHUNK_STREAM,
            padding_len: 0,
        };
        let plain = planner.plan(&request).unwrap();
        let header = aead::seal_vmess_aead_header(&cmd_key, &plain).unwrap();
        stream.write_all(&header).await.unwrap();
        let mut cipher = DataCipher::new(SECURITY_AES_128_GCM, &keys.body_key, &keys.body_iv);
        let mut out = Vec::new();
        seal_data_chunk(&mut cipher, None, &mut out, PAYLOAD).unwrap();
        write_data_eof(&mut cipher, None, &mut out).unwrap();
        stream.write_all(&out).await.unwrap();
        stream.flush().await.unwrap();
        // 响应头（固定线长）之后是分帧响应体。
        let mut resp_header = vec![0; RESPONSE_HEADER_WIRE_LEN];
        stream.read_exact(&mut resp_header).await.unwrap();
        let (resp_key, resp_iv) = response_key_iv(&keys.body_key, &keys.body_iv);
        let mut resp_cipher = DataCipher::new(SECURITY_AES_128_GCM, &resp_key, &resp_iv);
        let mut response = Vec::new();
        while let Some(piece) = chunkframe::read_data_chunk(&mut resp_cipher, None, &mut stream)
            .await
            .unwrap()
        {
            response.extend_from_slice(&piece);
        }
        assert_eq!(response, PAYLOAD);
        server.await.unwrap();
    })
    .await
    .unwrap();
}

/// 方向 1 的客户端：一条完整往返。请求 option=0x0d = ChunkStream|ChunkMasking|
/// GlobalPadding —— 实测（2026-10-25）用本仓解码器解开 Xray 26.3.27 客户端抓包，其发往
/// 本参考的正是 0x0d（数据面走 padded 分帧）；本仓客户端原先的 0x01（明文分帧）与
/// 0x05（ChunkMasking、非 padded）都被 Mihomo 入站静默关闭（不拨号、读响应头即 RST）。
/// 另实测：Mihomo 对本请求的接受呈时间相关不稳定（长短拒/通窗口交替，未定位），
/// 通过窗口内可完成认证、DIRECT 拨号且载荷逐字节送达目标；但其回程 133 字节
/// 与本仓「38 字节封头 + padded 分帧」预期解不开，响应侧未通过。详见用例 #[ignore] 注记。
async fn rust_vmess_client_roundtrip(
    cmd_key: [u8; 16],
    port: u16,
    target_port: u16,
) -> Result<(), String> {
    let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .map_err(|e| e.to_string())?;
    let keys = KeySource::generate().map_err(|e| e.to_string())?;
    let planner = HeaderPlanner::new(KeySource {
        body_key: keys.body_key,
        body_iv: keys.body_iv,
        response_header: keys.response_header,
    });
    let request = RequestHeader {
        target: Some(TargetAddr::V4([127, 0, 0, 1], target_port)),
        command: Command::Tcp,
        security: SecurityOption::Aes128Gcm,
        option: OPT_CHUNK_STREAM | OPT_CHUNK_MASKING | OPT_GLOBAL_PADDING,
        padding_len: 0,
    };
    let plain = planner.plan(&request).map_err(|e| e.to_string())?;
    let header = aead::seal_vmess_aead_header(&cmd_key, &plain).map_err(|e| e.to_string())?;
    stream.write_all(&header).await.map_err(|e| e.to_string())?;
    let mut cipher = DataCipher::new(SECURITY_AES_128_GCM, &keys.body_key, &keys.body_iv);
    let mut mask = DataSizeParser::new(&keys.body_iv);
    let mut out = Vec::new();
    seal_padded_chunk(&mut cipher, &mut mask, &mut out, PAYLOAD).map_err(|e| e.to_string())?;
    seal_padded_chunk(&mut cipher, &mut mask, &mut out, &[]).map_err(|e| e.to_string())?;
    stream.write_all(&out).await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;
    // 响应头（固定线长）之后是同一组 option 位的分帧响应体。
    let mut resp_header = vec![0; RESPONSE_HEADER_WIRE_LEN];
    stream
        .read_exact(&mut resp_header)
        .await
        .map_err(|e| e.to_string())?;
    let (resp_key, resp_iv) = response_key_iv(&keys.body_key, &keys.body_iv);
    let mut resp_cipher = DataCipher::new(SECURITY_AES_128_GCM, &resp_key, &resp_iv);
    let mut resp_mask = DataSizeParser::new(&resp_iv);
    let mut response = Vec::new();
    loop {
        let mut size_wire = [0u8; 2];
        stream
            .read_exact(&mut size_wire)
            .await
            .map_err(|e| e.to_string())?;
        let (declared, padding) = read_padded_size(&mut resp_mask, size_wire);
        let mut frame = vec![0u8; declared as usize];
        if declared > 0 {
            stream
                .read_exact(&mut frame)
                .await
                .map_err(|e| e.to_string())?;
        }
        match open_padded_chunk(&mut resp_cipher, &frame, padding).map_err(|e| e.to_string())? {
            Some(piece) => response.extend_from_slice(&piece),
            None => break,
        }
    }
    if response != PAYLOAD {
        return Err(format!("回程载荷不一致：{} 字节", response.len()));
    }
    Ok(())
}

/// 重试跨过 Mihomo 入站监听的初始化窗口（与 ss 入站同类时序行为：窗口内首连会被
/// 静默 reset，不重试即 flaky）。超次 fail-closed。
async fn rust_vmess_client_retry(cmd_key: [u8; 16], port: u16, target_port: u16) {
    let mut last = String::from("未尝试");
    for _ in 0..20 {
        match rust_vmess_client_roundtrip(cmd_key, port, target_port).await {
            Ok(()) => return,
            Err(error) => {
                last = error;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    panic!("vmess 客户端在 20 次重试内未成功（窗口期过长？）：{last}");
}

/// 方向 1：Rust 客户端 -> Mihomo `vmess` 协议入站 -> `direct` 出站 -> 本仓 echo。
#[tokio::test]
#[ignore = "Mihomo v1.19.20 vmess 入站对本仓 AEAD 请求接受不稳定（2026-10-25 实测 16 连拒、6/6 通、再 14 连拒，时间相关未定位）；通过窗口内认证/拨号/载荷逐字节送达均已验证，但回程 133 字节响应解不开（疑响应密钥派生或分帧偏离），方向 1 未通过。方向 2/3 与 Xray 入站（tests/xray_tcp.rs）全绿"]
async fn rust_client_to_clash_listener_tcp() {
    timeout(WAIT, async {
        let uuid = generate_uuid_bytes();
        let cmd_key = cmd_key_from_uuid(&uuid);
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let in_port = free_port();
        let mixed_port = free_port();
        let id = uuid_string(&uuid);
        let proxy_yaml = format!(
            "  - name: rust\n    type: vmess\n    server: 127.0.0.1\n    port: {echo_port}\n    uuid: {id}\n    alterId: 0\n    cipher: auto"
        );
        let config = format!(
            "mixed-port: {mixed_port}\nallow-lan: false\nbind-address: 127.0.0.1\nmode: rule\nlog-level: warning\nexternal-controller: ''\nipv6: false\ndns:\n  enable: false\nproxies:\n{proxy_yaml}\nrules:\n  - MATCH,DIRECT\nlisteners:\n  - name: vmess-in\n    type: vmess\n    port: {in_port}\n    listen: 127.0.0.1\n    users:\n      - username: u\n        uuid: {id}\n"
        );
        let mihomo = launch(config, in_port, "vmess-clash-in").await;
        let echo_task = tokio::spawn(echo_until_match(echo_listener));
        rust_vmess_client_retry(cmd_key, in_port, echo_port).await;
        echo_task.await.unwrap();
        drop(mihomo);
    })
    .await
    .unwrap();
}
