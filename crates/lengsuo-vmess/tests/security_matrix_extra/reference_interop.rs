//! 与**真实 Xray** 的档位互通取证（`#[ignore]`，需 `LENGSUO_XRAY`）。
//!
//! 语义基线：Xray commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。
//!
//! 运行方式：
//! ```text
//! LENGSUO_XRAY=~/ref/bin/xray cargo test -p lengsuo-vmess \
//!     --test security_matrix_extra --locked -- --ignored --nocapture
//! ```
//!
//! ## 为什么需要它
//!
//! 本卡的「档位不一致 ⇒ fail-closed」在**纯本仓**测试里只能证明本仓自己的
//! 两端自洽。要证明**与参考一致**，必须有参考实跑证据：
//!
//! 1. **逐档互通**：本仓客户端 → Xray 入站，三档各跑一遍，回程载荷逐字节一致
//!    （证明本仓的档位语义与参考的 `switch request.Security` 一致）。
//! 2. **降级不可行**：把本仓客户端的**数据段**换成 `none` 明文，但**头里声明**
//!    `aes-128-gcm`，打给 Xray 入站 ⇒ Xray 必须**拒绝**（不回数据）。
//!    这条直接验证「档位不一致必须握手失败，不是降级到明文」。
//!
//! ## 参考依据
//!
//! - `proxy/vmess/encoding/server.go:203`：服务端按**请求头**的 security 字节
//!   定档（`parseSecurityType`）⇒ 头里声明 AES、数据段发明文 ⇒ 按 AES 解 ⇒
//!   `common/crypto/auth.go:readInternal` 的 `r.auth.Open` 失败 ⇒ 连接断开。
//! - `proxy/vmess/encoding/server.go:242-243`：`UNKNOWN` / `AUTO` ⇒ 头阶段拒。
//! - `proxy/vmess/encoding/server.go:323`：`ZERO` 等其余档 ⇒ 体阶段
//!   `invalid option: Security`。

use std::path::PathBuf;
use std::time::Duration;

use lengsuo_vmess::aead;
use lengsuo_vmess::bodyframe::{BodyFrame, BodySuite, ChunkStreamFrame};
use lengsuo_vmess::chunkframe::DataSizeParser;
use lengsuo_vmess::request::{Command, HeaderPlanner, KeySource, RequestHeader, SecurityOption};
use ss_core::target::TargetAddr;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use super::refhelpers::{
    cmd_key_from_uuid, response_key_iv, spawn_echo, spawn_echo_counted, uuid_bytes, uuid_string,
};

/// 连接超时。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// 回程超时。
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
/// 固定 unix 秒（构造确定性 AuthID 用）。
///
/// ⛔ **参考侧不能用固定的历史时间**：`proxy/vmess/aead/authid.go:110` 的
/// `math.Abs(... - time.Now().Unix()) > 120` ⇒ 超过 120 秒的旧时间戳会被
/// 参考判成 `ErrInvalidTime`（用户校验阶段就拒），**根本到不了安全档判定**。
/// 所以打给参考的 AuthID 必须用**当前时间**；本仓自己的单元测试用固定
/// `NOW`（`common.rs`）是安全的，因为那走本仓的 `decode_request_header`
/// 显式传入时间。
const NOW: i64 = 1_700_000_000;

/// 假载荷（不含任何真实凭据）。
const PAYLOAD: &[u8] = b"vmess-security-matrix-extra-probe";

/// 惰性获取参考二进制；未设置时打印原因并返回 `None`（调用方 `return` 跳过）。
fn xray_bin() -> Option<PathBuf> {
    match std::env::var_os("LENGSUO_XRAY") {
        Some(path) => Some(PathBuf::from(path)),
        None => {
            eprintln!(
                "SKIP: 环境变量 LENGSUO_XRAY 未设置，跳过参考互通用例。\
                 原因：没有参考二进制可拉起，无法证明与参考的档位语义一致。"
            );
            None
        }
    }
}

/// 拉起一个 Xray VMess 入站（127.0.0.1，临时端口，UUID 为随机假凭据）。
///
/// 用参考二进制自己的 `run -c` 起进程；配置里只放一个 inbound（vmess）
/// 与一个 outbound（freedom）。UID 由调用方生成，**不打印**。
fn start_xray_inbound(bin: &PathBuf, uuid: &str) -> Result<(u16, std::process::Child), String> {
    // 端口探测：bind 0 后立即释放（与本仓既有夹具同一手法，不新增依赖）。
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| format!("探测空闲端口失败: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("取端口失败: {e}"))?
        .port();
    drop(listener);

    let dir = std::env::temp_dir().join(format!(
        "lengsuo-vmess-extra-{}-{}",
        std::process::id(),
        port
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建临时目录失败: {e}"))?;
    let cfg_path = dir.join("config.json");
    let config = format!(
        concat!(
            "{{\"log\":{{\"loglevel\":\"warning\"}},",
            "\"inbounds\":[{{\"tag\":\"vmess-in\",\"listen\":\"127.0.0.1\",\"port\":{port},",
            "\"protocol\":\"vmess\",\"settings\":{{\"clients\":[{{\"id\":\"{uuid}\",\"alterId\":0}}]}},",
            "\"streamSettings\":{{\"network\":\"tcp\"}}}}],",
            "\"outbounds\":[{{\"tag\":\"direct\",\"protocol\":\"freedom\",\"settings\":{{}}}}]}}"
        ),
        port = port,
        uuid = uuid,
    );
    std::fs::write(&cfg_path, &config).map_err(|e| format!("写配置失败: {e}"))?;
    let child = std::process::Command::new(bin)
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn xray 失败: {e}"))?;

    // 等端口就绪（有上限）。
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            return Ok((port, child));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut child = child;
    let _ = child.kill();
    let _ = child.wait();
    Err(format!("Xray 入站端口 {port} 在超时内未就绪"))
}

/// 本仓客户端 → Xray 入站 → 本地回显后端：回程载荷必须逐字节一致。
///
/// 逐档跑（`none` / `aes-128-gcm` / `chacha20-poly1305`）。
#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn every_tier_roundtrips_against_real_xray() {
    let Some(bin) = xray_bin() else { return };

    let uuid_bytes = uuid_bytes();
    let uuid = uuid_string(&uuid_bytes);
    let cmd_key = cmd_key_from_uuid(&uuid_bytes);
    let (echo_addr, echo_handle) = spawn_echo().await;

    // 参考的入站**不看**账号档位（`proxy/vmess/inbound/inbound.go` 全文无
    // `Security` 引用）⇒ 一个入站即可服务三档；档位由**请求头**决定
    // （`proxy/vmess/encoding/server.go:203`）。
    let (port, mut child) = match start_xray_inbound(&bin, &uuid) {
        Ok(v) => v,
        Err(report) => {
            eprintln!("{report}");
            panic!("启动 Xray 失败");
        }
    };

    for (tier, option) in [
        ("none", 0x01u8 | 0x04),
        ("aes-128-gcm", 0x01 | 0x04 | 0x08),
        ("chacha20-poly1305", 0x01 | 0x04 | 0x08),
    ] {
        let keys = KeySource::generate().expect("生成会话密钥");
        let target = TargetAddr::V4([127, 0, 0, 1], echo_addr.port());
        let security = match tier {
            "none" => SecurityOption::None,
            "aes-128-gcm" => SecurityOption::Aes128Gcm,
            _ => SecurityOption::ChaCha20Poly1305,
        };
        let plain = HeaderPlanner::new(KeySource {
            body_key: keys.body_key,
            body_iv: keys.body_iv,
            response_header: keys.response_header,
        })
        .plan_with(
            &RequestHeader {
                target: Some(target),
                command: Command::Tcp,
                security,
                option,
                padding_len: 0,
            },
            &[],
        )
        .expect("请求头明文可编码");
        let header = aead::seal_vmess_aead_header(&cmd_key, &plain).expect("请求头可封");

        let mut stream =
            tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(("127.0.0.1", port)))
                .await
                .expect("连接不超时")
                .expect("可连接");
        let echoed = tokio::time::timeout(RESPONSE_TIMEOUT, async {
            stream.write_all(&header).await.expect("可写头");
            if tier == "none" {
                // 参考 NONE 分支：chunk-stream（明文载荷、无 padding）。
                let mut frame = ChunkStreamFrame::with_iv(option, &keys.body_iv);
                frame
                    .write_to(&mut stream, PAYLOAD)
                    .await
                    .expect("可写载荷");
                frame.write_eof(&mut stream).await.expect("可写 EOF");
            } else {
                let suite = if tier == "aes-128-gcm" {
                    BodySuite::Aes128Gcm
                } else {
                    BodySuite::ChaCha20Poly1305
                };
                let mut frame = BodyFrame::for_request(
                    suite,
                    &keys.body_key,
                    &keys.body_iv,
                    &keys.body_key,
                    &keys.body_iv,
                    option,
                )
                .expect("帧上下文可建");
                frame
                    .write_to(&mut stream, PAYLOAD)
                    .await
                    .expect("可写载荷");
                frame.write_to(&mut stream, b"").await.expect("可写 EOF");
            }
            stream.flush().await.expect("可刷写");
            // 读响应头（38 字节）+ 响应体。
            let mut resp = [0u8; 38];
            stream.read_exact(&mut resp).await.expect("可读响应头");
            let (resp_key, resp_iv) = response_key_iv(&keys.body_key, &keys.body_iv);
            let mut out = Vec::new();
            if tier == "none" {
                let mut frame = ChunkStreamFrame::with_iv(option, &resp_iv);
                loop {
                    match frame.read_from(&mut stream).await {
                        Ok(Some(plain)) => out.extend_from_slice(&plain),
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
            } else {
                let suite = if tier == "aes-128-gcm" {
                    BodySuite::Aes128Gcm
                } else {
                    BodySuite::ChaCha20Poly1305
                };
                let mut frame = BodyFrame::for_request(
                    suite,
                    &resp_key,
                    &resp_iv,
                    &keys.body_key,
                    &keys.body_iv,
                    option,
                )
                .expect("响应帧上下文可建");
                loop {
                    match frame.read_from(&mut stream).await {
                        Ok(Some(plain)) => out.extend_from_slice(&plain),
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
            }
            out
        })
        .await
        .expect("回程不超时");

        assert_eq!(
            echoed,
            PAYLOAD,
            "档位 {tier} 的回程载荷必须逐字节一致（实际 {} 字节）",
            echoed.len()
        );
        eprintln!(
            "OK 档位={tier} 参考互通：回程 {} 字节逐字节一致",
            echoed.len()
        );
    }

    let _ = child.kill();
    let _ = child.wait();
    drop(echo_handle);
}

/// **档位不一致 ⇒ 参考必须拒绝**（不降级到明文）。
///
/// 头里声明 `aes-128-gcm`，数据段却用 `none` 明文 ⇒ 参考按头里的档位
/// （`server.go:203`）用 AES 解 ⇒ tag 失败 ⇒ 连接被断开、**不回数据**。
///
/// 这条是本卡安全关键路径的**参考实跑证据**。
#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn real_xray_rejects_tier_mismatch_instead_of_downgrading() {
    let Some(bin) = xray_bin() else { return };

    let uuid_bytes = uuid_bytes();
    let uuid = uuid_string(&uuid_bytes);
    let cmd_key = cmd_key_from_uuid(&uuid_bytes);
    let (echo_addr, echo_handle) = spawn_echo().await;

    let (port, mut child) = match start_xray_inbound(&bin, &uuid) {
        Ok(v) => v,
        Err(report) => {
            eprintln!("{report}");
            panic!("启动 Xray 失败");
        }
    };

    let keys = KeySource::generate().expect("生成会话密钥");
    let target = TargetAddr::V4([127, 0, 0, 1], echo_addr.port());
    // 头里声明 aes-128-gcm。
    let plain = HeaderPlanner::new(KeySource {
        body_key: keys.body_key,
        body_iv: keys.body_iv,
        response_header: keys.response_header,
    })
    .plan_with(
        &RequestHeader {
            target: Some(target),
            command: Command::Tcp,
            security: SecurityOption::Aes128Gcm,
            option: 0x01 | 0x04 | 0x08,
            padding_len: 0,
        },
        &[],
    )
    .expect("请求头明文可编码");
    let header = aead::seal_vmess_aead_header(&cmd_key, &plain).expect("请求头可封");

    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(("127.0.0.1", port)))
        .await
        .expect("连接不超时")
        .expect("可连接");
    stream.write_all(&header).await.expect("可写头");
    // 数据段：用 none 档（明文载荷）——与头里声明的档**不一致**。
    let mut parser = DataSizeParser::new(&keys.body_iv);
    let len_wire = parser.encode_size(PAYLOAD.len() as u16);
    stream.write_all(&len_wire).await.expect("可写长度段");
    stream.write_all(PAYLOAD).await.expect("可写明文载荷");
    let _ = stream.flush().await;

    // 参考必须拒绝 ⇒ 读不到任何响应数据（EOF 或超时），且绝不回显明文。
    let mut rest = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest)).await;
    match read {
        Ok(result) => assert_eq!(
            result.unwrap_or(0),
            0,
            "参考必须拒绝档位不一致的请求（不得回数据），实际回 {} 字节",
            rest.len()
        ),
        Err(_) => {
            // 超时 = 参考没交付任何数据；再确认没有明文回显。
            assert!(
                !rest.windows(PAYLOAD.len()).any(|w| w == PAYLOAD),
                "参考不得回显明文载荷"
            );
        }
    }
    eprintln!(
        "OK 参考拒绝档位不一致（头声明 aes-128-gcm / 数据段 none 明文）：\
         参考未回显明文（收到 {} 字节）",
        rest.len()
    );

    let _ = child.kill();
    let _ = child.wait();
    drop(echo_handle);
}

/// **`zero` 档必须被参考拒绝**（补上一版只有代码级对齐、没有实跑的缺口）。
///
/// 参考事实（固定 commit `d2758a02`）：
/// - 头阶段：`proxy/vmess/encoding/server.go:114-124` 的 `parseSecurityType`
///   认得 6 ⇒ `SecurityType_ZERO` ⇒ **头阶段放行**（不被 `:242-243` 的
///   `UNKNOWN`/`AUTO` 判定拦下）。
/// - 体阶段：`server.go:264-323` 的 `switch request.Security` **没有** `ZERO`
///   分支 ⇒ 落 `default:` ⇒ `invalid option: Security`。
///
/// ⇒ `zero` 档的请求**能过参考的头阶段、但过不了体阶段** ⇒ 参考必须
/// **不转发到后端**（后端连接数必须为 0）且**不回任何数据**。
///
/// 本仓客户端**没有** `SecurityOption::Zero`（`request.rs:82-97` 只有
/// None/Aes/ChaCha/AutoCipher）⇒ 这里手工构造：把请求头明文第 35 字节的
/// security 低 4 位改成 6，**重算 FNV 尾部**（FNV 覆盖整个明文含 security
/// 字节，不重算会先被校验和拒掉，测不到 security 判定），再封头。
#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn real_xray_rejects_the_zero_security_tier() {
    let Some(bin) = xray_bin() else { return };

    let uuid_bytes = uuid_bytes();
    let uuid = uuid_string(&uuid_bytes);
    let cmd_key = cmd_key_from_uuid(&uuid_bytes);
    // 带计数的回显后端：用来区分「参考拒绝了」与「参考转发了但没回数据」。
    let (echo_addr, echo_handle, accepts) = spawn_echo_counted().await;

    let (port, mut child) = match start_xray_inbound(&bin, &uuid) {
        Ok(v) => v,
        Err(report) => {
            eprintln!("{report}");
            panic!("启动 Xray 失败");
        }
    };

    let keys = KeySource::generate().expect("生成会话密钥");
    let target = TargetAddr::V4([127, 0, 0, 1], echo_addr.port());
    let mut plain = HeaderPlanner::new(KeySource {
        body_key: keys.body_key,
        body_iv: keys.body_iv,
        response_header: keys.response_header,
    })
    .plan_with(
        &RequestHeader {
            target: Some(target),
            command: Command::Tcp,
            // 用一个本仓**支持**的档构造明文，随后把线上字节改写成 zero。
            security: SecurityOption::Aes128Gcm,
            option: 0x01 | 0x04 | 0x08,
            padding_len: 0,
        },
        &[],
    )
    .expect("请求头明文可编码");
    // 改写 security 低 4 位 = 6（ZERO），并重算 FNV 尾部。
    plain[35] = (plain[35] & 0xF0) | 0x06;
    let body_len = plain.len() - 4;
    let tail = lengsuo_vmess::request::fnv1a32(&plain[..body_len]).to_be_bytes();
    plain[body_len..].copy_from_slice(&tail);

    // ⛔ AuthID 必须用**当前时间**：参考 `proxy/vmess/aead/authid.go:110` 对
    // 超过 120 秒的时间戳判 `ErrInvalidTime`（用户校验阶段就拒）⇒ 用固定的
    // 历史时间戳会**在到不了安全档判定之前**就被拒，测出来的是「用户校验
    // 失败」而不是「zero 档被拒」，那种用例是**假绿**。
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("系统时间")
        .as_secs() as i64;
    let auth = lengsuo_vmess::create_auth_id_with(&cmd_key, now, &[0x01, 0x02, 0x03, 0x04]);
    let header = aead::seal_header_with(&cmd_key, auth.as_bytes(), &[0x11; 8], &plain);
    let opened =
        lengsuo_vmess::aead::open_vmess_aead_header(&cmd_key, auth.as_bytes(), &header[16..])
            .expect("本仓自己封的头必须能解开");
    assert_eq!(
        opened[35] & 0x0F,
        6,
        "打给参考的请求头 security 字节必须是 6（ZERO）"
    );

    // ---- 对照组（differential control）----
    //
    // ⛔ 没有对照组，「参考拒绝」这句话是**不可归因**的：拒绝可能来自
    // 用户校验 / 时间窗 / FNV / 地址解析 / 体阶段，**任何**一个。
    // 对照组用**完全相同**的头（只把 security 字节从 6 改成 3）＋**完全
    // 相同**的数据段形状 ⇒ 它必须**成功**（回显逐字节一致、且后端被连上）。
    // 两者一成一败 ⇒ 拒绝的**唯一变量**就是 security 字节。
    {
        let mut control_plain = plain.clone();
        control_plain[35] = (control_plain[35] & 0xF0) | 0x03;
        let bl = control_plain.len() - 4;
        let t = lengsuo_vmess::request::fnv1a32(&control_plain[..bl]).to_be_bytes();
        control_plain[bl..].copy_from_slice(&t);
        let control_header =
            aead::seal_header_with(&cmd_key, auth.as_bytes(), &[0x22; 8], &control_plain);
        let mut ctl =
            tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(("127.0.0.1", port)))
                .await
                .expect("对照组连接不超时")
                .expect("对照组可连接");
        ctl.write_all(&control_header).await.expect("对照组可写头");
        let mut ctl_frame = BodyFrame::for_request(
            BodySuite::Aes128Gcm,
            &keys.body_key,
            &keys.body_iv,
            &keys.body_key,
            &keys.body_iv,
            0x01 | 0x04 | 0x08,
        )
        .expect("对照组帧上下文可建");
        ctl_frame
            .write_to(&mut ctl, PAYLOAD)
            .await
            .expect("对照组可写载荷");
        ctl_frame
            .write_to(&mut ctl, b"")
            .await
            .expect("对照组可写 EOF");
        let _ = ctl.flush().await;
        // 响应**是加密的**（数据段用响应方向的 key/iv）⇒ 必须解密后比对，
        // 不能在原始字节里找明文。
        let mut ctl_back = Vec::new();
        let ctl_read = tokio::time::timeout(Duration::from_secs(10), async {
            let mut resp = [0u8; 38];
            ctl.read_exact(&mut resp).await.expect("对照组可读响应头");
            let (resp_key, resp_iv) = response_key_iv(&keys.body_key, &keys.body_iv);
            let mut resp_frame = BodyFrame::for_request(
                BodySuite::Aes128Gcm,
                &resp_key,
                &resp_iv,
                &keys.body_key,
                &keys.body_iv,
                0x01 | 0x04 | 0x08,
            )
            .expect("对照组响应帧上下文可建");
            loop {
                match resp_frame.read_from(&mut ctl).await {
                    Ok(Some(plain)) => ctl_back.extend_from_slice(&plain),
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        })
        .await;
        assert!(
            ctl_read.is_ok(),
            "对照组（security=3）必须成功完成响应（否则 zero 组的拒绝不可归因）"
        );
        assert_eq!(
            ctl_back, PAYLOAD,
            "对照组（security=3）必须成功并回显逐字节一致（否则 zero 组的拒绝不可归因）"
        );
        // 等后端连接计数落定，供后面的 zero 组做差值。
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let accepts_after_control = accepts.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        accepts_after_control >= 1,
        "对照组必须真的连上后端（后端连接数 = {accepts_after_control}）"
    );

    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(("127.0.0.1", port)))
        .await
        .expect("连接不超时")
        .expect("可连接");
    stream.write_all(&header).await.expect("可写头");
    // 数据段随便发一点（参考在体阶段就会拒，用不到这段）。
    let mut parser = DataSizeParser::new(&keys.body_iv);
    let len_wire = parser.encode_size(PAYLOAD.len() as u16);
    stream.write_all(&len_wire).await.expect("可写长度段");
    stream.write_all(PAYLOAD).await.expect("可写载荷");
    let _ = stream.flush().await;

    // 参考必须拒绝 ⇒ 读不到任何响应数据（EOF 或超时），且绝不回显明文。
    let mut rest = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest)).await;
    match read {
        Ok(result) => assert_eq!(
            result.unwrap_or(0),
            0,
            "参考必须拒绝 zero 档请求（不得回数据），实际回 {} 字节",
            rest.len()
        ),
        Err(_) => {
            assert!(
                !rest.windows(PAYLOAD.len()).any(|w| w == PAYLOAD),
                "参考不得回显明文载荷"
            );
        }
    }
    // 关键判据：参考**不得**把 zero 档请求的载荷当成正常数据交付给客户端。
    //
    // ⛔ 注意参考的**处理顺序**：`proxy/vmess/inbound/inbound.go:281` 的
    // `dispatcher.Dispatch(...)`（连后端）发生在 `:289` 的
    // `svrSession.DecodeRequestBody(request, reader)`（体阶段解帧）**之前**
    // ⇒ 参考在体阶段拒 zero 档时，**后端可能已经被连上了**。
    // 所以判据是**客户端可观测**的那一侧：零字节响应、且绝不回显明文。
    // 后端连接数只做**记录**（对照组基线 vs zero 组），不作硬断言。
    let accepts_after_zero = accepts.load(std::sync::atomic::Ordering::SeqCst);
    eprintln!(
        "OK 参考拒绝 zero 档请求：未回数据（{} 字节）；后端连接数 对照组={} zero 组={} \
         （参考先 dispatch 后解体 ⇒ 后端可能被连上，判据取客户端可观测侧）",
        rest.len(),
        accepts_after_control,
        accepts_after_zero
    );

    let _ = child.kill();
    let _ = child.wait();
    drop(echo_handle);
}
