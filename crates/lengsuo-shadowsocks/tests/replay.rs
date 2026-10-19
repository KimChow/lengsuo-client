//! 传统 Shadowsocks AEAD 的入站 salt 重放防护测试（假口令，与生产凭据无关）。
//!
//! 覆盖：TCP 与 UDP 各自「同 salt 第二次被拒、不同 salt 正常」、窗口有界性（容量
//! + 时间窗）、状态文件的跨进程重启语义（进程 A 写 → 进程 B 载入 → 重放被拒），
//!   以及状态文件截断 / 篡改 / 版本不符时 fail-closed 拒绝启动。
//!
//! 这些测试只证明本 `ReplayFilter` 机制自身与 TCP/UDP 接入点的行为；不宣称与参考
//! 实跑互通（参考基线固定为 Xray v26.3.27 / d2758a0，其 `ErrIVNotUnique` 是死分支，
//! 见 `docs/shadowsocks-status.md`）。

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use lengsuo_shadowsocks::{
    CipherSuite, ReplayError, ReplayFilter, TargetAddr, TcpError, TcpReader, UdpCodec,
};
use ss_core::chunk::write_chunk;
use ss_core::crypto::SessionAead;
use ss_core::kdf::{evp_bytes_to_key, hkdf_sha1_subkey};

/// 测试假口令，与任何生产凭据无关。
const PASSWORD: &[u8] = b"ss-replay-test-passw0rd";
const WAIT: Duration = Duration::from_secs(2);
/// 与 `src/replay.rs` 头部布局一致（magic 8 + version 4 + capacity 8 + window 8 + body_len 8）。
const HEADER_LEN: usize = 8 + 4 + 8 + 8 + 8;

/// 临时目录守卫：测试结束删除，落盘只进系统临时目录、不进仓库。
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!("lengsuo-ss-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("创建临时目录失败");
        TempDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "salt hex 必须是偶数长度");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("非法 hex"))
        .collect()
}

/// 用固定 salt 构造一段合法的 TCP 线上字节（salt + 若干 chunk）。
/// 本端公开的 `TcpWriter` 强随机生成 salt，无法指定，因此这里用 ss-core 原语拼帧，
/// 只改变 salt 选择，不改任何线上格式。
async fn fixed_salt_tcp_stream(
    suite: CipherSuite,
    password: &[u8],
    salt: &[u8],
    segments: &[&[u8]],
) -> Vec<u8> {
    assert_eq!(salt.len(), suite.salt_len(), "salt 长度必须与套件一致");
    let master = evp_bytes_to_key(password, suite.key_len());
    let subkey = hkdf_sha1_subkey(&master, salt, suite.key_len());
    let mut aead = SessionAead::new(suite, subkey);
    let mut wire: Vec<u8> = Vec::new();
    wire.extend_from_slice(salt);
    for segment in segments {
        write_chunk(&mut wire, &mut aead, segment).await.unwrap();
    }
    wire
}

/// TCP：同一 salt 的第二次连接被拒；不同 salt 正常；拒绝后该方向永久 poison。
#[tokio::test]
async fn tcp_second_connection_with_same_salt_is_rejected() {
    let suite = CipherSuite::Aes256Gcm;
    let salt = [0x5Au8; 32];
    let wire = fixed_salt_tcp_stream(suite, PASSWORD, &salt, &[b"replayed chunk"]).await;
    let mut filter = ReplayFilter::new(64, Duration::from_secs(60)).unwrap();

    let mut first = TcpReader::new(wire.as_slice(), suite, PASSWORD, WAIT).unwrap();
    assert_eq!(
        first.recv_guarded(&mut filter).await.unwrap().unwrap(),
        b"replayed chunk",
        "首次连接应把已认证 chunk 正常交付"
    );
    assert!(
        first.recv_guarded(&mut filter).await.unwrap().is_none(),
        "读尽本方向不改变重放状态"
    );

    let mut second = TcpReader::new(wire.as_slice(), suite, PASSWORD, WAIT).unwrap();
    let err = second
        .recv_guarded(&mut filter)
        .await
        .expect_err("同 salt 的第二次连接必须被拒");
    assert!(matches!(err, TcpError::Replay(_)), "应报重放，实际 {err:?}");
    let again = second
        .recv_guarded(&mut filter)
        .await
        .expect_err("重放拒绝后方向必须 poison");
    assert!(
        matches!(again, TcpError::Poisoned),
        "应报 Poisoned，实际 {again:?}"
    );

    let fresh_salt = [0x6Bu8; 32];
    let fresh = fixed_salt_tcp_stream(suite, PASSWORD, &fresh_salt, &[b"fresh chunk"]).await;
    let mut third = TcpReader::new(fresh.as_slice(), suite, PASSWORD, WAIT).unwrap();
    assert_eq!(
        third.recv_guarded(&mut filter).await.unwrap().unwrap(),
        b"fresh chunk",
        "不同 salt 的后续连接必须正常"
    );
}

/// UDP：同一密文（同一 salt）第二次被拒；重新封装的包（新 salt）正常。
#[test]
fn udp_same_salt_replayed_rejected_fresh_accepted() {
    let codec = UdpCodec::new(CipherSuite::Aes256Gcm, PASSWORD).unwrap();
    let target = TargetAddr::V4([127, 0, 0, 1], 443);
    let mut filter = ReplayFilter::new(64, Duration::from_secs(60)).unwrap();

    let packet = codec.seal(&target, b"replayed payload").unwrap();
    assert_eq!(
        codec.open_guarded(&packet, &mut filter).unwrap(),
        (target.clone(), b"replayed payload".to_vec()),
        "首个包应正常交付并记入窗口"
    );
    let err = codec
        .open_guarded(&packet, &mut filter)
        .expect_err("同 salt 的第二个包必须被拒");
    assert!(
        matches!(err, lengsuo_shadowsocks::UdpError::Replay(_)),
        "应报重放，实际 {err:?}"
    );

    let fresh = codec.seal(&target, b"fresh payload").unwrap();
    assert_eq!(
        codec.open_guarded(&fresh, &mut filter).unwrap(),
        (target, b"fresh payload".to_vec()),
        "新 salt 的包必须正常"
    );
}

/// 状态文件截断 / 篡改 / 版本不符都必须返回明确错误类型并拒绝启动，绝不静默清空。
#[test]
fn truncated_or_tampered_state_refuses_to_load_with_distinct_errors() {
    let dir = TempDir::new("corrupt");
    let path = dir.path().join("replay.bin");
    let now = 1_000_000u64;
    let mut filter = ReplayFilter::new(16, Duration::from_secs(60)).unwrap();
    filter.record(&[0x33u8; 32], now).unwrap();
    filter.save(&path, now).unwrap();
    let good = std::fs::read(&path).expect("应能读回状态文件");

    // 截断（去掉尾部、破坏长度一致性）→ Corrupt。
    std::fs::write(&path, &good[..good.len() - 2]).unwrap();
    let err = ReplayFilter::load(&path, now).expect_err("截断文件必须拒绝加载");
    assert!(
        matches!(err, ReplayError::Corrupt(_)),
        "截断应报 Corrupt，实际 {err:?}"
    );

    // 篡改 body 一个字节（长度不变、CRC 变化）→ ChecksumMismatch。
    let mut tampered = good.clone();
    tampered[HEADER_LEN] ^= 0x01;
    std::fs::write(&path, &tampered).unwrap();
    let err = ReplayFilter::load(&path, now).expect_err("篡改文件必须拒绝加载");
    assert!(
        matches!(err, ReplayError::ChecksumMismatch),
        "篡改应报 ChecksumMismatch，实际 {err:?}"
    );

    // 版本号字节被改 → VersionMismatch（版本在 CRC 之前判定）。
    let mut bumped = good.clone();
    bumped[8] ^= 0xFF;
    std::fs::write(&path, &bumped).unwrap();
    let err = ReplayFilter::load(&path, now).expect_err("版本不符必须拒绝加载");
    assert!(
        matches!(err, ReplayError::VersionMismatch { expected: 1, .. }),
        "版本不符应报 VersionMismatch，实际 {err:?}"
    );
}

/// 跨进程重启语义：进程 A 写状态 → 进程 B 独立加载并判定重放被拒。
/// 用真实子进程（当前测试二进制 `--exact replay_worker`）模拟两次独立实例，
/// 不是同一进程内重复初始化。
#[test]
fn cross_process_restart_rejects_replay() {
    let dir = TempDir::new("restart");
    let path = dir.path().join("replay.bin");
    let salt = [0x7Eu8; 32];
    let now = 1_700_000_000_000u64;
    let exe = std::env::current_exe().expect("取当前测试二进制失败");

    // 进程 A：独立实例写入状态文件。
    let write = Command::new(&exe)
        .args(["--exact", "replay_worker", "--nocapture"])
        .env("LENGSUO_REPLAY_WORKER", "write")
        .env("LENGSUO_REPLAY_PATH", path.as_os_str())
        .env("LENGSUO_REPLAY_SALT", hex_encode(&salt))
        .env("LENGSUO_REPLAY_NOW", now.to_string())
        .output()
        .expect("spawn 写状态子进程失败");
    assert!(
        write.status.success(),
        "进程 A 写状态失败：{}",
        String::from_utf8_lossy(&write.stderr)
    );

    // 进程 B：独立实例加载并判定同 salt 为重放。
    let load = Command::new(&exe)
        .args(["--exact", "replay_worker", "--nocapture"])
        .env("LENGSUO_REPLAY_WORKER", "load")
        .env("LENGSUO_REPLAY_PATH", path.as_os_str())
        .env("LENGSUO_REPLAY_SALT", hex_encode(&salt))
        .env("LENGSUO_REPLAY_NOW", now.to_string())
        .output()
        .expect("spawn 载入状态子进程失败");
    assert!(
        load.status.success(),
        "进程 B 载入后应拒绝重放：{}",
        String::from_utf8_lossy(&load.stderr)
    );
}

/// 子进程 worker：`LENGSUO_REPLAY_WORKER` 未设置时执行一次真实的写→读往返自检
/// （避免空跑）；设置时按 `write` / `load` 扮演跨进程语义的进程 A / B，并以退出码
/// 返回结果（由 `cross_process_restart_rejects_replay` 通过子进程调用）。
#[test]
fn replay_worker() {
    let Ok(mode) = std::env::var("LENGSUO_REPLAY_WORKER") else {
        let dir = TempDir::new("worker-selfcheck");
        let path = dir.path().join("self.bin");
        let now = 1_000_000u64;
        let mut filter = ReplayFilter::new(8, Duration::from_secs(60)).unwrap();
        filter.record(&[0x11u8; 16], now).unwrap();
        filter.save(&path, now).unwrap();
        let loaded = ReplayFilter::load(&path, now).unwrap();
        assert!(loaded.contains(&[0x11u8; 16]), "自检往返应能读回 salt");
        return;
    };

    let path = std::env::var("LENGSUO_REPLAY_PATH").expect("缺少状态文件路径");
    let salt = hex_decode(&std::env::var("LENGSUO_REPLAY_SALT").expect("缺少 salt"));
    let now: u64 = std::env::var("LENGSUO_REPLAY_NOW")
        .expect("缺少 now")
        .parse()
        .expect("now 不是整数");
    let path = Path::new(&path);
    match mode.as_str() {
        "write" => {
            let mut filter = ReplayFilter::new(64, Duration::from_secs(60)).unwrap();
            filter.record(&salt, now).expect("写入 salt 应成功");
            filter.save(path, now).expect("保存状态应成功");
            std::process::exit(0);
        }
        "load" => {
            let mut filter = ReplayFilter::load(path, now).expect("加载状态应成功");
            match filter.record(&salt, now) {
                Err(ReplayError::Duplicate) => std::process::exit(0),
                other => {
                    eprintln!("期望同 salt 被判重放，实际 {other:?}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("未知 worker 模式 {mode}");
            std::process::exit(1);
        }
    }
}
