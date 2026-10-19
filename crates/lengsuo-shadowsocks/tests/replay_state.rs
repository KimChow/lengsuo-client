//! 重放状态文件的**密钥化完整性**（HMAC-SHA256）持久化测试（测试密钥与生产无关）。
//!
//! 覆盖：MAC 正确 → 正常恢复；状态体单字节改动 → 拒绝（本卡核心价值，独立用例）；
//! 截断 / 空文件 / 只有前缀 / 未知版本 / 密钥不匹配 → 拒绝；旧密钥签名 → 接受并升级
//! 重写、升级后旧密钥不再可用；原子写失败不破坏原文件。全部 fail-closed。
//!
//! 这些测试只证明 `persist` + `ReplayFilter` 的状态文件语义；跨进程重启与 TCP/UDP
//! 接入点行为见 `tests/replay.rs`。

use std::path::{Path, PathBuf};
use std::time::Duration;

use lengsuo_shadowsocks::{MacKey, ReplayError, ReplayFilter};

/// 状态文件布局：magic(8) + version(4) + body_len(8) + body + hmac(32)。
/// 正文（body）起始偏移与标签长度：mac 前缀 = magic + version + body_len = 20。
const BODY_OFFSET: usize = 8 + 4 + 8;
/// HMAC-SHA256 标签长度。
const MAC_LEN: usize = 32;

/// 测试密钥（与任何生产密钥无关）；当前密钥与上一代密钥各一。
fn current_key() -> MacKey {
    MacKey::new(b"replay-state-key-current".to_vec())
}

fn previous_key() -> MacKey {
    MacKey::new(b"replay-state-key-previous".to_vec())
}

/// 临时目录守卫：测试结束删除，落盘只进系统临时目录、不进仓库。
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("lengsuo-ss-state-{tag}-{}", std::process::id()));
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

/// 状态文件截断 / 篡改 / 版本不符都必须返回明确错误类型并拒绝启动，绝不静默清空。
/// 本卡把完整性校验从 CRC-32 换成 HMAC-SHA256：**任何**单字节改动都让标签失配。
#[test]
fn truncated_or_tampered_state_refuses_to_load_with_distinct_errors() {
    let dir = TempDir::new("corrupt");
    let path = dir.path().join("replay.bin");
    let key = current_key();
    let now = 1_000_000u64;
    let mut filter = ReplayFilter::new(16, Duration::from_secs(60)).unwrap();
    filter.record(&[0x33u8; 32], now).unwrap();
    filter.save_with_key(&path, now, &key).unwrap();
    let good = std::fs::read(&path).expect("应能读回状态文件");

    // 截断（去掉尾部、破坏长度一致性）→ Corrupt。
    std::fs::write(&path, &good[..good.len() - 2]).unwrap();
    let err =
        ReplayFilter::load_with_keys(&path, now, &key, None).expect_err("截断文件必须拒绝加载");
    assert!(
        matches!(err, ReplayError::Corrupt(_)),
        "截断应报 Corrupt，实际 {err:?}"
    );

    // 篡改 body 一个字节（长度不变、HMAC 失配）→ MacMismatch。
    let mut tampered = good.clone();
    tampered[BODY_OFFSET] ^= 0x01;
    std::fs::write(&path, &tampered).unwrap();
    let err =
        ReplayFilter::load_with_keys(&path, now, &key, None).expect_err("篡改文件必须拒绝加载");
    assert!(
        matches!(err, ReplayError::MacMismatch),
        "篡改应报 MacMismatch，实际 {err:?}"
    );

    // 版本号字节被改 → VersionMismatch（版本在 MAC 之前判定）。
    let mut bumped = good.clone();
    bumped[8] ^= 0xFF;
    std::fs::write(&path, &bumped).unwrap();
    let err =
        ReplayFilter::load_with_keys(&path, now, &key, None).expect_err("版本不符必须拒绝加载");
    assert!(
        matches!(err, ReplayError::VersionMismatch { expected: 1, .. }),
        "版本不符应报 VersionMismatch，实际 {err:?}"
    );
}

/// 核心价值用例：**状态体单字节改动 → 拒绝**。CRC-32 时代攻击者可改文件后重算校验，
/// 让已用过的 salt 重新被接受；密钥化 MAC 下攻击者没有密钥，改不出通过校验的文件。
/// 这里独立成用例，逐字节翻转比对（含 body 内与标签本身）。
#[test]
fn single_byte_body_mutation_is_rejected() {
    let dir = TempDir::new("mutate");
    let path = dir.path().join("replay.bin");
    let key = current_key();
    let now = 1_000_000u64;
    // 让 body 至少有 2 条记录，覆盖长度字节、salt 字节、seen 字节与标签。
    let mut filter = ReplayFilter::new(16, Duration::from_secs(60)).unwrap();
    filter.record(&[0x10u8; 16], now).unwrap();
    filter.record(&[0x20u8; 16], now + 1).unwrap();
    filter.save_with_key(&path, now, &key).unwrap();
    let good = std::fs::read(&path).expect("应能读回状态文件");
    assert!(good.len() > BODY_OFFSET + MAC_LEN, "文件应含正文与标签");

    // 正文区每一字节逐一翻转都必须被拒绝（长度/容量/时间窗/记录/标签全覆盖）。
    for index in BODY_OFFSET..good.len() {
        let mut mutated = good.clone();
        mutated[index] ^= 0x80;
        std::fs::write(&path, &mutated).unwrap();
        let result = ReplayFilter::load_with_keys(&path, now, &key, None);
        assert!(
            result.is_err(),
            "正文偏移 {index} 单字节改动未被拒绝：{result:?}"
        );
    }
    // 校验正确的原文件仍能载入（证明上面的拒绝来自 MAC，而非文件本就无效）。
    std::fs::write(&path, &good).unwrap();
    assert!(
        ReplayFilter::load_with_keys(&path, now, &key, None)
            .unwrap()
            .is_some(),
        "未改动的原始文件必须能载入"
    );
    let _ = std::fs::remove_dir_all(dir.path());
}

/// 截断（空文件 / 只有前缀 / 只有版本字节）与未知版本、密钥不匹配都必须 fail-closed。
#[test]
fn truncated_empty_unknown_version_and_wrong_key_are_rejected() {
    let dir = TempDir::new("shape");
    let path = dir.path().join("replay.bin");
    let key = current_key();
    let now = 1_000_000u64;

    // 空文件 → Corrupt。
    std::fs::write(&path, b"").unwrap();
    assert!(matches!(
        ReplayFilter::load_with_keys(&path, now, &key, None),
        Err(ReplayError::Corrupt(_))
    ));

    // 只有魔数+版本字节（无 body_len、无标签）→ Corrupt。
    std::fs::write(&path, b"LSS-REP2\x01\x00\x00\x00").unwrap();
    assert!(matches!(
        ReplayFilter::load_with_keys(&path, now, &key, None),
        Err(ReplayError::Corrupt(_))
    ));

    // 一个结构完整但正文为空的有效文件，用作「未知版本」与「密钥错误」的基底。
    let mut filter = ReplayFilter::new(4, Duration::from_secs(10)).unwrap();
    filter.record(&[0x01u8; 16], now).unwrap();
    filter.save_with_key(&path, now, &key).unwrap();
    let good = std::fs::read(&path).unwrap();

    // 未知版本字节（改成 2）→ VersionMismatch（不按旧格式猜解析）。
    let mut bumped = good.clone();
    bumped[8] = 0x02;
    std::fs::write(&path, &bumped).unwrap();
    assert!(matches!(
        ReplayFilter::load_with_keys(&path, now, &key, None),
        Err(ReplayError::VersionMismatch {
            file: 2,
            expected: 1
        })
    ));

    // 密钥不匹配 → MacMismatch。
    std::fs::write(&path, &good).unwrap();
    let wrong = MacKey::new(b"a-totally-different-key".to_vec());
    assert!(matches!(
        ReplayFilter::load_with_keys(&path, now, &wrong, None),
        Err(ReplayError::MacMismatch)
    ));
}

/// 密钥轮换：旧密钥签名的状态文件用「当前 + 上一代」加载被接受并标记升级；用当前密钥
/// 重写后，旧密钥单独不再可用（下一轮加载旧密钥必须 MacMismatch）。
#[test]
fn previous_key_state_is_accepted_and_upgraded_to_current() {
    let dir = TempDir::new("rotate");
    let path = dir.path().join("replay.bin");
    let current = current_key();
    let previous = previous_key();
    let now = 1_000_000u64;
    let salt = [0x44u8; 32];

    // 用上一代密钥写出状态（模拟轮换前的旧文件）。
    let mut filter = ReplayFilter::new(8, Duration::from_secs(60)).unwrap();
    filter.record(&salt, now).unwrap();
    filter.save_with_key(&path, now, &previous).unwrap();

    // 用当前 + 上一代加载 → 命中上一代，标记需要升级，且重放判定仍生效。
    let loaded = ReplayFilter::load_with_keys(&path, now, &current, Some(&previous))
        .unwrap()
        .expect("旧密钥状态应被接受");
    assert!(loaded.key_rotated, "应以旧密钥命中并标记升级");
    let mut restored = loaded.filter;
    assert!(restored.contains(&salt), "升级前窗口应保留旧记录");
    assert!(matches!(
        restored.record(&salt, now + 1),
        Err(ReplayError::Duplicate)
    ));

    // 升级：用当前密钥重写。
    restored.save_with_key(&path, now, &current).unwrap();

    // 升级后：当前密钥可载入且不再标记升级。
    let after = ReplayFilter::load_with_keys(&path, now, &current, Some(&previous))
        .unwrap()
        .expect("升级后应可用当前密钥载入");
    assert!(!after.key_rotated, "升级后不应再标记升级");

    // 升级后旧密钥单独不再可用（文件已是当前密钥签名）。
    assert!(matches!(
        ReplayFilter::load_with_keys(&path, now, &previous, None),
        Err(ReplayError::MacMismatch)
    ));
    let _ = std::fs::remove_dir_all(dir.path());
}

/// 原子写：目标父目录不可写（保存失败返回错误），**原文件不被破坏**。
#[test]
fn failed_atomic_write_returns_error_and_preserves_original() {
    let dir = TempDir::new("atomic");
    let path = dir.path().join("replay.bin");
    let key = current_key();
    let now = 1_000_000u64;

    // 先写一个有效状态作为「原文件」。
    let mut filter = ReplayFilter::new(8, Duration::from_secs(60)).unwrap();
    filter.record(&[0x55u8; 16], now).unwrap();
    filter.save_with_key(&path, now, &key).unwrap();
    let original = std::fs::read(&path).unwrap();

    // 把父目录改为只读：临时文件创建失败 → save 返回 Err。
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
        perms.set_mode(0o500);
        std::fs::set_permissions(dir.path(), perms).unwrap();

        let mut other = ReplayFilter::new(8, Duration::from_secs(60)).unwrap();
        other.record(&[0x66u8; 16], now).unwrap();
        let result = other.save_with_key(&path, now, &key);
        assert!(
            result.is_err(),
            "只读目录下保存必须返回错误，实际 {result:?}"
        );

        // 恢复可写以便读回与清理。
        let mut restore = std::fs::metadata(dir.path()).unwrap().permissions();
        restore.set_mode(0o700);
        std::fs::set_permissions(dir.path(), restore).unwrap();
    }

    // 原文件字节与可载入性都不受失败的写入影响。
    assert_eq!(
        std::fs::read(&path).unwrap(),
        original,
        "原文件必须不被破坏"
    );
    let loaded = ReplayFilter::load_with_keys(&path, now, &key, None)
        .unwrap()
        .expect("原文件应仍可载入");
    assert!(loaded.filter.contains(&[0x55u8; 16]));
    let _ = std::fs::remove_dir_all(dir.path());
}
