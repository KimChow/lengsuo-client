//! 参考二进制侧的**互通边界取证**（`#[ignore]`，须显式 `--ignored` 实跑）。
//!
//! # 为什么这里没有「进程级互通」用例
//!
//! 参考实现（Xray v26.3.27 / `d2758a0`）的 XEL 记录层**只能**作为
//! `mlkem768x25519plus.*` 会话握手的一部分上线：
//! - 入站侧 `decryption` 的解析强制要求 `mlkem768x25519plus.` 前缀
//!   （`infra/conf/vless.go:97`），其他值一律被拒；
//! - 出站侧 `encryption` 同样强制该前缀（`infra/conf/vless.go:323`）；
//! - 记录层密钥由握手派生（`proxy/vless/encryption/client.go:122`
//!   `NewAEAD(clientHello[…], c.UnitedKey, c.UseAES)`、
//!   `server.go:229`），配置里**没有**「注入会话密钥 / 只开记录层」的入口。
//!
//! ⇒ 「用固定密钥只开记录层，与参考进程对跑」在本卡**不可取证**。
//! 本仓 `Cargo.lock` 里也没有 ML-KEM 实现（只有 `x25519-dalek`）⇒ 握手层
//! 不在本仓能力范围内。**本卡不声称与参考进程级互通。**
//!
//! # 那这个文件证明什么
//!
//! 证明**互通的阻塞点是配置/握手层，而不是记录层本身**，且这个结论是**实跑**
//! 出来的、不是推断的：
//! 1. 参考进程**确实拒绝**「只开记录层」的��置（退出码非 0 + 明确错误文本）——
//!    即：记录层在参考端**没有独立入口**；
//! 2. 参考进程**确实接受**合规的 `mlkem768x25519plus.*` 配置（正常起服）——
//!    即：参考端的 XEL 只在完整握手下上线。
//!
//! 记录层本身的语义对齐由**字节级**证据给出：`tests/xel_wire/reference_golden.rs`
//! （组合形态）与既有 `tests/xel_golden.rs`（单层形态）。
//!
//! # 运行
//!
//! ```sh
//! LENGSUO_XRAY=/path/to/xray \
//!   cargo test -p lengsuo-vless --test xel_wire -- --ignored
//! ```
//!
//! 硬约束：只用回环地址与临时端口；配置里的密钥全为假值；每个进程操作都有
//! 截止时间；断言文本不含任何密钥。

use std::{
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

/// 参考进程的启动截止时间。
const START_TIMEOUT: Duration = Duration::from_secs(20);

/// 参考二进制路径（门禁经 `LENGSUO_XRAY` 注入，例如 `LENGSUO_XRAY=/path/to/xray`）。
fn reference_binary() -> PathBuf {
    PathBuf::from(
        std::env::var("LENGSUO_XRAY")
            .expect("必须显式指定固定版本参考二进制（如 /path/to/xray）"),
    )
}

/// 断言参考二进制就是固定基线（版本串含版本号与 commit 前缀）。
fn assert_baseline() -> String {
    let output = Command::new(reference_binary())
        .arg("version")
        .output()
        .expect("参考二进制必须可执行");
    assert!(
        output.status.success(),
        "参考二进制 `version` 必须成功退出，实际 {:?}",
        output.status
    );
    let version = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        version.contains("26.3.27") && version.contains("d2758a0"),
        "基线不匹配：{version}"
    );
    version
}

/// 写一份临时参考配置并跑参考进程，返回 (退出状态, 合并输出)。
///
/// 退出状态 `None` 表示进程在截止时间内**一直活着**（= 起服成功）。
///
/// 临时目录**每次调用独立**（含单调计数器）：两个用例默认并行跑，若共用
/// 一个按 PID 命名的目录，先跑完的会删掉另一个还在用的配置文件 ⇒ 偶发失败。
fn run_reference(config: &str) -> (Option<i32>, String) {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "lengsuo-xel-ref-{}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("创建临时目录");
    let path = directory.join("config.json");
    std::fs::write(&path, config).expect("写配置");
    let mut child = Command::new(reference_binary())
        .args(["run", "-config"])
        .arg(&path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("启动参考进程");
    // 起服成功的进程会一直跑 ⇒ 短时轮询后杀掉，视为「活着」。
    let deadline = std::time::Instant::now() + START_TIMEOUT;
    loop {
        match child.try_wait().expect("轮询参考进程") {
            Some(status) => {
                let output = child.wait_with_output().ok();
                let mut text = String::new();
                if let Some(output) = output {
                    text.push_str(&String::from_utf8_lossy(&output.stdout));
                    text.push_str(&String::from_utf8_lossy(&output.stderr));
                }
                let _ = std::fs::remove_dir_all(&directory);
                return (Some(status.code().unwrap_or(-1)), text);
            }
            None => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = std::fs::remove_dir_all(&directory);
                    return (None, String::new());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// 互通的**阻塞点**取证：参考进程拒绝「只开记录层」的入站配置。
///
/// 判据：进程**非零退出**，且输出里明确指出 `decryption` 不被支持。
/// 这条正是「进程级互通不可取证」的**直接依据**——参考端根本没有
/// 「注入会话密钥 / 只开记录层」的入口。
#[test]
#[ignore = "需要显式提供固定版本参考二进制"]
fn reference_rejects_record_layer_only_inbound_config() {
    let _version = assert_baseline();
    // 端口取一个临时高位端口：参考进程应当**在监听之前**就因配置被拒而退出，
    // 端口冲突不会影响本用例的判据（配置解析先于绑定）。
    let port = 18_443;
    let config = format!(
        r#"{{"inbounds":[{{"protocol":"vless","port":{port},
          "settings":{{"clients":[{{"id":"11111111-1111-1111-1111-111111111111"}}],
          "decryption":"xor"}},
          "streamSettings":{{"network":"tcp"}}}}],
          "outbounds":[{{"protocol":"freedom"}}]}}"#
    );
    let (code, text) = run_reference(&config);
    let code = code.expect("参考进程必须退出，不得一直监听（配置应被拒）");
    assert_ne!(code, 0, "只开记录层的配置必须被参考进程拒绝");
    assert!(
        text.contains("unsupported") && text.contains("decryption"),
        "参考进程必须明确指出 `decryption` 不被支持，实际输出：{text}"
    );
}

/// 互通的**阻塞点**取证（正面）：参考进程**接受**合规的 XEL 配置并正常起服。
///
/// 判据：进程在截止时间内**一直活着**（未退出）⇒ 配置合法、参考端 XEL
/// 只在完整 `mlkem768x25519plus.*` 握手下上线。
///
/// 这条与上一条合起来说明：参考端的 XEL 记录层**没有独立入口**，
/// 互通被阻塞在**握手/配置**层，不是记录层语义层。
#[test]
#[ignore = "需要显式提供固定版本参考二进制"]
fn reference_accepts_conforming_xel_inbound_config() {
    let _version = assert_baseline();
    // 32 字节假公钥（base64 raw-url，无 padding）——参考端只校验长度。
    let public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let port = 18_444;
    let config = format!(
        r#"{{"inbounds":[{{"protocol":"vless","port":{port},
          "settings":{{"clients":[{{"id":"11111111-1111-1111-1111-111111111111"}}],
          "decryption":"mlkem768x25519plus.random.600s.{public_key}"}},
          "streamSettings":{{"network":"tcp"}}}}],
          "outbounds":[{{"protocol":"freedom"}}]}}"#
    );
    let (code, _text) = run_reference(&config);
    assert!(
        code.is_none(),
        "合规的 XEL 配置必须让参考进程正常起服（进程应一直活着），实际退出码 {code:?}"
    );
}
