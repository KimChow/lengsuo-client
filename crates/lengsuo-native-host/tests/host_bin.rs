//! 跨进程集成测试：用 [`Command`] 拉起**本次构建产出的真宿主二进制**
//! （`CARGO_BIN_EXE_lengsuo-native-host` 由 cargo 注入，指向 target 里的可执行文件）。
//!
//! # 钉住的 Chromium 行为（本测试的期望值来源）
//!
//! - `argv[1]` 恒为扩展 origin（`launch_context.cc:204-206`，注释原文「origin 必须是
//!   第一个参数」，两平台一致）；
//! - 仅 Windows 在其后追加 `--parent-window=<句柄>`（`launch_context.cc:210-213`）
//!   ⇒ `argv[2..]` 必须被忽略而不是拒绝；
//! - 管道帧 = 4 字节**本机字节序**长度头 + JSON 文本（`native_message_process_host.cc`
//!   `:202-207` 写侧 / `:318-320` 读侧）；
//! - **stdout 是协议通道**：任何失败路径都不得往 stdout 写一个字节（每条用例独立断言）。
//!
//! 期望值全部是手写字面量 / 向量文件字段；⛔ 不用自家 roundtrip 生成期望。

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// 本次构建产出的宿主可执行文件（cargo 为集成测试注入的环境变量）。
const HOST_EXE: &str = env!("CARGO_BIN_EXE_lengsuo-native-host");

/// 本扩展的规范 origin（契约 §5.0；与 `extension::EXTENSION_ORIGIN` 同值的手写字面量）。
const OUR_ORIGIN: &str = "chrome-extension://ejlmmjamfpkoopjachjhcbdjlddknhok/";

/// 合法格式的**外来**扩展 origin：仅末位 `k`→`l`，格式完全合法但不是本扩展。
const FOREIGN_ORIGIN: &str = "chrome-extension://ejlmmjamfpkoopjachjhcbdjlddknhol/";

/// 退出码：无 `argv[1]`（缺 origin）。
const EXIT_MISSING_ORIGIN: i32 = 2;
/// 退出码：来源校验失败。
const EXIT_ORIGIN_REJECTED: i32 = 4;
/// 退出码：主循环失败。
const EXIT_LOOP: i32 = 5;

/// 起宿主子进程：三个标准流全部管道化。
fn spawn_host(args: &[&str]) -> Child {
    Command::new(HOST_EXE)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("宿主二进制必须能被拉起")
}

/// 写完 stdin 即关（EOF），等进程退出，读回（退出码, stdout 字节, stderr 文本）。
fn run_host_piped(args: &[&str], input: &[u8]) -> (Option<i32>, Vec<u8>, String) {
    let mut child = spawn_host(args);
    if !input.is_empty() {
        child
            .stdin
            .as_mut()
            .expect("stdin 已接管")
            .write_all(input)
            .expect("写 stdin 必须成功");
    }
    drop(child.stdin.take());
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .expect("stdout 已接管")
        .read_to_end(&mut stdout)
        .expect("读 stdout 必须成功");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("stderr 已接管")
        .read_to_string(&mut stderr)
        .expect("读 stderr 必须成功");
    let status = child.wait().expect("等宿主退出必须成功");
    (status.code(), stdout, stderr)
}

fn vector() -> &'static serde_json::Value {
    static CACHE: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors/native-host-io-v1.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("读不到向量文件"))
            .expect("向量文件必须是合法 JSON")
    })
}

/// 从向量取一条**整条管道帧**（文件按小端记录长度头；大端机器翻回头 4 字节）。
fn vector_pipe_frame(name: &str) -> Vec<u8> {
    let text = vector()["frames"][name]
        .as_str()
        .expect("向量字段必须是字符串");
    let mut bytes = hex::decode(text).expect("向量 hex 必须合法");
    if cfg!(target_endian = "big") {
        bytes[..4].reverse();
    }
    bytes
}

/// 手工装一条管道帧：4 字节本机序长度头 + 载荷（写侧 `OnMessage` 的字节语义）。
fn pipe_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_ne_bytes());
    out.extend_from_slice(payload);
    out
}

/// 用例 1：不带参数 ⇒ 退出码非 0；stdout 零字节；stderr 非空。
#[test]
fn no_args_fails_without_stdout() {
    let (code, stdout, stderr) = run_host_piped(&[], b"");
    assert_eq!(code, Some(EXIT_MISSING_ORIGIN), "缺 origin 必须以 2 退出");
    assert!(
        stdout.is_empty(),
        "失败路径 stdout 必须零字节，实际 {stdout:?}"
    );
    assert!(!stderr.is_empty(), "诊断必须走 stderr（非空）");
}

/// 用例 2：正确 origin + 立即关 stdin ⇒ 帧边界 EOF ⇒ 退出 0；stdout 零字节。
#[test]
fn correct_origin_then_eof_exits_zero() {
    let (code, stdout, _stderr) = run_host_piped(&[OUR_ORIGIN], b"");
    assert_eq!(code, Some(0), "帧边界 EOF 是正常关闭");
    assert!(
        stdout.is_empty(),
        "无回帧 ⇒ stdout 必须零字节，实际 {stdout:?}"
    );
}

/// 用例 3：本扩展 ID 末位改一个字符（格式合法但不是我们）⇒ 严格值校验必须拒绝。
#[test]
fn valid_format_but_foreign_id_rejected() {
    let (code, stdout, _stderr) = run_host_piped(&[FOREIGN_ORIGIN], b"");
    assert_eq!(code, Some(EXIT_ORIGIN_REJECTED));
    assert!(
        stdout.is_empty(),
        "来源不对 ⇒ 一个字节都不读/写，实际 {stdout:?}"
    );
}

/// 用例 4：`argv[1]` 是 https origin ⇒ 形状不对 ⇒ 拒绝。
#[test]
fn https_origin_rejected() {
    let (code, stdout, _stderr) = run_host_piped(&["https://evil.example/"], b"");
    assert_eq!(code, Some(EXIT_ORIGIN_REJECTED));
    assert!(
        stdout.is_empty(),
        "来源不对 ⇒ 一个字节都不读/写，实际 {stdout:?}"
    );
}

/// 用例 5：正确 origin + 额外 `--parent-window=12345`（模拟 Windows，`launch_context.cc:210-213`）
/// ⇒ `argv[2..]` 一律忽略 ⇒ 与用例 2 同：退出 0。
#[test]
fn windows_extra_parent_window_arg_accepted() {
    let (code, stdout, _stderr) = run_host_piped(&[OUR_ORIGIN, "--parent-window=12345"], b"");
    assert_eq!(code, Some(0), "额外的 Windows 参数必须被忽略，不得拒绝");
    assert!(stdout.is_empty(), "实际 {stdout:?}");
}

/// 用例 6：正确 origin + 一条合法信封（`empty_business_frame_b64` 组信封）
/// ⇒ `UnwiredDispatch` ⇒ `NoReply` ⇒ stdout 零字节；EOF 后退出 0。
#[test]
fn valid_envelope_dispatches_no_reply_stdout_zero() {
    let envelope = vector()["frames"]["list_credentials_envelope"]
        .as_str()
        .expect("向量字段必须是字符串");
    assert_eq!(
        envelope, "{\"frame_b64\":\"AAAAAAAAAAA\"}",
        "空业务帧组信封必须是这个手写字面量"
    );
    let frame = vector_pipe_frame("list_credentials_pipe_frame_hex");
    let (code, stdout, _stderr) = run_host_piped(&[OUR_ORIGIN], &frame);
    assert_eq!(code, Some(0), "合法信封被接受，stdin EOF 后正常退出");
    assert!(
        stdout.is_empty(),
        "NoReply ⇒ stdout 必须零字节，实际 {stdout:?}"
    );
}

/// 用例 7：正确 origin + 坏信封（base64 非法）⇒ 主循环失败 ⇒ 退出码非 0；stdout 零字节。
#[test]
fn bad_envelope_fails_without_stdout() {
    let frame = pipe_frame(b"{\"frame_b64\":\"!!!\"}");
    let (code, stdout, _stderr) = run_host_piped(&[OUR_ORIGIN], &frame);
    assert_eq!(code, Some(EXIT_LOOP), "坏信封 ⇒ LoopError::Envelope ⇒ 5");
    assert!(stdout.is_empty(), "实际 {stdout:?}");
}

/// 用例 8：长度头声明 0x0020_0000（2 MiB > 1 MiB 上限）⇒ **关通道不截断** ⇒ 退出码非 0；
/// stdout 零字节。
#[test]
fn overlong_length_header_closes_channel() {
    let mut frame = 0x0020_0000u32.to_ne_bytes().to_vec();
    frame.extend_from_slice(b"payload-must-not-be-read");
    let (code, stdout, _stderr) = run_host_piped(&[OUR_ORIGIN], &frame);
    assert_eq!(code, Some(EXIT_LOOP), "超限长度头 ⇒ LoopError::TooLong ⇒ 5");
    assert!(stdout.is_empty(), "实际 {stdout:?}");
}

/// 用例 9：正确 origin + 一条合法信封后**不关 stdin** ⇒ 宿主必须阻塞在等下一帧，
/// 不得把「半开连接」当 EOF 提前退出；stdout 仍零字节；随后关 stdin 才正常退出。
#[test]
fn host_waits_for_next_frame_until_eof() {
    let mut child = spawn_host(&[OUR_ORIGIN]);
    let frame = vector_pipe_frame("list_credentials_pipe_frame_hex");
    child
        .stdin
        .as_mut()
        .expect("stdin 已接管")
        .write_all(&frame)
        .expect("写 stdin 必须成功");
    child
        .stdin
        .as_mut()
        .expect("stdin 已接管")
        .flush()
        .expect("flush");
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        child.try_wait().expect("try_wait 必须成功").is_none(),
        "没关 stdin 宿主就退出了：它把半开连接当成了 EOF"
    );
    drop(child.stdin.take());
    let status = child.wait().expect("等宿主退出必须成功");
    assert_eq!(status.code(), Some(0), "帧边界 EOF ⇒ 正常关闭");
    // 进程活着期间写进管道的字节不会消失：退出后读到的就是它的全部 stdout。
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .expect("stdout 已接管")
        .read_to_end(&mut stdout)
        .expect("读 stdout 必须成功");
    assert!(stdout.is_empty(), "stdout 必须零字节，实际 {stdout:?}");
}

/// 用例 10：stdout 纯度**总断言** —— 每条失败路径逐条独立断言 `stdout == b""`。
#[test]
fn stdout_purity_across_all_failures() {
    let overlong = 0x0020_0000u32.to_ne_bytes().to_vec();
    let cases: Vec<(&str, Vec<&str>, Vec<u8>)> = vec![
        ("用例1 无参数", vec![], Vec::new()),
        ("用例3 外来扩展ID", vec![FOREIGN_ORIGIN], Vec::new()),
        (
            "用例4 https origin",
            vec!["https://evil.example/"],
            Vec::new(),
        ),
        (
            "用例7 坏信封",
            vec![OUR_ORIGIN],
            pipe_frame(b"{\"frame_b64\":\"!!!\"}"),
        ),
        ("用例8 超限长度头", vec![OUR_ORIGIN], overlong),
    ];
    for (name, args, input) in &cases {
        let (code, stdout, _stderr) = run_host_piped(args, input);
        assert_ne!(code, Some(0), "{name}：必须以非 0 退出");
        assert!(
            stdout.is_empty(),
            "{name}：stdout 必须零字节，实际 {stdout:?}"
        );
    }
}
