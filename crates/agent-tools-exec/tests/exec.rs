//! ExecRunner 验收：echo/cwd/退出码/超时/截断/PowerShell 不支持/无注入。

use std::time::Duration;

use agent_tools_exec::{ExecConfig, ExecRunner, Shell};

/// 测试用配置：短默认超时，小截断上限。
fn runner(cap: usize) -> ExecRunner {
    ExecRunner::new(ExecConfig {
        default_timeout: Duration::from_millis(500),
        max_output_bytes: cap,
        allowed_shells: vec![Shell::Bash],
    })
}

/// 等异步结果必须有超时：卡住的测试不能挂着 CI。
async fn with_deadline<T: Send + 'static>(f: impl std::future::Future<Output = T> + Send) -> T {
    tokio::time::timeout(Duration::from_secs(20), f)
        .await
        .expect("测试等待超时")
}

#[tokio::test]
async fn echo_captures_stdout_and_exit_zero() {
    let r = with_deadline(runner(1000).run(Shell::Bash, "echo hello", None, None))
        .await
        .expect("deadline");
    assert_eq!(r.exit_code, 0);
    assert_eq!(r.stdout.trim(), "hello");
    assert!(r.stderr.is_empty());
    assert!(!r.timed_out);
    assert!(!r.truncated);
}

#[tokio::test]
async fn stderr_is_kept_separate_from_stdout() {
    let cmd = "echo out; echo err >&2";
    let r = with_deadline(runner(1000).run(Shell::Bash, cmd, None, None))
        .await
        .expect("deadline");
    assert_eq!(r.stdout.trim(), "out");
    assert_eq!(r.stderr.trim(), "err");
}

#[tokio::test]
async fn nonzero_exit_code_is_reported() {
    let r = with_deadline(runner(1000).run(Shell::Bash, "exit 7", None, None))
        .await
        .expect("deadline");
    assert_eq!(r.exit_code, 7);
    assert!(!r.timed_out);
}

#[tokio::test]
async fn cwd_is_applied_to_the_child() {
    let dir = tempfile::tempdir().expect("临时目录");
    let canonical = dir.path().canonicalize().expect("规范化临时目录");
    let r = with_deadline(runner(1000).run(Shell::Bash, "pwd", Some(&canonical), None))
        .await
        .expect("deadline");
    assert_eq!(r.exit_code, 0, "stderr: {:?}", r.stderr);
    // cwd 用 canonicalize 传入，避免 /tmp 符号链接造成字符串不等。
    assert_eq!(r.stdout.trim(), canonical.to_string_lossy().trim_end());
}

#[tokio::test]
async fn sleep_past_the_timeout_reports_timed_out() {
    let cfg = runner(1000);
    let r = with_deadline(cfg.run(
        Shell::Bash,
        "sleep 5",
        None,
        Some(Duration::from_millis(100)),
    ))
    .await
    .expect("run");
    assert!(r.timed_out, "sleep 5 + 100ms 超时必须置 timed_out");
    assert_eq!(r.exit_code, -1);
    assert!(r.duration_ms < 5_000, "不该等满 5 秒: {}ms", r.duration_ms);
}

#[tokio::test]
async fn timeout_keeps_output_produced_before_the_deadline() {
    let cmd = "echo first; sleep 5";
    let r =
        with_deadline(runner(1000).run(Shell::Bash, cmd, None, Some(Duration::from_millis(300))))
            .await
            .expect("run");
    assert!(r.timed_out);
    assert_eq!(
        r.stdout.trim(),
        "first",
        "超时前的输出必须保留: {:?}",
        r.stdout
    );
}

#[tokio::test]
async fn timeout_kills_the_whole_process_group() {
    // 后台后代在 400ms 后落一个标记文件；它同时持有 stdout 写端。
    // 只杀直接子进程 ⇒ 标记文件出现、管道不 EOF；杀干净整组 ⇒ 标记不存在。
    // （不用 pgrep：并行任务线在同一台机器上跑，全局匹配不可靠。）
    let dir = tempfile::tempdir().expect("临时目录");
    let marker = dir.path().join("survived");
    let cmd = format!(
        "( sleep 0.4; echo alive > '{}' ) & sleep 30",
        marker.display()
    );
    let r =
        with_deadline(runner(1000).run(Shell::Bash, &cmd, None, Some(Duration::from_millis(100))))
            .await
            .expect("run");
    assert!(r.timed_out);
    assert!(
        !marker.exists(),
        "后台后代活了下来：进程组没有被 SIGKILL 覆盖"
    );
}

#[tokio::test]
async fn output_is_truncated_at_the_byte_cap() {
    let cmd = "printf 'x%.0s' $(seq 1 3000)";
    let cap = 100;
    let r = with_deadline(runner(cap).run(Shell::Bash, cmd, None, None))
        .await
        .expect("deadline");
    assert!(r.truncated);
    assert_eq!(r.stdout.len(), cap, "stdout 必须正好截到上限");
    assert!(r.stdout.chars().all(|c| c == 'x'));
}

#[tokio::test]
async fn truncation_holds_even_across_many_chunks() {
    // head -c 64000 远大于 8 KiB 块：验证不会整体读进内存。
    let cmd = "head -c 64000 /dev/zero | tr '\\0' 'a'";
    let r = with_deadline(runner(4096).run(Shell::Bash, cmd, None, None))
        .await
        .expect("deadline");
    assert!(r.truncated);
    assert_eq!(r.stdout.len(), 4096);
}

#[tokio::test]
async fn a_bounded_child_is_not_mistaken_for_truncated() {
    let r = with_deadline(runner(30_000).run(Shell::Bash, "echo short", None, None))
        .await
        .expect("deadline");
    assert!(!r.truncated, "小输出不该置 truncated");
}

#[tokio::test]
async fn powershell_is_unsupported_on_linux() {
    let cfg = runner(1000);
    let err = cfg
        .run(Shell::PowerShell, "Get-Process", None, None)
        .await
        .expect_err("Linux 上 PowerShell 必须不支持");
    assert!(
        matches!(err, agent_tools_exec::ExecError::Unsupported(_)),
        "错误类型应为 Unsupported，实得 {err:?}"
    );
}

#[tokio::test]
async fn shell_not_in_allowed_shells_is_unsupported() {
    let cfg = ExecRunner::new(ExecConfig {
        default_timeout: Duration::from_millis(500),
        max_output_bytes: 1000,
        allowed_shells: Vec::new(),
    });
    let err = cfg
        .run(Shell::Bash, "echo hi", None, None)
        .await
        .expect_err("空白名单必须拒绝");
    assert!(matches!(err, agent_tools_exec::ExecError::Unsupported(_)));
}

#[tokio::test]
async fn command_text_is_passed_as_one_argv_without_host_side_expansion() {
    // 反引号/分号属于用户命令自身的 shell 语义：能生效说明没有被二次包裹。
    let cmd = "echo $(echo nested)";
    let r = with_deadline(runner(1000).run(Shell::Bash, cmd, None, None))
        .await
        .expect("deadline");
    assert_eq!(r.stdout.trim(), "nested");

    // 我们绝不把命令拼进 shell 的 argv：单引号内容原样保留。
    let quoted = "printf '%s' 'a;b c'";
    let r = with_deadline(runner(1000).run(Shell::Bash, quoted, None, None))
        .await
        .expect("deadline");
    assert_eq!(r.stdout, "a;b c");
}

#[tokio::test]
async fn default_config_matches_the_frozen_spec() {
    let cfg = ExecConfig::default();
    assert_eq!(cfg.default_timeout, Duration::from_secs(30));
    assert_eq!(cfg.max_output_bytes, 30_000);
    assert_eq!(cfg.allowed_shells, vec![Shell::Bash]);
}
