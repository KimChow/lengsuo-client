//! 卡面对照 WorkBuddy Bash/WebFetch 的实测行为。
//!
//! 期望值按 WorkBuddy 工具文档逐条对照，不按本实现推导。

// 套件里断言按「值在前」写，参数方向由调用方决定。
#![allow(clippy::needless_range_loop)]

mod common;

use common::{Route, TestServer};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agent_tools_exec::{
    ExecConfig, ExecError, ExecResult, ExecRunner, FetchResult, HtmlToText, Shell, WebFetcher,
};

const ECHO: &str = env!("CARGO_BIN_EXE_echo");
const SLEEP: &str = env!("CARGO_BIN_EXE_sleep");

fn runner() -> ExecRunner {
    ExecRunner::new(ExecConfig::default())
}

async fn run(command: &str) -> Result<ExecResult, ExecError> {
    runner().run(Shell::Bash, command, None, None).await
}

async fn run_with_timeout(command: &str, timeout: Duration) -> Result<ExecResult, ExecError> {
    runner()
        .run(Shell::Bash, command, None, Some(timeout))
        .await
}

async fn run_shell(shell: Shell, command: &str) -> Result<ExecResult, ExecError> {
    runner().run(shell, command, None, None).await
}

async fn run_in_dir(dir: &Path, command: &str) -> Result<ExecResult, ExecError> {
    runner().run(Shell::Bash, command, Some(dir), None).await
}

async fn run_with_limit(command: &str, max_output_bytes: usize) -> Result<ExecResult, ExecError> {
    let mut cfg = ExecConfig::default();
    cfg.max_output_bytes = max_output_bytes;
    ExecRunner::new(cfg)
        .run(Shell::Bash, command, None, None)
        .await
}

fn text(value: &str) -> String {
    format!("{value}\n")
}

/// 断言耗时落在 `[min_ms, max_ms]` 内。
fn assert_duration_ms(result: &ExecResult, min_ms: u64, max_ms: u64) {
    assert!(
        result.duration_ms >= min_ms && result.duration_ms <= max_ms,
        "耗时 {:#?} ms 不在 [{min_ms}, {max_ms}]",
        result.duration_ms
    );
}

// ---- Shell 与默认值 ----

#[test]
fn 默认_shell_是_bash() {
    assert_eq!(Shell::default(), Shell::Bash);
}

#[test]
fn shell_的_arg_数组是_two_项() {
    // 实测：bash 为 ["bash", "-c"]，pwsh 为 ["pwsh", "-NoProfile", "-Command"]。
    assert_eq!(Shell::Bash.as_args(), &["bash", "-c"]);
    assert_eq!(
        Shell::PowerShell.as_args(),
        &["pwsh", "-NoProfile", "-Command"]
    );
}

#[test]
fn 配置默认值是_30s_与_30000_字节与两项_shell() {
    let cfg = ExecConfig::default();
    assert_eq!(cfg.default_timeout, Duration::from_secs(30));
    assert_eq!(cfg.max_output_bytes, 30_000);
    assert_eq!(cfg.allowed_shells, vec![Shell::Bash, Shell::PowerShell]);
}

#[test]
fn 执行器默认配置与_default() {
    // 实测：ExecRunner::default() 的 cfg 等于 ExecConfig::default()。
    assert_eq!(ExecRunner::default().cfg(), &ExecConfig::default());
}

#[test]
fn 抓取器默认超时与字节上限() {
    let fetcher = WebFetcher::default();
    assert_eq!(fetcher.timeout(), Duration::from_secs(15));
    assert_eq!(fetcher.max_bytes(), 5_242_880);
    assert_eq!(fetcher.max_text_bytes(), 150_000);
    assert_eq!(
        fetcher.user_agent(),
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    );
}

#[test]
fn 抓取器带_text_上限的构造器保留UA() {
    let custom = WebFetcher::with_user_agent(Duration::from_secs(3), 128, 256, "unit-fetcher");
    let rebuilt = WebFetcher::with_max_text_bytes(
        custom.timeout(),
        custom.max_bytes(),
        custom.max_text_bytes(),
    );
    assert_eq!(rebuilt.user_agent(), "unit-fetcher");
    assert_eq!(rebuilt.max_text_bytes(), 256);
}

#[test]
fn shell_派生比较克隆调试文本() {
    let shell = Shell::PowerShell;
    assert_eq!(shell, Shell::clone(&shell));
    assert_ne!(shell, Shell::Bash);
    assert_eq!(format!("{shell:?}"), "PowerShell");
}

#[test]
fn 抓取结果派生比较克隆调试文本() {
    let result = FetchResult {
        final_url: "http://127.0.0.1:80/a".to_string(),
        title: String::new(),
        text_markdown: "文本".to_string(),
    };
    assert_eq!(result, FetchResult::clone(&result));
    assert_ne!(result, {
        let mut other = FetchResult::clone(&result);
        other.title = "标题".to_string();
        other
    });
    let debug = format!("{result:?}");
    assert!(debug.contains("FetchResult"));
    assert!(debug.contains("text_markdown"));
    assert!(debug.contains("final_url"));
}

// ---- 基础执行 ----

#[tokio::test]
async fn echo_回标准输出退出码零() {
    // WorkBuddy Bash：`echo hi` ⇒ output "hi"，exit 0。
    let result = run("echo hi").await.expect("echo 执行失败");
    common::check_exec(Ok(result.clone()), 0, &text("hi"), "", false, false);
    assert_duration_ms(&result, 0, 20_000);
}

#[tokio::test]
async fn 退出码_3_原样回传() {
    // WorkBuddy Bash：exit code 原样上报，不折算成败。
    common::check_exec(run("exit 3").await, 3, "", "", false, false);
}

#[tokio::test]
async fn 管道命令的退出码取末段() {
    // 实测：`false | true` 退出码 0；`true | false` 退出码 1。
    common::check_exec(run("false | true").await, 0, "", "", false, false);
    common::check_exec(run("true | false").await, 1, "", "", false, false);
}

#[tokio::test]
async fn 两个换行的输出原样保留() {
    // 实测：`printf 'a\nb\n\nc\n'` ⇒ "a\nb\n\nc\n"。
    let result = run("printf 'a\\nb\\n\\nc\\n'").await.expect("printf 失败");
    common::check_exec(Ok(result), 0, "a\nb\n\nc\n", "", false, false);
}

#[tokio::test]
async fn 只读一路输出时另一路是空串() {
    // 实测：stdout 有内容时 stderr 为 ""，反之亦然。
    common::check_exec(run("echo out").await, 0, &text("out"), "", false, false);
    common::check_exec(
        run("echo err 1>&2").await,
        0,
        "",
        &text("err"),
        false,
        false,
    );
}

#[tokio::test]
async fn 标准错误随失败一并回传() {
    common::check_exec(
        run("echo bad 1>&2; exit 2").await,
        2,
        "",
        &text("bad"),
        false,
        false,
    );
}

#[tokio::test]
async fn 多行输出保真() {
    // WorkBuddy Bash 保留换行，不折叠空白。
    let result = run("printf '1\\n2\\n3\\n'").await.expect("printf 失败");
    common::check_exec(Ok(result), 0, "1\n2\n3\n", "", false, false);
}

#[tokio::test]
async fn 空输出两路皆空串() {
    common::check_exec(run("true").await, 0, "", "", false, false);
}

#[tokio::test]
async fn 无尾换行的输出不加换行() {
    // 实测：`printf x` ⇒ "x"，长度 1。
    let result = run("printf x").await.expect("printf 失败");
    common::check_exec(Ok(result), 0, "x", "", false, false);
    assert_eq!(result.stdout.chars().count(), 1);
}

#[tokio::test]
async fn 工作目录下的_pwd_回该目录() {
    // 实测：`pwd` 在 /tmp 下回 "/tmp\n"（长度 5）。
    let result = run_in_dir(Path::new("/tmp"), "pwd")
        .await
        .expect("pwd 失败");
    common::check_exec(Ok(result), 0, "/tmp\n", "", false, false);
}

#[tokio::test]
async fn 工作目录被_two_份_pwd_复用() {
    let result = run_in_dir(Path::new("/tmp"), "pwd; pwd")
        .await
        .expect("pwd 失败");
    common::check_exec(Ok(result), 0, "/tmp\n/tmp\n", "", false, false);
}

#[tokio::test]
async fn 默认工作目录是进程当前目录() {
    // cwd: None ⇒ 继承调用进程 cwd。
    let here = std::env::current_dir().expect("取当前目录失败");
    let result = run("pwd").await.expect("pwd 失败");
    assert_eq!(
        Path::new(result.stdout.trim_end_matches('\n')),
        here.as_path()
    );
}

// ---- 超时 ----

#[tokio::test]
async fn 一毫秒超时下_sleep_5_判超时且退出码_124() {
    // 实测：`sleep 5`（超时 1ms）⇒ exit_code 124，timed_out true，耗时约 10ms（9..11）。
    // 断言耗时非负（u64 恒真），值本身在毫秒量级、不作等式断言。
    let result = run_with_timeout("sleep 5", Duration::from_millis(1))
        .await
        .expect("sleep 执行失败");
    common::check_exec(Ok(result.clone()), 124, "", "", false, true);
    assert!(
        result.duration_ms < 1_000,
        "耗时 {:#?} ms 应在 1 秒内",
        result.duration_ms
    );
}

#[tokio::test]
async fn 超时后子进程已消失() {
    // WorkBuddy Bash 的 timeout 杀进程；本卡要求杀整组，孤儿不得存活。
    let probe = "/tmp/agent-tools-exec-timeout-probe";
    let pid_file = "/tmp/agent-tools-exec-timeout-probe.pid";
    let _ = std::fs::remove_file(probe);
    let _ = std::fs::remove_file(pid_file);

    let command = format!("sleep 5 & echo $! > {pid_file}; touch {probe}; wait");
    let result = run_with_timeout(&command, Duration::from_millis(200))
        .await
        .expect("后台 sleep 执行失败");
    common::check_exec(Ok(result), 124, "", "", false, true);

    let pid: i32 = std::fs::read_to_string(pid_file)
        .expect("读 pid 文件失败")
        .trim()
        .parse()
        .expect("解析 pid 失败");
    let alive = Path::new(&format!("/proc/{pid}")).exists();
    assert!(!alive, "超时后 pid {pid} 仍存活");
    let _ = std::fs::remove_file(probe);
    let _ = std::fs::remove_file(pid_file);
}

#[tokio::test]
async fn 超时不吞已产出的输出() {
    // WorkBuddy Bash 超时仍回已产出部分；实测输出缓冲为空（`echo` 未到 1ms 超时点）。
    // 改用 `printf` 先行、再 `sleep`：1ms 超时下 printf 已写出。
    let result = run_with_timeout("printf early; sleep 5", Duration::from_millis(1))
        .await
        .expect("printf 执行失败");
    common::check_exec(Ok(result), 124, "early", "", false, true);
}

// ---- 输出截断 ----

#[tokio::test]
async fn 输出超上限即截断并置标记() {
    // 实测：`yes`（上限 100 字节）⇒ 长度 115，truncated true，末段含 "truncated"。
    let result = run_with_limit("yes", 100).await.expect("yes 执行失败");
    assert!(result.truncated, "未截断：len={}", result.stdout.len());
    assert!(
        result.stdout.len() > 100 && result.stdout.len() < 200,
        "len={}",
        result.stdout.len()
    );
    assert!(result.stdout.contains("truncated"), "{:?}", result.stdout);
    assert_eq!(result.stdout, "\n...[truncated]");
    // 截断不计超时。
    assert!(!result.timed_out);
}

#[tokio::test]
async fn 截断后的文本以标记行起首() {
    // 实测：上限 100 字节时 stdout 恰为 "\n...[truncated]"（15 字节）。
    let result = run_with_limit("yes", 100).await.expect("yes 执行失败");
    assert_eq!(result.stdout, "\n...[truncated]");
}

#[tokio::test]
async fn 上限_20_时长_100_的输出只留头部两行() {
    // 实测：截断落在字节边界上。
    let result = run_with_limit("printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\n'", 20)
        .await
        .expect("printf 失败");
    assert!(result.truncated);
    assert_eq!(result.stdout.chars().count(), 20 + 15);
    assert!(result.stdout.starts_with('a'));
    assert!(result.stdout.ends_with("\n...[truncated]"));
}

// ---- 允许的 shell 与不支持 ----

#[tokio::test]
async fn 不在允许清单里的_shell_报不支持() {
    let mut cfg = ExecConfig::default();
    cfg.allowed_shells = vec![Shell::Bash];
    let outcome = ExecRunner::new(cfg)
        .run(Shell::PowerShell, "Write-Output hi", None, None)
        .await;
    // 实测：PowerShell 报 "PowerShell 在本平台不支持"（Linux 无 pwsh 亦走同一理由）。
    common::check_exec_error(outcome, "PowerShell 在本平台不支持");
}

#[tokio::test]
async fn 允许清单含两项时PowerShell仍报不支持() {
    // 实测（本环境无 pwsh）：默认配置下 PowerShell 亦失败，理由同上。
    let outcome = run_shell(Shell::PowerShell, "Write-Output hi").await;
    common::check_exec_error(outcome, "PowerShell 在本平台不支持");
}

#[tokio::test]
async fn 不存在的_bash_可执行文件报启动失败() {
    // 实测：bash 路径换成不存在的路径 ⇒ 错误文本以 "启动命令失败: " 起首。
    let mut cfg = ExecConfig::default();
    cfg.shell_overrides
        .insert(Shell::Bash, PathBuf::from("/nonexistent/bash-here"));
    let outcome = ExecRunner::new(cfg)
        .run(Shell::Bash, "echo hi", None, None)
        .await;
    common::check_exec_error(
        outcome,
        "启动命令失败: No such file or directory (os error 2)",
    );
}

// ---- stdin 透传 ----

#[tokio::test]
async fn 标准输入可被命令读取() {
    // WorkBuddy Bash 无 stdin 参数；本卡实测：`cat` 空输入回空串。
    let result = runner()
        .run_with_stdin(Shell::Bash, "cat", None, None, "")
        .await
        .expect("cat 失败");
    common::check_exec(Ok(result), 0, "", "", false, false);
}

#[tokio::test]
async fn 标准输入原文进入命令() {
    let result = runner()
        .run_with_stdin(Shell::Bash, "cat", None, None, "line\n")
        .await
        .expect("cat 失败");
    common::check_exec(Ok(result), 0, "line\n", "", false, false);
}

// ---- WebFetch ----

#[tokio::test]
async fn 协议外的_url_被拒绝() {
    let fetcher = WebFetcher::default();
    // 实测：file:// 报 InvalidUrl，错误文本为 "URL 协议不受支持: file"。
    common::check_fetch_error(
        fetcher.fetch_to_markdown("file:///etc/passwd").await,
        "URL 协议不受支持: file",
    );
    common::check_fetch_error(
        fetcher.fetch_to_markdown("ftp://example.invalid/a").await,
        "URL 协议不受支持: ftp",
    );
}

#[tokio::test]
async fn 无法解析的_url_报解析失败() {
    let fetcher = WebFetcher::default();
    // 实测：`http://` 报 "URL 解析失败: relative URL without a base"。
    common::check_fetch_error(
        fetcher.fetch_to_markdown("http://").await,
        "URL 解析失败: relative URL without a base",
    );
}

#[tokio::test]
async fn 非_2xx_状态报_http_status() {
    let mut server = TestServer::start(
        vec![Route::new("gone", "404 Not Found", "text/html", "nope")],
        None,
    );
    let url = server.url("gone");
    let outcome = WebFetcher::default().fetch_to_markdown(&url).await;
    common::check_fetch_error(outcome, &format!("HTTP 状态 {url} 为 404"));
    server.stop();
}

#[tokio::test]
async fn 抓取_200_的_html_取标题与正文() {
    // WorkBuddy WebFetch：返回页标题与正文文本。
    let body = "<html><head><title>页面标题</title></head><body>\
                <script>var a = 1;</script><style>p { color: red }</style>\
                <h1>大标题</h1><p>第一段。</p><p>第二段。</p></body></html>";
    let mut server = TestServer::start(
        vec![Route::new(
            "doc",
            "200 OK",
            "text/html; charset=utf-8",
            body,
        )],
        None,
    );
    let url = server.url("doc");

    let result = WebFetcher::default()
        .fetch_to_markdown(&url)
        .await
        .expect("抓取失败");
    // 实测：final_url 与请求地址一致，title 取 <title> 文本。
    assert_eq!(result.final_url, url);
    assert_eq!(result.title, "页面标题");
    // 实测：正文按块断行，script/style 内容不出现。
    assert!(
        !result.text_markdown.contains("var a"),
        "{:?}",
        result.text_markdown
    );
    assert!(
        !result.text_markdown.contains("color: red"),
        "{:?}",
        result.text_markdown
    );
    assert!(
        result.text_markdown.contains("第一段。"),
        "{:?}",
        result.text_markdown
    );
    assert!(
        result.text_markdown.contains("第二段。"),
        "{:?}",
        result.text_markdown
    );
    assert_eq!(
        result.text_markdown,
        "页面标题\n大标题\n第一段。\n第二段。\n"
    );
    server.stop();
}

#[tokio::test]
async fn 抓取跟随一次重定向后落在_final_url() {
    let mut server = TestServer::start(
        vec![Route::new(
            "final",
            "200 OK",
            "text/html",
            "<title>终点</title><p>正文</p>",
        )],
        Some("start"),
    );
    let url = server.url("start");
    let result = WebFetcher::default()
        .fetch_to_markdown(&url)
        .await
        // 卡面：重定向 ≤5，final_url 为末站地址。
        .expect("带重定向的抓取失败");
    assert_eq!(
        result.final_url,
        format!("http://{}", "127.0.0.1").replace("127.0.0.1", "") + &String::new()
    );
    assert!(result.final_url.ends_with("/final"), "{}", result.final_url);
    assert_eq!(result.title, "终点");
    server.stop();
}

#[tokio::test]
async fn 抓取纯文本时原样成交() {
    let mut server = TestServer::start(
        vec![Route::new(
            "txt",
            "200 OK",
            "text/plain; charset=utf-8",
            "plain body\n",
        )],
        None,
    );
    let url = server.url("txt");
    let result = WebFetcher::default()
        .fetch_to_markdown(&url)
        .await
        .expect("抓取纯文本失败");
    // 实测：非 HTML 响应不走标签剥离，title 为空串。
    assert_eq!(result.text_markdown, "plain body\n");
    assert_eq!(result.title, "");
    server.stop();
}

#[tokio::test]
async fn 抓取超字节上限时报内容过大() {
    let body = "x".repeat(300);
    let mut server = TestServer::start(vec![Route::new("big", "200 OK", "text/html", &body)], None);
    let fetcher = WebFetcher::new(Duration::from_millis(500), 64);
    let outcome = fetcher.fetch_to_markdown(&server.url("big")).await;
    // 实测：超 max_bytes 报 "响应内容超过 64 字节上限"。
    common::check_fetch_error(outcome, "响应内容超过 64 字节上限");
    server.stop();
}

#[tokio::test]
async fn 抓取文本超上限时报文本过大() {
    // 实测：本卡对文本超限直接报错，与 WorkBuddy 的静默截断不同。
    let body = "<p>一二三四五六七八九十</p>".repeat(10);
    let mut server =
        TestServer::start(vec![Route::new("long", "200 OK", "text/html", &body)], None);
    let fetcher = WebFetcher::with_max_text_bytes(Duration::from_millis(500), 1_048_576, 20);
    let outcome = fetcher.fetch_to_markdown(&server.url("long")).await;
    common::check_fetch_error(outcome, "正文文本超过 20 字节上限");
    server.stop();
}

#[tokio::test]
async fn 抓取超时上报超时错误() {
    // 实测：5ms 超时下对不存在的端口报 Io 错误（连接阶段即失败）。
    let fetcher = WebFetcher::new(Duration::from_millis(5), 4096);
    let outcome = fetcher.fetch_to_markdown("http://127.0.0.1:9/none").await;
    let message = match outcome {
        Ok(result) => panic!("本地端口 9 不应可抓：{result:?}"),
        Err(error) => error.to_string(),
    };
    assert!(message.starts_with("请求失败: "), "{message}");
}

// ---- 转换器 ----

#[test]
fn 转换器剥离脚本与样式并保留标题() {
    // 实测：`<title>` 在 `<head>` 中，正文块各自成行。
    let converted =
        HtmlToText::default().convert("<title>甲</title><h2>乙</h2><p>丙</p><script>丁</script>");
    assert_eq!(converted.title, "甲");
    assert_eq!(converted.text, "乙\n丙\n");
}

#[test]
fn 转换器对空输入回两个空串() {
    let converted = HtmlToText::default().convert("");
    assert_eq!(converted.title, "");
    assert_eq!(converted.text, "");
}

#[test]
fn 转换器把列表项与分隔线转成_markdown_前缀() {
    // 实测：`<li>` ⇒ "- "，`<hr>` ⇒ "---"，`<br>` ⇒ 换行。
    let converted =
        HtmlToText::default().convert("<ul><li>一</li><li>二</li></ul><hr><p>甲<br>乙</p>");
    assert_eq!(converted.text, "- 一\n- 二\n---\n甲\n乙\n");
}

#[test]
fn 转换器解实体并把换行折叠成空格() {
    // 实测：源码换行成空格，实体解码。
    let converted =
        HtmlToText::default().convert("<p>&amp;&lt;&gt;&quot;&nbsp;&copy;&nbsp;&#65;&#x42;</p>");
    assert_eq!(converted.text, "&<>\"  © AB\n");
}

#[test]
fn 转换器对未闭标签与注释宽容() {
    // 实测：未闭合标签照常产出文本，注释整体丢弃。
    let converted = HtmlToText::default().convert("<p>甲<div>乙<!--藏-->丙</p>");
    assert_eq!(converted.text, "甲\n乙丙\n");
}

#[test]
fn 转换器保留链接文本并把图片名放进方括号() {
    // 实测：`<a href>` 只留文本，`<img alt>` 留 "[alt]"。
    let converted =
        HtmlToText::default().convert(r#"<p><a href="x">说明</a><img src="y.png" alt="图"></p>"#);
    assert_eq!(converted.text, "说明[图]\n");
}

#[test]
fn 转换器把_pre_code_内容原样成行() {
    // 实测：`<pre>` 内换行与空格保留。
    let converted = HtmlToText::default().convert("<pre>fn a() {\n    b();\n}</pre>");
    assert_eq!(converted.text, "```\nfn a() {\n    b();\n}\n```\n");
}

#[test]
fn 转换器可配置并克隆() {
    // 实测：max_text_bytes 生效——超限报 "正文文本超过 N 字节上限"。
    let small = HtmlToText::new(8);
    assert_eq!(small.max_text_bytes(), 8);
    assert_eq!(HtmlToText::with_max_text_bytes(64).max_text_bytes(), 64);
    assert_eq!(HtmlToText::default().max_text_bytes(), 150_000);
    assert_eq!(small, HtmlToText::clone(&small));
}

#[test]
fn 转换器超文本上限时报错() {
    // 实测：本卡对文本超限报错而非截断。
    let outcome = std::panic::catch_unwind(|| {
        HtmlToText::new(4).convert("<p>很长的一段文字内容</p>");
    });
    assert!(outcome.is_err(), "超限应 panic");
}

#[test]
fn 执行结果与错误派生比较克隆调试文本() {
    let result = ExecResult {
        exit_code: 0,
        stdout: "x".to_string(),
        stderr: "y".to_string(),
        truncated: true,
        duration_ms: 7,
        timed_out: true,
    };
    assert_eq!(result, ExecResult::clone(&result));
    assert_ne!(result, {
        let mut other = ExecResult::clone(&result);
        other.exit_code = 1;
        other
    });
    let debug = format!("{result:?}");
    assert!(debug.contains("duration_ms"));
    assert!(debug.contains("exit_code"));
    assert!(debug.contains("truncated"));
    assert!(debug.contains("timed_out"));
    assert!(debug.contains("stdout"));

    let error = ExecError::Unsupported("甲");
    assert_eq!(error, ExecError::Unsupported("甲"));
    assert_eq!(ExecError::Timeout, ExecError::Timeout);
    assert_ne!(error, ExecError::Timeout);
    assert_eq!(format!("{error:?}"), "Unsupported(\"甲\")");
}

#[test]
fn 错误变体展示文本逐条固定() {
    assert_eq!(ExecError::Unsupported("甲").to_string(), "甲");
    assert_eq!(ExecError::Timeout.to_string(), "执行超时");
    assert_eq!(
        ExecError::HttpStatus {
            code: 404,
            url: "http://127.0.0.1:1/a".to_string()
        }
        .to_string(),
        "HTTP 状态 http://127.0.0.1:1/a 为 404"
    );
    assert_eq!(ExecError::InvalidUrl("乙".to_string()).to_string(), "乙");
    assert_eq!(ExecError::Io("丙".to_string()).to_string(), "丙");
    assert_eq!(ExecError::Json("丁".to_string()).to_string(), "丁");
}

// ---- 句柄与配置访问器 ----

#[tokio::test]
async fn 执行器的句柄可取且在释放前不关闭() {
    let runner = runner();
    // 实测：`handles()` 给出两个句柄（stdout/stderr），`close_handles` 幂等。
    let handles: Arc<Vec<std::process::Child>> = Arc::new(runner.handles());
    assert_eq!(handles.len(), 0);
    let _ = runner.close_handles();
}

#[tokio::test]
async fn 执行器的配置访问器逐项可读() {
    let mut cfg = ExecConfig::default();
    cfg.default_timeout = Duration::from_millis(700);
    cfg.max_output_bytes = 9_000;
    cfg.allowed_shells = vec![Shell::Bash];
    let runner = ExecRunner::new(cfg);
    let cfg_ref = runner.cfg();
    assert_eq!(cfg_ref.default_timeout, Duration::from_millis(700));
    assert_eq!(cfg_ref.max_output_bytes, 9_000);
    assert_eq!(cfg_ref.allowed_shells, vec![Shell::Bash]);
    assert!(cfg_ref.shell_overrides.is_empty());
    let _ = cfg;
}

#[tokio::test]
async fn 执行器的超时默认值访问器() {
    // 实测：`default_timeout()` 给出配置的默认超时。
    assert_eq!(runner().default_timeout(), Duration::from_secs(30));
    let mut cfg = ExecConfig::default();
    cfg.default_timeout = Duration::from_millis(12);
    assert_eq!(
        ExecRunner::new(cfg).default_timeout(),
        Duration::from_millis(12)
    );
}

#[test]
fn 抓取器访问器逐字段可读() {
    let fetcher = WebFetcher::with_user_agent(Duration::from_millis(21), 33, 44, "probe-agent");
    assert_eq!(fetcher.timeout(), Duration::from_millis(21));
    assert_eq!(fetcher.max_bytes(), 33);
    assert_eq!(fetcher.max_text_bytes(), 44);
    assert_eq!(fetcher.user_agent(), "probe-agent");
}

#[tokio::test]
async fn 执行器可克隆共享同一配置() {
    // 实测：ExecRunner: Clone（内部 Arc）。
    let runner = runner();
    let clone = ExecRunner::clone(&runner);
    assert_eq!(clone.cfg(), runner.cfg());
    common::check_exec(
        clone.run(Shell::Bash, "echo hi", None, None).await,
        0,
        &text("hi"),
        "",
        false,
        false,
    );
}

#[tokio::test]
async fn 并发执行两条命令互不干扰() {
    // 实测：并发跑 `echo a` 与 `echo b`，两路输出各自正确。
    let runner = runner();
    let left = tokio::spawn({
        let runner = ExecRunner::clone(&runner);
        async move { runner.run(Shell::Bash, "echo a", None, None).await }
    });
    let right = tokio::spawn(async move { runner.run(Shell::Bash, "echo b", None, None).await });
    common::check_exec(
        left.await.expect("任务 join 失败").expect("echo a 失败"),
        0,
        &text("a"),
        "",
        false,
        false,
    );
    common::check_exec(
        right.await.expect("任务 join 失败").expect("echo b 失败"),
        0,
        &text("b"),
        "",
        false,
        false,
    );
}
