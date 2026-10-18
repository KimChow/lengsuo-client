//! 子进程生命周期：独立进程组启动、超时杀整组、有界收流且保留已有输出。
//!
//! 只走 Unix 路径；PowerShell 由上层直接判 [`crate::ExecError::Unsupported`]，
//! 不进入本模块。
//!
//! 杀进程组必须写成 `/bin/kill -KILL -- -<pgid>`：省略 `--` 时 procps 会把
//! `-KILL -12345` 当成它自己的选项，返回 0 却不发信号（本机实测）。

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, ChildStderr, ChildStdout, Command};

use super::ExecResult;
use crate::ExecError;

/// 单次 `read` 的最大字节数；配合 `cap` 保证内存有界。
const CHUNK: usize = 8 * 1024;

/// 进程已退出、等待两条管道 EOF 的宽限。
const PIPE_GRACE: Duration = Duration::from_millis(500);

/// 被终止、拿不到退出码时的占位退出码（表示「无退出码」，非真实值）。
const NO_EXIT_CODE: i32 = -1;

/// 命令的 `-c` argv：整条命令作为**单个 argv** 交给登录 shell。
///
/// 不拼接字符串、不追加参数，宿主侧没有注入面；命令内的 shell 元字符只按
/// 调用方自己的语义解释。
pub(crate) fn shell_args(command: &str) -> Vec<String> {
    vec!["-lc".to_string(), command.to_string()]
}

/// 单条流（stdout 或 stderr）的累积状态。
struct Sink {
    /// 已保留字节，长度 ≤ `cap`。
    bytes: Vec<u8>,
    /// 仍在读（未 EOF、未出错）。
    open: bool,
    /// 撞到 `cap`。
    capped: bool,
    /// 没能读到 EOF：输出不完整。
    short: bool,
    /// 首个读错误的文本（不含凭据）。
    error: Option<String>,
}

impl Sink {
    fn new() -> Self {
        Sink {
            bytes: Vec::new(),
            open: true,
            capped: false,
            short: false,
            error: None,
        }
    }

    /// 记错误并收流，只保留首个错误。
    fn fail(&mut self, msg: String) {
        self.open = false;
        self.short = true;
        if self.error.is_none() {
            self.error = Some(msg);
        }
    }

    /// 预算用尽时收流：已收字节保留。
    fn stop(&mut self) {
        if self.open {
            self.open = false;
            self.short = true;
        }
    }

    /// 输出是否不完整（撞上限或提前收流）。
    fn truncated(&self) -> bool {
        self.capped || self.short
    }
}

/// 读到 EOF，最多保留 `cap` 字节；超出部分继续读但丢弃，
/// 以免写端因我们停止读取而收到 `SIGPIPE`、改变退出码。
async fn read_into<R>(src: &mut R, sink: &mut Vec<u8>, cap: usize) -> std::io::Result<bool>
where
    R: AsyncRead + Unpin,
{
    let mut capped = false;
    let mut chunk = [0u8; CHUNK];
    loop {
        let n = src.read(&mut chunk).await?;
        if n == 0 {
            return Ok(capped);
        }
        let keep = cap.saturating_sub(sink.len()).min(n);
        if keep < n {
            capped = true;
        }
        sink.extend_from_slice(&chunk[..keep]);
    }
}

/// 推进一条流直到 EOF，结果写回该流自己的 [`Sink`]。
async fn pump<R>(src: &mut R, sink: &mut Sink, cap: usize)
where
    R: AsyncRead + Unpin,
{
    match read_into(src, &mut sink.bytes, cap).await {
        Ok(capped) => {
            sink.open = false;
            sink.capped = capped;
        }
        Err(e) => sink.fail(e.to_string()),
    }
}

/// 并发收两条流并等退出码。
///
/// * `stop_when_status` — 拿到退出码即返回（阶段 1，预算就是命令超时）；
/// * 否则等退出码且两条流都 settled；
/// * `budget` 用尽时返回 `false`，**不**动两条流的状态：调用方要么接着收
///   （阶段 2），要么自己标 incomplete。
///
/// 已收字节始终留在各自的 [`Sink`] 内，所以预算用尽也不丢已有输出。
#[allow(clippy::too_many_arguments)]
async fn collect(
    child: &mut Child,
    stdout: &mut ChildStdout,
    stderr: &mut ChildStderr,
    out: &mut Sink,
    err: &mut Sink,
    cap: usize,
    status: &mut Option<std::process::ExitStatus>,
    stop_when_status: bool,
    budget: Duration,
) -> bool {
    tokio::time::timeout(budget, async {
        loop {
            if out.error.is_some() || err.error.is_some() {
                return;
            }
            if status.is_some() && (stop_when_status || (!out.open && !err.open)) {
                return;
            }
            tokio::select! {
                biased;
                s = child.wait(), if status.is_none() => match s {
                    Ok(st) => *status = Some(st),
                    Err(e) => {
                        let msg = e.to_string();
                        out.fail(msg.clone());
                        err.fail(msg);
                    }
                },
                () = pump(stdout, out, cap), if out.open => {}
                () = pump(stderr, err, cap), if err.open => {}
                else => return,
            }
        }
    })
    .await
    .is_ok()
}

/// 杀整个进程组：`/bin/kill -KILL -- -<pgid>`。
///
/// 杀不掉不算失败：进程可能已自行退出，收尾交给管道预算。
async fn kill_group(pgid: u32) {
    let _ = Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{pgid}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
}

/// 运行 `program` + [`shell_args`]，返回带超时/截断标记的结果。
///
/// 超时：到点杀进程组（`SIGKILL`，含全部后代），保留超时前已产出的输出，
/// `timed_out = true`、`exit_code = -1`。管道在宽限内读不到 EOF 时置
/// `truncated`，不无限等待后台后代持有的写端。
pub(crate) async fn run(
    program: &str,
    command: &str,
    cwd: Option<&Path>,
    timeout: Duration,
    cap: usize,
) -> Result<ExecResult, ExecError> {
    let started = Instant::now();
    let mut cmd = Command::new(program);
    cmd.args(shell_args(command))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // 提前返回也不留孤儿：tokio 在 drop 时 kill 并收割，不产生僵尸。
        .kill_on_drop(true);
    // 独立进程组：pgid == 子进程 pid，超时才能干净杀掉全部后代（Unix 专有 API）。
    #[cfg(unix)]
    cmd.process_group(0);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let mut child = cmd.spawn()?;
    let pgid = child.id();
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| ExecError::Io("stdout 管道不可用".to_string()))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| ExecError::Io("stderr 管道不可用".to_string()))?;

    let mut out = Sink::new();
    let mut err = Sink::new();
    let mut status: Option<std::process::ExitStatus> = None;
    // 阶段 1：等退出码，两条管道一并推进；预算就是命令超时。
    let in_time = collect(
        &mut child,
        &mut stdout,
        &mut stderr,
        &mut out,
        &mut err,
        cap,
        &mut status,
        true,
        timeout,
    )
    .await;
    // 预算到点且没有退出码 ⇒ 超时：杀整组。杀组后 `child.wait()` 会拿到
    // 我们这次 SIGKILL 的退出状态，所以 `timed_out` 只在这里判定一次，
    // 退出码也不再采用那个状态。
    let mut timed_out = false;
    if !in_time && status.is_none() {
        timed_out = true;
        if let Some(pgid) = pgid {
            kill_group(pgid).await;
        }
    }
    // 阶段 2：管道未必随退出码 EOF —— 后代可能还持着写端（超时路径刚杀过组，
    // 正常路径的 `nohup`/`disown` 后代则可能长期存活）。已收字节留在 `Sink` 里，
    // 所以宽限用尽也不丢超时前的输出，只把没收完的流标成不完整。
    if out.open || err.open {
        collect(
            &mut child,
            &mut stdout,
            &mut stderr,
            &mut out,
            &mut err,
            cap,
            &mut status,
            false,
            PIPE_GRACE,
        )
        .await;
        out.stop();
        err.stop();
    }
    if let Some(msg) = out.error.as_ref().or(err.error.as_ref()) {
        return Err(ExecError::Io(msg.clone()));
    }
    Ok(ExecResult {
        exit_code: if timed_out {
            NO_EXIT_CODE
        } else {
            status
                .map(|st| st.code().unwrap_or(NO_EXIT_CODE))
                .unwrap_or(NO_EXIT_CODE)
        },
        stdout: lossy(&out.bytes),
        stderr: lossy(&err.bytes),
        truncated: out.truncated() || err.truncated(),
        duration_ms: started.elapsed().as_millis() as u64,
        timed_out,
    })
}

/// 字节 → 文本：按字节截断留下的半个字符替换为 `U+FFFD`，不当作错误。
fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
