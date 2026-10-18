//! 真实子进程：起进程、后台线程收流与 stdin 写入、轮询 reap 取退出码。

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

/// 收流结束标志：主线程 reap 后置位，工作线程看到即退出。
#[derive(Default)]
struct DoneFlag(AtomicBool);

impl DoneFlag {
    fn done(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    fn set(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

type SharedDone = Arc<DoneFlag>;

/// 后台线程按行读一路输出直到 EOF，或读到 `done` 置位；每行之间查一次标志。
fn spawn_line_reader(
    source: impl Read + Send + 'static,
    done: SharedDone,
) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    let _ = thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            let mut buffer = String::new();
            let mut lines = BufReader::new(source).lines();
            while let Ok(Some(line)) = lines.next() {
                buffer.push_str(&line);
                buffer.push('\n');
                if done.done() {
                    break;
                }
            }
            let _ = tx.send(buffer);
        });
    rx
}

/// 一个已启动的同步子进程：stdin 已交后台线程写入，两路输出由工作线程收取。
pub struct TestProcess {
    child: Child,
    stdin_writer: Option<thread::JoinHandle<()>>,
    stdout_rx: mpsc::Receiver<String>,
    stderr_rx: mpsc::Receiver<String>,
    done: SharedDone,
}

/// 起进程：`cwd` 为工作目录，`input` 写 stdin。
pub fn spawn_process(program: &Path, args: &[&str], cwd: &Path, input: &str) -> TestProcess {
    let mut child = match Command::new(program)
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => panic!(
            "启动 {} 失败：{} {error}",
            program.display(),
            args.join(" ")
        ),
    };

    let payload = input.to_string();
    let mut stdin = match child.stdin.take() {
        Some(stdin) => stdin,
        None => panic!("stdin 未接管道"),
    };
    let stdin_writer = thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            let mut cursor = payload.as_bytes();
            let mut chunk = [0_u8; 8192];
            loop {
                match cursor.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        if stdin.write_all(&chunk[..read]).is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = stdin.flush();
            drop(stdin);
        })
        .expect("起 stdin 线程");

    let done = Arc::new(DoneFlag::default());
    let Some(stdout_pipe) = child.stdout.take() else {
        panic!("stdout 未接管道")
    };
    let Some(stderr_pipe) = child.stderr.take() else {
        panic!("stderr 未接管道")
    };
    let stdout_rx = spawn_line_reader(stdout_pipe, Arc::clone(&done));
    let stderr_rx = spawn_line_reader(stderr_pipe, Arc::clone(&done));

    TestProcess {
        child,
        stdin_writer: Some(stdin_writer),
        stdout_rx,
        stderr_rx,
        done,
    }
}

impl TestProcess {
    /// 等待退出至多 `timeout`，回 `(退出码, stdout, stderr)`；超时则杀进程回 `None`。
    ///
    /// 顺序要紧：先 join stdin 线程（否则 stdin 悬挂，进程不退出），再轮询 reap，
    /// 最后置收流标志取回缓冲。
    pub fn finish(&mut self, timeout: Duration) -> Option<(i32, String, String)> {
        if let Some(handle) = self.stdin_writer.take() {
            let _ = handle.join();
        }
        let started = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.done.set();
                    let code = status
                        .code()
                        .unwrap_or_else(|| status.signal().unwrap_or(0));
                    return Some((
                        code,
                        self.drain(&mut self.stdout_rx),
                        self.drain(&mut self.stderr_rx),
                    ));
                }
                Ok(None) => {
                    if started.elapsed() > timeout {
                        let _ = self.child.kill();
                        let _ = self.child.wait();
                        self.done.set();
                        return None;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("轮询退出状态失败：{error}"),
            }
        }
    }

    /// 收流线程在 `done` 置位后很快发回缓冲；2s 等待是有余量的上界。
    fn drain(&self, rx: &mut mpsc::Receiver<String>) -> String {
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(text) | Err(mpsc::RecvTimeoutError::Disconnected) => text,
            Err(mpsc::RecvTimeoutError::Timeout) => String::new(),
        }
    }
}

/// 在 `cwd` 跑一条命令，回其 stdout（断言成功）。
pub fn run_in(program: &Path, args: &[&str], cwd: &Path) -> String {
    let mut process = spawn_process(program, args, cwd, "");
    match process.finish(Duration::from_secs(10)) {
        Some((0, stdout, _stderr)) => stdout,
        Some((code, _stdout, stderr)) => panic!("{} 退出 {code}：{stderr}", program.display()),
        None => panic!("{} 超时", program.display()),
    }
}
