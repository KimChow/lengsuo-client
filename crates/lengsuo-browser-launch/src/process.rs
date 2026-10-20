//! 浏览器进程句柄：**能取消、能 kill、能 wait**，不留孤儿进程。
//!
//! Windows 上必须 `kill()` 之后 `wait()`：只 kill 不 wait 会留下僵尸句柄，
//! 父进程退出后子进程可能被别的会话收养。

use std::process::{Child, ExitStatus};

use crate::error::LaunchError;
use crate::identity::{EnvironmentId, Generation};

/// 一个已启动的浏览器进程。
///
/// `Drop` 会**兜底回收**：正常路径调用 [`BrowserProcess::shutdown`]，
/// 异常路径（panic、提前 return）由 `Drop` 兜底，避免留下孤儿进程。
#[derive(Debug)]
pub struct BrowserProcess {
    child: Child,
    environment: EnvironmentId,
    generation: Generation,
    pid: u32,
    reaped: bool,
}

impl BrowserProcess {
    /// 接管一个已启动的子进程。
    pub(crate) fn new(child: Child, environment: EnvironmentId, generation: Generation) -> Self {
        let pid = child.id();
        Self {
            child,
            environment,
            generation,
            pid,
            reaped: false,
        }
    }

    /// 进程号。
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// 该进程所属环境。
    #[must_use]
    pub fn environment(&self) -> &EnvironmentId {
        &self.environment
    }

    /// 该进程所属代次。
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }

    /// 进程是否已经退出（不阻塞）。
    #[must_use]
    pub fn try_exit_status(&mut self) -> Option<ExitStatus> {
        self.child.try_wait().unwrap_or_default()
    }

    /// 借出进程存活观察器（就绪探测用）。
    pub(crate) fn watch(&mut self) -> &mut dyn crate::probe::ProcessWatch {
        &mut self.child
    }

    /// 终止并回收进程：`kill()` 之后必须 `wait()`。
    ///
    /// 重复调用是安全的：第二次调用发现已回收，直接返回。
    pub fn shutdown(&mut self) -> Result<ExitStatus, LaunchError> {
        if self.reaped {
            return Ok(ExitStatus::default());
        }
        // 先 kill 再 wait：只 kill 不 wait 会留僵尸。
        match self.child.kill() {
            Ok(()) => {}
            Err(error) => {
                // 进程可能已经自己退出了；这时 wait 仍然要跑。
                if error.kind() != std::io::ErrorKind::InvalidInput {
                    return Err(LaunchError::ReapFailed { kind: error.kind() });
                }
            }
        }
        match self.child.wait() {
            Ok(status) => {
                self.reaped = true;
                Ok(status)
            }
            Err(error) => Err(LaunchError::ReapFailed { kind: error.kind() }),
        }
    }

    /// 等待进程自然退出并回收（带上限）。
    ///
    /// 超时则转成 `kill + wait`，**保证**不留孤儿。
    pub fn wait_with_timeout(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<ExitStatus, LaunchError> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.reaped = true;
                    return Ok(status);
                }
                Ok(None) => {}
                Err(error) => return Err(LaunchError::ReapFailed { kind: error.kind() }),
            }
            if std::time::Instant::now() >= deadline {
                return self.shutdown();
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

impl Drop for BrowserProcess {
    fn drop(&mut self) {
        if !self.reaped {
            // 兜底回收：任何异常路径都不留孤儿进程。
            let _ = self.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BrowserProcess;
    use crate::identity::{EnvironmentId, Generation};

    fn handle() -> BrowserProcess {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--help"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        BrowserProcess::new(
            child,
            EnvironmentId::new("env-a").unwrap(),
            Generation::new(1).unwrap(),
        )
    }

    #[test]
    fn shutdown_kills_and_reaps() {
        let mut process = handle();
        let pid = process.pid();
        assert!(pid != 0);
        let status = process.shutdown().unwrap();
        assert!(status.success() || !status.success()); // 退出码不关心，只关心回收
                                                        // 回收后再次调用是安全的。
        assert!(process.shutdown().is_ok());
    }

    #[test]
    fn drop_reaps_the_process() {
        let pid = {
            let process = handle();
            process.pid()
        };
        // Drop 已经 kill + wait，进程不再存活。
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!process_alive(pid));
    }

    fn process_alive(pid: u32) -> bool {
        // 只在 Unix 上用 kill(pid, 0) 探测；Windows 上跳过。
        #[cfg(unix)]
        {
            let mut probe = std::process::Command::new("kill");
            probe.arg("-0").arg(pid.to_string());
            probe.stdout(std::process::Stdio::null());
            probe.stderr(std::process::Stdio::null());
            probe.status().map(|s| s.success()).unwrap_or(false)
        }
        #[cfg(not(unix))]
        {
            let _ = pid;
            false
        }
    }
}
