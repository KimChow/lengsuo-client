//! 会话关闭、中止与 `Drop`。

use super::*;

impl Session {
    /// 正常关闭：关闭写侧（让服务端得到 stdin EOF），等待子进程退出；
    /// `kill_after` 到点仍未退出则强杀后再等一次。
    ///
    /// # Errors
    /// 等待子进程失败或强杀后仍不退出时返回 [`Error::Transport`]。
    pub(crate) async fn close(&self, kill_after: Duration) -> Result<i32, Error> {
        self.inner.close_writer();
        let mut guard = self.child.lock().await;
        let code = match guard.as_mut() {
            // 未安装传输（或子进程已回收）：没有进程可等，视为已退出。
            None => Ok(0),
            Some(child) => match tokio::time::timeout(kill_after, child.wait()).await {
                Ok(status) => status.map_err(|e| Error::Transport {
                    reason: format!("等待子进程退出失败：{e}"),
                }),
                Err(_) => {
                    let _ = child.start_kill();
                    tokio::time::timeout(kill_after, child.wait())
                        .await
                        .map_err(|_| Error::Transport {
                            reason: "子进程在强杀后仍未退出".to_string(),
                        })?
                        .map_err(|e| Error::Transport {
                            reason: format!("等待子进程退出失败：{e}"),
                        })
                }
            }
            .map(|status| status.code().unwrap_or(-1)),
        };
        let _ = guard.take();
        drop(guard);
        self.finish_shutdown();
        code
    }

    /// 立即强杀子进程并回收（异常清理路径，例如握手失败），停 reader。
    pub(crate) async fn abort(&self) {
        self.inner.close_writer();
        {
            let mut guard = self.child.lock().await;
            if let Some(child) = guard.as_mut() {
                let _ = child.start_kill();
                let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
            }
            let _ = guard.take();
        }
        self.finish_shutdown();
    }

    /// 标记 poisoned 并清理连接（超时后重建前调用）。
    #[allow(dead_code)] // 保留给上层显式丢弃语义；当前由 request 超时内部完成
    pub(crate) async fn hard_kill(&self, reason: String) {
        self.inner.poison(reason);
        self.abort().await;
    }

    /// 连接生命周期收尾：标记 closed、撤下在途请求、停 reader 任务。
    fn finish_shutdown(&self) {
        self.inner.closed.store(true, Ordering::Release);
        if let Some(task) = self.reader_task.lock().expect("reader 锁不中毒").take() {
            task.abort();
        }
    }

    /// `Drop` 前半程：停 reader、关写侧（不阻塞当前线程）。子进程由
    /// `kill_on_drop` 回收。
    pub(crate) fn finalize_drop(&self) -> Result<(), Error> {
        self.inner.close_writer();
        if let Ok(mut guard) = self.reader_task.try_lock() {
            if let Some(task) = guard.take() {
                task.abort();
            }
        }
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // 先停 reader，再关闭写侧；不阻塞当前线程。子进程由 transport 的
        // `kill_on_drop` 负责，测试通过显式 shutdown/abort 验证无残留。
        let _ = self.finalize_drop();
    }
}
