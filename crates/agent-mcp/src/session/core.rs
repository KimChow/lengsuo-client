//! 会话构造、传输安装与只读访问。

use super::*;

impl Session {
    /// 建立会话状态但不安装传输：`has_transport()` 为 `false`，任何请求都会
    /// 以 [`Error::Transport`] fail-closed 拒绝，直到 [`Self::attach_stdio`]。
    #[must_use]
    pub(crate) fn with_config(config: SessionConfig) -> Arc<Self> {
        let (notify_tx, rx) = broadcast::channel(config.notify_capacity.max(MIN_NOTIFY_CAPACITY));
        let inner = Arc::new(Inner {
            framing: config.framing,
            max_frame_bytes: config.max_frame_bytes,
            default_timeout: config.default_timeout,
            writer: AsyncMutex::new(None),
            transport: AtomicBool::new(false),
            pending: Mutex::new(BTreeMap::new()),
            poison: Mutex::new(None),
            closed: AtomicBool::new(false),
            notify_tx,
            notify_seed: Mutex::new(Some(rx)),
            notify_dropped: AtomicU64::new(0),
            server_requests: Mutex::new(Vec::new()),
            unmatched_responses: AtomicU64::new(0),
            ignored_messages: AtomicU64::new(0),
        });
        Arc::new(Self {
            inner,
            child: AsyncMutex::new(None),
            next_id: AtomicI64::new(1),
            reader_task: Mutex::new(None),
        })
    }

    /// 安装 stdio 传输：接管子进程管道并启动 reader 任务。只能成功一次。
    ///
    /// # Errors
    /// [`Error::Transport`]：该会话已安装过传输（不覆盖，避免旧管道泄漏）。
    pub(crate) async fn attach_stdio(
        &self,
        stdin: ChildStdin,
        stdout: ChildStdout,
        child: Child,
    ) -> Result<(), Error> {
        {
            let mut writer = self.inner.writer.lock().await;
            if writer.is_some() || self.inner.transport.load(Ordering::Acquire) {
                return Err(Error::Transport {
                    reason: "会话已安装传输，不能重复安装".to_string(),
                });
            }
            *writer = Some(stdin);
            *self.child.lock().await = Some(child);
            self.inner.transport.store(true, Ordering::Release);
        }
        let task = tokio::spawn(reader_loop(
            BufReader::with_capacity(READ_CHUNK_BYTES, stdout),
            Arc::clone(&self.inner),
        ));
        *self.reader_task.lock().expect("reader 锁不中毒") = Some(task);
        Ok(())
    }

    /// 是否已安装传输。
    #[must_use]
    pub(crate) fn has_transport(&self) -> bool {
        self.inner.transport.load(Ordering::Acquire)
    }

    /// 以显式标记 poisoned：上层在握手失败等路径上留下原因文本。
    pub(crate) fn fail(&self, reason: &str) {
        self.inner.poison(reason.to_string());
    }

    #[must_use]
    pub(crate) fn framing(&self) -> Framing {
        self.inner.framing
    }

    #[must_use]
    pub(crate) fn default_timeout(&self) -> Duration {
        self.inner.default_timeout
    }

    /// 连接是否被标记 poisoned。
    #[must_use]
    pub(crate) fn is_poisoned(&self) -> bool {
        self.inner.poison_reason().is_some()
    }

    /// poisoned 原因（若有）。
    #[must_use]
    pub(crate) fn poison_reason(&self) -> Option<String> {
        self.inner.poison_reason()
    }

    /// 会话是否已结束（EOF 或主动关闭）。
    #[must_use]
    pub(crate) fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    /// 无法匹配到在途请求的响应数量（迟到响应或陌生 id）。
    #[must_use]
    pub(crate) fn unmatched_responses(&self) -> u64 {
        self.inner.unmatched_responses.load(Ordering::Acquire)
    }

    /// 被忽略的畸形消息数量（不损坏流，仅计数）。
    #[must_use]
    pub(crate) fn ignored_messages(&self) -> u64 {
        self.inner.ignored_messages.load(Ordering::Acquire)
    }

    /// 因订阅者滞后而被丢弃的通知数量。
    #[must_use]
    pub(crate) fn notify_dropped(&self) -> u64 {
        self.inner.notify_dropped.load(Ordering::Acquire)
    }

    /// 订阅服务端主动通知。每个订阅端独立；滞后时该端丢最旧（读循环不阻塞）。
    pub(crate) fn subscribe_notifications(&self) -> broadcast::Receiver<JsonRpcNotification> {
        self.inner.notify_tx.subscribe()
    }

    /// 取出并清空已记录的服务端请求（v0 只记录并自动拒绝，不处理）。
    pub(crate) fn drain_server_requests(&self) -> Vec<ServerRequest> {
        std::mem::take(
            &mut *self
                .inner
                .server_requests
                .lock()
                .expect("server request 锁不中毒"),
        )
    }
}
