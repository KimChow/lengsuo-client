//! 请求/通知/服务端回复的发送与等待路径。

use super::*;

impl Session {
    fn alloc_id(&self) -> Result<RequestId, Error> {
        match self.next_id.fetch_add(1, Ordering::Relaxed) {
            // 取尽：回退并永久钉在 MAX，后续调用持续 fail-closed
            // （与 ss-core nonce 取尽同一语义：不可逆，不静默复用）。
            i64::MAX => {
                self.next_id.store(i64::MAX, Ordering::Relaxed);
                Err(Error::InvalidConfig {
                    reason: "请求 id 已取尽，必须重建会话".to_string(),
                })
            }
            n => Ok(RequestId::Number(n)),
        }
    }

    /// 发送请求并等待响应，返回 `result` 值；对端 `error` 分支映射为
    /// [`Error::JsonRpc`]。`timeout` 为 `None` 时使用会话默认值。
    ///
    /// # Errors
    /// 见 [`Error`]：超时（并 poison 连接）、传输中断、帧损坏、对端 JSON-RPC 错误。
    pub(crate) async fn request(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Option<Duration>,
    ) -> Result<Value, Error> {
        let payload = self.request_payload(method, params, timeout).await?;
        match payload {
            ResponsePayload::Result(v) => Ok(v),
            ResponsePayload::Error(e) => Err(e.to_error()),
        }
    }

    /// 发送请求并等待响应负载（保留 `error` 分支原样，供需要细粒度处理的调用方）。
    #[allow(dead_code)] // v0 出口：将来 sampling/进度等需要区分 result/error 形状时使用
    pub(crate) async fn request_payload(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Option<Duration>,
    ) -> Result<ResponsePayload, Error> {
        let timeout = timeout.unwrap_or(self.inner.default_timeout);
        let start = Instant::now();
        let deadline = start + timeout;
        self.inner.ensure_usable()?;
        let id = self.alloc_id()?;
        let (tx, rx) = oneshot::channel();
        self.inner.register(id.clone(), tx);

        let envelope = RequestEnvelope {
            jsonrpc: "2.0",
            id: id.clone(),
            method: method.to_string(),
            params,
        };
        if let Err(e) = self.inner.send_frame(&envelope).await {
            self.inner.deregister(&id);
            return Err(e);
        }

        match tokio::time::timeout_at(deadline, rx).await {
            // rx 的 item 已是 `Result<ResponsePayload, Error>`：读侧投递的
            // 连接级失败（poisoned）原样返回，不伪装成一条响应。
            Ok(Ok(payload)) => payload,
            Ok(Err(_canceled)) => {
                // reader 收尾时撤下 sender：连接已结束。
                self.inner.deregister(&id);
                Err(self.inner.failure_reason())
            }
            Err(_elapsed) => {
                self.inner.deregister(&id);
                let elapsed_ms = (Instant::now() - start).as_millis() as u64;
                self.inner
                    .poison(format!("method={method} 等待响应超过 {timeout:?}"));
                // fail-closed：同会话其余在途请求一并失败，不复用半可信连接。
                self.inner.fail_all(&Error::Poisoned {
                    reason: format!("同会话内 method={method} 超时"),
                });
                Err(Error::Timeout { elapsed_ms })
            }
        }
    }

    /// 发送通知（无 id、无响应）。
    ///
    /// # Errors
    /// 写侧失败或连接不可用。
    pub(crate) async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), Error> {
        self.inner.ensure_usable()?;
        let envelope = NotificationEnvelope {
            jsonrpc: "2.0",
            method: method.to_string(),
            params,
        };
        self.inner.send_frame(&envelope).await
    }

    /// 回复服务端发起的请求（v0 提供出口，便于将来实现 sampling）。
    ///
    /// # Errors
    /// 写侧失败或连接不可用。
    #[allow(dead_code)] // 同上：v0 reader 自动拒绝，此出口留给后续实现
    pub(crate) async fn respond_to_server(
        &self,
        id: RequestId,
        payload: ResponsePayload,
    ) -> Result<(), Error> {
        let body = match payload {
            ResponsePayload::Result(v) => serde_json::json!({
                "jsonrpc": "2.0", "id": id, "result": v
            }),
            ResponsePayload::Error(e) => serde_json::json!({
                "jsonrpc": "2.0", "id": id, "error": e
            }),
        };
        self.inner.send_frame(&body).await
    }
}
