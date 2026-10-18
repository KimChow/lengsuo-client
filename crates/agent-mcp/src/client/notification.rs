//! [`NotificationReceiver`]：服务端主动通知的订阅端。

use serde_json::Value;
use tokio::sync::broadcast;

use crate::protocol::JsonRpcNotification;

use super::McpClient;

/// 服务端主动通知（`notifications/*` 等）的订阅端。
///
/// 订阅点是「建立订阅的那一刻」：之前的通知不回放（会话只在广播通道里保留
/// 在途消息）。订阅端滞后时丢最旧并累加 [`NotificationReceiver::lagged`]，
/// 绝不反压读循环。
#[derive(Debug)]
pub struct NotificationReceiver {
    rx: broadcast::Receiver<JsonRpcNotification>,
    lagged: u64,
}

impl NotificationReceiver {
    pub(crate) fn new(rx: broadcast::Receiver<JsonRpcNotification>) -> Self {
        Self { rx, lagged: 0 }
    }

    /// 取下一条通知；会话结束（广播通道关闭）时返回 `None`。
    ///
    /// 滞后不视为结束：跳过缺口继续收下一条。
    pub async fn recv(&mut self) -> Option<(String, Value)> {
        loop {
            match self.rx.recv().await {
                Ok(note) => return Some(into_pair(note)),
                Err(broadcast::error::RecvError::Lagged(_skipped)) => self.lagged += 1,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }

    /// 非阻塞取一条通知（测试与轮询用）。队列为空、或刚发生滞后跳过时返回
    /// `None`（滞后由 [`Self::lagged`] 计数，下一次调用继续收最新的一条）。
    #[must_use]
    pub fn try_recv(&mut self) -> Option<(String, Value)> {
        match self.rx.try_recv() {
            Ok(note) => Some(into_pair(note)),
            Err(broadcast::error::TryRecvError::Lagged(_skipped)) => {
                self.lagged += 1;
                None
            }
            Err(broadcast::error::TryRecvError::Empty)
            | Err(broadcast::error::TryRecvError::Closed) => None,
        }
    }

    /// 本订阅端因滞后被跳过的通知条数。
    #[must_use]
    pub fn lagged(&self) -> u64 {
        self.lagged
    }
}

fn into_pair(note: JsonRpcNotification) -> (String, Value) {
    (note.method, note.params.unwrap_or(Value::Null))
}

impl McpClient {
    /// 订阅服务端主动通知。可以在任何时候建立，每个订阅端独立；
    /// 建立之前的通知不回放。
    #[must_use]
    pub fn subscribe_notifications(&self) -> NotificationReceiver {
        NotificationReceiver::new(self.session.subscribe_notifications())
    }
}
