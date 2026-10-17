use agent_core::{runtime::Runtime, schema::Isolation};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Request, State,
    },
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpListener, sync::watch, task::JoinHandle};

#[derive(Clone)]
pub struct GatewayConfig {
    pub handshake_path: PathBuf,
    pub isolation: Isolation,
}
impl GatewayConfig {
    pub fn new(path: impl Into<PathBuf>, isolation: Isolation) -> Self {
        Self {
            handshake_path: path.into(),
            isolation,
        }
    }
}
#[derive(Clone)]
pub(crate) struct App {
    pub runtime: Runtime,
    pub isolation: Isolation,
    pub token: Arc<str>,
    pub closing: watch::Receiver<bool>,
}
/// Owns a single listener. Tokens are intentionally excluded from Debug.
pub struct GatewayHandle {
    port: u16,
    token: Arc<str>,
    path: PathBuf,
    shutdown: watch::Sender<bool>,
    task: Option<JoinHandle<std::io::Result<()>>>,
}
impl GatewayHandle {
    pub async fn start(runtime: Runtime, config: GatewayConfig) -> std::io::Result<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|_| std::io::Error::other("token generation failed"))?;
        let token: Arc<str> = bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            .into();
        write_handshake(&config.handshake_path, port, &token)?;
        let (shutdown, closing) = watch::channel(false);
        let state = App {
            runtime,
            isolation: config.isolation,
            token: token.clone(),
            closing: closing.clone(),
        };
        let app = Router::new()
            .route("/rpc", post(crate::rpc::handle))
            .route("/events", get(events))
            .fallback(|| async {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({"code":404,"msg":"unknown route","data":null})),
                )
            })
            .layer(middleware::from_fn_with_state(state.clone(), authenticate))
            .with_state(state);
        let task = tokio::spawn(async move {
            let mut closing = closing;
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = closing.changed().await;
                })
                .await
        });
        Ok(Self {
            port,
            token,
            path: config.handshake_path,
            shutdown,
            task: Some(task),
        })
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn token(&self) -> &str {
        &self.token
    }
    pub async fn shutdown(mut self) -> std::io::Result<()> {
        let _ = self.shutdown.send(true);
        if let Some(mut task) = self.task.take() {
            match tokio::time::timeout(Duration::from_secs(5), &mut task).await {
                Ok(r) => r.map_err(|_| std::io::Error::other("gateway task failed"))??,
                Err(_) => {
                    task.abort();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "gateway shutdown timed out",
                    ));
                }
            }
        }
        Ok(())
    }
}
impl Drop for GatewayHandle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(t) = self.task.take() {
            t.abort();
        }
        remove_handshake(&self.path, &self.token);
    }
}
fn write_handshake(path: &Path, port: u16, token: &str) -> std::io::Result<()> {
    #[cfg(not(unix))]
    return Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "private handshake ACL not yet verified on this platform",
    ));
    #[cfg(unix)]
    {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        // The host must supply an existing private directory. Never replace another process's file.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let content = json!({"port":port,"pid":std::process::id(),"token":token}).to_string();
        if let Err(e) = file
            .write_all(content.as_bytes())
            .and_then(|_| file.sync_all())
        {
            let _ = std::fs::remove_file(path);
            return Err(e);
        }
        Ok(())
    }
}
fn remove_handshake(path: &Path, token: &str) {
    if let Ok(bytes) = std::fs::read(path) {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            if v["token"].as_str() == Some(token) {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}
async fn authenticate(State(app): State<App>, req: Request, next: Next) -> Response {
    let valid = req
        .headers()
        .get("X-Gateway-Token")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| equal_token(v.as_bytes(), app.token.as_bytes()));
    if !valid {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"code":403,"msg":"forbidden","data":null})),
        )
            .into_response();
    }
    next.run(req).await
}
fn equal_token(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |n, (x, y)| n | (x ^ y)) == 0
}
async fn events(State(app): State<App>, upgrade: WebSocketUpgrade) -> Response {
    let subscription = app.runtime.subscribe(&app.isolation.key());
    upgrade
        .on_upgrade(move |socket| stream(socket, app, subscription))
        .into_response()
}
async fn stream(mut socket: WebSocket, app: App, sub: agent_core::bus::Subscription) {
    let mut closing = app.closing.clone();
    let mut tick = tokio::time::interval(Duration::from_millis(10));
    loop {
        tokio::select! {
            _=closing.changed()=>break,
            received=socket.recv()=>match received {
                Some(Ok(Message::Close(_)))|None|Some(Err(_))=>break,
                Some(Ok(Message::Ping(bytes)))=>{if socket.send(Message::Pong(bytes)).await.is_err(){break;}},
                _=>{}
            },
            _=tick.tick()=> {
                // Drain a bounded batch; never starve shutdown or inbound control frames.
                for _ in 0..64 {
                    let Some(event)=sub.try_next() else {break;};
                    if !app.runtime.get_session(event.session_id).is_ok_and(|s|s.isolation==app.isolation){continue;}
                    let value=json!({"seq":event.seq,"session_id":event.session_id,"kind":event.kind,"payload":event.payload,"ts_ms":event.ts_ms});
                    if !matches!(tokio::time::timeout(Duration::from_secs(5),socket.send(Message::Text(value.to_string()))).await,Ok(Ok(()))){return;}
                }
            }
        }
    }
    let _ = tokio::time::timeout(Duration::from_secs(1), socket.close()).await;
}
