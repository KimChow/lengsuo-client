//! WebFetch：只走 http/https 的小额度抓取，正文收成纯文本。
//!
//! 边界（与冻结 API 一致）：
//! * 只接受 `http`/`https`，其它 scheme（`file://`、`gopher://`…）⇒ [`ExecError::InvalidUrl`]；
//! * 重定向默认最多 5 次（[`WebFetcher::with_max_redirects`] 可调）；
//! * 非 2xx ⇒ [`ExecError::HttpStatus`]；
//! * 响应体最多读生效的 `max_bytes` 字节，超出即停止；
//! * HTML 走 [`crate::html`] 的极简转换，不引入解析器。
//!
//! 抓取器缓存一个 [`reqwest::Client`]：连接池在它的持有者（通常是一个
//! `Arc<WebFetcher>`）里共享复用，不必每次抓取重造 TLS 上下文。缓存的用法：
//! * 缓存为空 ⇒ 按当前配置建客户端；
//! * 缓存的超时**宽于**当前要求 ⇒ 直接报错（放宽额度可以，悄悄丢掉调用方的超时
//!   预算不行）；
//! * 缓存的字节上限**严于**当前要求 ⇒ 跟着缓存走，不复用一个读得比缓存客户端
//!   本身还多的额度。
//!
//! 缓存的键是建它时用的配置，所以 `with_*` 都会作废缓存；并发初始化时若输给
//! 另一个调用方，上面两条规则负责判定该复用还是该拒绝。
//!
//! 本模块不做 robots.txt / 域名白名单判断：授权由调用方的权限门决定。

use std::fmt::Debug;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, USER_AGENT};
use tokio::sync::OnceCell;
use url::Url;

use crate::error::ExecError;
use crate::html;

/// 默认 User-Agent：可被调用方覆盖，但不伪装成浏览器。
const DEFAULT_USER_AGENT: &str = "lengsuo-agent-tools-exec/0.1";

/// 默认最多跟随的重定向次数。
const DEFAULT_MAX_REDIRECTS: usize = 5;

/// 抓取同时接受 HTML 与纯文本，具体按响应的 `Content-Type` 决定要不要走标签转换。
const ACCEPT_HTML_AND_TEXT: &str = "text/html;q=0.9,text/plain;q=0.8,*/*;q=0.5";

/// 语言提示：抓到的正文只给本客户端的模型读，不做按站点语言的自动降级。
const ACCEPT_LANGUAGE_VALUE: &str = "en";

/// 一次抓取的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchResult {
    /// 跟随重定向后的最终 URL。
    pub final_url: String,
    /// `<title>` 文本；没有则为 `None`。
    pub title: Option<String>,
    /// HTML → 纯文本正文（非 HTML 内容按原文保留）。
    pub text_markdown: String,
}

/// 决定一次抓取（含缓存客户端）长什么样的配置集合。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Config {
    user_agent: String,
    timeout: Duration,
    max_bytes: usize,
    max_redirects: usize,
}

impl Config {
    fn new(timeout: Duration, max_bytes: usize) -> Self {
        Config {
            user_agent: DEFAULT_USER_AGENT.to_string(),
            timeout,
            max_bytes,
            max_redirects: DEFAULT_MAX_REDIRECTS,
        }
    }

    /// 缓存客户端的默认请求头。
    fn headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, user_agent_value(&self.user_agent));
        headers.insert(ACCEPT, HeaderValue::from_static(ACCEPT_HTML_AND_TEXT));
        headers.insert(
            ACCEPT_LANGUAGE,
            HeaderValue::from_static(ACCEPT_LANGUAGE_VALUE),
        );
        headers
    }
}

/// 抓取器。
///
/// 比较与调试只看配置：缓存里装着连接池，既没有可比性也没有可读性。
#[derive(Clone)]
pub struct WebFetcher {
    config: Config,
    /// 建好的客户端连同建它时用的配置：判定该复用、该降级还是该拒绝。
    client: OnceCell<(Config, reqwest::Client)>,
}

impl Debug for WebFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebFetcher")
            .field("config", &self.config)
            .field("client_cached", &self.client.get().is_some())
            .finish()
    }
}

impl PartialEq for WebFetcher {
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config
    }
}

impl Eq for WebFetcher {}

impl WebFetcher {
    /// 用超时与字节上限构造抓取器；UA 与重定向数用默认值。
    pub fn new(timeout: Duration, max_bytes: usize) -> Self {
        WebFetcher {
            config: Config::new(timeout, max_bytes),
            client: OnceCell::new(),
        }
    }

    /// 换用 User-Agent；缓存的客户端随之作废。
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.config.user_agent = user_agent.into();
        self.reset_client()
    }

    /// 换用超时；缓存的客户端随之作废。
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self.reset_client()
    }

    /// 换用响应体字节上限；缓存的客户端随之作废。
    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.config.max_bytes = max_bytes;
        self.reset_client()
    }

    /// 换用重定向上限；缓存的客户端随之作废。
    pub fn with_max_redirects(mut self, max_redirects: usize) -> Self {
        self.config.max_redirects = max_redirects;
        self.reset_client()
    }

    /// 生效的 User-Agent。
    pub fn user_agent(&self) -> &str {
        &self.config.user_agent
    }

    /// 生效的超时。
    pub fn timeout(&self) -> Duration {
        self.config.timeout
    }

    /// 生效的响应体字节上限。
    pub fn max_bytes(&self) -> usize {
        self.config.max_bytes
    }

    /// 生效的重定向上限。
    pub fn max_redirects(&self) -> usize {
        self.config.max_redirects
    }

    /// 抓取 `url` 并返回纯文本结果。
    pub async fn fetch_to_markdown(&self, url: &str) -> Result<FetchResult, ExecError> {
        let parsed = self.check_url(url)?;
        let (cached, client) = self.cached_client().await?;
        let max_bytes = cached.max_bytes.min(self.config.max_bytes);
        let resp = client
            .get(parsed)
            .send()
            .await
            .map_err(|e| map_reqwest(e, &cached.user_agent))?;
        let final_url = resp.url().to_string();
        let status = resp.status();
        if !status.is_success() {
            return Err(ExecError::HttpStatus {
                code: status.as_u16(),
                url: final_url,
            });
        }
        let is_html = content_type_is_html(resp.headers().get(CONTENT_TYPE));
        let body = read_body(resp, max_bytes).await?;
        let text = String::from_utf8_lossy(&body);
        let (title, text_markdown) = if is_html {
            (
                html::extract_title(&text),
                html::to_text(&text).trim().to_string(),
            )
        } else {
            (None, text.trim().to_string())
        };
        Ok(FetchResult {
            final_url,
            title,
            text_markdown,
        })
    }

    /// 只允许 http/https；其它 scheme 一律拒绝。
    fn check_url(&self, url: &str) -> Result<Url, ExecError> {
        let parsed = Url::parse(url).map_err(|e| ExecError::InvalidUrl(e.to_string()))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(ExecError::InvalidUrl(format!(
                "只允许 http/https，收到 {:?}",
                parsed.scheme()
            )));
        }
        Ok(parsed)
    }

    /// 取缓存的客户端，必要时按当前配置建一个。
    async fn cached_client(&self) -> Result<&(Config, reqwest::Client), ExecError> {
        let cached = self
            .client
            .get_or_try_init(|| {
                let config = self.config.clone();
                async move {
                    let client = build_client(&config)?;
                    Ok::<_, ExecError>((config, client))
                }
            })
            .await?;
        // 缓存比当前要求宽松 ⇒ 不能假装满足：调用方的超时预算会被悄悄丢掉。
        if cached.0.timeout > self.config.timeout {
            return Err(ExecError::Io(format!(
                "共享抓取客户端已按 {:?} 建好，宽于本次要求的 {:?}，无法复用",
                cached.0.timeout, self.config.timeout
            )));
        }
        Ok(cached)
    }

    fn reset_client(mut self) -> Self {
        self.client = OnceCell::new();
        self
    }
}

/// 按配置建客户端。
fn build_client(config: &Config) -> Result<reqwest::Client, ExecError> {
    reqwest::Client::builder()
        .default_headers(config.headers())
        .timeout(config.timeout)
        .redirect(reqwest::redirect::Policy::limited(config.max_redirects))
        .build()
        .map_err(|e| ExecError::Io(e.to_string()))
}

/// UA 头只接受可见 ASCII；非法或空值退回默认 UA，而不是让整个抓取失败。
fn user_agent_value(user_agent: &str) -> HeaderValue {
    if !user_agent.is_empty() {
        if let Ok(value) = HeaderValue::from_str(user_agent) {
            return value;
        }
    }
    HeaderValue::from_static(DEFAULT_USER_AGENT)
}

fn content_type_is_html(value: Option<&HeaderValue>) -> bool {
    value
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.to_ascii_lowercase().contains("html"))
}

/// 按字节上限流式读取响应体；`Content-Length` 只是提示，以实际读取为准。
async fn read_body(resp: reqwest::Response, max_bytes: usize) -> Result<Vec<u8>, ExecError> {
    let mut body: Vec<u8> = Vec::new();
    let mut resp = resp;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| ExecError::Io(e.to_string()))?
    {
        let keep = max_bytes.saturating_sub(body.len()).min(chunk.len());
        body.extend_from_slice(&chunk[..keep]);
        if body.len() >= max_bytes {
            break;
        }
    }
    Ok(body)
}

/// reqwest 错误分类。
fn map_reqwest(e: reqwest::Error, _user_agent: &str) -> ExecError {
    if e.is_timeout() {
        ExecError::Timeout
    } else if e.is_redirect() {
        ExecError::Io("重定向超过上限".to_string())
    } else {
        ExecError::Io(e.to_string())
    }
}
