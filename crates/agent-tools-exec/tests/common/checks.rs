//! 结果逐字段断言与抓取器构造。

use std::time::Duration;

use agent_tools_exec::{ExecError, ExecResult, FetchResult, WebFetcher};

/// 结果与期望逐字段比对。
pub fn check_exec(
    outcome: Result<ExecResult, ExecError>,
    exit: i32,
    stdout: &str,
    stderr: &str,
    truncated: bool,
    timed_out: bool,
) {
    let result = match outcome {
        Ok(result) => result,
        Err(error) => panic!("执行失败：{error}"),
    };
    assert_eq!(result.exit_code, exit, "退出码；stderr={:?}", result.stderr);
    assert_eq!(result.stdout, stdout, "stdout");
    assert_eq!(result.stderr, stderr, "stderr");
    assert_eq!(result.truncated, truncated, "truncated");
    assert_eq!(result.timed_out, timed_out, "timed_out");
}

/// 断言失败路径的错误展示文本。
pub fn check_exec_error(outcome: Result<ExecResult, ExecError>, message: &str) {
    match outcome {
        Ok(result) => panic!("期望失败，实际成功：{result:?}"),
        Err(error) => assert_eq!(error.to_string(), message),
    }
}

/// 抓取成功路径的逐字段比对。
pub fn check_fetch(
    outcome: Result<FetchResult, ExecError>,
    final_url: &str,
    title: &str,
    markdown: &str,
) {
    let result = match outcome {
        Ok(result) => result,
        Err(error) => panic!("抓取失败：{error}"),
    };
    assert_eq!(result.final_url, final_url, "final_url");
    assert_eq!(result.title, title, "title");
    assert_eq!(result.text_markdown, markdown, "text_markdown");
}

/// 断言抓取失败的错误展示文本。
pub fn check_fetch_error(outcome: Result<FetchResult, ExecError>, message: &str) {
    match outcome {
        Ok(result) => panic!("期望失败，实际成功：{result:?}"),
        Err(error) => assert_eq!(error.to_string(), message),
    }
}

pub fn default_fetcher() -> WebFetcher {
    WebFetcher::new(Duration::from_millis(500), 1_048_576)
}

/// 抓取器，把响应字节上限与文本上限一并设成 `limit`。
pub fn fetcher_at_limit(limit: usize) -> WebFetcher {
    WebFetcher::with_max_text_bytes(Duration::from_millis(500), limit, limit)
}

pub fn fetcher_with_timeout(timeout: Duration) -> WebFetcher {
    WebFetcher::new(timeout, 4096)
}
