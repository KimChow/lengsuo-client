//! `lengsuo-node-dryrun <config.json>`：加载节点配置并对每节点做 dry-run。
//!
//! 退出码：0 = 全部节点握手到认证完成；1 = 至少一个节点失败；
//! 2 = 用法/配置文件错误。输出逐节点一行 `name [protocol] ok|fail: 原因`，
//! 失败原因不含密码或其摘要。

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use lengsuo_node::config;
use lengsuo_node::dryrun;

/// 单步（TLS/拨号/帧读写）截止时间。
const WAIT: Duration = Duration::from_secs(10);
/// trojan 认证拒绝观察窗。
const OBSERVE: Duration = Duration::from_millis(500);

fn main() -> ExitCode {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(run())
}

async fn run() -> ExitCode {
    let mut args = std::env::args();
    let program = args
        .next()
        .unwrap_or_else(|| "lengsuo-node-dryrun".to_owned());
    let Some(path) = args.next() else {
        eprintln!("用法：{program} <config.json>");
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("用法：{program} <config.json>");
        return ExitCode::from(2);
    }
    let nodes = match config::load_nodes(Path::new(&path)) {
        Ok(nodes) => nodes,
        Err(error) => {
            eprintln!("配置错误：{error}");
            return ExitCode::from(2);
        }
    };
    if nodes.is_empty() {
        eprintln!("配置错误：节点列表为空");
        return ExitCode::from(2);
    }
    let reports = dryrun::dry_run(&nodes, WAIT, OBSERVE).await;
    let mut failed = 0usize;
    for report in &reports {
        match &report.reason {
            None => println!("{} [{:?}] ok", report.name, report.protocol),
            Some(reason) => {
                failed += 1;
                println!("{} [{:?}] fail: {reason}", report.name, report.protocol);
            }
        }
    }
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
