//! `lengsuo-client <config.toml>`：读配置 → 组装运行时 → 打印监听地址 → 跑循环。
//!
//! 这里只做参数解析与组装；分流 / 拨号 / 拼接逻辑在 [`ss_client::runtime`]。

use std::process::exit;

use ss_client::config::load_config;
use ss_client::runtime::Runtime;

const USAGE: &str = "usage: lengsuo-client <config.toml>";

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let path = match (args.next(), args.next()) {
        (None, _) => {
            eprintln!("{USAGE}");
            exit(2);
        }
        (Some(flag), _) if flag == "-h" || flag == "--help" => {
            println!("{USAGE}");
            exit(0);
        }
        (Some(_), Some(_)) => {
            eprintln!("{USAGE}");
            exit(2);
        }
        (Some(path), None) => path,
    };

    let config = match load_config(&path) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("config error: {err}");
            exit(2);
        }
    };

    let runtime = match Runtime::new(config).await {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("runtime error: {err}");
            exit(2);
        }
    };

    match runtime.local_addr() {
        Ok(addr) => println!("listening on {addr}"),
        Err(err) => {
            eprintln!("runtime error: {err}");
            exit(2);
        }
    }

    if let Err(err) = runtime.run().await {
        eprintln!("runtime error: {err}");
        exit(1);
    }
}
