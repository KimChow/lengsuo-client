//! `lengsuo-ss-relay-server [--bind <ip:port>] [--method <name>] [--password <pwd>]`
//! —— 可部署的自研 Shadowsocks 出口服务端（TUN-3 自研路线，见 `docs/tun3-egress-nodes.md` §4）。
//!
//! 本文件只做参数解析与组装；服务主体（真 `TcpListener` + 真 AEAD 握手 + fail-closed
//! 中继）全部复用 `lengsuo_shadowsocks::RelayService`。
//!
//! - 口令优先取环境变量 `LENGSUO_SS_PASSWORD`（避免 `ps` 泄漏），`--password` 仅兜底；
//!   显式设了空口令视为配置错误。任何输出都不含口令。
//! - 启动成功后向 stdout 打印**一行** `LISTEN <ip:port>` 并 flush（`--bind` 端口为 0 时
//!   给出实际随机端口），供部署脚本 / 测试解析。
//! - fail-closed：未知参数 / `--bind` 形状非法 / `--method` 非法 / 缺口令 ⇒ 退出码 2；
//!   绑定或启动失败 ⇒ 退出码 3。绝不退化成明文 / 无认证转发。
//! - SIGINT/SIGTERM：tokio 的 `signal` feature 未启用且共享 `Cargo.toml` 是禁区，无法
//!   注册自定义 handler ⇒ 走系统默认处置直接终止进程；监听 fd 由内核回收，本二进制
//!   不派生子进程 ⇒ 无残留监听 fd、无遗留子进程。

use std::io::Write as _;
use std::net::SocketAddr;
use std::process::exit;
use std::time::Duration;

use lengsuo_shadowsocks::{CipherSuite, RelayConfig, RelayConfigParts, RelayService};

const USAGE: &str =
    "usage: lengsuo-ss-relay-server [--bind <ip:port>] [--method <name>] [--password <pwd>]\n\
       defaults: --bind 0.0.0.0:25002  --method aes-256-gcm\n\
       password: env LENGSUO_SS_PASSWORD (preferred) or --password";

/// 已解析的命令行选项（`password` 只是 `--password` 兜底值；环境变量在 `main` 里优先）。
struct Options {
    bind: SocketAddr,
    method: String,
    password: Option<String>,
}

/// 逐个解析 `--flag <value>`；形状错误（未知参数 / 缺值 / 地址不可解析）⇒ 退出码 2。
fn parse_args() -> Options {
    let mut options = Options {
        bind: "0.0.0.0:25002".parse().expect("default bind is valid"),
        method: "aes-256-gcm".to_string(),
        password: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        if flag == "-h" || flag == "--help" {
            println!("{USAGE}");
            exit(0);
        }
        let Some(value) = args.next() else {
            eprintln!("missing value for {flag}\n{USAGE}");
            exit(2);
        };
        match flag.as_str() {
            "--bind" => match value.parse() {
                Ok(bind) => options.bind = bind,
                Err(_) => {
                    eprintln!("invalid --bind {value} (want <ip:port>)");
                    exit(2);
                }
            },
            "--method" => options.method = value,
            "--password" => options.password = Some(value),
            other => {
                eprintln!("unknown argument {other}\n{USAGE}");
                exit(2);
            }
        }
    }
    options
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let options = parse_args();
    // method 必须是 ss-core 认识的 AEAD 套件名；拼错即拒绝启动，不猜。
    let Some(suite) = CipherSuite::from_name(&options.method) else {
        eprintln!(
            "unknown --method {} (supported: aes-128-gcm, aes-256-gcm, \
             chacha20-ietf-poly1305, xchacha20-ietf-poly1305)",
            options.method
        );
        exit(2);
    };
    // 环境变量优先（避免 ps 泄漏）；两者皆缺、或显式设了空口令 ⇒ 拒绝启动。
    let password = std::env::var("LENGSUO_SS_PASSWORD")
        .ok()
        .or(options.password)
        .filter(|password| !password.is_empty());
    let Some(password) = password else {
        eprintln!("missing password: set LENGSUO_SS_PASSWORD or pass --password");
        exit(2);
    };

    let config = RelayConfig::new(
        RelayConfigParts {
            suite,
            idle_timeout: Duration::from_secs(10),
            replay: None,
        },
        password.as_bytes(),
    );

    // `RelayService::start` 内部 `spawn_local` ⇒ 必须在 `LocalSet` 里跑（同 e2e_chain）。
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let service = match RelayService::bind(options.bind, config).await {
                Ok(service) => service,
                Err(err) => {
                    eprintln!("bind {} failed: {err}", options.bind);
                    exit(3);
                }
            };
            let addr = match service.local_addr() {
                Ok(addr) => addr,
                Err(err) => {
                    eprintln!("local_addr failed: {err}");
                    exit(3);
                }
            };
            // 就绪行：恰好一行 `LISTEN <ip:port>`；部署脚本 / 测试依赖此形状。
            {
                let mut stdout = std::io::stdout().lock();
                writeln!(stdout, "LISTEN {addr}").expect("write LISTEN line");
                stdout.flush().expect("flush LISTEN line");
            }
            let handle = match service.start().await {
                Ok(handle) => handle,
                Err(err) => {
                    eprintln!("start failed: {err}");
                    exit(3);
                }
            };
            // 服务循环在 `spawn_local` 的任务里；句柄保持存活（drop 即停服务），
            // 主 future 永不完成 ⇒ 进程一直服务到被终止（信号语义见模块文档）。
            let _keep_alive = handle;
            std::future::pending::<()>().await;
        })
        .await;
}
