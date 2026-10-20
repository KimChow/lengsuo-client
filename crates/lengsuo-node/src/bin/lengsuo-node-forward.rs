//! `lengsuo-node-forward <config.json>`：启动流量转发服务。
//!
//! 退出码：
//! - `0` = 转发服务正常停止（收到停止信号或标准输入关闭）；
//! - `1` = 运行期失败（监听失败、配置非法、路由引用了不存在的节点等）；
//! - `2` = 用法错误（缺参数、多参数、配置文件读不了或格式非法）。
//!
//! 本地监听是 **SOCKS5 CONNECT**（`RFC 1928`）：目标地址由客户端在握手里
//! 给出，转发器按规则选节点、走出站会话并双向转发。**失败一律断开，绝不直连**。
//!
//! 配置形态见 `lengsuo_node::forward::ForwardConfig` 的模块注释（顶层数组
//! 或 `{"nodes": [...], "forward": {...}}` 两种都接受）。
//!
//! 停止方式：读标准输入，收到 EOF（Ctrl-D）或一行 `stop` 即优雅收尾。
//! 这样**不需要** `tokio` 的 `signal` 特性（工作区的 tokio 未启用该特性，
//! 而 `Cargo.toml` 由基建卡独占，本卡不得改动）。

use std::io::BufRead;
use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;

use lengsuo_node::forward::{self, Forwarder, NodePool};

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
        .unwrap_or_else(|| "lengsuo-node-forward".to_owned());
    let Some(path) = args.next() else {
        eprintln!("用法：{program} <config.json>");
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("用法：{program} <config.json>");
        return ExitCode::from(2);
    }

    // 加载配置（节点 + 转发段）。缺转发段 ⇒ 用法错误（这个命令必须要有转发段）。
    let loaded = match forward::load_config(Path::new(&path)) {
        Ok(loaded) => loaded,
        Err(error) => {
            eprintln!("配置错误：{error}");
            return ExitCode::from(2);
        }
    };
    let Some(config) = loaded.forward else {
        eprintln!("配置错误：配置里没有 forward 段（无转发服务可启动）");
        return ExitCode::from(2);
    };

    // 路由表：规则冲突 / 引用了不存在的节点 ⇒ 配置加载阶段就报错。
    let routes = match config.route_table(&loaded.nodes) {
        Ok(routes) => routes,
        Err(error) => {
            eprintln!("配置错误：{error}");
            return ExitCode::from(2);
        }
    };
    // 监听地址：配置给 `host:port`；端口 0 交给内核分配。
    let listen: SocketAddr = match config.listen.parse() {
        Ok(addr) => addr,
        Err(error) => {
            eprintln!("配置错误：forward.listen 不是合法的 host:port：{error}");
            return ExitCode::from(2);
        }
    };

    let node_count = loaded.nodes.len();
    let pool = NodePool::new(loaded.nodes);
    let forwarder = match Forwarder::bind(listen, pool, routes, config).await {
        Ok(forwarder) => forwarder,
        Err(error) => {
            eprintln!("启动失败：{error}");
            return ExitCode::from(1);
        }
    };
    let local = match forwarder.local_addr() {
        Ok(addr) => addr,
        Err(error) => {
            eprintln!("启动失败：{error}");
            return ExitCode::from(1);
        }
    };
    let handle = match forwarder.start().await {
        Ok(handle) => handle,
        Err(error) => {
            eprintln!("启动失败：{error}");
            return ExitCode::from(1);
        }
    };
    println!("转发服务已启动：本地 SOCKS5 监听 {local}，节点 {node_count} 个");

    // 等待停止指令（标准输入 EOF 或一行 `stop`），随后优雅收尾。
    wait_for_stop().await;
    eprintln!("收到停止指令，正在收尾…");
    match handle.shutdown().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("收尾失败：{error}");
            ExitCode::from(1)
        }
    }
}

/// 等标准输入的停止指令。读线程是阻塞的，放到独立线程里，主 runtime 不被占。
async fn wait_for_stop() {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut line = String::new();
        loop {
            line.clear();
            match stdin.lock().read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if line.trim().eq_ignore_ascii_case("stop") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = tx.send(());
    });
    let _ = rx.await;
}
