//! **测试夹具**：假浏览器可执行文件。
//!
//! 这不是一个浏览器，也**不是**生产代码：它是 `lengsuo-browser-launch` 的
//! 集成测试用的替身，用来在**不下载真浏览器、不连公网**的前提下验证
//! 「参数正确注入」「目录隔离」「进程可回收」。
//!
//! 行为：
//! 1. 从 `--user-data-dir=<dir>` 取出本环境的用户数据目录；
//! 2. 把收到的**全部参数**逐行写进 `<dir>/args.txt`；
//! 3. 把收到的**全部环境变量**写进 `<dir>/env.txt`（测试用假凭据）；
//! 4. 在 `127.0.0.1:0` 上监听一个端口，把端口号写进 `<dir>/DevToolsActivePort`
//!    —— 于是 `ReadinessStrategy::DevToolsPort` 的判据（读端口文件 + 连端口）
//!    真的能被触发；
//! 5. 一直存活，直到父进程把它 kill 掉。
//!
//! 它只监听**本地回环**，不发起任何出网连接。

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(dir) = user_data_dir(&args) else {
        // 没有用户数据目录 ⇒ 不是本夹具的合法调用，直接失败。
        std::process::exit(9);
    };
    if std::fs::create_dir_all(&dir).is_err() {
        std::process::exit(10);
    }

    // 1) 参数落盘。
    let mut args_file = match std::fs::File::create(dir.join("args.txt")) {
        Ok(file) => file,
        Err(_) => std::process::exit(11),
    };
    for arg in &args {
        let _ = writeln!(args_file, "{arg}");
    }
    let _ = args_file.flush();

    // 2) 环境变量落盘（键与值一行一条）。
    let mut env_file = match std::fs::File::create(dir.join("env.txt")) {
        Ok(file) => file,
        Err(_) => std::process::exit(12),
    };
    let mut env: Vec<(String, String)> = std::env::vars().collect();
    env.sort();
    for (key, value) in env {
        let _ = writeln!(env_file, "{key}={value}");
    }
    let _ = env_file.flush();

    // 3) 监听回环端口并写 DevToolsActivePort。
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(_) => std::process::exit(13),
    };
    let port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(_) => std::process::exit(14),
    };
    let mut port_file = match std::fs::File::create(dir.join("DevToolsActivePort")) {
        Ok(file) => file,
        Err(_) => std::process::exit(15),
    };
    let _ = writeln!(port_file, "{port}");
    let _ = port_file.flush();
    drop(port_file);

    // 4) 接受连接（让就绪探测的 TCP connect 有真实的对面）。
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let _ = stream.flush();
    }
}

/// 从 `--user-data-dir=<dir>` 里取出目录。
fn user_data_dir(args: &[String]) -> Option<PathBuf> {
    const PREFIX: &str = "--user-data-dir=";
    args.iter()
        .find_map(|arg| arg.strip_prefix(PREFIX))
        .map(PathBuf::from)
}
