// 共享常量与助手：超时上限、参考二进制定位、时钟、回显后端、载荷构造、
// 最小 socks5 CONNECT。
// 本文件由 `tests/xray_multitier_server.rs` 用 `include!` 文本并入同一模块（用例名
// 不带模块前缀，与拆分前逐字一致）；`use` 全部留在入口文件。

/// 单次读写的超时上限（避免挂死）。
const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// 入站监听端口就绪的等待上限。
const START_TIMEOUT: Duration = Duration::from_secs(15);

/// 惰性获取参考二进制；未设置时打印原因并返回 `None`（调用方 `return` 跳过）。
fn xray_bin() -> Option<PathBuf> {
    match std::env::var_os("LENGSUO_XRAY") {
        Some(path) => Some(PathBuf::from(path)),
        None => {
            eprintln!(
                "SKIP: 环境变量 LENGSUO_XRAY 未设置，跳过多安全档反向互通用例。\
                 原因：没有参考二进制可拉起，无法证明 Xray→Rust 的档位互通。"
            );
            None
        }
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时钟在 UNIX 纪元之后")
        .as_secs() as i64
}

/// 本地 raw TCP 回显后端（读到关闭即关闭）。
fn spawn_echo_backend() -> (SocketAddr, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("回显后端绑定");
    let addr = listener.local_addr().expect("回显后端地址");
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                let mut buffer = [0u8; 16384];
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buffer[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = stream.shutdown(Shutdown::Both);
            });
        }
    });
    (addr, handle)
}

/// 最小 socks5 CONNECT（无认证）。
fn socks5_connect(socks_port: u16, target: SocketAddrV4) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", socks_port))?;
    let _ = stream.set_nodelay(true);
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method)?;
    if method != [0x05, 0x00] {
        return Err(std::io::Error::other("socks 握手被拒"));
    }
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request)?;
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply)?;
    if reply[1] != 0x00 {
        return Err(std::io::Error::other(format!(
            "socks CONNECT 失败：{}",
            reply[1]
        )));
    }
    Ok(stream)
}

/// 三段载荷：1B / 4KiB / 256KiB。
fn payloads() -> Vec<u8> {
    let total = 1 + 4 * 1024 + 256 * 1024;
    (0..total).map(|i| (i % 251) as u8).collect()
}
