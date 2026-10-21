// 共享常量与助手：选项位、时钟、参考二进制定位、载荷构造、回显后端、
// 最小 socks5 CONNECT。
// 本文件由 `tests/xray_vmess_server.rs` 用 `include!` 文本并入同一模块（用例名
// 不带模块前缀，与拆分前逐字一致）；`use` 全部留在入口文件。

/// 选项位（`common/protocol/headers.go`；本仓 consts 的 OPTION_* 是旧命名，勿混用）。
const OPT_CHUNK_STREAM: u8 = 0x01;
const OPT_CHUNK_MASKING: u8 = 0x04;
const OPT_GLOBAL_PADDING: u8 = 0x08;
const OPT_AUTHENTICATED_LENGTH: u8 = 0x10;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时钟在 UNIX 纪元之后")
        .as_secs() as i64
}

fn xray_bin() -> Option<PathBuf> {
    let path: PathBuf = std::env::var_os("LENGSUO_XRAY")?.into();
    path.is_file().then_some(path)
}

fn payload_1b_4kib_256kib() -> Vec<u8> {
    let total = 1 + 4 * 1024 + 256 * 1024;
    (0..total).map(|i| (i % 251) as u8).collect()
}

/// 本地 raw TCP 回显后端（读到关闭即关闭）。
fn spawn_echo_backend() -> (SocketAddr, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("回显后端绑定");
    let addr = listener.local_addr().expect("回显后端地址");
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(60)));
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
