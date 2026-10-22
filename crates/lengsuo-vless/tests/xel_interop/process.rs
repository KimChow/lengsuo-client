// ② 跨进程收发：父进程角色、对端子进程（server 角色）。
async fn send_wire(stream: &mut TcpStream, wire: &[u8], mut mask: Option<&mut XorMask>) {
    let mut piece = wire.to_vec();
    let mut position = 0;
    for size in splits(wire.len()) {
        let end = position + size;
        // 掩蔽器原地改写：只推进密钥流到被掩蔽的头部字节上。
        if let Some(mask) = mask.as_deref_mut() {
            mask.mask_outgoing(&mut piece[position..end])
                .unwrap_or_else(|error| panic!("发送侧掩蔽失败：{error}"));
        }
        stream.write_all(&piece[position..end]).await.unwrap();
        position = end;
    }
    stream.flush().await.unwrap();
}

/// 收完整条流（对端已关闭写半）：`(还原条目, 首个致命错误, 是否被中止)`。
///
/// `mask` 按借用推进分段，因此各段共享同一方向的密钥流状态。
async fn collect(
    stream: &mut TcpStream,
    sink: &mut Sink,
    mut mask: Option<&mut XorMask>,
) -> (Vec<Vec<u8>>, Option<Error>, bool) {
    let mut items = Vec::new();
    let mut buffer = vec![0u8; 997];
    let mut aborted = false;
    let mut failure = None;
    while failure.is_none() {
        let read = match timeout(WAIT, stream.read(&mut buffer)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(size)) => size,
            // 对端在读完之前退出会发 RST：只记"流被中止"，不断言具体错误码。
            Ok(Err(_)) => {
                aborted = true;
                break;
            }
            Err(_) => panic!("接收超时：对端未按约定关闭写半"),
        };
        let slice = &mut buffer[..read];
        if let Some(mask) = mask.as_mut() {
            if let Err(error) = mask.unmask_incoming(slice) {
                failure = Some(error);
                break;
            }
        }
        if let Err(error) = sink.push(slice) {
            failure = Some(error);
            break;
        }
        loop {
            match sink.next_item() {
                Ok(Some(item)) => items.push(item),
                Ok(None) => break,
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
    }
    if failure.is_none() {
        failure = sink.finish().err();
    }
    (items, failure, aborted)
}

/// 把剩余字节读到 EOF：让对端干净退出（避免残字节变成 RST）。
async fn drain_to_eof(stream: &mut TcpStream) {
    let mut buffer = [0u8; 512];
    loop {
        match timeout(WAIT, stream.read(&mut buffer)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
            Ok(Ok(_)) => continue,
        }
    }
}

/// client 角色：发送用例线上字节 → 关闭写半 → 校验对端回显或失效拒绝。
async fn parent_role(case: &str, stream: &mut TcpStream) {
    let wire = outgoing_wire(case);
    let mut out_mask = if uses_xor(case) {
        Some(up_mask())
    } else {
        None
    };
    send_wire(stream, &wire, out_mask.as_mut()).await;
    stream.shutdown().await.unwrap();

    // 接收方向用的是 client 侧的正确密钥：失效用例只会安静地收到 EOF。
    let mut sink = recv_sink(case, key_down());
    let mut in_mask = if uses_xor(case) {
        Some(up_mask())
    } else {
        None
    };
    let (items, failure, aborted) = collect(stream, &mut sink, in_mask.as_mut()).await;
    assert_eq!(failure, None, "{case} 本端接收不应出现协议错误");
    assert!(!aborted, "{case} 对端应正常关闭写半而非中止");
    if expects_reject(case) {
        assert!(items.is_empty(), "{case} 失效流不得还原出任何条目");
    } else {
        assert_eq!(
            items,
            expected_items(case),
            "{case} 跨进程往返必须逐字节一致"
        );
    }
}

/// server 角色（子进程）：收 client 记录 → 校验 → 用本方向密钥回显。
async fn serve(case: &str, port: u16) {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let key = if case == "wrong-key" {
        key_evil()
    } else {
        key_up()
    };
    let mut sink = recv_sink(case, key);
    let mut in_mask = if uses_xor(case) {
        Some(down_mask())
    } else {
        None
    };
    let (items, failure, aborted) = collect(&mut stream, &mut sink, in_mask.as_mut()).await;
    if expects_reject(case) {
        let expected = if case == "bad-magic" {
            Error::InvalidHeader
        } else {
            // XEL 线上不携带序号：nonce 失步与错钥在 AEAD 层不可区分。
            Error::AuthFailed
        };
        assert_eq!(
            failure,
            Some(expected),
            "{case} 必须以 {expected} fail-closed，实际 {failure:?}"
        );
        assert!(items.is_empty(), "{case} 失效流不得还原出任何明文");
        assert!(!aborted, "{case} 本端已关闭写半，不应看到中止");
        assert!(sink.is_poisoned(), "{case} 失效后方向必须永久 poison");
        drain_to_eof(&mut stream).await;
        return;
    }
    assert_eq!(failure, None, "{case} 正常流不得失败");
    assert!(!aborted, "{case} 本端已关闭写半，不应看到中止");
    assert_eq!(
        items,
        expected_items(case),
        "{case} 收到的条目必须与发送侧一致"
    );
    let wire = echo_wire(case);
    let mut out_mask = if uses_xor(case) {
        Some(down_mask())
    } else {
        None
    };
    send_wire(&mut stream, &wire, out_mask.as_mut()).await;
    stream.shutdown().await.unwrap();
    // 等 client 写完再退出，避免残字节变成 RST。
    drain_to_eof(&mut stream).await;
}

fn peer_log_path(port: u16) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "lengsuo-xel-peer-{}-{port}.log",
        std::process::id()
    ))
}

fn spawn_server(case: &str, port: u16) -> Child {
    let log = std::fs::File::create(peer_log_path(port)).unwrap();
    let error_log = log.try_clone().unwrap();
    Command::new(std::env::current_exe().unwrap())
        .args([PEER_TEST, "--exact", "--ignored", "--nocapture"])
        .env("LENGSUO_XEL_CASE", case)
        .env("LENGSUO_XEL_PORT", port.to_string())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(error_log))
        .stdin(Stdio::null())
        .spawn()
        .unwrap()
}

async fn reap(child: &mut Child, port: u16, case: &str) -> ExitStatus {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            // 回读子进程日志（含 panic 断言文本），失败时一并呈现。
            let path = peer_log_path(port);
            let output = std::fs::read_to_string(&path).unwrap_or_default();
            let _ = std::fs::remove_file(&path);
            println!("对端 {case} 日志尾部：{}", tail(&output));
            return status;
        }
        assert!(Instant::now() < deadline, "对端进程超时未退出");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn tail(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let keep = lines.len().min(40);
    lines[lines.len() - keep..].join("\n")
}

async fn run_case(case: &str) {
    timeout(WAIT, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut child = spawn_server(case, port);
        let (mut stream, _) = timeout(WAIT, listener.accept())
            .await
            .expect("对端进程未在超时内连接")
            .unwrap();
        parent_role(case, &mut stream).await;
        drop(stream);
        let status = reap(&mut child, port, "port").await;
        assert!(
            status.success(),
            "对端进程以 {status} 失败退出（见上方日志）"
        );
    })
    .await
    .unwrap();
}

/// 对端角色：由上面的用例以 `--exact --ignored` 启动为独立进程。
#[tokio::test]
#[ignore = "由互通测试作为对端子进程显式启动（LENGSUO_XEL_CASE / LENGSUO_XEL_PORT）"]
async fn xel_peer_server() {
    let case = std::env::var("LENGSUO_XEL_CASE")
        .expect("对端进程必须由 xel_interop 父测试启动，缺少 LENGSUO_XEL_CASE");
    let port: u16 = std::env::var("LENGSUO_XEL_PORT")
        .expect("对端进程缺少 LENGSUO_XEL_PORT")
        .parse()
        .expect("LENGSUO_XEL_PORT 必须是端口号");
    timeout(WAIT, serve(&case, port)).await.unwrap();
}
