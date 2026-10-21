// 用例 C：直连本仓入站，截断/篡改请求头被拒不 panic、不回任何字节。
// 不依赖 Xray 二进制。
// 本文件由 `tests/xray_vmess_server.rs` 用 `include!` 文本并入同一模块（用例名
// 不带模块前缀，与拆分前逐字一致）；`use` 全部留在入口文件。

/// 用例 C：直连本仓入站，截断/篡改请求头被拒不 panic、不回任何字节。
/// 不依赖 Xray 二进制。
#[test]
#[ignore = "直接打击本仓入站的畸形输入矩阵"]
fn malformed_direct_headers_are_rejected() {
    let uuid = generate_uuid_bytes();
    let cmd_key = cmd_key_from_uuid(&uuid);
    let (echo_addr, _echo) = spawn_echo_backend();
    let inbound = start_vmess_inbound(vec![cmd_key], Some(echo_addr));

    let keys = KeySource::generate().expect("会话密钥");
    let target = TargetAddr::V4([127, 0, 0, 1], echo_addr.port());
    let plain = HeaderPlanner::new(keys)
        .plan_with(
            &RequestHeader {
                target: Some(target),
                command: ProxyCommand::Tcp,
                security: SecurityOption::Aes128Gcm,
                option: OPT_CHUNK_STREAM | OPT_CHUNK_MASKING | OPT_GLOBAL_PADDING,
                padding_len: 0,
            },
            &[],
        )
        .expect("头明文");

    let good = seal_vmess_aead_header(&cmd_key, &plain).expect("合法头");
    let junk_tail = vec![0x41u8; 8192];

    // C1 错误 UUID（cmdKey 不符）。
    let mut evil_key = cmd_key;
    evil_key[0] ^= 0xFF;
    let wrong_user = seal_vmess_aead_header(&evil_key, &plain).expect("可封");
    let mut c1 = wrong_user;
    c1.extend_from_slice(&junk_tail);
    assert_rejected(inbound.addr, &c1, "C1 错误 cmdKey");

    // C2 半截头（AuthID + 12 字节后断连）。
    let mut c2 = good[..16 + 12].to_vec();
    c2.extend_from_slice(&junk_tail);
    assert_rejected(inbound.addr, &c2, "C2 截断头");

    // C3 长度段 tag 篡改。
    let mut c3 = good.clone();
    c3[17] ^= 0x01;
    c3.extend_from_slice(&junk_tail);
    assert_rejected(inbound.addr, &c3, "C3 长度段 tag");

    // C4 载荷段 tag 篡改。
    let mut c4 = good;
    let last = c4.len() - 1;
    c4[last] ^= 0x01;
    c4.extend_from_slice(&junk_tail);
    assert_rejected(inbound.addr, &c4, "C4 载荷段 tag");

    assert!(
        !inbound.panicked.load(Ordering::SeqCst),
        "畸形输入不得导致 panic"
    );
}

fn assert_rejected(addr: SocketAddr, bytes: &[u8], case: &str) {
    let mut stream = TcpStream::connect(addr).expect("连接入站");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("读超时");
    stream.write_all(bytes).expect("写出畸形输入");
    stream.shutdown(Shutdown::Write).expect("半关闭");

    let mut got = Vec::new();
    let mut buffer = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let now = Instant::now();
        if now >= deadline {
            panic!("{case}：10s 内未被关闭");
        }
        stream
            .set_read_timeout(Some(deadline - now))
            .expect("读超时");
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buffer[..n]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                panic!("{case}：10s 内未被关闭（读超时）");
            }
            Err(_) => break,
        }
    }
    assert!(
        got.is_empty(),
        "{case}：不得回任何字节（实得 {} 字节）",
        got.len()
    );
}
