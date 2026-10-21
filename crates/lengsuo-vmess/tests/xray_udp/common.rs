// 共享常量与助手：超时上限、参考二进制定位、UDP 回显后端、传统关联建连、
// 数据段 cipher、单数据报往返。
// 本文件由 `tests/xray_udp.rs` 用 `include!` 文本并入同一模块（用例名不带
// 模块前缀，与拆分前逐字一致）；`use`、常量与共享助手都在入口文件。

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
/// 无监听端口用例的观察上限（任务书 ≤30s）。
const UNBOUND_TIMEOUT: Duration = Duration::from_secs(30);

fn xray_bin() -> Option<PathBuf> {
    match std::env::var_os("LENGSUO_XRAY") {
        Some(path) => Some(PathBuf::from(path)),
        None => {
            eprintln!(
                "SKIP: 环境变量 LENGSUO_XRAY 未设置，跳过依赖真实 Xray 的 UDP 互通用例。\
                 原因：没有参考二进制可拉起，无法证明 Rust↔Xray 的 RequestCommand_UDP 互通。"
            );
            None
        }
    }
}

/// 本地 UDP 回显后端：直接持有 socket（不释放端口），收到的每个数据报
/// 原样发回来源地址。返回实际绑定地址与 socket。
async fn spawn_udp_echo() -> (SocketAddr, UdpSocket) {
    let socket = UdpSocket::bind(("127.0.0.1", 0))
        .await
        .expect("回显后端绑定 127.0.0.1:0");
    let addr = socket.local_addr().expect("回显后端地址");
    (addr, socket)
}

/// VMess 传统关联建连（`Command::Udp` + 真实目标）：写头后返回流与请求体 cipher。
async fn open_classic_association(
    fixture: &XrayFixture,
    cmd_key: &[u8; 16],
    keys: &KeySource,
    target: &TargetAddr,
) -> Result<(TcpStream, DataCipher), String> {
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(fixture.address()))
        .await
        .map_err(|_| "连接 Xray 超时".to_string())?
        .map_err(|e| format!("连接 Xray 失败: {e}"))?;

    // plan 校验字段序（UDP 命令 + 真实目标），seal 产线上字节（AuthID/nonce 随机）。
    // 注意：必须把 `Command::Udp` 真正传进 seal，否则封进 AEAD 的仍是 TCP 命令。
    let planned = codec::build_request_plaintext_with(keys, target, Command::Udp, 0, 0)
        .map_err(|e| format!("构造 UDP 请求头明文失败: {e:?}"))?;
    assert_eq!(
        planned[37],
        Command::Udp.to_byte(),
        "命令字节必须落位明文头 37"
    );

    let header = codec::seal_request_header_with(cmd_key, keys, target, Command::Udp)
        .map_err(|e| format!("封装请求头失败: {e:?}"))?;
    stream
        .write_all(&header)
        .await
        .map_err(|e| format!("写请求头失败: {e:?}"))?;
    Ok((stream, body_cipher(keys)))
}

fn body_cipher(keys: &KeySource) -> DataCipher {
    DataCipher::new(SECURITY_AES_128_GCM, &keys.body_key, &keys.body_iv)
}

/// 传统关联单数据报往返：发一个数据报、后端原样回显、收一个 chunk 逐字节比对。
///
/// **每次调用独立生成会话密钥**：参考 `client.go` 每条 VMess 连接用自己的
/// `requestBodyKey/IV` 派 chunk nonce（`GenerateChunkNonce(requestBodyIV, nonceSize)`
/// 落 `encoding/client.go` / `server.go` 的 AES128_GCM 分支）。两个数据报共用一套
/// 密钥意味着第二条关联的 body IV 与第一条相同 → chunk nonce 序列重叠，
/// 观测表现就是第二个数据报被服务端丢弃（本卡首轮实测：A1 第 1 个 ok、第 2 个超时）。
async fn classic_assoc_roundtrip(
    fixture: &XrayFixture,
    cmd_key: &[u8; 16],
    target: &TargetAddr,
    payload: &[u8],
    echo: &UdpSocket,
) -> Result<(), String> {
    let keys = KeySource::generate().expect("生成会话密钥");
    let (mut stream, mut cipher) =
        open_classic_association(fixture, cmd_key, &keys, target).await?;

    tokio::time::timeout(
        RESPONSE_TIMEOUT,
        codec::write_chunk(&mut cipher, &mut stream, payload),
    )
    .await
    .map_err(|_| "数据报写出超时".to_string())?
    .map_err(|e| format!("数据报写出失败: {e:?}"))?;

    let mut buf = vec![0u8; 65536];
    // 有界等待：Xray 未投递时明确失败，不把「读阻塞」当通过。
    let (n, from) = tokio::time::timeout(RESPONSE_TIMEOUT, echo.recv_from(&mut buf))
        .await
        .map_err(|_| "后端在超时内未收到数据报（Xray 未投递）".to_string())?
        .map_err(|e| format!("回显收包失败: {e}"))?;
    assert_eq!(
        n,
        payload.len(),
        "数据报到达后端尺寸不一致\n{}",
        fixture.report()
    );
    echo.send_to(&buf[..n], from)
        .await
        .map_err(|e| format!("回显发包失败: {e}"))?;

    let got = tokio::time::timeout(
        RESPONSE_TIMEOUT,
        codec::read_datagram_response(
            &mut stream,
            &keys.body_key,
            &keys.body_iv,
            keys.response_header,
        ),
    )
    .await
    .map_err(|_| "应答超时".to_string())?
    .map_err(|e| format!("应答读取失败: {e:?}"))?
    .ok_or_else(|| format!("应答为 EOF 帧而非数据报\n{}", fixture.report()))?;
    assert_eq!(
        got.as_slice(),
        payload,
        "应答逐字节不一致\n{}",
        fixture.report()
    );
    Ok(())
}

