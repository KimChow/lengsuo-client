//! SIP023 EIH 固定向量、拒绝路径、链式解析与服务端方向（纯 Rust，默认套件）。
//!
//! 向量由参考原语独立生成：Go `lukechampine.com/blake3` + `crypto/aes`，按
//! `sing-shadowsocks v0.2.7` 的 `writeExtendedIdentityHeaders` 公式计算。
//! 这些断言锁定「salt 之后是 16 字节 AES 块身份头」的线格式；真实互通见
//! `tests/xray_eih.rs`（Xray 多用户入站，`#[ignore]`）。
use lengsuo_ss2022::{
    crypto::{Key, Method},
    eih::{
        decode_chain, decode_header, EihServer, IdentityChain, User, UserTable,
        IDENTITY_HEADER_LEN, MAX_IDENTITY_LAYERS,
    },
    tcp::{receive::clock_at, Association, Direction, Reader, SessionReplay, Writer},
    Error,
};
use ss_core::target::TargetAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(5);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时钟应晚于纪元")
        .as_secs()
}

fn clock() -> lengsuo_ss2022::receiver::Clock {
    clock_at(now_secs(), Instant::now())
}

fn key(method: Method, byte: u8) -> Key {
    Key::new(method, &vec![byte; method.key_len()]).expect("假 PSK 长度应匹配套件")
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn table(user_key: Key, uid: u64) -> UserTable {
    UserTable::new(vec![User { uid, key: user_key }]).expect("单用户表应合法")
}

async fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("回环可监听");
    let client = TcpStream::connect(listener.local_addr().expect("有地址"))
        .await
        .expect("回环可连接");
    let (server, _peer) = listener.accept().await.expect("回环可接受");
    (client, server)
}

#[test]
fn identity_headers_match_go_reference_vectors() {
    // Go: blake3.Sum512(psk)[:16]；aes.NewCipher(blake3.DeriveKey(iPSK||salt))。
    let identity128 = key(Method::Aes128, 0x11);
    let user128 = key(Method::Aes128, 0x22);
    let chain = IdentityChain::new(vec![identity128], user128).expect("AES-128 链");
    assert_eq!(
        to_hex(&chain.headers(&[0u8; 16]).expect("可编码")),
        "5c0477dfa5593697e65ed8d41dc1d482"
    );

    let identity256 = key(Method::Aes256, 0x11);
    let user256 = key(Method::Aes256, 0x22);
    let chain = IdentityChain::new(vec![identity256], user256).expect("AES-256 链");
    assert_eq!(
        to_hex(&chain.headers(&[0u8; 32]).expect("可编码")),
        "917dd2469bd4046323f5f88523d7a3aa"
    );

    // 两层链：第一层指纹指向 iPSK1，第二层指向 uPSK（0x33）。
    let chain = IdentityChain::new(
        vec![key(Method::Aes256, 0x11), key(Method::Aes256, 0x22)],
        key(Method::Aes256, 0x33),
    )
    .expect("两层链");
    let headers = chain.headers(&[0u8; 32]).expect("可编码");
    assert_eq!(headers.len(), 2 * IDENTITY_HEADER_LEN);
    assert_eq!(
        to_hex(&headers),
        "917dd2469bd4046323f5f88523d7a3aa61dcdc089942d9edb64a274907ee832e"
    );
}

#[test]
fn decoding_one_layer_resolves_the_local_uid() {
    let identity = key(Method::Aes256, 0x11);
    let user = key(Method::Aes256, 0x22);
    let salt = [0u8; 32];
    let headers = IdentityChain::new(vec![identity.clone()], user.clone())
        .expect("链")
        .headers(&salt)
        .expect("可编码");
    let resolved = decode_header(&identity, &table(user.clone(), 42), &salt, &headers)
        .expect("应能解析出用户");
    assert_eq!(resolved.uid, 42);
    // 解出的密钥必须能重新生成同一身份头（证明拿到的正是用户 PSK）。
    let again = IdentityChain::new(vec![identity], resolved.key)
        .expect("链")
        .headers(&salt)
        .expect("可编码");
    assert_eq!(again, headers);
}

#[test]
fn chained_decoding_reports_every_layer_in_order() {
    let identity = key(Method::Aes256, 0x11);
    let relay_user = key(Method::Aes256, 0x22);
    let user = key(Method::Aes256, 0x33);
    let salt = [0u8; 32];
    let headers = IdentityChain::new(vec![identity.clone(), relay_user.clone()], user.clone())
        .expect("链")
        .headers(&salt)
        .expect("可编码");
    let users = UserTable::new(vec![
        User {
            uid: 1,
            key: relay_user,
        },
        User { uid: 2, key: user },
    ])
    .expect("用户表");
    let (chain, consumed) = decode_chain(&identity, &users, &salt, &headers, 2).expect("可解析");
    assert_eq!(consumed, 2 * IDENTITY_HEADER_LEN);
    assert_eq!(chain.uids(), vec![1, 2]);
    assert_eq!(chain.next.as_deref().map(|next| next.uid), Some(2));
    assert_eq!(chain.len(), 2);
    // 解析结果可按本地 uid 链重新编码，逐字节回到同一线格式。
    assert_eq!(
        chain.encode(&identity, &users, &salt).expect("可编码"),
        headers
    );
    assert!(matches!(
        chain.encode(&identity, &table(key(Method::Aes256, 0x44), 1), &salt),
        Err(Error::IdentityUnknown)
    ));

    // 只解一层时只消费 16 字节，余下留给中继。
    let (first, consumed) = decode_chain(&identity, &users, &salt, &headers, 1).expect("可解析");
    assert_eq!(consumed, IDENTITY_HEADER_LEN);
    assert_eq!(first.uids(), vec![1]);
}

#[test]
fn truncated_unknown_and_wrong_salt_are_fail_closed() {
    let identity = key(Method::Aes256, 0x11);
    let user = key(Method::Aes256, 0x22);
    let salt = [0x5Au8; 32];
    let users = table(user.clone(), 7);
    let headers = IdentityChain::new(vec![identity.clone()], user)
        .expect("链")
        .headers(&salt)
        .expect("可编码");

    // 截断：不足一个 AES 块。
    assert!(matches!(
        decode_header(
            &identity,
            &users,
            &salt,
            &headers[..IDENTITY_HEADER_LEN - 1]
        ),
        Err(Error::EihTruncated)
    ));
    // 指纹不在表中（未知身份）。
    let stranger = key(Method::Aes256, 0x99);
    let unknown = IdentityChain::new(vec![identity.clone()], stranger)
        .expect("链")
        .headers(&salt)
        .expect("可编码");
    assert!(matches!(
        decode_header(&identity, &users, &salt, &unknown),
        Err(Error::IdentityUnknown)
    ));
    // salt 不匹配 → 解出的指纹是伪随机值 → 未知身份，绝不回退单用户。
    assert!(matches!(
        decode_header(&identity, &users, &[0x77; 32], &headers),
        Err(Error::IdentityUnknown)
    ));
    // 长度不符的 salt 直接拒绝。
    assert!(matches!(
        decode_header(&identity, &users, &[0x77; 16], &headers),
        Err(Error::KeyLength)
    ));
}

#[test]
fn chain_bounds_and_shape_are_enforced() {
    let identity = key(Method::Aes128, 0x11);
    let user = key(Method::Aes128, 0x22);
    let users = table(user.clone(), 1);
    let salt = [0u8; 16];
    let headers = IdentityChain::new(vec![identity.clone()], user.clone())
        .expect("链")
        .headers(&salt)
        .expect("可编码");

    assert!(matches!(
        decode_chain(&identity, &users, &salt, &headers, 0),
        Err(Error::EihMissing)
    ));
    assert!(matches!(
        decode_chain(&identity, &users, &salt, &headers, MAX_IDENTITY_LAYERS + 1),
        Err(Error::EihChainTooLong)
    ));
    assert!(matches!(
        decode_chain(&identity, &users, &salt, &headers, 2),
        Err(Error::EihTruncated)
    ));

    // 客户端链同样受限；空身份列表是合法的单用户形态（不写身份头）。
    let mut too_many = Vec::new();
    for byte in 0..=MAX_IDENTITY_LAYERS {
        too_many.push(key(Method::Aes128, byte as u8));
    }
    assert!(matches!(
        IdentityChain::new(too_many, user.clone()),
        Err(Error::EihChainTooLong)
    ));
    let single = IdentityChain::new(Vec::new(), user).expect("单用户链");
    assert_eq!(single.layers(), 0);
    assert!(single.headers(&salt).expect("可编码").is_empty());

    // 混合套件在构造期拒绝。
    assert!(matches!(
        IdentityChain::new(vec![key(Method::Aes256, 0x11)], key(Method::Aes128, 0x22)),
        Err(Error::KeyLength)
    ));
    // 参考 MultiService 明确只支持 AES；ChaCha 身份链拒绝。
    assert!(matches!(
        IdentityChain::new(Vec::new(), key(Method::ChaCha20, 0x22)),
        Err(Error::Unsupported)
    ));
}

#[test]
fn user_table_rejects_empty_duplicates_and_is_lookupable() {
    assert!(matches!(
        UserTable::new(Vec::new()),
        Err(Error::EihUserTable)
    ));
    let user = key(Method::Aes128, 0x22);
    assert!(matches!(
        UserTable::new(vec![
            User {
                uid: 1,
                key: user.clone()
            },
            User {
                uid: 1,
                key: key(Method::Aes128, 0x33)
            }
        ]),
        Err(Error::EihUserTable)
    ));
    assert!(matches!(
        UserTable::new(vec![
            User {
                uid: 1,
                key: user.clone()
            },
            User {
                uid: 2,
                key: user.clone()
            }
        ]),
        Err(Error::EihUserTable)
    ));
    let table = UserTable::new(vec![User { uid: 9, key: user }]).expect("合法表");
    assert_eq!(table.len(), 1);
    assert!(!table.is_empty());
    assert_eq!(table.by_uid(9).map(|user| user.uid), Some(9));
    assert!(table.by_uid(10).is_none());
    assert_eq!(table.method(), Method::Aes128);
}

#[tokio::test]
async fn writer_accepts_identity_headers_only_in_request_direction() {
    let user = key(Method::Aes256, 0x22);
    assert!(matches!(
        Writer::random(&user, Direction::Response)
            .expect("写端")
            .with_identity_headers(vec![0u8; IDENTITY_HEADER_LEN]),
        Err(Error::EihDirection)
    ));
    assert!(matches!(
        Writer::random(&user, Direction::Request)
            .expect("写端")
            .with_identity_headers(Vec::new()),
        Err(Error::EihShape)
    ));
    assert!(matches!(
        Writer::random(&user, Direction::Request)
            .expect("写端")
            .with_identity_headers(vec![0u8; IDENTITY_HEADER_LEN - 1]),
        Err(Error::EihShape)
    ));

    let mut writer = Writer::random(&user, Direction::Request)
        .expect("写端")
        .with_identity_headers(vec![0xAB; IDENTITY_HEADER_LEN])
        .expect("合法身份头");
    let target = TargetAddr::V4([127, 0, 0, 1], 9);
    writer
        .write_request_header(&mut Vec::new(), &target, b"x", now_secs(), 0)
        .await
        .expect("开场可写");
    // 开场后不得再改身份头。
    assert!(matches!(
        writer.set_identity_headers(vec![0xCD; IDENTITY_HEADER_LEN]),
        Err(Error::SessionPolicy)
    ));
}

#[tokio::test]
async fn server_accept_never_falls_back_to_single_user_psk() {
    let identity = key(Method::Aes256, 0x11);
    let user = key(Method::Aes256, 0x22);
    let server = EihServer::new(
        identity.clone(),
        table(user.clone(), 7),
        Duration::from_secs(2),
    )
    .expect("服务端可构造");

    // 没有 EIH 的单用户开场：服务端必须拒绝，不能当成 user PSK 直接解密。
    let (mut client, mut server_stream) = loopback_pair().await;
    let mut writer = Writer::random(&user, Direction::Request).expect("写端");
    let mut plain = Vec::new();
    writer
        .write_request_header(
            &mut plain,
            &TargetAddr::V4([127, 0, 0, 1], 9),
            b"no-eih\n",
            now_secs(),
            0,
        )
        .await
        .expect("可写");
    client.write_all(&plain).await.expect("可写回环");
    let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
    let outcome = timeout(
        WAIT,
        server.accept(&mut server_stream, &mut replay, clock()),
    )
    .await
    .expect("拒绝判定超时");
    match outcome {
        Ok(_) => panic!("缺少 EIH 时服务端不得回退单用户 PSK"),
        Err(error) => assert!(
            matches!(error, Error::IdentityUnknown | Error::EihTruncated),
            "缺 EIH 应 fail-closed，实际 {error:?}"
        ),
    }

    // 截断到只有 salt：必须明确报 EihTruncated，而不是挂起。
    let (mut client, mut server_stream) = loopback_pair().await;
    client.write_all(&[0x5A; 32]).await.expect("只写 salt");
    client.shutdown().await.expect("关写半");
    let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
    let outcome = timeout(
        WAIT,
        server.accept(&mut server_stream, &mut replay, clock()),
    )
    .await
    .expect("截断判定超时");
    match outcome {
        Ok(_) => panic!("截断身份头必须失败"),
        Err(error) => assert!(
            matches!(error, Error::EihTruncated),
            "截断应报 EihTruncated，实际 {error:?}"
        ),
    }
}

#[tokio::test]
async fn eih_server_and_client_roundtrip_over_loopback() {
    let identity = key(Method::Aes256, 0x11);
    let user = key(Method::Aes256, 0x22);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("回环可监听");
    let address = listener.local_addr().expect("有地址");
    let server_identity = identity.clone();
    let server_user = user.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await.expect("可接受");
        let server = EihServer::new(
            server_identity,
            table(server_user.clone(), 7),
            Duration::from_secs(5),
        )
        .expect("服务端");
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let (_reader, opened, uid) = server
            .accept(&mut stream, &mut replay, clock())
            .await
            .expect("EIH 开场应通过");
        assert_eq!(uid, 7);
        assert!(
            matches!(opened.association, Association::Request(_)),
            "请求方向应带目标地址"
        );
        assert_eq!(opened.payload, b"ping\n");
        let mut writer = Writer::random(&server_user, Direction::Response).expect("写端");
        writer
            .write_response_header(&mut stream, &opened.request_salt, b"pong\n", now_secs())
            .await
            .expect("响应头");
        writer.write_finish(&mut stream).await.expect("响应收尾");
    });

    let mut stream = TcpStream::connect(address).await.expect("连接回环");
    let mut writer = Writer::random(&user, Direction::Request).expect("写端");
    let chain = IdentityChain::new(vec![identity], user.clone()).expect("身份链");
    writer
        .set_identity_headers(chain.headers(writer.salt()).expect("身份头"))
        .expect("挂载身份头");
    writer
        .write_request_header(
            &mut stream,
            &TargetAddr::V4([127, 0, 0, 1], 9),
            b"ping\n",
            now_secs(),
            0,
        )
        .await
        .expect("请求开场");
    writer.write_finish(&mut stream).await.expect("请求收尾");

    let mut reader =
        Reader::new(user.clone(), Direction::Response, Duration::from_secs(5)).expect("读端");
    let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
    let opened = timeout(
        WAIT,
        reader.open(&mut stream, &mut replay, clock(), Some(writer.salt())),
    )
    .await
    .expect("响应开场超时")
    .expect("响应开场应通过");
    let mut reply = opened.payload;
    while let Some(chunk) = reader.read_payload(&mut stream).await.expect("读载荷") {
        reply.extend_from_slice(&chunk);
    }
    assert_eq!(reply, b"pong\n");
    timeout(WAIT, server)
        .await
        .expect("服务任务超时")
        .expect("服务任务");
}
