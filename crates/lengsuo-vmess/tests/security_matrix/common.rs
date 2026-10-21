// 共享常量与助手（原 `tests/security_matrix.rs` 顶部搬移，文字未改）。
//
// 本文件由 `tests/security_matrix.rs` 用 `include!` 文本并入同一模块，故这里的
// 常量/函数对同目录其余分文件直接可见（无需 `pub`）；`use` 全部写在入口文件。

/// 每个用例的总超时上限。
const CASE_TIMEOUT: Duration = Duration::from_secs(10);
/// 假 cmd key（测试假凭据）。
const CMD_KEY: [u8; 16] = *b"b831381d-6324-4d";
/// 假会话密钥。
const BODY_KEY: [u8; 16] = *b"request-body-key";
/// 假会话 IV。
const BODY_IV: [u8; 16] = *b"request-body-iv!";
/// 固定 unix 秒（AuthID 时间窗可控）。
const NOW: i64 = 1_700_000_000;

/// 三个安全档 → 线上安全档字节。
const TIERS: [(SecurityOption, u8); 3] = [
    (SecurityOption::None, SECURITY_NONE),
    (SecurityOption::Aes128Gcm, SECURITY_AES_128_GCM),
    (SecurityOption::ChaCha20Poly1305, SECURITY_CHACHA20_POLY1305),
];

/// 档位 → 数据段套件（`None` 档没有 AEAD）。
fn suite_of(security: SecurityOption) -> BodySuite {
    security.resolve().expect("三档都可解析")
}

/// 造一个可用的请求头明文（固定 padding 长度，消掉随机项）。
fn plan_header(security: SecurityOption) -> Vec<u8> {
    let planner = HeaderPlanner::new(KeySource {
        body_key: BODY_KEY,
        body_iv: BODY_IV,
        response_header: 0x33,
    });
    let header = RequestHeader {
        target: Some(TargetAddr::Domain("example.invalid".into(), 443)),
        command: Command::Tcp,
        security,
        option: 0,
        padding_len: 0,
    };
    planner.plan_with(&header, &[]).expect("请求头明文可编码")
}

/// 造一条完整请求头线上字节（AuthID 时间固定在窗口内）。
fn seal_request(security: SecurityOption) -> Vec<u8> {
    let plain = plan_header(security);
    let auth = lengsuo_vmess::create_auth_id_with(&CMD_KEY, NOW, &[0x01, 0x02, 0x03, 0x04]);
    aead::seal_header_with(&CMD_KEY, auth.as_bytes(), &[0x11; 8], &plain)
}

/// 一次性会话过滤器（总是接受）。
fn accept_session() -> impl FnMut(&[u8; 16], &[u8; 16], &[u8; 16]) -> bool {
    |_, _, _| true
}
