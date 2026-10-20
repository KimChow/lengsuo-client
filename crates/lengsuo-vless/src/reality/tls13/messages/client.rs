//! ClientHello 的构造与解析（RFC 8446 §4.1.2）。
//!
//! 参考实现：`xtls/reality` 的 `handshake_messages.go`
//! （`clientHelloMsg.marshal` / `clientHelloMsg.unmarshal`）。
//!
//! 从 [`super`] 拆出以符合 400 行软目标；公开 API 不变。

use super::{
    extension, push_ext, put_handshake, put_u16_vec, put_u8_vec, take_ext, Cursor, MessageError,
    CIPHER_SUITE_AES_128_GCM_SHA256, CIPHER_SUITE_AES_256_GCM_SHA384, GROUP_X25519, LEGACY_VERSION,
    SIG_ED25519, VERSION_TLS13,
};

/// 客户端构造 ClientHello 所需的输入。
#[derive(Debug, Clone)]
pub struct ClientHelloParams {
    /// `client_random`（32 字节）。
    pub random: [u8; 32],
    /// `legacy_session_id`（32 字节，全零）。参考 `reality.go:141`
    /// 用 `make([]byte, 32)` 造了 32 字节全零的 SessionId。
    pub session_id: [u8; 32],
    /// SNI（`server_name`）。
    pub server_name: String,
    /// 本次握手的 X25519 临时公钥（32 字节）。
    pub key_share: [u8; 32],
}

/// 构造 TLS 1.3 ClientHello 的**握手消息载荷**（不含记录层头）。
///
/// 扩展顺序对齐参考 `xtls/reality` 的 `clientHelloMsg.marshal`
/// （`handshake_messages.go`）与 utls 的 Chrome 风格：
/// `supported_versions` → `supported_groups` → `key_share` → `signature_algorithms`
/// → `server_name` → `alpn`。
///
/// **注意**：REALITY 要求 `SessionId` 恰好 32 字节（参考把它当定长视图，
/// `raw[39..71]` 是密文区），故本函数固定写 32 字节。
pub fn build_client_hello(params: &ClientHelloParams) -> Vec<u8> {
    let mut body = Vec::with_capacity(256);
    body.extend_from_slice(&LEGACY_VERSION.to_be_bytes());
    body.extend_from_slice(&params.random);
    // legacy_session_id_echo：定长 32 字节。
    put_u8_vec(&mut body, &params.session_id);
    // cipher_suites：TLS 1.3 套件 + 一个 TLS 1.2 套件（兼容中间件）。
    let mut suites = Vec::with_capacity(8);
    suites.extend_from_slice(&CIPHER_SUITE_AES_128_GCM_SHA256.to_be_bytes());
    suites.extend_from_slice(&CIPHER_SUITE_AES_256_GCM_SHA384.to_be_bytes());
    suites.extend_from_slice(&0x002f_u16.to_be_bytes()); // TLS_RSA_WITH_AES_128_GCM_SHA256
    put_u16_vec(&mut body, &suites);
    // compression_methods：null。
    put_u8_vec(&mut body, &[0]);

    // ---- 扩展 ----
    let mut exts = Vec::with_capacity(256);

    // supported_versions: TLS 1.3。
    //
    // 布局（RFC 8446 §4.2.1）：`ProtocolVersion versions<2..254>` 的长度前缀
    // 是 **uint8**（参考 `handshake_messages.go:591` 用
    // `extData.ReadUint8LengthPrefixed(&versList)`），不是 uint16。
    let mut versions = Vec::with_capacity(2);
    versions.extend_from_slice(&VERSION_TLS13.to_be_bytes());
    let mut ext = Vec::with_capacity(3);
    put_u8_vec(&mut ext, &versions);
    push_ext(&mut exts, extension::SUPPORTED_VERSIONS, &ext);

    // supported_groups: 只宣告 x25519（REALITY 的 REALITY 服务端只接受它）。
    let mut groups = Vec::with_capacity(2);
    groups.extend_from_slice(&GROUP_X25519.to_be_bytes());
    let mut ext = Vec::with_capacity(4);
    put_u16_vec(&mut ext, &groups);
    push_ext(&mut exts, extension::SUPPORTED_GROUPS, &ext);

    // key_share: x25519。
    let mut share = Vec::with_capacity(38);
    share.extend_from_slice(&GROUP_X25519.to_be_bytes());
    put_u16_vec(&mut share, &params.key_share);
    let mut ext = Vec::with_capacity(40);
    put_u16_vec(&mut ext, &share);
    push_ext(&mut exts, extension::KEY_SHARE, &ext);

    // signature_algorithms: ed25519（REALITY 服务端用 Ed25519 签 CertificateVerify）。
    let mut algs = Vec::with_capacity(4);
    algs.extend_from_slice(&SIG_ED25519.to_be_bytes());
    algs.extend_from_slice(&0x0403_u16.to_be_bytes()); // ecdsa_secp256r1_sha256
    algs.extend_from_slice(&0x0804_u16.to_be_bytes()); // rsa_pss_rsae_sha256
    algs.extend_from_slice(&0x0401_u16.to_be_bytes()); // rsa_pkcs1_sha256
    let mut ext = Vec::with_capacity(8);
    put_u16_vec(&mut ext, &algs);
    push_ext(&mut exts, extension::SIGNATURE_ALGORITHMS, &ext);

    // server_name: host_name。
    //
    // 布局（RFC 6066 §3，参考 `handshake_messages.go:477`）：
    // `ServerNameList` = `uint16 列表长度` + 若干
    // `name_type(1) + 主机名(uint16 长度 + 字节)`。
    // 扩展数据**就是**这个列表本身，外面不能再套一层长度前缀
    // （参考解析用的是 `extData.ReadUint16LengthPrefixed(&nameList)`）。
    let host = params.server_name.as_bytes();
    let mut name = Vec::with_capacity(host.len() + 3);
    name.push(0); // name_type = host_name
    name.extend_from_slice(&(host.len() as u16).to_be_bytes());
    name.extend_from_slice(host);
    let mut names = Vec::with_capacity(name.len() + 2);
    put_u16_vec(&mut names, &name);
    push_ext(&mut exts, extension::SERVER_NAME, &names);

    // alpn: 宣告 http/1.1（REALITY 服务端 `NextProtos` 为 nil，不强制协商）。
    //
    // 布局：`ProtocolNameList` = `uint16 列表长度` + 若干
    // `uint8 长度 + 协议名`。
    let mut protos = Vec::with_capacity(11);
    put_u8_vec(&mut protos, b"http/1.1");
    let mut ext = Vec::with_capacity(protos.len() + 2);
    put_u16_vec(&mut ext, &protos);
    push_ext(&mut exts, extension::ALPN, &ext);

    put_u16_vec(&mut body, &exts);

    let mut out = Vec::with_capacity(body.len() + 4);
    put_handshake(&mut out, super::handshake_type::CLIENT_HELLO, &body);
    out
}

/// 客户端从 ClientHello 里解出的关键字段（服务端用）。
#[derive(Debug, Clone)]
pub struct ClientHelloInfo {
    /// `client_random`。
    pub random: [u8; 32],
    /// `legacy_session_id`。
    pub session_id: Vec<u8>,
    /// SNI。
    pub server_name: Option<String>,
    /// X25519 key_share 公钥。
    pub x25519_key_share: Option<[u8; 32]>,
    /// ALPN 协议列表。
    pub alpn_protocols: Vec<String>,
}

/// 解析 ClientHello 的握手消息载荷（不含 4 字节消息头）。
///
/// 对齐参考 `xtls/reality` 的 `clientHelloMsg.unmarshal`
/// （`handshake_messages.go:418`）。
pub fn parse_client_hello(body: &[u8]) -> Result<ClientHelloInfo, MessageError> {
    let mut cursor = Cursor::new(body);
    let _legacy_version = cursor.u16()?;
    let random_bytes = cursor.take(32)?;
    let mut random = [0u8; 32];
    random.copy_from_slice(random_bytes);
    let session_id = cursor.u8_vec()?.to_vec();
    let _cipher_suites = cursor.u16_vec()?;
    let _compression = cursor.u8_vec()?;
    if cursor.is_empty() {
        return Ok(ClientHelloInfo {
            random,
            session_id,
            server_name: None,
            x25519_key_share: None,
            alpn_protocols: Vec::new(),
        });
    }
    let exts = cursor.u16_vec()?;
    let mut info = ClientHelloInfo {
        random,
        session_id,
        server_name: None,
        x25519_key_share: None,
        alpn_protocols: Vec::new(),
    };
    let mut exts = exts;
    while !exts.is_empty() {
        let (kind, data, rest) = take_ext(exts)?;
        exts = rest;
        match kind {
            extension::SERVER_NAME => info.server_name = parse_server_name(data)?,
            extension::KEY_SHARE => info.x25519_key_share = parse_key_share(data)?,
            extension::ALPN => info.alpn_protocols = parse_alpn(data)?,
            _ => {}
        }
    }
    Ok(info)
}

/// 解析 `server_name` 扩展，返回 `host_name`。
fn parse_server_name(data: &[u8]) -> Result<Option<String>, MessageError> {
    let mut cursor = Cursor::new(data);
    let list = cursor.u16_vec()?;
    let mut cursor = Cursor::new(list);
    while !cursor.is_empty() {
        let name_type = cursor.u8()?;
        let name = cursor.u16_vec()?;
        if name_type == 0 {
            let host = std::str::from_utf8(name).map_err(|_| MessageError::MalformedServerName)?;
            return Ok(Some(host.to_owned()));
        }
    }
    Ok(None)
}

/// 解析 `key_share` 扩展，取第一个 `x25519` 条目。
///
/// **这是 ClientHello 的布局**（RFC 8446 §4.2.8）：
/// `client_shares`（uint16 长度前缀的列表）+ 若干
/// `KeyShareEntry{group(2), key_exchange(uint16 长度前缀)}`。
///
/// ⛔ **ServerHello 的 `key_share` 布局不同**（没有外层列表），
/// 必须用 [`super::parse_server_key_share`]。
/// 对齐参考 `xtls/reality` `handshake_messages.go:607-620`
/// （`clientHelloMsg.unmarshal` 的 `case extensionKeyShare`）。
fn parse_key_share(data: &[u8]) -> Result<Option<[u8; 32]>, MessageError> {
    let mut cursor = Cursor::new(data);
    let shares = cursor.u16_vec()?;
    let mut cursor = Cursor::new(shares);
    while !cursor.is_empty() {
        let group = cursor.u16()?;
        let key = cursor.u16_vec()?;
        if group == GROUP_X25519 && key.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(key);
            return Ok(Some(out));
        }
    }
    Ok(None)
}

/// 解析 `alpn` 扩展。
fn parse_alpn(data: &[u8]) -> Result<Vec<String>, MessageError> {
    let mut cursor = Cursor::new(data);
    let list = cursor.u16_vec()?;
    let mut cursor = Cursor::new(list);
    let mut out = Vec::new();
    while !cursor.is_empty() {
        let name = cursor.u8_vec()?;
        out.push(
            std::str::from_utf8(name)
                .map_err(|_| MessageError::MalformedExtension)?
                .to_owned(),
        );
    }
    Ok(out)
}
