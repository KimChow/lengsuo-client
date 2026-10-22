// ① 共用夹具：假密钥、用例判定、载荷构造与线上字节拼装。
/// 用例总超时：对端是本地进程，20 秒足够冷启动。
const WAIT: Duration = Duration::from_secs(20);
/// 对端角色测试名（子进程用 `--exact` 只跑它）。
const PEER_TEST: &str = "xel_peer_server";

/// client → server 方向的记录密钥（假密钥）。
fn key_up() -> XelKey {
    XelKey::new(&[0xA1; 32]).unwrap()
}
/// server → client 方向的记录密钥（假密钥）。
fn key_down() -> XelKey {
    XelKey::new(&[0xB2; 32]).unwrap()
}
/// 与 [`key_up`] 不匹配的密钥，用于错钥用例。
fn key_evil() -> XelKey {
    XelKey::new(&[0x99; 32]).unwrap()
}
/// XOR 头部掩蔽的 CTR IV（16 字节 = AES 块长）。
const IV_UP: [u8; 16] = [0x11; 16];
const IV_DOWN: [u8; 16] = [0x22; 16];

fn cipher_of(case: &str) -> XelCipher {
    match case {
        "aead-chacha" => XelCipher::ChaCha20Poly1305,
        "aead-aes" | "aead-xor" | "wrong-key" | "nonce-gap" | "bad-magic" => XelCipher::Aes256Gcm,
        other => unreachable!("未知 AEAD 用例 {other}"),
    }
}

/// 线上是否叠加 XOR 头部掩蔽（对应参考端 `random` 模式 + AEAD 记录）。
fn uses_xor(case: &str) -> bool {
    matches!(case, "aead-xor" | "xor-only")
}

/// 记录体是否 AEAD 认证（`xor-only` 只验证分帧，记录体明文透传）。
fn uses_aead(case: &str) -> bool {
    case != "xor-only"
}

/// 期望对端 fail-closed 且不得回显任何条目的用例。
fn expects_reject(case: &str) -> bool {
    matches!(case, "wrong-key" | "nonce-gap" | "bad-magic")
}

/// AEAD 用例的应用明文：1 字节、最小记录、4096、超过 8192 分片边界。
fn payloads() -> Vec<Vec<u8>> {
    vec![
        vec![0xF0u8],
        vec![0x11; 1],
        vec![0xAB; 4096],
        vec![0xCD; 8200],
        vec![0x42; 17],
    ]
}

/// `xor-only` 用例的记录体（XEL 记录体最小 17 字节）。
fn xor_bodies() -> Vec<Vec<u8>> {
    vec![
        vec![0x7Fu8; 17],
        vec![0x31; 24],
        vec![0xAB; 4096],
        vec![0xCD; 8200],
    ]
}

/// 明文记录 = 5 字节头（魔数 + BE16 = 记录体长度）+ 记录体。
fn plain_records() -> Vec<Vec<u8>> {
    xor_bodies()
        .into_iter()
        .map(|body| {
            let mut record = RecordHeader::new(body.len()).unwrap().encode().to_vec();
            record.extend_from_slice(&body);
            record
        })
        .collect()
}

fn expected_items(case: &str) -> Vec<Vec<u8>> {
    if uses_aead(case) {
        payloads()
    } else {
        plain_records()
    }
}

/// 用给定密钥密封成连续线上字节。
fn sealed(cipher: XelCipher, key: XelKey, items: &[Vec<u8>]) -> Vec<u8> {
    let mut writer = RecordWriter::new(cipher, key);
    let mut wire = Vec::new();
    for item in items {
        wire.extend_from_slice(&writer.seal(item).unwrap());
    }
    wire
}

/// 本端（client 角色）发送的线上字节；失效用例刻意构造坏流。
fn outgoing_wire(case: &str) -> Vec<u8> {
    match case {
        // 魔数不符但长度合法：帧器必须判非法头并 poison。
        "bad-magic" => {
            let mut wire = vec![24, 3, 3, 0, 17];
            wire.resize(wire.len() + 17, 0x5A);
            wire
        }
        // 丢掉第一条记录的线上字节：期望 nonce 从此失步。
        "nonce-gap" => {
            let all = sealed(cipher_of(case), key_up(), &payloads());
            let first = RecordHeader::new(payloads()[0].len() + 16)
                .unwrap()
                .record_len();
            all[first..].to_vec()
        }
        "wrong-key" | "aead-aes" | "aead-chacha" | "aead-xor" => {
            sealed(cipher_of(case), key_up(), &payloads())
        }
        "xor-only" => plain_records().concat(),
        other => unreachable!("未知用例 {other}"),
    }
}

/// 回显：AEAD 用例用本方向密钥重新密封；`xor-only` 原样回送还原出的记录。
fn echo_wire(case: &str) -> Vec<u8> {
    if uses_aead(case) {
        sealed(cipher_of(case), key_down(), &payloads())
    } else {
        plain_records().concat()
    }
}

/// 接收侧状态：AEAD 记录读取器，或纯帧器（`xor-only`）。
enum Sink {
    Aead(RecordReader),
    Plain(RecordFramer),
}

impl Sink {
    fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        match self {
            Self::Aead(reader) => reader.push(bytes),
            Self::Plain(framer) => framer.push(bytes),
        }
    }

    fn next_item(&mut self) -> Result<Option<Vec<u8>>, Error> {
        match self {
            Self::Aead(reader) => reader.next_plaintext(),
            Self::Plain(framer) => framer.next_record(),
        }
    }

    fn finish(&mut self) -> Result<(), Error> {
        match self {
            Self::Aead(reader) => reader.finish(),
            Self::Plain(framer) => framer.finish(),
        }
    }

    fn is_poisoned(&self) -> bool {
        match self {
            Self::Aead(reader) => reader.is_poisoned(),
            Self::Plain(framer) => framer.is_poisoned(),
        }
    }
}

fn recv_sink(case: &str, key: XelKey) -> Sink {
    if uses_aead(case) {
        Sink::Aead(RecordReader::new(cipher_of(case), key))
    } else {
        Sink::Plain(RecordFramer::new())
    }
}

fn up_mask() -> XorMask {
    XorMask::new(&key_up(), &IV_UP, &key_down(), &IV_DOWN).expect("XOR 掩蔽器建立失败")
}

fn down_mask() -> XorMask {
    XorMask::new(&key_down(), &IV_DOWN, &key_up(), &IV_UP).expect("XOR 掩蔽器建立失败")
}

/// 不规则分块：迫使每一段字节都落在跨记录/跨头的任意切分点上。
fn splits(total: usize) -> Vec<usize> {
    const PATTERN: [usize; 6] = [1, 4, 3, 5, 997, 2048];
    let mut sizes = Vec::new();
    let mut left = total;
    let mut index = 0;
    while left > 0 {
        let size = PATTERN[index % PATTERN.len()].min(left);
        sizes.push(size);
        left -= size;
        index += 1;
    }
    sizes
}
