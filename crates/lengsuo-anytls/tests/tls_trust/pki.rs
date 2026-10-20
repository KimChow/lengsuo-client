//! 测试专用 PKI：openssl 现签，只写临时目录、用后即删、不提交仓库。
//!
//! 口径与 `tests/interop_server/tls.rs` 一致：两级链（测试 CA → 叶子，
//! SAN=localhost/127.0.0.1、serverAuth）。过期叶子用 `openssl ca
//! -startdate/-enddate` 造（OpenSSL 3.0 的 `req -days` 不接受负数）。
#![allow(dead_code)]
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// 生成的测试 PKI（全部为 PEM 字节，直接喂给产品层 `ClientTrust`/`ServerIdentity`）。
pub struct Pki {
    /// 测试 CA 的 PEM——客户端唯一信任锚。
    pub ca_pem: Vec<u8>,
    /// 服务端出示的 PEM 链：叶子 + CA。
    pub chain_pem: Vec<u8>,
    /// 叶子私钥（PKCS#8 PEM）。
    pub key_pem: Vec<u8>,
    /// 另一棵独立 CA 的 PEM（CA 不匹配反例）。
    pub other_ca_pem: Vec<u8>,
    /// 与 [`Pki::chain_pem`] 不配对的另一把 PKCS#8 私钥（反例）。
    pub other_key_pem: Vec<u8>,
    /// 已过期叶子（+CA）的 PEM 链。
    pub expired_chain_pem: Vec<u8>,
    /// 已过期叶子的私钥（PKCS#8 PEM）。
    pub expired_key_pem: Vec<u8>,
    /// 证书/私钥 PEM 正文的各自行片段，供「错误信息不泄漏材料」断言使用。
    pub fragments: Vec<String>,
}

fn ok(args: &[&str]) -> bool {
    Command::new("openssl")
        .args(args)
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// PEM 正文第一行（BASE64），用于断言错误信息不含材料。
fn body_line(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    text.lines()
        .find(|line| !line.starts_with("-----"))
        .unwrap_or_default()
        .to_owned()
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_default()
}

/// 生成测试 PKI；环境无 openssl 时返回 None（调用方跳过并如实说明）。
pub fn generate() -> Option<Pki> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "lengsuo-anytls-tls-trust-{}-{nanos}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;
    let p = |name: &str| dir.join(name).to_str().unwrap_or_default().to_owned();

    // 测试 CA + 另一棵无关 CA。
    for (key, pem, cn) in [
        ("ca-key.pem", "ca.pem", "lengsuo-tls-trust-ca"),
        (
            "other-ca-key.pem",
            "other-ca.pem",
            "lengsuo-tls-trust-other-ca",
        ),
    ] {
        if !ok(&[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            &p(key),
            "-out",
            &p(pem),
            "-days",
            "1",
            "-subj",
            &format!("/CN={cn}"),
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]) {
            return cleanup(dir, None);
        }
    }

    // 叶子：SAN=localhost/127.0.0.1，PKCS#8 私钥（openssl 3 默认输出）。
    if !ok(&[
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        &p("leaf-key.pem"),
        "-out",
        &p("leaf.csr"),
        "-subj",
        "/CN=localhost",
    ]) {
        return cleanup(dir, None);
    }
    std::fs::write(dir.join("leaf.ext"), LEAF_EXT).ok()?;
    if !ok(&[
        "x509",
        "-req",
        "-in",
        &p("leaf.csr"),
        "-CA",
        &p("ca.pem"),
        "-CAkey",
        &p("ca-key.pem"),
        "-set_serial",
        "01",
        "-days",
        "1",
        "-extfile",
        &p("leaf.ext"),
        "-out",
        &p("leaf.pem"),
    ]) {
        return cleanup(dir, None);
    }

    // 过期叶子：同一测试 CA 签发，SAN 同上，效期固定在过去。
    if !ok(&[
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        &p("expired-key.pem"),
        "-out",
        &p("expired.csr"),
        "-subj",
        "/CN=localhost",
    ]) {
        return cleanup(dir, None);
    }
    std::fs::write(dir.join("index.txt"), b"").ok()?;
    std::fs::write(dir.join("serial"), b"1000").ok()?;
    std::fs::create_dir_all(dir.join("newcerts")).ok()?;
    std::fs::write(
        dir.join("ca.cnf"),
        format!(
            "[ca]\ndefault_ca = CA_default\n[CA_default]\ndatabase = {}\nnew_certs_dir = {}\n\
             certificate = {}\nprivate_key = {}\nserial = {}\ndefault_md = sha256\n\
             policy = policy_any\n[policy_any]\ncommonName = optional\n",
            dir.join("index.txt").to_str().unwrap_or_default(),
            dir.join("newcerts").to_str().unwrap_or_default(),
            dir.join("ca.pem").to_str().unwrap_or_default(),
            dir.join("ca-key.pem").to_str().unwrap_or_default(),
            dir.join("serial").to_str().unwrap_or_default(),
        ),
    )
    .ok()?;
    if !ok(&[
        "ca",
        "-config",
        &p("ca.cnf"),
        "-batch",
        "-in",
        &p("expired.csr"),
        "-out",
        &p("expired-leaf.pem"),
        "-notext",
        "-startdate",
        "20200101000000Z",
        "-enddate",
        "20210101000000Z",
        "-extfile",
        &p("leaf.ext"),
    ]) {
        return cleanup(dir, None);
    }

    // 不配对私钥：只取另一把钥匙，其证书丢弃。
    if !ok(&[
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        &p("other-key.pem"),
        "-out",
        &p("unused.csr"),
        "-subj",
        "/CN=localhost",
    ]) {
        return cleanup(dir, None);
    }

    let chain_pem = concat_files(&dir.join("leaf.pem"), &dir.join("ca.pem"))?;
    let expired_chain_pem = concat_files(&dir.join("expired-leaf.pem"), &dir.join("ca.pem"))?;
    let pki = Pki {
        ca_pem: read(&dir.join("ca.pem")),
        chain_pem,
        key_pem: read(&dir.join("leaf-key.pem")),
        other_ca_pem: read(&dir.join("other-ca.pem")),
        other_key_pem: read(&dir.join("other-key.pem")),
        expired_chain_pem,
        expired_key_pem: read(&dir.join("expired-key.pem")),
        fragments: [
            body_line(&dir.join("leaf.pem")),
            body_line(&dir.join("leaf-key.pem")),
            body_line(&dir.join("ca.pem")),
            body_line(&dir.join("expired-key.pem")),
        ]
        .into_iter()
        .filter(|line| line.len() >= 24)
        .collect(),
    };
    cleanup(dir, Some(pki))
}

const LEAF_EXT: &str = "subjectAltName=DNS:localhost,IP:127.0.0.1\n\
                        basicConstraints=critical,CA:FALSE\n\
                        keyUsage=critical,digitalSignature,keyEncipherment\n\
                        extendedKeyUsage=serverAuth\n";

fn concat_files(a: &Path, b: &Path) -> Option<Vec<u8>> {
    let mut out = read(a);
    out.extend_from_slice(&read(b));
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// 读完全部材料后删目录，再交出结果。
fn cleanup<T>(dir: std::path::PathBuf, value: Option<T>) -> Option<T> {
    let _ = std::fs::remove_dir_all(dir);
    value
}
