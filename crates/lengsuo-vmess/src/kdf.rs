//! VMess KDFv1 —— 参考 `proxy/vmess/aead/kdf.go` 的 `KDF` / `KDF16` 对象级忠实移植
//! （固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）。
//!
//! **为什么不能写成直觉简式。** 参考实现：
//!
//! ```go
//! hmacf := hmac.New(sha256.New, []byte(KDFSaltConstVMessAEADKDF))
//! for _, v := range path {
//!     first := true
//!     hmacf = hmac.New(func() hash.Hash {
//!         if first { first = false; return hash2{hmacf} }
//!         return hmacf
//!     }, []byte(v))
//! }
//! hmacf.Write(key)
//! return hmacf.Sum(nil)
//! ```
//!
//! `hash2{hmacf}` 只是内嵌 `hash.Hash` 的透明包装，方法全部透传；`crypto/hmac.New`
//! 把 NewHash 回调调用两次（分别赋给 outer / inner），两次拿到的是**同一个上一层
//! 对象**（接口值不等恰好绕过 Go 的唯一性检查）。因此从 level-1 起，每层的
//! outer 与 inner **别名共享**上一层，`Write`/`Sum`/`Reset` 按标准库 `crypto/hmac`
//! 的定义逐字转发，最终所有字节都交织进**同一个** level-0 SHA-256 状态。
//! 简式 `acc = HMAC(path, HMAC(salt, acc))` 与此不等价：
//! `KDF16(cmdKey, "AES Auth ID Encryption")` 简式得 `9f1703e5…`，参考得
//! `52416081…`（黄金向量已锁定）。
//!
//! **本模块的建模。** [`Node`] 枚举对应 Go `hash.Hash` 的两种形态：
//! `Plain`（裸 SHA-256）与 `Hmac`（标准库 hmac 结构的 outer/inner/ipad/opad）。
//! 节点间用 `Rc<RefCell<>>` 引用如实表达别名；`node_write` / `node_sum` /
//! `node_reset` 逐字对应标准库非 marshal 分支（marshal 分支只是把 ipad/opad
//! 已写入的状态缓存起来省去重复写入，数学等价）：
//!
//! - `Write(p)` → `inner.Write(p)`；
//! - `Sum(in)` → `inner.Sum` → `outer.Reset` → `outer.Write(opad)` →
//!   `outer.Write(内层摘要)` → `outer.Sum`；
//! - `Reset()` → `inner.Reset()` + `inner.Write(ipad)`（嵌套层的 inner 是 hmac
//!   对象、不实现 `BinaryMarshaler`，标准库在此提前返回，不再触碰 outer）。
//!
//! **长路径元素的折叠副作用。** `hmac.New` 对 `len(key) > 64` 的 key 先
//! `outer.Write(key)`、`key = outer.Sum(nil)` 折叠；别名共享下 outer 没有任何
//! `Reset`，这次写入**不会被清洗**，随后新层 `inner.Write(ipad)` 直接续接在
//! 上一层已有状态之后。64/65 字节路径输出因此不同（黄金向量锁定）。
//!
//! 输出长度：`kdf` 返回完整 32 字节标签，`kdf16` / `kdf_n` 取前缀（参考里就是
//! `KDF(...)[:16]`、`[:12]` 的切片用法）。
//!
//! **验收依据。** 下方 15 条黄金向量全部由 47 上 Go 工具链实跑参考 `kdf.go`
//! 逐字复制的最小程序产出（覆盖任务书 6 条 + 空 key / 长 key / 无路径 /
//! 64·65·70·71·100 字节长路径折叠 / 二进制路径 / 6 层路径），命令与输出记录在
//! `results/close-vmess-kdf-handoff.md`。

use std::cell::RefCell;
use std::rc::Rc;

use sha2::{Digest, Sha256};

use crate::consts::KDF_SALT_VMESS_AEAD_KDF;
use crate::{Error, Result};

/// HMAC-SHA256 标签长度（字节）= 参考 `KDF` 的完整输出。
pub const KDF_MAX_LEN: usize = 32;
/// `KDF16` 输出长度（= AuthID/密钥长度 16 字节）。
pub const ID_BYTES: usize = 16;
/// 单个 path 元素。参考里 path 是 `string`，Go 字符串可含任意字节
/// （authID/nonce 是二进制），因此这里接受 `&[u8]`。
pub type PathElem<'a> = &'a [u8];

/// SHA-256 分块大小（`crypto/hmac` 的 blocksize，折叠阈值）。
const BLOCK: usize = 64;
/// SHA-256 摘要长度。
const DIGEST: usize = 32;

/// Go `hash.Hash` 节点：裸 SHA-256，或标准库 hmac 结构（outer/inner 别名共享
/// 上层节点）。ipad/opad 是按块长补零再异化的密钥拷贝。
enum Node {
    Plain(Sha256),
    Hmac {
        outer: Hash,
        inner: Hash,
        ipad: Vec<u8>,
        opad: Vec<u8>,
    },
}

type Hash = Rc<RefCell<Node>>;

fn plain() -> Hash {
    Rc::new(RefCell::new(Node::Plain(Sha256::new())))
}

/// `hmac.Write(p)`：转发到 inner。
fn node_write(h: &Hash, msg: &[u8]) {
    let next = match &mut *h.borrow_mut() {
        Node::Plain(s) => {
            s.update(msg);
            return;
        }
        Node::Hmac { inner, .. } => inner.clone(),
    };
    node_write(&next, msg);
}

/// `hmac.Sum(nil)`：inner 摘要 → outer 复位吃 opad → 吃内层摘要 → outer 摘要。
/// `Plain` 分支即 `sha256.Sum`：clone 后 finalize，不改变原状态。
fn node_sum(h: &Hash) -> [u8; DIGEST] {
    let (inner, outer, opad) = match &*h.borrow() {
        Node::Plain(s) => {
            let digest = s.clone().finalize();
            let mut out = [0u8; DIGEST];
            out.copy_from_slice(&digest);
            return out;
        }
        Node::Hmac {
            outer, inner, opad, ..
        } => (inner.clone(), outer.clone(), opad.clone()),
    };
    let tmp = node_sum(&inner);
    node_reset(&outer);
    node_write(&outer, &opad);
    node_write(&outer, &tmp);
    node_sum(&outer)
}

/// `hmac.Reset()`：inner 复位并重放 ipad。嵌套层 inner 是 hmac 对象、不实现
/// `BinaryMarshaler`，标准库在此提前返回，因此不再触碰 outer。
fn node_reset(h: &Hash) {
    let (inner, ipad) = match &mut *h.borrow_mut() {
        Node::Plain(s) => {
            *s = Sha256::new();
            return;
        }
        Node::Hmac { inner, ipad, .. } => (inner.clone(), ipad.clone()),
    };
    node_reset(&inner);
    node_write(&inner, &ipad);
}

/// `hmac.New(hNew, key)`：outer/inner 各取一个新 hash；别名模式下两者都是上一层
/// 节点。key 超过块长先经 outer 折叠（该写入按参考语义**不清洗**）；随后 ipad/opad
/// 补零异化，inner 写入 ipad。
fn new_hmac(key: &[u8], prev: Option<&Hash>) -> Hash {
    let (outer, inner) = match prev {
        None => (plain(), plain()),
        Some(p) => (p.clone(), p.clone()),
    };
    let mut key = key.to_vec();
    if key.len() > BLOCK {
        node_write(&outer, &key);
        key = node_sum(&outer).to_vec();
    }
    let mut ipad = vec![0u8; BLOCK];
    let mut opad = vec![0u8; BLOCK];
    ipad[..key.len()].copy_from_slice(&key);
    opad[..key.len()].copy_from_slice(&key);
    for b in &mut ipad {
        *b ^= 0x36;
    }
    for b in &mut opad {
        *b ^= 0x5c;
    }
    node_write(&inner, &ipad);
    Rc::new(RefCell::new(Node::Hmac {
        outer,
        inner,
        ipad,
        opad,
    }))
}

/// `KDF(key, path...)`：根层以固定盐为 key，逐个 path 元素包一层，最后把 `key`
/// 作为消息写入，返回 32 字节标签。
pub fn kdf(key: &[u8], paths: &[PathElem<'_>]) -> Vec<u8> {
    let mut node = new_hmac(KDF_SALT_VMESS_AEAD_KDF.as_bytes(), None);
    for p in paths {
        node = new_hmac(p, Some(&node));
    }
    node_write(&node, key);
    node_sum(&node).to_vec()
}

/// 输出长度参数化的 `KDF`：取标签前缀 `out_len` 字节。
///
/// `out_len > 32` 是协议外用法（参考只做切片截断），fail-closed 拒绝。
pub fn kdf_n(key: &[u8], paths: &[PathElem<'_>], out_len: usize) -> Result<Vec<u8>> {
    if out_len > KDF_MAX_LEN {
        return Err(Error::BadLength {
            declared: out_len,
            got: KDF_MAX_LEN,
        });
    }
    let full = kdf(key, paths);
    Ok(full[..out_len].to_vec())
}

/// `KDF16(key, path...)`：16 字节密钥前缀。
pub fn kdf16(key: &[u8], paths: &[PathElem<'_>]) -> [u8; ID_BYTES] {
    let full = kdf(key, paths);
    let mut out = [0u8; ID_BYTES];
    out.copy_from_slice(&full[..ID_BYTES]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 任务书与 docs/vmess-status.md 的固定验证材料。
    const CMD_KEY: &str = "d1ee7a1cd85245585b5dcae432b8ac63";
    const AUTH: &str = "000102030405060708090a0b0c0d0e0f";
    const NONCE: &str = "1011121314151617";

    /// 断言 `kdf(key, paths)` 的 32 字节十六进制等于参考实跑输出。
    fn assert_kdf(name: &str, key: &[u8], paths: &[&[u8]], expect: &str) {
        let got = kdf(key, paths);
        assert_eq!(hex::encode(got), expect, "{name}");
    }

    /// 任务书 6 条黄金向量（16 字节前缀即 docs/vmess-status.md 所列）。
    #[test]
    fn matches_reference_golden_vectors() {
        let key = hex::decode(CMD_KEY).expect("cmd key");
        let auth = hex::decode(AUTH).expect("auth id");
        let nonce = hex::decode(NONCE).expect("nonce");
        assert_kdf(
            "auth_id_enc",
            &key,
            &[b"AES Auth ID Encryption"],
            "524160810d101b2a41c81c60cc345f49d6e7363c41ffee5c13fdd32fd129636c",
        );
        assert_kdf(
            "header_key_2p",
            &key,
            &[b"AES Auth ID Encryption", b"VMess Header AEAD Key"],
            "8c52861a50ea4047173477da3396a4b308559b5d48c8c33ee0e552212a202cbf",
        );
        assert_kdf(
            "len_key_3p",
            &key,
            &[b"VMess Header AEAD Key_Length", &auth, &nonce],
            "c6fd91071819857c980b7bc978df2e3ee98b664399df7f06c7a57a00dd51f3bc",
        );
        assert_kdf(
            "len_iv_3p",
            &key,
            &[b"VMess Header AEAD Nonce_Length", &auth, &nonce],
            "5b8458f09b6e8f13355a96120471ec6573306c1efa7eb09e3d86df828b78d41f",
        );
        assert_kdf(
            "payload_key_3p",
            &key,
            &[b"VMess Header AEAD Key", &auth, &nonce],
            "f2b44c8a0876c31e523e571ce90507ea89d5994c9b68fa3666d571cbe8649601",
        );
        assert_kdf(
            "payload_iv_3p",
            &key,
            &[b"VMess Header AEAD Nonce", &auth, &nonce],
            "b61ac08be72ee66581eadfae75188e6a113bda9368873e99e609bc42d011369e",
        );
    }

    /// 边界向量：空 key / 长 key / 无路径 / 64·65·70·71·100 字节长路径折叠 /
    /// 二进制路径 / 6 层路径。全部 Go 实跑。
    #[test]
    fn matches_reference_edge_vectors() {
        let key = hex::decode(CMD_KEY).expect("cmd key");
        assert_kdf(
            "no_path",
            &key,
            &[],
            "e548a51de1a1192f4cfa20486d99cee1592d87022a64e68033148838ba821a0b",
        );
        assert_kdf(
            "empty_key",
            &[],
            &[b"AES Auth ID Encryption"],
            "609e97fb93f07b7b856e7936dd3f6a6811a91417433532ea78b5734c40f25056",
        );
        let long_key = vec![0u8; 200];
        assert_kdf(
            "long_key_200",
            &long_key,
            &[b"AES Auth ID Encryption"],
            "46604a385b6b3c01db43cdafa89d00e8edb8a5222c0f7945fa86be582d3d7cad",
        );
        let p64 = vec![0u8; 64];
        let p65 = vec![0u8; 65];
        let p70 = vec![0u8; 70];
        let p71 = vec![0u8; 71];
        let p100 = vec![0u8; 100];
        assert_kdf(
            "long_p1_65",
            &key,
            &[&p65],
            "4604049df7a149db5b46731ccfa950e2223c52c480f2be3d33323275b9aac769",
        );
        assert_kdf(
            "long_p1_64",
            &key,
            &[&p64],
            "7d00af740eda2315fb83dc408d334fbc8a1ebe1f141cc895fbff54db04b81bf6",
        );
        assert_kdf(
            "long_p2_100",
            &key,
            &[b"VMess Header AEAD Key", &p100],
            "99d298f34220f6575bf1f8a3a47ef04b089d74eb87040d10b65164e7c0eebd5f",
        );
        assert_kdf(
            "long_both_70_71",
            &key,
            &[&p70, &p71],
            "bde3f9700ce2be57666ee9d3c4f00c3e5fa26bacb0314a21cbe09e63972b675b",
        );
        let auth = hex::decode(AUTH).expect("auth id");
        let nonce = hex::decode(NONCE).expect("nonce");
        assert_kdf(
            "six_paths",
            &key,
            &[b"a", b"bb", b"ccc", &auth, b"ddddd", &nonce],
            "be3115540269b31512e9f3b299c7d70eca046702f5d883801121a5f564b89098",
        );
        assert_kdf(
            "binary_path",
            &key,
            &[&[0xFF, 0x00, 0x80], b"x"],
            "af0ba3c68fdb0a080ecb533fc4be204e63c3bc3f50c8f1caff22ba5009342bed",
        );
    }

    #[test]
    fn kdf_output_is_deterministic_and_len_parametric() {
        let key = [7u8; 16];
        let a = kdf(&key, &[b"x".as_slice()]);
        let b = kdf(&key, &[b"x".as_slice()]);
        assert_eq!(a, b);
        assert_eq!(a.len(), KDF_MAX_LEN);
        assert_eq!(kdf16(&key, &[b"x".as_slice()])[..], a[..16]);
        assert_eq!(kdf_n(&key, &[b"x".as_slice()], 12).unwrap(), a[..12]);
    }

    #[test]
    fn kdf_path_elements_are_not_commutative() {
        let key = [3u8; 16];
        let ab = kdf(&key, &[b"A".as_slice(), b"B".as_slice()]);
        let ba = kdf(&key, &[b"B".as_slice(), b"A".as_slice()]);
        assert_ne!(ab, ba);
        // 单元素路径也不等于拼接路径（层叠别名不是简单连接）。
        let joined = kdf(&key, &[b"AB".as_slice()]);
        assert_ne!(ab, joined);
    }

    #[test]
    fn kdf_overlong_output_fails_closed() {
        assert!(matches!(
            kdf_n(&[0u8; 16], &[], KDF_MAX_LEN + 1),
            Err(Error::BadLength { .. })
        ));
    }

    /// 简式反例锁定：直接嵌套 HMAC 与参考结构不等价（文档记录的失败形态）。
    #[test]
    fn naive_chain_is_not_equivalent_to_reference() {
        use hmac::{Hmac, Mac};
        let key = hex::decode(CMD_KEY).expect("cmd key");
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"VMess AEAD KDF").unwrap();
        mac.update(&key);
        let acc = mac.finalize().into_bytes();
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"AES Auth ID Encryption").unwrap();
        mac.update(&acc);
        let naive = mac.finalize().into_bytes();
        assert_ne!(
            &naive[..16],
            &kdf16(&key, &[b"AES Auth ID Encryption"]),
            "简式不得与参考混同"
        );
    }
}
