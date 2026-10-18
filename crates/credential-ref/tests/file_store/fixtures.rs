//! file_store 集成测试的共享 fixture（自原 file_store.rs 原样搬移）。

//! FileStore 硬规则测试：落盘往返、口令错误、篡改、截断、版本不识别、
//! 跨作用域不可见、过期、并发、文件内不含明文与元数据。
//!
//! 所有用例使用固定/可控时钟与测试专用假口令，不触碰真实凭据。

// 头部偏移常量与读取辅助是布局契约的完整记录，保留备用（与 tests/support 同规则）。
#![allow(dead_code)]

use std::fs;

// 供各主题测试文件 `use crate::fixtures::*` 一并可见（原单文件顶层的 use）。
pub use crate::support::{
    assert_error_clean, file_contains, windows_contains, ManualClock, TempDir,
};
pub use credential_ref::{
    CredentialRef, FileStore, KdfParams, Plaintext, Scope, SecretStore, StoreError,
};

pub const PASSPHRASE: &str = "test-passphrase-DoNotLog";
pub const WRONG_PASSPHRASE: &str = "wrong-test-passphrase";
pub const PLAINTEXT: &str = "file-store-sup3r-token-DoNotLog";
pub const TARGET: &str = "env-file-target";

/// 新建带可控时钟的文件库（测试假口令，固定起始时刻）。
pub fn store_at(path: &std::path::Path, now_ms: u64) -> (FileStore, ManualClock) {
    let clock = ManualClock::new(now_ms);
    let store = FileStore::with_clock(path, PASSPHRASE, clock.clock()).expect("open store");
    (store, clock)
}

/// 写入一条环境作用域凭据并返回引用（`u64::MAX` 表示永不过期）。
pub fn put_env(store: &dyn SecretStore, target: &str, value: &str) -> CredentialRef {
    let reference = CredentialRef::env(target, u64::MAX);
    store
        .put(&reference, &Plaintext::from(value))
        .expect("put succeeds");
    reference
}

pub fn read_bytes(path: &std::path::Path) -> Vec<u8> {
    fs::read(path).expect("store file must exist")
}

/// 头部定长前缀：magic(8) + schema_version(4) + iterations(4) + key_len(4) + salt(16) = 36。
pub const PREFIX_LEN: usize = 36;
pub const OFFSET_SCHEMA_VERSION: usize = 8;
pub const OFFSET_ITERATIONS: usize = 12;
pub const OFFSET_KEY_LEN: usize = 16;
pub const OFFSET_SALT: usize = 20;
pub const OFFSET_VERIFIER_LEN: usize = 36;
pub const OFFSET_VERIFIER_BODY: usize = 40;

/// 头部字节长度：定长前缀 + verifier 长度域 + verifier（nonce+密文+tag）。
pub fn header_len(bytes: &[u8]) -> usize {
    let verifier_len = u32::from_le_bytes(
        bytes[OFFSET_VERIFIER_LEN..OFFSET_VERIFIER_LEN + 4]
            .try_into()
            .expect("verifier length field"),
    ) as usize;
    PREFIX_LEN + 4 + verifier_len
}

pub fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32 field"))
}
