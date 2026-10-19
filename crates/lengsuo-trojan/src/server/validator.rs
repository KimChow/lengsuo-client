//! 多用户凭据存储与常量时间哈希校验，分层对齐 `proxy/trojan/validator.go`。
//!
//! 参考实现用「密码哈希的十六进制字符串」作 key 建 map，`Get(hash)` 直接查表；
//! 本仓保留同样的 `Add` / `Get` / `GetByEmail` / `Del` / `GetCount` 分层与命名，
//! 但把“查中哪个用户”改成对**全部用户**做 `subtle` 常量时间比较。功能等价
//! （都是按线上哈希选中用户），安全上不通过 map 命中时间泄露“某哈希是否存在”。
//!
//! 邮箱去重沿用参考规则：非空邮箱不区分大小写且必须唯一；空邮箱不参与去重
//! （参考 `Validator.Add`）。原始密码不被持有——`Credential` 只保留哈希，且其
//! `Debug` 始终脱敏，密码与哈希都不会进入日志。

use std::collections::HashMap;
use std::sync::Arc;

use subtle::ConstantTimeEq as _;

use crate::credential::Credential;
use crate::server::Error;

/// 一个已登记的 trojan 用户；只暴露邮箱，凭据字段保持私有。
#[derive(Clone)]
pub struct User {
    email: String,
    credential: Credential,
}

impl User {
    #[must_use]
    pub fn email(&self) -> &str {
        &self.email
    }
}

/// 服务端用户集：按线上哈希常量时间选中用户，并按邮箱做去重与反查。
#[derive(Clone, Default)]
pub struct Validator {
    users: Vec<Arc<User>>,
    emails: HashMap<String, Arc<User>>,
}

impl Validator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 参考 `Validator.Add`：非空邮箱必须唯一（小写去重），否则拒绝整个用户。
    pub fn add(&mut self, email: &str, password: &str) -> Result<Arc<User>, Error> {
        let key = email.to_lowercase();
        if !email.is_empty() && self.emails.contains_key(&key) {
            return Err(Error::DuplicateEmail(email.to_owned()));
        }
        let user = Arc::new(User {
            email: email.to_owned(),
            credential: Credential::new(password),
        });
        self.users.push(user.clone());
        if !email.is_empty() {
            self.emails.insert(key, user.clone());
        }
        Ok(user)
    }

    /// 与线上 56 字节哈希常量时间比对，返回命中的用户；失败返回 `None`。
    #[must_use]
    pub fn get(&self, hash: &[u8]) -> Option<Arc<User>> {
        for user in &self.users {
            if bool::from(user.credential.as_bytes().ct_eq(hash)) {
                return Some(user.clone());
            }
        }
        None
    }

    /// 参考 `Validator.GetByEmail`：邮箱小写后反查。
    #[must_use]
    pub fn get_by_email(&self, email: &str) -> Option<Arc<User>> {
        self.emails.get(&email.to_lowercase()).cloned()
    }

    /// 参考 `Validator.Del`：空邮箱直接拒绝，未命中报用户不存在。
    pub fn delete(&mut self, email: &str) -> Result<(), Error> {
        if email.is_empty() {
            return Err(Error::EmailRequired);
        }
        let key = email.to_lowercase();
        let removed = self
            .emails
            .remove(&key)
            .ok_or_else(|| Error::UserNotFound(email.to_owned()))?;
        if let Some(position) = self
            .users
            .iter()
            .position(|user| user.email.to_lowercase() == key && Arc::ptr_eq(user, &removed))
        {
            self.users.swap_remove(position);
        }
        Ok(())
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.users.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }
}
