//! 节点配置校验规则。

use super::{ConfigError, NodeConfig, Protocol};

impl NodeConfig {
    /// 校验单个节点配置的完整性；失败带节点名与原因（不含凭据原文）。
    pub fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |reason: &str| ConfigError::Invalid {
            name: self.name.clone(),
            reason: reason.to_string(),
        };
        if self.name.trim().is_empty() {
            return Err(invalid("name 不能为空"));
        }
        if self.endpoint.host.trim().is_empty() {
            return Err(invalid("endpoint.host 不能为空"));
        }
        if self.endpoint.port == 0 {
            return Err(invalid("endpoint.port 不能为 0"));
        }
        if let Some(probe) = &self.probe_target {
            if probe.host.trim().is_empty() {
                return Err(invalid("probe_target.host 不能为空"));
            }
            if probe.port == 0 {
                return Err(invalid("probe_target.port 不能为 0"));
            }
        }
        if let Some(tls) = &self.tls {
            if tls.insecure && tls.ca_pem.is_some() {
                return Err(invalid("tls.insecure 与 tls.ca_pem 不能同时设置"));
            }
            if let Some(name) = tls.server_name.as_deref() {
                if name.trim().is_empty() {
                    return Err(invalid("tls.server_name 不能为空"));
                }
            }
        }
        self.validate_reality(&invalid)?;
        self.validate_vision(&invalid)?;
        self.validate_encryption(&invalid)?;
        self.validate_xel(&invalid)?;
        self.validate_mux(&invalid)?;
        self.validate_credentials(&invalid)?;
        Ok(())
    }

    /// REALITY 配置段的协议范围校验（fail-closed）。
    ///
    /// 只判「该段能否出现在这个协议上」：**形态**校验（base64 / hex / 指纹）
    /// 交给协议 crate 的 `RealityConfig::from_settings`，避免在 node 侧复制实现。
    ///
    /// - `protocol != vless` 却带 `reality` ⇒ 显式报错（不静默忽略）。
    /// - `protocol == vless` 且带 `reality` ⇒ 公钥与口令**至少给一个**
    ///   （两者都空时协议 crate 会 fail-closed，这里提前给出更贴近配置的报错）。
    fn validate_reality(&self, invalid: &impl Fn(&str) -> ConfigError) -> Result<(), ConfigError> {
        let Some(reality) = &self.reality else {
            return Ok(());
        };
        if self.protocol != Protocol::Vless {
            return Err(invalid("reality 配置段只允许用于 vless 协议"));
        }
        if reality.public_key.trim().is_empty()
            && reality
                .password
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(invalid("reality.public_key 与 reality.password 至少给一个"));
        }
        if let Some(name) = reality.server_name.as_deref() {
            if name.trim().is_empty() {
                return Err(invalid("reality.server_name 不能为空"));
            }
        }
        Ok(())
    }

    /// 按协议的凭据要求逐项校验（fail-closed，报错不含凭据原文）。
    fn validate_credentials(
        &self,
        invalid: &impl Fn(&str) -> ConfigError,
    ) -> Result<(), ConfigError> {
        // 需要口令的协议：password 非空。
        if !self.protocol.uses_secret_fields() && self.auth.password.is_empty() {
            return Err(invalid("auth.password 不能为空"));
        }
        match self.protocol {
            Protocol::Trojan | Protocol::AnyTls | Protocol::Hysteria => {}
            Protocol::Vless | Protocol::Vmess => {
                // 参考的 ID 是 16 字节 UUID；这里只校验形态，具体解析在 outbound。
                if !is_uuid(self.auth.password.trim()) {
                    return Err(invalid("auth.password 必须是 16 字节 UUID 文本"));
                }
            }
            Protocol::Shadowsocks | Protocol::Ss2022 => {
                if self
                    .auth
                    .secret_key
                    .as_deref()
                    .is_none_or(|key| key.is_empty())
                {
                    return Err(invalid("auth.secret_key 不能为空"));
                }
                if self.method.as_deref().is_none_or(|m| m.trim().is_empty()) {
                    return Err(invalid("method 不能为空（shadowsocks/ss2022 需要）"));
                }
            }
            Protocol::Wireguard => {
                if self
                    .auth
                    .private_key
                    .as_deref()
                    .is_none_or(|k| k.trim().is_empty())
                {
                    return Err(invalid("auth.private_key 不能为空"));
                }
                if self
                    .auth
                    .public_key
                    .as_deref()
                    .is_none_or(|k| k.trim().is_empty())
                {
                    return Err(invalid("auth.public_key 不能为空"));
                }
            }
        }
        Ok(())
    }
}

/// UUID 文本形态检查：`8-4-4-4-12` 十六进制，大小写不敏感。
/// 只做形态检查，不做版本位判断（由协议 crate 的 ID 派生决定）。
fn is_uuid(text: &str) -> bool {
    let mut groups = text.split('-');
    let Some(shape) = [8, 4, 4, 4, 12]
        .iter()
        .map(|_| groups.next())
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    if groups.next().is_some() {
        return false;
    }
    shape
        .iter()
        .zip([8, 4, 4, 4, 12])
        .all(|(group, want)| group.len() == want && group.bytes().all(|b| b.is_ascii_hexdigit()))
}
