//! 承接孤儿用例 `crates/ss-cli/tests/config/**`（30 例）与 `crates/ss-cli/tests/setup.rs`（1 例）。
//!
//! 背景见 `docs/ss-cli-orphan-tests.md`：
//! - `crates/ss-cli/` 从进入 git 历史起就没有 `Cargo.toml`、不在 workspace members、
//!   `Cargo.lock` 无 `ss_cli` 条目 ⇒ 那 31 个用例**从未被编译过、从未被运行过**。
//! - 真实配置实现在 `crates/ss-client/src/config.rs`。该文件原先**既未在 `lib.rs` 里声明为模块、
//!   也缺少 `serde`/`toml` 依赖、还调用了不存在的 `Error::config`** ⇒ 它本身也是孤儿，
//!   `ss_client::config` 不可达。**现已激活**（见 `docs/ss-client-config-activate.md`）：
//!   `lib.rs` 声明了 `pub mod config;`，依赖问题用手写 TOML 读取器解决（不新增依赖），
//!   `Error::config` 改为类型化的 `Error::Config(ConfigError)`。
//! - 因此 30 个配置用例**逐条**都无实现可承接；本 target 只承接**能被真实实现证伪/证实**的那几条。
//!
//! 手法与孤儿用例保持一致：用 `include!` **文本并入**同一模块（不是 `mod` 子模块），
//! 这样用例名**不带模块前缀**、与孤儿用例**逐字一致**。
//! 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

use ss_core::crypto::CipherSuite;
use ss_core::error::Error as SsCoreError;

include!("ss_cli_config/setup.rs");
include!("ss_cli_config/cipher.rs");
