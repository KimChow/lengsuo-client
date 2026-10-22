// 用例按主题拆到 `tests/config/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

mod setup;

use setup::Fixture;
use ss_cli::config::{Action, MuxConfig, Rule, SsUrlError};

include!("config/url.rs");
include!("config/rules.rs");
include!("config/mux_dns.rs");
include!("config/serde.rs");
include!("config/domain.rs");
include!("config/roundtrip.rs");
