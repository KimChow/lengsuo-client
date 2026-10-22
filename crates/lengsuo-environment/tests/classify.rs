//! 流分类与出口归属的纯内存验证：每条 fail-closed 分支都实测，
//! 用例统一在超时保护内运行（不建套接字、不碰真实设备、不做真实等待）。
//! DNS 端口语义与会话表上限见 `tests/dns.rs`。

// 用例按主题拆到 `tests/classify/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

use lengsuo_environment::{DenyReason, Direction, FlowKey, Timestamp, TrafficKind};
use std::time::Duration;

mod support;
use support::{
    classifier, dns_pair, guard, info, online_router, tcp_pair, v6, CLIENT, DEV_A, DEV_B, DEV_C,
    DNS_SERVER, ENV_A, ENV_B, HARD, IDLE, SERVER, SLACK, T0, V6_CLIENT, V6_DNS, V6_SERVER,
};

include!("classify/registry.rs");
include!("classify/capacity.rs");
include!("classify/lifecycle.rs");
