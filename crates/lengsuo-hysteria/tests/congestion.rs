//! Brutal 参数/协商面测试：`Bandwidth` 解析矩阵、CC 头编解码向量、
//! `CongestionConfig` 校验矩阵、协商推导。
//!
//! 期望值均来自参考 Xray（`infra/conf/transport_internet.go` 的
//! `Bandwidth.Bps()` 行 460-511 与 `QuicParams` 校验行 1897-1920，
//! `hub.go`/`dialer.go` 的 switch 分支）。每条断言注明参考出处。

// 用例按主题拆到 `tests/congestion/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

use lengsuo_hysteria::congestion::{
    bandwidth::BandwidthError, negotiate_client_rate, negotiate_server_rate, Bandwidth, CcHeader,
    ConfigError, CongestionConfig, CongestionMode, HeaderError, BRUTAL_MIN_BPS,
};

use lengsuo_hysteria::congestion::bandwidth::Bandwidth as BW;

include!("congestion/bandwidth.rs");
include!("congestion/cc_header.rs");
include!("congestion/config.rs");
include!("congestion/negotiate.rs");
