//! Shared builders for the integration tests. These describe a *plausible*
//! desktop profile; each test mutates exactly the field under examination so a
//! failure points at one rule.

#![allow(dead_code)]

use std::collections::BTreeMap;

use lengsuo_browser_profile::{
    DimensionPools, HardwareSpec, LocaleSpec, Platform, PoolCatalogV1, ProfileSpec, ScreenSpec,
    SCHEMA_VERSION_V1,
};

/// 16 lowercase hex characters == 8 seed bytes.
pub const GOOD_SEED: &str = "0123456789abcdef";

pub fn slots() -> BTreeMap<String, u32> {
    let mut m = BTreeMap::new();
    m.insert("canvas".to_string(), 1);
    m.insert("webgl".to_string(), 2);
    m.insert("audio".to_string(), 3);
    m.insert("fonts".to_string(), 4);
    m.insert("client_rects".to_string(), 5);
    m.insert("gpu".to_string(), 6);
    m.insert("ua".to_string(), 7);
    m
}

pub fn spec() -> ProfileSpec {
    ProfileSpec {
        schema_version: SCHEMA_VERSION_V1,
        environment_id: "env-0001_a".to_string(),
        pool_version: "pool-2026-10".to_string(),
        noise_version: 1,
        noise_seed_hex: GOOD_SEED.to_string(),
        platform: Platform::Windows,
        screen: ScreenSpec::default(),
        hardware: HardwareSpec::default(),
        locale: LocaleSpec::default(),
        webrtc_ip_handling_policy: None,
        slots: slots(),
    }
}

pub fn mobile_spec() -> ProfileSpec {
    let mut s = spec();
    s.environment_id = "env-mobile-1".to_string();
    s.platform = Platform::Android;
    s.hardware.max_touch_points = 5;
    s.screen.width = 1080;
    s.screen.height = 2400;
    s.screen.dpr_milli = 3000;
    s.hardware.cpu_cores = 8;
    s.hardware.memory_mib = 4096;
    s
}

pub fn full_ids() -> Vec<u32> {
    (1..=8).collect()
}

pub fn catalog() -> PoolCatalogV1 {
    let mut pools: DimensionPools = BTreeMap::new();
    for dim in lengsuo_browser_profile::DIMENSIONS {
        pools.insert(dim.to_string(), full_ids().into_iter().collect());
    }
    PoolCatalogV1::new("pool-2026-10", pools).expect("test catalog must be valid")
}
