//! Pool catalog matching tests. The core requirement: a profile whose pool
//! version or tier id is not present in the catalog is refused outright. No
//! modulo, no nearest neighbour, no random substitution.

use std::collections::BTreeSet;

use lengsuo_browser_profile::{
    DimensionPools, Platform, PoolCatalogV1, ProfileError, Reject, DIMENSIONS,
};

mod support;
use support::{catalog, full_ids, mobile_spec, spec};

fn pools_with(mut tweak: impl FnMut(&str, &mut BTreeSet<u32>)) -> DimensionPools {
    let mut pools: DimensionPools = DimensionPools::new();
    for dim in DIMENSIONS {
        let mut ids: BTreeSet<u32> = full_ids().into_iter().collect();
        tweak(dim, &mut ids);
        pools.insert(dim.to_string(), ids);
    }
    pools
}

#[test]
fn a_matching_profile_passes() {
    catalog().validate(&spec()).unwrap();
    catalog().validate(&mobile_spec()).unwrap();
}

#[test]
fn pool_version_must_match_exactly() {
    for other in [
        "pool-2026-11",
        "pool-2026-1",
        "pool-2026-10-a",
        "POOL-2026-10",
        "pool_2026_10",
    ] {
        let mut s = spec();
        s.pool_version = other.to_string();
        let (side, err) = catalog().validate(&s).expect_err("pool version accepted");
        assert_eq!(side, Reject::Mapping);
        assert!(
            matches!(err, ProfileError::PoolVersionMismatch { .. }),
            "unexpected error {err}"
        );
        assert!(err.to_string().contains("pool-2026-10"));
    }
}

#[test]
fn tier_id_outside_the_named_pool_is_refused() {
    // Slot 9 exists in no pool at all; slot 8 exists only in `ua`.
    let pools = pools_with(|dim, ids| {
        if dim != "ua" {
            ids.remove(&8);
        }
        ids.remove(&9);
    });
    let catalog = PoolCatalogV1::new("pool-2026-10", pools).unwrap();

    let mut s = spec();
    s.slots.insert("ua".to_string(), 8);
    catalog.validate(&s).unwrap();

    for dim in DIMENSIONS.iter().filter(|d| **d != "ua") {
        let mut s = spec();
        s.slots.insert((*dim).to_string(), 8);
        let (side, err) = catalog
            .validate(&s)
            .expect_err(&format!("{dim} tier 8 accepted"));
        assert_eq!(side, Reject::Mapping);
        assert_eq!(
            err,
            ProfileError::SlotIdNotInPool {
                dimension: (*dim).to_string(),
                id: 8,
            }
        );
    }

    // Out-of-pool ids must not be rescued by taking them modulo the pool size.
    for fake in [9u32, 13, 16, 100, 1_000_000] {
        let mut s = spec();
        s.slots.insert("canvas".to_string(), fake);
        let (side, err) = catalog.validate(&s).expect_err("modulo fallback allowed");
        assert_eq!(side, Reject::Mapping);
        match err {
            ProfileError::SlotIdNotInPool { dimension, id } => {
                assert_eq!(dimension, "canvas");
                assert_eq!(id, fake, "id was silently remapped");
            }
            other => panic!("unexpected error for {fake}: {other}"),
        }
    }
}

#[test]
fn missing_dimension_pool_is_refused() {
    for dim in DIMENSIONS {
        let pools = pools_with(|d, ids| {
            if d == dim {
                ids.clear();
            }
        });
        // An empty pool for a dimension is rejected when building the catalog,
        // because such a pool could never satisfy any profile.
        let err = PoolCatalogV1::new("pool-2026-10", pools)
            .expect_err(&format!("empty pool for {dim} accepted"));
        assert!(matches!(err, ProfileError::CatalogShape(_)), "{err}");
    }
}

#[test]
fn catalog_with_extra_or_missing_dimension_is_refused() {
    let mut pools: DimensionPools = DimensionPools::new();
    for dim in DIMENSIONS {
        pools.insert(dim.to_string(), full_ids().into_iter().collect());
    }
    pools.insert("webgpu".to_string(), [1u32].into_iter().collect());
    assert_eq!(
        PoolCatalogV1::new("pool-2026-10", pools.clone()).err(),
        Some(ProfileError::CatalogShape(
            "dimension set must equal the seven supported dimensions"
        ))
    );

    pools.remove("gpu");
    assert!(PoolCatalogV1::new("pool-2026-10", pools).is_err());

    // Case and spelling variants are not supported dimensions.
    for wrong in ["GPU", "client-rects", "canvas ", "", "Ua"] {
        let mut pools: DimensionPools = DimensionPools::new();
        for dim in DIMENSIONS {
            pools.insert(dim.to_string(), full_ids().into_iter().collect());
        }
        pools.remove("gpu");
        pools.insert(wrong.to_string(), full_ids().into_iter().collect());
        assert!(
            PoolCatalogV1::new("pool-2026-10", pools).is_err(),
            "catalog dimension {wrong:?} accepted"
        );
    }
}

#[test]
fn catalog_rejects_bad_pool_version_and_zero_ids() {
    let good = || {
        let mut pools: DimensionPools = DimensionPools::new();
        for dim in DIMENSIONS {
            pools.insert(dim.to_string(), full_ids().into_iter().collect());
        }
        pools
    };
    for bad_version in ["", "pool/2026", "pool..10", "pool 10", "é-pool"] {
        assert!(
            PoolCatalogV1::new(bad_version, good()).is_err(),
            "catalog pool version {bad_version:?} accepted"
        );
    }

    let mut pools = good();
    pools.insert("ua".to_string(), [0u32, 1].into_iter().collect());
    assert_eq!(
        PoolCatalogV1::new("pool-2026-10", pools).err(),
        Some(ProfileError::CatalogShape(
            "tier ids must be non-zero and within the slot range"
        ))
    );

    let mut pools = good();
    pools.insert(
        "ua".to_string(),
        [lengsuo_browser_profile::MAX_SLOT_ID + 1]
            .into_iter()
            .collect(),
    );
    assert!(PoolCatalogV1::new("pool-2026-10", pools).is_err());
}

#[test]
fn catalog_reports_which_side_is_invalid() {
    // An invalid profile is blamed on the profile, not on the mapping.
    // Schema 2 is a legal version now (it just requires an explicit policy),
    // so an unsupported version 3 stands in for the old "bad schema" case.
    let mut s = spec();
    s.schema_version = 3;
    let (side, err) = catalog().validate(&s).expect_err("bad schema accepted");
    assert_eq!(side, Reject::Profile);
    assert_eq!(err, ProfileError::SchemaVersion(3));

    let mut s = spec();
    s.slots.remove("ua");
    let (side, _) = catalog().validate(&s).expect_err("missing slot accepted");
    assert_eq!(side, Reject::Profile);

    // A structurally broken catalog is blamed on the catalog.
    let mut pools: DimensionPools = DimensionPools::new();
    for dim in DIMENSIONS.iter().take(3) {
        pools.insert(dim.to_string(), full_ids().into_iter().collect());
    }
    let broken = serde_json::json!({
        "schema_version": 1,
        "pool_version": "pool-2026-10",
        "dimensions": pools,
    })
    .to_string();
    let err = PoolCatalogV1::from_json_str(&broken).expect_err("partial catalog parsed");
    assert!(matches!(err, ProfileError::CatalogShape(_)), "{err}");
}

#[test]
fn an_old_profile_keeps_its_own_pool_mapping() {
    // Regression guard for "old profiles must keep their original pool":
    // a v1 profile pinned to an older pool only validates against that older
    // catalog, and never against a renamed successor with identical ids.
    let mut old_pools: DimensionPools = DimensionPools::new();
    for dim in DIMENSIONS {
        old_pools.insert(dim.to_string(), [1u32, 2].into_iter().collect());
    }
    let old_catalog = PoolCatalogV1::new("pool-2025-01", old_pools).unwrap();

    let mut s = spec();
    s.pool_version = "pool-2025-01".to_string();
    for dim in DIMENSIONS {
        s.slots.insert((*dim).to_string(), 2);
    }
    old_catalog.validate(&s).unwrap();
    let (side, err) = catalog()
        .validate(&s)
        .expect_err("old pool matched new catalog");
    assert_eq!(side, Reject::Mapping);
    assert!(matches!(err, ProfileError::PoolVersionMismatch { .. }));

    // Tier 3 does not exist in the old pool at all.
    let mut drifted = s.clone();
    drifted.slots.insert("canvas".to_string(), 3);
    assert!(old_catalog.validate(&drifted).is_err());
}

#[test]
fn catalog_json_is_closed() {
    let text = r#"{
        "schema_version": 1,
        "pool_version": "pool-2026-10",
        "dimensions": {
            "canvas": [1,2], "webgl": [1], "audio": [1], "fonts": [1],
            "client_rects": [1], "gpu": [1], "ua": [1]
        }
    }"#;
    let parsed = PoolCatalogV1::from_json_str(text).unwrap();
    assert_eq!(parsed.pool_version(), "pool-2026-10");
    assert_eq!(parsed.ids("canvas"), Some(&[1u32, 2].into_iter().collect()));
    assert_eq!(parsed.ids("webgpu"), None);
    assert_eq!(parsed.dimensions().len(), DIMENSIONS.len());

    let mut value: serde_json::Value = serde_json::from_str(text).unwrap();
    value["signing_key"] = serde_json::json!("private");
    assert!(PoolCatalogV1::from_json_str(&value.to_string()).is_err());

    value = serde_json::from_str(text).unwrap();
    value["dimensions"]["canvas"] = serde_json::json!({"a": 1});
    assert!(PoolCatalogV1::from_json_str(&value.to_string()).is_err());

    value = serde_json::from_str(text).unwrap();
    value["schema_version"] = serde_json::json!(2);
    assert!(PoolCatalogV1::from_json_str(&value.to_string()).is_err());
}

#[test]
fn catalog_roundtrip_is_stable() {
    let catalog = catalog();
    let once = catalog.to_json().unwrap();
    let twice = PoolCatalogV1::from_json_str(&once)
        .unwrap()
        .to_json()
        .unwrap();
    assert_eq!(once, twice);
    assert_eq!(PoolCatalogV1::from_json_str(&once).unwrap(), catalog);
}

#[test]
fn mobile_catalog_validation_is_the_same_code_path() {
    // Touch consistency is a profile rule; the catalog does not re-litigate it,
    // but an inconsistent mobile profile must not pass a catalog check either.
    let mut s = mobile_spec();
    s.platform = Platform::Android;
    s.hardware.max_touch_points = 0;
    let (side, _) = catalog()
        .validate(&s)
        .expect_err("touch contradiction accepted");
    assert_eq!(side, Reject::Profile);
}
