//! Slot-pool manifest (`PoolCatalogV1`).
//!
//! A catalog is data handed to the client from wherever pools are authored.
//! This crate only *checks* profiles against it: it does not generate pools,
//! tier values, or device-population distributions.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::ProfileError;
use crate::spec::ProfileSpec;

/// Per-dimension set of tier ids that one pool version actually contains.
/// Repeated tier ids in JSON arrays normalize to set membership; duplicate
/// dimension keys are ambiguous and are rejected.
pub type DimensionPools = std::collections::BTreeMap<String, BTreeSet<u32>>;

/// Which side of a pool check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// The catalog itself is structurally invalid.
    Catalog,
    /// The profile is structurally invalid.
    Profile,
    /// The profile references a pool version or tier id the catalog lacks.
    ///
    /// This is the contract's refusal path: a missing old pool, an unknown
    /// tier, or a moved pool version must stop the environment. There is never
    /// a modulo, nearest-neighbour or random substitution.
    Mapping,
}

/// Catalog of tier ids available for one pool version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolCatalogV1 {
    pub schema_version: u32,
    pub pool_version: String,
    #[serde(deserialize_with = "crate::json::unique_map")]
    pub dimensions: DimensionPools,
}

impl PoolCatalogV1 {
    fn validate_shape(&self) -> Result<(), ProfileError> {
        if self.schema_version != crate::SCHEMA_VERSION_V1 {
            return Err(ProfileError::SchemaVersion(self.schema_version));
        }
        crate::validate::check_safe_identifier("pool_version", &self.pool_version)?;
        if self.dimensions.len() != crate::DIMENSIONS.len()
            || crate::DIMENSIONS
                .iter()
                .any(|d| !self.dimensions.contains_key(*d))
        {
            return Err(ProfileError::CatalogShape(
                "dimension set must equal the seven supported dimensions",
            ));
        }
        for ids in self.dimensions.values() {
            if ids.is_empty() {
                return Err(ProfileError::CatalogShape(
                    "dimension pools must not be empty",
                ));
            }
            if ids
                .iter()
                .any(|id| !(crate::MIN_SLOT_ID..=crate::MAX_SLOT_ID).contains(id))
            {
                return Err(ProfileError::CatalogShape(
                    "tier ids must be non-zero and within the slot range",
                ));
            }
        }
        Ok(())
    }

    /// Validate and build a catalog for one pool version.
    pub fn new(
        pool_version: impl Into<String>,
        dimensions: DimensionPools,
    ) -> Result<Self, ProfileError> {
        let catalog = Self {
            schema_version: crate::SCHEMA_VERSION_V1,
            pool_version: pool_version.into(),
            dimensions,
        };
        catalog.validate_shape()?;
        Ok(catalog)
    }

    /// Parse catalog JSON, then validate it.
    pub fn from_json_str(text: &str) -> Result<Self, ProfileError> {
        crate::json::check_size(text, crate::MAX_CATALOG_JSON_BYTES)?;
        let catalog: Self = serde_json::from_str(text).map_err(crate::spec::deser_error)?;
        catalog.validate_shape()?;
        Ok(catalog)
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, ProfileError> {
        self.validate_shape()?;
        serde_json::to_string(self).map_err(|e| ProfileError::Serialization(e.to_string()))
    }

    /// The catalog's pool version.
    pub fn pool_version(&self) -> &str {
        &self.pool_version
    }

    /// Dimension -> tier pools.
    pub fn dimensions(&self) -> &DimensionPools {
        &self.dimensions
    }

    /// Known tier ids for one dimension, if the dimension is present.
    pub fn ids(&self, dimension: &str) -> Option<&BTreeSet<u32>> {
        self.dimensions.get(dimension)
    }

    /// Check a profile against this catalog.
    ///
    /// Requires the exact pool version string, the exact dimension key set on
    /// both sides, and membership of every tier id in the matching pool. The
    /// error carries the [`Reject`] side that failed.
    pub fn validate(&self, spec: &ProfileSpec) -> Result<(), (Reject, ProfileError)> {
        self.validate_shape().map_err(|e| (Reject::Catalog, e))?;
        spec.validate().map_err(|e| (Reject::Profile, e))?;
        if spec.pool_version != self.pool_version {
            return Err((
                Reject::Mapping,
                ProfileError::PoolVersionMismatch {
                    profile: spec.pool_version.clone(),
                    catalog: self.pool_version.clone(),
                },
            ));
        }
        for (dimension, id) in &spec.slots {
            if !self.dimensions[dimension].contains(id) {
                return Err((
                    Reject::Mapping,
                    ProfileError::SlotIdNotInPool {
                        dimension: dimension.clone(),
                        id: *id,
                    },
                ));
            }
        }
        Ok(())
    }
}
