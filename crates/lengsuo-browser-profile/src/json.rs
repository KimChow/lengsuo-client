//! Resource bounds for JSON envelopes, independently of the native wire size.
use crate::ProfileError;
use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer,
};
use std::{collections::BTreeMap, fmt, marker::PhantomData};

/// Profile JSON envelope limit, including whitespace and escaped characters.
/// This exceeds every compact schema-1 profile and the 4096-byte native frame.
pub const MAX_PROFILE_JSON_BYTES: usize = 64 * 1024;
/// Catalog envelope limit. A compact catalog containing every permitted tier
/// id in all seven dimensions fits (less than 51 MiB). Excessive whitespace or
/// escaping can still exceed this explicit operational input limit.
pub const MAX_CATALOG_JSON_BYTES: usize = 64 * 1024 * 1024;

pub(crate) fn check_size(text: &str, limit: usize) -> Result<(), ProfileError> {
    if text.len() > limit {
        return Err(ProfileError::JsonTooLarge {
            bytes: text.len(),
            limit,
        });
    }
    Ok(())
}

/// Deserialize maps directly from tokens; converting through Value would lose
/// duplicate keys before validation. Use for both profile and catalog maps.
pub(crate) fn unique_map<'de, D, V>(deserializer: D) -> Result<BTreeMap<String, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    struct Unique<V>(PhantomData<V>);
    impl<'de, V: Deserialize<'de>> Visitor<'de> for Unique<V> {
        type Value = BTreeMap<String, V>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an object with unique dimension names")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut input: M) -> Result<Self::Value, M::Error> {
            let mut values = BTreeMap::new();
            while let Some(key) = input.next_key::<String>()? {
                if values.contains_key(&key) {
                    return Err(de::Error::custom("duplicate dimension name"));
                }
                values.insert(key, input.next_value()?);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_map(Unique(PhantomData))
}
