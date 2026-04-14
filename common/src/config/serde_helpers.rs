//! Serde helpers shared by YAOTL profile modules.

use serde::{Deserialize, Deserializer};

/// Deserialise an optional `String` into an optional [`zeroize::Zeroizing`] wrapper.
pub(crate) fn deserialize_optional_zeroizing_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<zeroize::Zeroizing<String>>, D::Error> {
    use zeroize::Zeroizing;
    let opt = Option::<String>::deserialize(deserializer)?;
    Ok(opt.map(Zeroizing::new))
}

pub(crate) fn deserialize_zeroizing_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<zeroize::Zeroizing<String>, D::Error> {
    use zeroize::Zeroizing;
    let s = String::deserialize(deserializer)?;
    Ok(Zeroizing::new(s))
}

pub(crate) fn default_true() -> bool {
    true
}

pub(crate) const fn default_api_rate_limit_per_minute() -> u32 {
    60
}

pub(crate) fn default_max_retries() -> u32 {
    3
}

pub(crate) fn default_retry_base_delay_secs() -> u64 {
    1
}

pub(crate) fn deserialize_one_or_many<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany<T> {
        One(T),
        Many(Vec<T>),
    }

    let Some(value) = Option::<OneOrMany<T>>::deserialize(deserializer)? else {
        return Ok(Vec::new());
    };

    Ok(match value {
        OneOrMany::One(value) => vec![value],
        OneOrMany::Many(values) => values,
    })
}
