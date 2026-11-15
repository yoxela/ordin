// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Serde support for types whose form is a string: they serialize as the
//! text they show and deserialize by parsing it, so nothing invalid gets in
//! through serde.

/// Implements `Serialize` (as `Display`) and `Deserialize` (with `FromStr`)
/// for a type.
macro_rules! impl_serde {
    ($name:ty) => {
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let text = <std::borrow::Cow<'de, str> as serde::Deserialize>::deserialize(d)?;
                text.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

pub(crate) use impl_serde;
