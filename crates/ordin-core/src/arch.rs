// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Architectures.

use core::fmt;
use core::str::FromStr;

use crate::error::Error;

/// The architecture a package is built for.
///
/// The list is closed: a package for an architecture Ordin doesn't know
/// can't be installed anyway, so it is refused when parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Arch {
    /// 64-bit x86 (`x86_64`).
    X86_64,
    /// 64-bit Arm (`aarch64`).
    Aarch64,
    /// Not tied to an architecture: data, documentation, scripts
    /// (`noarch`).
    Noarch,
}

impl Arch {
    /// Every architecture, in order.
    pub const ALL: [Self; 3] = [Self::X86_64, Self::Aarch64, Self::Noarch];

    /// The architecture's name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
            Self::Noarch => "noarch",
        }
    }
}

impl FromStr for Arch {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|a| a.as_str() == text)
            .ok_or_else(|| Error::UnknownArch(text.chars().take(64).collect()))
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

crate::serde_str::impl_serde!(Arch);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_architectures_round_trip() {
        for arch in Arch::ALL {
            assert_eq!(arch.as_str().parse::<Arch>(), Ok(arch));
            assert_eq!(arch.to_string(), arch.as_str());
        }
        assert_eq!(Arch::X86_64.as_str(), "x86_64");
        assert_eq!(Arch::Aarch64.as_str(), "aarch64");
        assert_eq!(Arch::Noarch.as_str(), "noarch");
    }

    #[test]
    fn other_names_are_refused() {
        for text in ["", "amd64", "arm64", "X86_64", "all", "x86_64 ", "i386"] {
            assert_eq!(
                text.parse::<Arch>(),
                Err(Error::UnknownArch(text.into())),
                "{text:?}"
            );
        }
        // The error doesn't echo unbounded input.
        let long = "x".repeat(1000);
        assert_eq!(
            long.parse::<Arch>(),
            Err(Error::UnknownArch("x".repeat(64)))
        );
    }
}
