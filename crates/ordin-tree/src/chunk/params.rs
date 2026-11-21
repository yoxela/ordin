// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The chunker's settings, as a chunk index records them.

use std::fmt;

/// The masks FastCDC 2020 tests the gear hash against, by the number of
/// bits a chunk length's average has. The values for 6 to 17 bits come
/// from the C reference implementation (destor), the others from
/// restic's FastCDC, as the `fastcdc` crate has them. Index 5 and 25 are
/// used only with normalization level 3.
const MASKS: [u64; 21] = [
    0x0000_0000_0180_4110, // 5
    0x0000_0000_0180_3110, // 6: 64 bytes
    0x0000_0000_1803_5100, // 7: 128 bytes
    0x0000_0018_0003_5300, // 8: 256 bytes
    0x0000_0190_0035_3000, // 9: 512 bytes
    0x0000_5900_0353_0000, // 10: 1 KiB
    0x0000_d900_0353_0000, // 11: 2 KiB
    0x0000_d901_0353_0000, // 12: 4 KiB
    0x0000_d903_0353_0000, // 13: 8 KiB
    0x0000_d903_1353_0000, // 14: 16 KiB
    0x0000_d90f_0353_0000, // 15: 32 KiB
    0x0000_d903_0353_7000, // 16: 64 KiB
    0x0000_d907_0353_7000, // 17: 128 KiB
    0x0000_d907_0753_7000, // 18: 256 KiB
    0x0000_d917_0753_7000, // 19: 512 KiB
    0x0000_d917_4753_7000, // 20: 1 MiB
    0x0000_d917_6753_7000, // 21: 2 MiB
    0x0000_d937_6753_7000, // 22: 4 MiB
    0x0000_d937_7753_7000, // 23: 8 MiB
    0x0000_d937_7757_7000, // 24: 16 MiB
    0x0000_db37_7757_7000, // 25
];

/// The bit count of [`MASKS`]' first entry.
const FIRST_MASK_BITS: u32 = 5;

/// The smallest and largest minimum chunk length.
pub const MINIMUM_BOUNDS: (u32, u32) = (64, 1_048_576);
/// The smallest and largest average chunk length.
pub const AVERAGE_BOUNDS: (u32, u32) = (256, 4_194_304);
/// The smallest and largest maximum chunk length.
pub const MAXIMUM_BOUNDS: (u32, u32) = (1024, 16_777_216);
/// The highest normalization level.
pub const NORMALIZATION_MAX: u8 = 3;

/// Why a set of chunker settings was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParamsError {
    /// A length outside its bounds.
    #[error("the {field} chunk length is between {min} and {max} bytes; this one is {value}")]
    OutOfBounds {
        /// `minimum`, `average` or `maximum`.
        field: &'static str,
        /// The length given.
        value: u64,
        /// The smallest allowed.
        min: u32,
        /// The largest allowed.
        max: u32,
    },
    /// A length that isn't a power of two.
    #[error("the {field} chunk length is a power of two; this one is {value}")]
    NotPowerOfTwo {
        /// `minimum`, `average` or `maximum`.
        field: &'static str,
        /// The length given.
        value: u64,
    },
    /// The lengths decrease somewhere.
    #[error(
        "the minimum, average and maximum chunk lengths can't decrease: {minimum}, {average}, {maximum}"
    )]
    Unordered {
        /// The minimum given.
        minimum: u32,
        /// The average given.
        average: u32,
        /// The maximum given.
        maximum: u32,
    },
    /// A whole-file threshold outside the chunk lengths.
    #[error(
        "the whole-file threshold is between the minimum and maximum chunk lengths ({minimum} and {maximum}); this one is {value}"
    )]
    WholeBelow {
        /// The threshold given.
        value: u64,
        /// The minimum chunk length.
        minimum: u32,
        /// The maximum chunk length.
        maximum: u32,
    },
    /// An unknown normalization level.
    #[error("the normalization level is 0 to 3; this one is {0}")]
    Normalization(u64),
}

/// How a file is cut into chunks: FastCDC as published in 2020, with the
/// gear table and masks fixed in the format, and these settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChunkParams {
    minimum: u32,
    average: u32,
    maximum: u32,
    whole_below: u32,
    normalization: u8,
    /// The mask for positions before the average.
    small: u64,
    /// The mask for positions from the average on.
    large: u64,
}

/// Checks one length against its bounds and requires a power of two.
fn length(field: &'static str, value: u64, (min, max): (u32, u32)) -> Result<u32, ParamsError> {
    let refused = ParamsError::OutOfBounds {
        field,
        value,
        min,
        max,
    };
    let length = u32::try_from(value).map_err(|_| refused.clone())?;
    if length < min || length > max {
        return Err(refused);
    }
    if !length.is_power_of_two() {
        return Err(ParamsError::NotPowerOfTwo { field, value });
    }
    Ok(length)
}

/// The mask for an average of `2^bits`, if the format has one.
fn mask(bits: u32) -> Option<u64> {
    let index = bits.checked_sub(FIRST_MASK_BITS)?;
    MASKS.get(usize::try_from(index).ok()?).copied()
}

impl ChunkParams {
    /// The settings `ordin pack` writes, from ORD-100: chunks of 256 KiB to
    /// 4 MiB, 1 MiB on average, normalization level 1, and files under
    /// 1 MiB kept whole.
    pub const DEFAULT: Self = Self {
        minimum: 262_144,
        average: 1_048_576,
        maximum: 4_194_304,
        whole_below: 1_048_576,
        normalization: 1,
        small: 0x0000_d917_6753_7000,
        large: 0x0000_d917_0753_7000,
    };

    /// Checks a set of settings.
    ///
    /// # Errors
    ///
    /// Each length must be a power of two within its bounds
    /// ([`MINIMUM_BOUNDS`], [`AVERAGE_BOUNDS`], [`MAXIMUM_BOUNDS`]), the
    /// three must not decrease, the whole-file threshold must lie between
    /// the minimum and the maximum, and normalization is 0 to 3.
    pub fn new(
        minimum: u64,
        average: u64,
        maximum: u64,
        whole_below: u64,
        normalization: u64,
    ) -> Result<Self, ParamsError> {
        let minimum = length("minimum", minimum, MINIMUM_BOUNDS)?;
        let average = length("average", average, AVERAGE_BOUNDS)?;
        let maximum = length("maximum", maximum, MAXIMUM_BOUNDS)?;
        if minimum > average || average > maximum {
            return Err(ParamsError::Unordered {
                minimum,
                average,
                maximum,
            });
        }
        let threshold = u32::try_from(whole_below)
            .ok()
            .filter(|t| (minimum..=maximum).contains(t))
            .ok_or(ParamsError::WholeBelow {
                value: whole_below,
                minimum,
                maximum,
            })?;
        let level = u8::try_from(normalization)
            .ok()
            .filter(|n| *n <= NORMALIZATION_MAX)
            .ok_or(ParamsError::Normalization(normalization))?;
        let bits = average.trailing_zeros();
        let shift = u32::from(level);
        // An average of 2⁸ to 2²² bytes and a level of at most 3 always
        // has both masks.
        let (small, large) = mask(bits + shift)
            .zip(mask(bits - shift))
            .ok_or(ParamsError::Normalization(normalization))?;
        Ok(Self {
            minimum,
            average,
            maximum,
            whole_below: threshold,
            normalization: level,
            small,
            large,
        })
    }

    /// No chunk but a file's last is shorter.
    #[must_use]
    pub fn minimum(&self) -> u32 {
        self.minimum
    }

    /// The length chunks are normalized around.
    #[must_use]
    pub fn average(&self) -> u32 {
        self.average
    }

    /// No chunk is longer.
    #[must_use]
    pub fn maximum(&self) -> u32 {
        self.maximum
    }

    /// A file shorter than this is one chunk, and isn't listed in a chunk
    /// index.
    #[must_use]
    pub fn whole_below(&self) -> u32 {
        self.whole_below
    }

    /// The normalization level, 0 to 3: how much more likely a cut is
    /// after the average than before it.
    #[must_use]
    pub fn normalization(&self) -> u8 {
        self.normalization
    }

    /// The masks before and from the average.
    pub(crate) fn masks(&self) -> (u64, u64) {
        (self.small, self.large)
    }
}

impl fmt::Display for ChunkParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fastcdc-2020, {} to {} bytes, {} on average, normalization {}, whole below {}",
            self.minimum, self.maximum, self.average, self.normalization, self.whole_below
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_masks_are_fastcdcs() {
        for (bits, ours) in (FIRST_MASK_BITS..).zip(MASKS) {
            assert_eq!(ours, fastcdc::v2020::MASKS[bits as usize], "{bits} bits");
        }
        assert_eq!(MASKS.len() + 5, fastcdc::v2020::MASKS.len());
    }

    #[test]
    fn a_mask_exists_only_for_the_formats_bit_counts() {
        assert_eq!(mask(4), None);
        assert_eq!(mask(5), Some(0x0000_0000_0180_4110));
        assert_eq!(mask(25), Some(0x0000_db37_7757_7000));
        assert_eq!(mask(26), None);
    }

    #[test]
    fn the_default_is_ord_100s_and_checks() {
        let checked = ChunkParams::new(262_144, 1_048_576, 4_194_304, 1_048_576, 1).unwrap();
        assert_eq!(checked, ChunkParams::DEFAULT);
        assert_eq!(ChunkParams::DEFAULT.minimum(), 262_144);
        assert_eq!(ChunkParams::DEFAULT.average(), 1_048_576);
        assert_eq!(ChunkParams::DEFAULT.maximum(), 4_194_304);
        assert_eq!(ChunkParams::DEFAULT.whole_below(), 1_048_576);
        assert_eq!(ChunkParams::DEFAULT.normalization(), 1);
        assert_eq!(
            ChunkParams::DEFAULT.to_string(),
            "fastcdc-2020, 262144 to 4194304 bytes, 1048576 on average, normalization 1, whole below 1048576"
        );
    }

    #[test]
    fn the_masks_follow_the_average_and_level() {
        for bits in 8..=22 {
            for level in 0..=3 {
                let average = 1u64 << bits;
                let p = ChunkParams::new(64, average, 16_777_216, 1024, level).unwrap();
                let level = level as usize;
                let bits = bits as usize;
                assert_eq!(
                    p.masks(),
                    (
                        fastcdc::v2020::MASKS[bits + level],
                        fastcdc::v2020::MASKS[bits - level]
                    )
                );
            }
        }
    }

    #[test]
    fn every_length_is_bounded() {
        for (field, below, above, make) in [
            (
                "minimum",
                63,
                2_097_152,
                (|v| ChunkParams::new(v, 4_194_304, 16_777_216, 4_194_304, 1))
                    as fn(u64) -> Result<ChunkParams, ParamsError>,
            ),
            ("average", 128, 8_388_608, |v| {
                ChunkParams::new(64, v, 16_777_216, 1024, 1)
            }),
            ("maximum", 512, 33_554_432, |v| {
                ChunkParams::new(64, 256, v, 256, 1)
            }),
        ] {
            for value in [below, above, u64::MAX] {
                assert!(
                    matches!(
                        make(value),
                        Err(ParamsError::OutOfBounds { field: f, value: v, .. }) if f == field && v == value
                    ),
                    "{field} {value}"
                );
            }
        }
        // Each bound itself is allowed.
        ChunkParams::new(64, 256, 1024, 64, 0).unwrap();
        ChunkParams::new(1_048_576, 4_194_304, 16_777_216, 16_777_216, 3).unwrap();
    }

    #[test]
    fn every_length_is_a_power_of_two() {
        assert_eq!(
            ChunkParams::new(96, 256, 1024, 256, 1),
            Err(ParamsError::NotPowerOfTwo {
                field: "minimum",
                value: 96
            })
        );
        assert_eq!(
            ChunkParams::new(64, 384, 1024, 256, 1),
            Err(ParamsError::NotPowerOfTwo {
                field: "average",
                value: 384
            })
        );
        assert_eq!(
            ChunkParams::new(64, 256, 1536, 256, 1),
            Err(ParamsError::NotPowerOfTwo {
                field: "maximum",
                value: 1536
            })
        );
    }

    #[test]
    fn the_lengths_never_decrease() {
        let unordered = |minimum, average, maximum| ParamsError::Unordered {
            minimum,
            average,
            maximum,
        };
        assert_eq!(
            ChunkParams::new(512, 256, 1024, 512, 1),
            Err(unordered(512, 256, 1024))
        );
        assert_eq!(
            ChunkParams::new(64, 2048, 1024, 512, 1),
            Err(unordered(64, 2048, 1024))
        );
        // Equal lengths are allowed.
        ChunkParams::new(1024, 1024, 1024, 1024, 0).unwrap();
    }

    #[test]
    fn the_threshold_lies_between_minimum_and_maximum() {
        let refused = |value| ParamsError::WholeBelow {
            value,
            minimum: 256,
            maximum: 4096,
        };
        for value in [255, 4097, u64::MAX] {
            assert_eq!(
                ChunkParams::new(256, 1024, 4096, value, 1),
                Err(refused(value))
            );
        }
        for value in [256, 1000, 4096] {
            let p = ChunkParams::new(256, 1024, 4096, value, 1).unwrap();
            assert_eq!(u64::from(p.whole_below()), value);
        }
    }

    #[test]
    fn normalization_is_zero_to_three() {
        for level in [4, 256, u64::MAX] {
            assert_eq!(
                ChunkParams::new(64, 256, 1024, 256, level),
                Err(ParamsError::Normalization(level))
            );
        }
        for level in 0..=3 {
            let p = ChunkParams::new(64, 256, 1024, 256, level).unwrap();
            assert_eq!(u64::from(p.normalization()), level);
        }
    }

    #[test]
    fn errors_explain_themselves() {
        assert_eq!(
            ChunkParams::new(64, 384, 1024, 256, 1)
                .unwrap_err()
                .to_string(),
            "the average chunk length is a power of two; this one is 384"
        );
        assert_eq!(
            ChunkParams::new(32, 256, 1024, 256, 1)
                .unwrap_err()
                .to_string(),
            "the minimum chunk length is between 64 and 1048576 bytes; this one is 32"
        );
        assert_eq!(
            ChunkParams::new(512, 256, 1024, 512, 1)
                .unwrap_err()
                .to_string(),
            "the minimum, average and maximum chunk lengths can't decrease: 512, 256, 1024"
        );
        assert_eq!(
            ChunkParams::new(64, 256, 1024, 2048, 1)
                .unwrap_err()
                .to_string(),
            "the whole-file threshold is between the minimum and maximum chunk lengths (64 and 1024); this one is 2048"
        );
        assert_eq!(
            ChunkParams::new(64, 256, 1024, 256, 9)
                .unwrap_err()
                .to_string(),
            "the normalization level is 0 to 3; this one is 9"
        );
    }
}
