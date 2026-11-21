// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Where FastCDC 2020 cuts.
//!
//! The gear hash rolls one byte at a time: `hash = (hash << 1) + GEAR[b]`.
//! It starts at the minimum chunk length, from zero, so bytes before the
//! minimum never matter. A chunk ends before the first byte whose hash
//! has none of the mask's bits set. The mask has more bits before the
//! average and fewer from it on, so cuts cluster around the average
//! (normalized chunking). Past the maximum, the chunk ends anyway.
//!
//! The 2020 paper rolls two bytes per step with a shifted copy of the
//! table. That gives the same cuts as this loop, with one quirk kept
//! here: the search stops at the last even position, so the last byte of
//! odd-length data is never a cut.

use super::params::ChunkParams;

/// The gear table: for each byte value `b`, the first 8 bytes, read big
/// endian, of the MD5 digest of 64 bytes all equal to `b`.
#[rustfmt::skip]
pub(crate) const GEAR: [u64; 256] = [
    0x3b5d3c7d207e37dc, 0x784d68ba91123086, 0xcd52880f882e7298, 0xeacf8e4e19fdcca7,
    0xc31f385dfbd1632b, 0x1d5f27001e25abe6, 0x83130bde3c9ad991, 0xc4b225676e9b7649,
    0xaa329b29e08eb499, 0xb67fcbd21e577d58, 0x0027baaada2acf6b, 0xe3ef2d5ac73c2226,
    0x0890f24d6ed312b7, 0xa809e036851d7c7e, 0xf0a6fe5e0013d81b, 0x1d026304452cec14,
    0x03864632648e248f, 0xcdaacf3dcd92b9b4, 0xf5e012e63c187856, 0x8862f9d3821c00b6,
    0xa82f7338750f6f8a, 0x1e583dc6c1cb0b6f, 0x7a3145b69743a7f1, 0xabb20fee404807eb,
    0xb14b3cfe07b83a5d, 0xb9dc27898adb9a0f, 0x3703f5e91baa62be, 0xcf0bb866815f7d98,
    0x3d9867c41ea9dcd3, 0x1be1fa65442bf22c, 0x14300da4c55631d9, 0xe698e9cbc6545c99,
    0x4763107ec64e92a5, 0xc65821fc65696a24, 0x76196c064822f0b7, 0x485be841f3525e01,
    0xf652bc9c85974ff5, 0xcad8352face9e3e9, 0x2a6ed1dceb35e98e, 0xc6f483badc11680f,
    0x3cfd8c17e9cf12f1, 0x89b83c5e2ea56471, 0xae665cfd24e392a9, 0xec33c4e504cb8915,
    0x3fb9b15fc9fe7451, 0xd7fd1fd1945f2195, 0x31ade0853443efd8, 0x255efc9863e1e2d2,
    0x10eab6008d5642cf, 0x46f04863257ac804, 0xa52dc42a789a27d3, 0xdaaadf9ce77af565,
    0x6b479cd53d87febb, 0x6309e2d3f93db72f, 0xc5738ffbaa1ff9d6, 0x6bd57f3f25af7968,
    0x67605486d90d0a4a, 0xe14d0b9663bfbdae, 0xb7bbd8d816eb0414, 0xdef8a4f16b35a116,
    0xe7932d85aaaffed6, 0x08161cbae90cfd48, 0x855507beb294f08b, 0x91234ea6ffd399b2,
    0xad70cf4b2435f302, 0xd289a97565bc2d27, 0x8e558437ffca99de, 0x96d2704b7115c040,
    0x0889bbcdfc660e41, 0x5e0d4e67dc92128d, 0x72a9f8917063ed97, 0x438b69d409e016e3,
    0xdf4fed8a5d8a4397, 0x00f41dcf41d403f7, 0x4814eb038e52603f, 0x9dafbacc58e2d651,
    0xfe2f458e4be170af, 0x4457ec414df6a940, 0x06e62f1451123314, 0xbd1014d173ba92cc,
    0xdef318e25ed57760, 0x9fea0de9dfca8525, 0x459de1e76c20624b, 0xaeec189617e2d666,
    0x126a2c06ab5a83cb, 0xb1321532360f6132, 0x65421503dbb40123, 0x2d67c287ea089ab3,
    0x6c93bff5a56bd6b6, 0x4ffb2036cab6d98d, 0xce7b785b1be7ad4f, 0xedb42ef6189fd163,
    0xdc905288703988f6, 0x365f9c1d2c691884, 0xc640583680d99bfe, 0x3cd4624c07593ec6,
    0x7f1ea8d85d7c5805, 0x014842d480b57149, 0x0b649bcb5a828688, 0xbcd5708ed79b18f0,
    0xe987c862fbd2f2f0, 0x982731671f0cd82c, 0xbaf13e8b16d8c063, 0x8ea3109cbd951bba,
    0xd141045bfb385cad, 0x2acbc1a0af1f7d30, 0xe6444d89df03bfdf, 0xa18cc771b8188ff9,
    0x9834429db01c39bb, 0x214add07fe086a1f, 0x8f07c19b1f6b3ff9, 0x56a297b1bf4ffe55,
    0x94d558e493c54fc7, 0x40bfc24c764552cb, 0x931a706f8a8520cb, 0x32229d322935bd52,
    0x2560d0f5dc4fefaf, 0x9dbcc48355969bb6, 0x0fd81c3985c0b56a, 0xe03817e1560f2bda,
    0xc1bb4f81d892b2d5, 0xb0c4864f4e28d2d7, 0x3ecc49f9d9d6c263, 0x51307e99b52ba65e,
    0x8af2b688da84a752, 0xf5d72523b91b20b6, 0x6d95ff1ff4634806, 0x562f21555458339a,
    0xc0ce47f889336346, 0x487823e5089b40d8, 0xe4727c7ebc6d9592, 0x5a8f7277e94970ba,
    0xfca2f406b1c8bb50, 0x5b1f8a95f1791070, 0xd304af9fc9028605, 0x5440ab7fc930e748,
    0x312d25fbca2ab5a1, 0x10f4a4b234a4d575, 0x90301d55047e7473, 0x3b6372886c61591e,
    0x293402b77c444e06, 0x451f34a4d3e97dd7, 0x3158d814d81bc57b, 0x034942425b9bda69,
    0xe2032ff9e532d9bb, 0x62ae066b8b2179e5, 0x9545e10c2f8d71d8, 0x7ff7483eb2d23fc0,
    0x00945fcebdc98d86, 0x8764bbbe99b26ca2, 0x1b1ec62284c0bfc3, 0x58e0fcc4f0aa362b,
    0x5f4abefa878d458d, 0xfd74ac2f9607c519, 0xa4e3fb37df8cbfa9, 0xbf697e43cac574e5,
    0x86f14a3f68f4cd53, 0x24a23d076f1ce522, 0xe725cd8048868cc8, 0xbf3c729eb2464362,
    0xd8f6cd57b3cc1ed8, 0x6329e52425541577, 0x62aa688ad5ae1ac0, 0x0a242566269bf845,
    0x168b1a4753aca74b, 0xf789afefff2e7e3c, 0x6c3362093b6fccdb, 0x4ce8f50bd28c09b2,
    0x006a2db95ae8aa93, 0x975b0d623c3d1a8c, 0x18605d3935338c5b, 0x5bb6f6136cad3c71,
    0x0f53a20701f8d8a6, 0xab8c5ad2e7e93c67, 0x40b5ac5127acaa29, 0x8c7bf63c2075895f,
    0x78bd9f7e014a805c, 0xb2c9e9f4f9c8c032, 0xefd6049827eb91f3, 0x2be459f482c16fbd,
    0xd92ce0c5745aaa8c, 0x0aaa8fb298d965b9, 0x2b37f92c6c803b15, 0x8c54a5e94e0f0e78,
    0x95f9b6e90c0a3032, 0xe7939faa436c7874, 0xd16bfe8f6a8a40c9, 0x44982b86263fd2fa,
    0xe285fb39f984e583, 0x779a8df72d7619d3, 0xf2d79a8de8d5dd1e, 0xd1037354d66684e2,
    0x004c82a4e668a8e5, 0x31d40a7668b044e6, 0xd70578538bd02c11, 0xdb45431078c5f482,
    0x977121bb7f6a51ad, 0x73d5ccbd34eff8dd, 0xe437a07d356e17cd, 0x47b2782043c95627,
    0x9fb251413e41d49a, 0xccd70b60652513d3, 0x1c95b31e8a1b49b2, 0xcae73dfd1bcb4c1b,
    0x34d98331b1f5b70f, 0x784e39f22338d92f, 0x18613d4a064df420, 0xf1d8dae25f0bcebe,
    0x33f77c15ae855efc, 0x3c88b3b912eb109c, 0x956a2ec96bafeea5, 0x1aa005b5e0ad0e87,
    0x5500d70527c4bb8e, 0xe36c57196421cc44, 0x13c4d286cc36ee39, 0x5654a23d818b2a81,
    0x77b1dc13d161abdc, 0x734f44de5f8d5eb5, 0x60717e174a6c89a2, 0xd47d9649266a211e,
    0x5b13a4322bb69e90, 0xf7669609f8b5fc3c, 0x21e6ac55bedcdac9, 0x9b56b62b61166dea,
    0xf48f66b939797e9c, 0x35f332f9c0e6ae9a, 0xcc733f6a9a878db0, 0x3da161e41cc108c2,
    0xb7d74ae535914d51, 0x4d493b0b11d36469, 0xce264d1dfba9741a, 0xa9d1f2dc7436dc06,
    0x70738016604c2a27, 0x231d36e96e93f3d5, 0x7666881197838d19, 0x4a2a83090aaad40c,
    0xf1e761591668b35d, 0x7363236497f730a7, 0x301080e37379dd4d, 0x502dea2971827042,
    0xc2c5eb858f32625f, 0x786afb9edfafbdff, 0xdaee0d868490b2a4, 0x617366b3268609f6,
    0xae0e35a0fe46173e, 0xd1a07de93e824f11, 0x079b8b115ea4cca8, 0x93a99274558faebb,
    0xfb1e6e22e08a03b3, 0xea635fdba3698dd0, 0xcf53659328503a5c, 0xcde3b31e6fd5d780,
    0x8e3e4221d3614413, 0xef14d0d86bf1a22c, 0xe1d830d3f16c5ddb, 0xaabd2b2a451504e1,
];

/// The length of the chunk at the start of `data`, at least 1 unless
/// `data` is empty. `data` is everything that's left of the file, or at
/// least [`ChunkParams::maximum`] bytes of it.
pub(crate) fn cut(data: &[u8], params: &ChunkParams) -> usize {
    let minimum = usize::try_from(params.minimum()).unwrap_or(usize::MAX);
    if data.len() <= minimum {
        return data.len();
    }
    let maximum = usize::try_from(params.maximum()).unwrap_or(usize::MAX);
    let average = usize::try_from(params.average()).unwrap_or(usize::MAX);
    let remaining = data.len().min(maximum);
    // The paper's two-byte steps end at even positions.
    let small_until = remaining.min(average) & !1;
    let search_until = remaining & !1;
    let (small, large) = params.masks();
    let mut hash: u64 = 0;
    for (position, &byte) in data.iter().enumerate().take(search_until).skip(minimum) {
        hash = (hash << 1).wrapping_add(GEAR[usize::from(byte)]);
        let mask = if position < small_until { small } else { large };
        if hash & mask == 0 {
            return position;
        }
    }
    remaining
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(minimum: u64, average: u64, maximum: u64, level: u64) -> ChunkParams {
        ChunkParams::new(minimum, average, maximum, minimum, level).unwrap()
    }

    /// Bytes from a fixed xorshift sequence.
    fn noise(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[0]
            })
            .collect()
    }

    /// fastcdc 3.2.1's first cut in `data`.
    fn theirs(data: &[u8], p: &ChunkParams) -> usize {
        let level = match p.normalization() {
            0 => fastcdc::v2020::Normalization::Level0,
            1 => fastcdc::v2020::Normalization::Level1,
            2 => fastcdc::v2020::Normalization::Level2,
            _ => fastcdc::v2020::Normalization::Level3,
        };
        fastcdc::v2020::FastCDC::with_level(data, p.minimum(), p.average(), p.maximum(), level)
            .next()
            .map_or(0, |c| c.length)
    }

    #[test]
    fn the_gear_table_is_fastcdcs() {
        let (gear, _) = fastcdc::v2020::get_gear_with_seed(0);
        assert_eq!(GEAR, *gear);
    }

    #[test]
    fn the_gear_table_is_md5_of_each_byte() {
        // Two entries from `md5sum`, as a check that doesn't depend on
        // another implementation: `head -c 64 /dev/zero | md5sum`, and the
        // same with every byte 0xff.
        assert_eq!(GEAR[0], 0x3b5d_3c7d_207e_37dc);
        assert_eq!(GEAR[255], 0xaabd_2b2a_4515_04e1);
    }

    #[test]
    fn short_data_is_one_chunk() {
        let p = params(64, 256, 1024, 1);
        assert_eq!(cut(&[], &p), 0);
        assert_eq!(cut(&[7], &p), 1);
        assert_eq!(cut(&noise(1, 64), &p), 64);
        assert_ne!(cut(&noise(1, 4000), &p), 4000);
    }

    #[test]
    fn no_chunk_is_longer_than_the_maximum() {
        // Zeros match none of these masks, so every chunk is as long as it
        // can be.
        let p = params(64, 256, 1024, 1);
        for (len, expected) in [(5000, 1024), (1001, 1001), (1024, 1024)] {
            let zeros = vec![0; len];
            assert_eq!(theirs(&zeros, &p), expected);
            assert_eq!(cut(&zeros, &p), expected);
        }
    }

    #[test]
    fn cuts_match_fastcdc_everywhere() {
        // Small chunks, so thousands of cuts are compared, including cuts
        // on both sides of the average, at the last position searched, and
        // at odd lengths.
        let mut compared = 0;
        for level in 0..=3 {
            for (minimum, average, maximum) in
                [(64, 256, 1024), (256, 256, 1024), (256, 1024, 1024)]
            {
                let p = params(minimum, average, maximum, level);
                for seed in 0..1500 {
                    let len = 40 + (seed as usize * 7) % 1200;
                    let data = noise(seed + 1, len);
                    assert_eq!(cut(&data, &p), theirs(&data, &p), "{p}, seed {seed}");
                    compared += 1;
                }
            }
        }
        assert_eq!(compared, 18_000);
    }

    #[test]
    fn a_cut_can_fall_on_the_average() {
        // Position 256 is the first that uses the large mask. Find inputs
        // whose cut is there, so the switch between masks is tested at its
        // exact position.
        let p = params(64, 256, 1024, 1);
        let at_average = (1..20_000)
            .map(|seed| noise(seed, 900))
            .filter(|data| theirs(data, &p) == 256)
            .inspect(|data| assert_eq!(cut(data, &p), 256))
            .count();
        assert!(at_average > 0);
    }

    #[test]
    fn the_last_byte_of_odd_data_is_never_a_cut() {
        // With 67 bytes and a minimum of 64, positions 64 and 65 are
        // searched and 66 isn't. Find inputs whose hash would match at 66
        // and nowhere earlier: they are one chunk, as in fastcdc.
        let p = params(64, 256, 1024, 0);
        let (_, large) = p.masks();
        let would_cut_last = (1..50_000)
            .map(|seed| noise(seed, 67))
            .filter(|data| {
                let hash = data[64..]
                    .iter()
                    .fold(0u64, |h, &b| (h << 1).wrapping_add(GEAR[usize::from(b)]));
                hash & large == 0 && theirs(data, &p) == 67
            })
            .inspect(|data| assert_eq!(cut(data, &p), 67))
            .count();
        assert!(would_cut_last > 0);
    }
}
