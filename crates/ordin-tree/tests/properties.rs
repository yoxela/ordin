// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Property tests: a valid tree round-trips byte for byte whatever order
//! its entries come in, removing fields is refused or round-trips
//! exactly, and damaged bytes never make the reader panic.

#[cfg(test)]
mod properties {
    use std::collections::BTreeMap;

    use ordin_core::json::{self, Value};
    use ordin_core::{Account, Algorithm, Digest, Mode};
    use ordin_tree::{Capabilities, Dir, Entry, File, Kind, Symlink, Tree, Xattrs};
    use proptest::prelude::*;

    const EVERYTHING: &[u8] = include_bytes!("data/everything.json");

    const NAMES: [&str; 6] = ["a", "b", "a b", "\u{e9}", "~x", "a.b"];

    /// One generated path: indices into `NAMES`, a kind and some numbers.
    type Spec = (Vec<usize>, u8, u64, bool);

    fn spec() -> impl Strategy<Value = Spec> {
        (
            prop::collection::vec(0..NAMES.len(), 1..4),
            0u8..4,
            0u64..1_000_000,
            any::<bool>(),
        )
    }

    fn file(path: &str, size: u64, odd: bool) -> Kind {
        let mut xattrs = Xattrs::new();
        let mut capabilities = None;
        if odd {
            xattrs.insert("user.k".parse().unwrap(), path.as_bytes().to_vec());
            capabilities = Some(Capabilities {
                permitted: ["cap_net_raw".parse().unwrap()].into(),
                inheritable: [].into(),
                effective: size.is_multiple_of(2),
            });
        }
        Kind::File(File {
            mode: if odd {
                Mode::new(0o4755).unwrap()
            } else {
                Mode::FILE
            },
            owner: if odd {
                "_apt".parse().unwrap()
            } else {
                Account::root()
            },
            group: Account::root(),
            size,
            content: Digest::blake3(path.as_bytes()),
            fsverity: Digest::new(Algorithm::Sha256, [u8::try_from(size % 256).unwrap(); 32]),
            xattrs,
            capabilities,
        })
    }

    fn dir(odd: bool) -> Kind {
        Kind::Dir(Dir {
            mode: if odd {
                Mode::new(0o2775).unwrap()
            } else {
                Mode::DIR
            },
            owner: Account::root(),
            group: if odd {
                "adm".parse().unwrap()
            } else {
                Account::root()
            },
            xattrs: Xattrs::new(),
        })
    }

    /// A valid tree from the specs: every parent becomes a directory, and
    /// hard links point at a file.
    fn build(specs: &[Spec]) -> Vec<Entry> {
        let mut kinds: BTreeMap<String, Kind> = BTreeMap::new();
        let mut parents = Vec::new();
        for (names, kind, size, odd) in specs {
            let parts: Vec<&str> = names.iter().map(|&i| NAMES[i]).collect();
            for depth in 1..parts.len() {
                parents.push(format!("/{}", parts[..depth].join("/")));
            }
            let path = format!("/{}", parts.join("/"));
            let k = match kind {
                0 => file(&path, *size, *odd),
                1 => dir(*odd),
                2 => Kind::Symlink(Symlink {
                    target: if *odd { "../x" } else { "/usr/bin/x" }.parse().unwrap(),
                    owner: Account::root(),
                    group: Account::root(),
                }),
                // Pointed at a file below.
                _ => Kind::HardLink("/z".parse().unwrap()),
            };
            kinds.insert(path, k);
        }
        for p in parents {
            kinds.insert(p, dir(false));
        }
        // Hard links point at the first file, or become one.
        let first_file = kinds
            .iter()
            .find(|(_, k)| matches!(k, Kind::File(_)))
            .map(|(p, _)| p.clone());
        for (path, k) in &mut kinds {
            if matches!(k, Kind::HardLink(_)) {
                *k = match &first_file {
                    Some(target) => Kind::HardLink(target.parse().unwrap()),
                    None => file(path, 1, false),
                };
            }
        }
        kinds
            .into_iter()
            .map(|(path, kind)| Entry {
                path: path.parse().unwrap(),
                kind,
            })
            .collect()
    }

    #[test]
    fn the_generator_makes_every_entry_type_and_odd_field() {
        let specs: Vec<Spec> = vec![
            (vec![0, 1], 0, 7, true),
            (vec![2], 1, 0, true),
            (vec![3], 2, 0, false),
            (vec![4], 3, 0, false),
            (vec![5], 2, 0, true),
        ];
        let tree = Tree::new(build(&specs)).unwrap();
        let text = String::from_utf8(tree.to_canonical_bytes().unwrap()).unwrap();
        for needle in [
            "\"type\":\"file\"",
            "\"type\":\"dir\"",
            "\"type\":\"symlink\"",
            "\"type\":\"hardlink\"",
            "\"capabilities\":",
            "\"xattrs\":",
            "\"owner\":",
            "\"group\":",
            "\"mode\":",
            "\"target\":\"../x\"",
            "a b",
            "\u{e9}",
            "~x",
        ] {
            assert!(text.contains(needle), "{needle} missing from {text}");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn valid_trees_round_trip_in_any_order(specs in prop::collection::vec(spec(), 0..40), seed in any::<u64>()) {
            let entries = build(&specs);
            let tree = Tree::new(entries.clone()).map_err(|e| TestCaseError::fail(e.to_string()))?;
            let bytes = tree.to_canonical_bytes().map_err(|e| TestCaseError::fail(e.to_string()))?;
            let (read, id) = Tree::from_canonical_bytes(&bytes).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(&read, &tree);
            prop_assert_eq!(id, Digest::blake3(&bytes));
            // The same entries in another order give the same bytes.
            let mut shuffled = entries;
            let len = shuffled.len().max(1);
            shuffled.rotate_left(usize::try_from(seed).unwrap_or(0) % len);
            if seed % 2 == 1 {
                shuffled.reverse();
            }
            let again = Tree::new(shuffled).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(again.to_canonical_bytes().ok(), Some(bytes));
        }

        #[test]
        fn removing_fields_is_refused_or_round_trips(drops in prop::collection::vec((0usize..14, 0usize..10), 1..6)) {
            let Value::Object(mut top) = json::parse(std::str::from_utf8(EVERYTHING).unwrap()).unwrap() else {
                return Err(TestCaseError::fail("not an object"));
            };
            if let Some(Value::Array(entries)) = top.get_mut("entries") {
                for (entry, field) in drops {
                    if let Some(Value::Object(map)) = entries.get_mut(entry) {
                        let key = map.keys().nth(field % map.len().max(1)).cloned();
                        if let Some(key) = key {
                            map.remove(&key);
                        }
                    }
                }
            }
            let text = json::canonical(&Value::Object(top));
            if let Ok((tree, _)) = Tree::from_canonical_bytes(text.as_bytes()) {
                prop_assert_eq!(tree.to_canonical_bytes().ok(), Some(text.into_bytes()));
            }
        }

        #[test]
        fn damaged_bytes_never_panic(changes in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..6)) {
            let mut bytes = EVERYTHING.to_vec();
            for (at, b) in changes {
                let i = at.index(bytes.len());
                bytes[i] = b;
            }
            if let Ok((tree, id)) = Tree::from_canonical_bytes(&bytes) {
                prop_assert_eq!(tree.to_canonical_bytes().ok(), Some(bytes.clone()));
                prop_assert_eq!(id, Digest::blake3(&bytes));
            }
        }
    }
}
