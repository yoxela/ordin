// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Ordin orders every package version in Debian trixie exactly as dpkg
//! does.
//!
//! `data/trixie-versions.txt` holds the versions in dpkg's order, one line
//! per group of versions dpkg calls equal. `cargo xtask version-corpus`
//! made it, and CI checks it against the real dpkg with `--check`, so this
//! test compares Ordin with dpkg, not with itself.

use std::cmp::Ordering;

use ordin_version::Version;

const CORPUS: &str = include_str!("data/trixie-versions.txt");

/// The corpus as groups of equal versions, each with its text.
fn groups() -> Result<Vec<Vec<(String, Version)>>, String> {
    CORPUS
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|line| {
            line.split_whitespace()
                .map(|text| {
                    text.parse()
                        .map(|v| (text.to_owned(), v))
                        .map_err(|e| format!("{text}: {e}"))
                })
                .collect()
        })
        .collect()
}

#[test]
fn the_corpus_is_all_of_trixie() {
    let groups = groups().unwrap();
    let versions: usize = groups.iter().map(Vec::len).sum();
    assert_eq!(versions, 23_260, "the corpus was cut short or regenerated");
    // Equal versions written differently, the case equality must get right.
    assert!(groups.iter().filter(|g| g.len() > 1).count() > 400);
}

#[test]
fn ordin_agrees_with_dpkg_on_every_adjacent_and_equal_pair() {
    let groups = groups().unwrap();
    for group in &groups {
        let (first, v) = &group[0];
        for (other, w) in &group[1..] {
            assert_eq!(v.cmp(w), Ordering::Equal, "dpkg: {first} = {other}");
            assert_eq!(v, w, "dpkg: {first} = {other}");
        }
    }
    for pair in groups.windows(2) {
        let (a, v) = &pair[0][0];
        let (b, w) = &pair[1][0];
        assert_eq!(v.cmp(w), Ordering::Less, "dpkg: {a} < {b}");
        assert_eq!(w.cmp(v), Ordering::Greater, "dpkg: {b} > {a}");
    }
}

#[test]
fn sorting_the_shuffled_corpus_gives_dpkgs_order() {
    let groups = groups().unwrap();
    let expected: Vec<String> = groups.iter().map(|g| g[0].0.clone()).collect();
    // A fixed shuffle: interleave the second half with the reversed first
    // half.
    let mut all: Vec<(String, Version)> = groups.into_iter().map(|g| g[0].clone()).collect();
    let back = all.split_off(all.len() / 2);
    all.reverse();
    let mut shuffled = Vec::with_capacity(all.len() + back.len());
    let mut back = back.into_iter();
    for item in all {
        shuffled.push(item);
        if let Some(b) = back.next() {
            shuffled.push(b);
        }
    }
    shuffled.extend(back);
    shuffled.sort_by(|a, b| a.1.cmp(&b.1));
    let sorted: Vec<String> = shuffled.into_iter().map(|(text, _)| text).collect();
    assert_eq!(sorted, expected);
}

#[test]
fn every_version_survives_being_shown_and_read_back() {
    for group in groups().unwrap() {
        for (text, v) in group {
            let again: Version = v.to_string().parse().unwrap();
            assert_eq!(again, v, "{text}");
            if !text.starts_with("0:") {
                assert_eq!(v.to_string(), text, "Debian versions show as written");
            }
        }
    }
}
