// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Property tests: the ordering is a total order, versions survive being
//! shown and read back, and without `^` the text comparison is dpkg's.

use std::cmp::Ordering;

use ordin_version::{Version, compare_text};
use proptest::prelude::*;

/// Version text from a small alphabet, so equal and nearly equal versions
/// come up often. Only text that parses is kept.
fn version() -> impl Strategy<Value = Version> {
    "([0-9]:)?[0-9][0-2a~^.+]{0,6}(-[0-2a~^.+]{1,4})?(\\+u[0-3])?"
        .prop_filter_map("must parse", |text| text.parse().ok())
}

/// Text of the characters that matter to the ordering, valid or not.
fn text() -> impl Strategy<Value = String> {
    "[0-9a-zA-Z~.+-]{0,8}"
}

/// A literal port of dpkg's `verrevcmp` (lib/dpkg/version.c), which has no
/// `^`. It is the reference `compare_text` must match on such text.
fn dpkg_verrevcmp(a: &str, b: &str) -> Ordering {
    fn order(c: Option<u8>) -> i32 {
        match c {
            None => 0,
            Some(c) if c.is_ascii_digit() => 0,
            Some(c) if c.is_ascii_alphabetic() => i32::from(c),
            Some(b'~') => -1,
            Some(c) => i32::from(c) + 256,
        }
    }
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    let at = |s: &[u8], k: usize| s.get(k).copied();
    while at(a, i).is_some() || at(b, j).is_some() {
        let mut first_diff = 0;
        while at(a, i).is_some_and(|c| !c.is_ascii_digit())
            || at(b, j).is_some_and(|c| !c.is_ascii_digit())
        {
            let (ac, bc) = (order(at(a, i)), order(at(b, j)));
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }
        while at(a, i) == Some(b'0') {
            i += 1;
        }
        while at(b, j) == Some(b'0') {
            j += 1;
        }
        while at(a, i).is_some_and(|c| c.is_ascii_digit())
            && at(b, j).is_some_and(|c| c.is_ascii_digit())
        {
            if first_diff == 0 {
                first_diff = i32::from(a[i]) - i32::from(b[j]);
            }
            i += 1;
            j += 1;
        }
        if at(a, i).is_some_and(|c| c.is_ascii_digit()) {
            return Ordering::Greater;
        }
        if at(b, j).is_some_and(|c| c.is_ascii_digit()) {
            return Ordering::Less;
        }
        if first_diff != 0 {
            return first_diff.cmp(&0);
        }
    }
    Ordering::Equal
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn without_a_caret_the_comparison_is_dpkgs(a in text(), b in text()) {
        prop_assert_eq!(compare_text(&a, &b), dpkg_verrevcmp(&a, &b), "{:?} vs {:?}", a, b);
    }

    #[test]
    fn the_ordering_is_reflexive_and_antisymmetric(a in version(), b in version()) {
        prop_assert_eq!(a.cmp(&a), Ordering::Equal);
        prop_assert_eq!(a.cmp(&b), b.cmp(&a).reverse());
        prop_assert_eq!(a == b, a.cmp(&b) == Ordering::Equal);
    }

    #[test]
    fn the_ordering_is_transitive(a in version(), b in version(), c in version()) {
        let mut v = [a, b, c];
        v.sort();
        prop_assert!(v[0] <= v[1] && v[1] <= v[2] && v[0] <= v[2]);
        if v[0] == v[1] && v[1] == v[2] {
            prop_assert!(v[0] == v[2]);
        }
    }

    #[test]
    fn text_comparison_is_a_total_order(a in "[0-2a~^.+]{0,5}", b in "[0-2a~^.+]{0,5}", c in "[0-2a~^.+]{0,5}") {
        prop_assert_eq!(compare_text(&a, &b), compare_text(&b, &a).reverse());
        if compare_text(&a, &b) != Ordering::Greater && compare_text(&b, &c) != Ordering::Greater {
            prop_assert_ne!(compare_text(&a, &c), Ordering::Greater, "{:?} <= {:?} <= {:?}", a, b, c);
        }
    }

    #[test]
    fn a_version_survives_being_shown_and_read_back(v in version()) {
        let shown = v.to_string();
        let again: Version = shown.parse().map_err(|e| TestCaseError::fail(format!("{shown}: {e}")))?;
        prop_assert_eq!(&again, &v);
        prop_assert_eq!(again.to_string(), shown);
        prop_assert_eq!((again.epoch(), again.upstream(), again.release(), again.update()),
                        (v.epoch(), v.upstream(), v.release(), v.update()));
    }

    #[test]
    fn any_text_parses_or_fails_without_panicking(s in "\\PC{0,40}") {
        if let Ok(v) = s.parse::<Version>() {
            prop_assert!(v.to_string().parse::<Version>().is_ok());
        }
    }

    #[test]
    fn the_compatible_bound_is_above_the_base(v in version()) {
        let bound = v.compatible_bound();
        prop_assert!(bound > v, "{} < {}", v, bound);
        prop_assert!(v.is_compatible_with(&v));
        prop_assert!(!bound.is_compatible_with(&v));
    }
}
