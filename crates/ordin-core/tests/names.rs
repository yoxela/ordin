// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Property tests and serde round trips for names, atoms and architectures.

use ordin_core::{Arch, Atom, Capability, FilePath, PackageName, Soname};
use proptest::prelude::*;

/// Text that is mostly valid atom material, with some characters that
/// aren't, so both outcomes come up.
fn atomish() -> impl Strategy<Value = String> {
    "(cap:|so:|file:/|x:)?[a-z0-9+.\\-_/A-Z :()]{0,12}"
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn an_atom_either_fails_or_survives_being_shown_and_read_back(text in atomish()) {
        if let Ok(atom) = text.parse::<Atom>() {
            let shown = atom.to_string();
            prop_assert_eq!(&shown, &text, "atoms show exactly as parsed");
            prop_assert_eq!(shown.parse::<Atom>().ok(), Some(atom));
        }
    }

    #[test]
    fn any_text_is_refused_or_accepted_without_panicking(text in "\\PC{0,40}") {
        let _ = text.parse::<Atom>();
        let _ = text.parse::<Arch>();
        let _ = text.parse::<FilePath>();
        let _ = text.parse::<Soname>();
    }

    #[test]
    fn every_name_of_the_grammar_parses(
        name in "[a-z0-9][a-z0-9+.\\-]{1,127}"
    ) {
        prop_assume!(!ordin_core::KEYWORDS.contains(&name.as_str()));
        let parsed: PackageName = name.parse().map_err(|e| TestCaseError::fail(format!("{name}: {e}")))?;
        prop_assert_eq!(parsed.as_str(), name.as_str());
        prop_assert!(name.parse::<Capability>().is_ok());
    }

    #[test]
    fn normalized_absolute_paths_parse(parts in prop::collection::vec("[a-z0-9_.\\-]{1,8}", 1..6)) {
        prop_assume!(parts.iter().all(|p| p != "." && p != ".."));
        let path = format!("/{}", parts.join("/"));
        prop_assert!(path.parse::<FilePath>().is_ok(), "{}", path);
        let trailing = format!("{path}/");
        let dot = format!("{path}/.");
        let double = path.replacen('/', "//", 1);
        prop_assert!(trailing.parse::<FilePath>().is_err());
        prop_assert!(dot.parse::<FilePath>().is_err());
        prop_assert!(double.parse::<FilePath>().is_err());
    }
}

#[test]
fn serde_reads_and_writes_the_string_form() {
    let atoms: Vec<Atom> = ["nginx", "cap:mta", "so:libc.so.6", "file:/usr/bin/sh"]
        .iter()
        .map(|t| t.parse().unwrap())
        .collect();
    let json = serde_json::to_string(&atoms).unwrap();
    assert_eq!(
        json,
        r#"["nginx","cap:mta","so:libc.so.6","file:/usr/bin/sh"]"#
    );
    let back: Vec<Atom> = serde_json::from_str(&json).unwrap();
    assert_eq!(back, atoms);

    let name: PackageName = serde_json::from_str(r#""libstdc++6""#).unwrap();
    assert_eq!(serde_json::to_string(&name).unwrap(), r#""libstdc++6""#);
    let arch: Arch = serde_json::from_str(r#""aarch64""#).unwrap();
    assert_eq!(arch, Arch::Aarch64);
    assert_eq!(serde_json::to_string(&Arch::Noarch).unwrap(), r#""noarch""#);

    // Escaped JSON strings are decoded first, then checked.
    let escaped: Capability = serde_json::from_str(r#""http""#).unwrap();
    assert_eq!(escaped.as_str(), "http");
    let soname: Soname = serde_json::from_str(r#""libz.so.1""#).unwrap();
    assert_eq!(soname.as_str(), "libz.so.1");
    let path: FilePath = serde_json::from_str(r#""/etc/shells""#).unwrap();
    assert_eq!(path.as_str(), "/etc/shells");
}

#[test]
fn serde_refuses_what_parsing_refuses() {
    let err = |json: &str| serde_json::from_str::<Atom>(json).unwrap_err().to_string();
    assert!(err(r#""and""#).contains("keyword"));
    assert!(err(r#""Nginx""#).contains("lowercase"));
    assert!(err(r#""pkg:x""#).contains("isn't an atom"));
    assert!(err("42").contains("expected a string") || err("42").contains("invalid type"));
    assert!(
        serde_json::from_str::<Arch>(r#""amd64""#)
            .unwrap_err()
            .to_string()
            .contains("unknown architecture")
    );
    assert!(serde_json::from_str::<PackageName>(r#""a""#).is_err());
    assert!(serde_json::from_str::<FilePath>(r#""/a/../b""#).is_err());
    assert!(serde_json::from_str::<Soname>(r#""a/b""#).is_err());
    assert!(serde_json::from_str::<Capability>(r#""""#).is_err());
}
