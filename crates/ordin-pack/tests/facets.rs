// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Facet classification (ORD-114), on trees built in memory.

#[cfg(test)]
mod facets {
    use std::collections::BTreeSet;

    use ordin_core::{Account, Algorithm, Digest, Facet};
    use ordin_pack::{
        FacetError, FacetErrorKind, FacetNote, FacetOverride, Facets, Placement, Reason, classify,
    };
    use ordin_tree::{Dir, Entry, FILE_MODE, File, Kind, Symlink, Tree, TreePath, Xattrs};
    use proptest::prelude::*;

    fn p(path: &str) -> TreePath {
        path.parse().unwrap()
    }

    fn f(name: &str) -> Facet {
        name.parse().unwrap()
    }

    fn dir_as(path: &str, mode: &str) -> Entry {
        Entry {
            path: p(path),
            kind: Kind::Dir(Dir {
                mode: mode.parse().unwrap(),
                owner: Account::root(),
                group: Account::root(),
                xattrs: Xattrs::new(),
            }),
        }
    }

    fn dir(path: &str) -> Entry {
        dir_as(path, "0755")
    }

    fn file(path: &str, size: u64) -> Entry {
        Entry {
            path: p(path),
            kind: Kind::File(File {
                mode: FILE_MODE,
                owner: Account::root(),
                group: Account::root(),
                size,
                content: Digest::blake3(path.as_bytes()),
                fsverity: Digest::new(Algorithm::Sha256, [7; 32]),
                xattrs: Xattrs::new(),
                capabilities: None,
            }),
        }
    }

    fn symlink(path: &str, target: &str) -> Entry {
        Entry {
            path: p(path),
            kind: Kind::Symlink(Symlink {
                target: target.parse().unwrap(),
                owner: Account::root(),
                group: Account::root(),
            }),
        }
    }

    fn hardlink(path: &str, target: &str) -> Entry {
        Entry {
            path: p(path),
            kind: Kind::HardLink(p(target)),
        }
    }

    /// A tree of these entries, with every missing parent added.
    fn tree(entries: Vec<Entry>) -> Tree {
        let given: BTreeSet<String> = entries.iter().map(|e| e.path.to_string()).collect();
        let mut parents = BTreeSet::new();
        for e in &entries {
            let mut at = e.path.as_str();
            while let Some((up, _)) = at.rsplit_once('/').filter(|(up, _)| !up.is_empty()) {
                parents.insert(up.to_owned());
                at = up;
            }
        }
        let mut all = entries;
        all.extend(parents.difference(&given).map(|path| dir(path)));
        Tree::new(all).unwrap()
    }

    fn split(entries: Vec<Entry>) -> Facets {
        classify(&tree(entries), &[]).unwrap()
    }

    fn overridden(entries: Vec<Entry>, overrides: &[(&str, &str)]) -> Result<Facets, FacetError> {
        let overrides: Vec<FacetOverride> = overrides
            .iter()
            .map(|(path, facet)| FacetOverride {
                path: p(path),
                facet: f(facet),
            })
            .collect();
        classify(&tree(entries), &overrides)
    }

    /// Each placement as (path, facet).
    fn placed(facets: &Facets) -> Vec<(&str, &str)> {
        facets
            .placements
            .iter()
            .map(|pl| (pl.path.as_str(), pl.facet.as_str()))
            .collect()
    }

    fn paths_in<'a>(facets: &'a Facets, facet: &str) -> Vec<&'a str> {
        facets.facets[&f(facet)]
            .tree
            .entries()
            .iter()
            .map(|e| e.path.as_str())
            .collect()
    }

    #[test]
    fn each_rule_has_its_facet() {
        let facets = split(vec![
            file("/usr/bin/nginx", 100),
            file("/usr/lib/debug/.build-id/ab/cd.debug", 50),
            file("/usr/share/doc/nginx/README", 10),
            file("/usr/share/man/man8/nginx.8.gz", 5),
            file("/usr/share/info/nginx.info", 6),
            file("/usr/share/locale/de/LC_MESSAGES/nginx.mo", 7),
            file("/usr/share/locale/pt_BR/LC_MESSAGES/nginx.mo", 8),
            file("/usr/include/nginx.h", 3),
            file("/usr/lib/libngx.a", 4),
            file("/usr/lib/x86_64-linux-gnu/pkgconfig/ngx.pc", 2),
            file("/usr/share/pkgconfig/ngx2.pc", 2),
        ]);
        assert_eq!(
            placed(&facets),
            [
                ("/usr/bin/nginx", "runtime"),
                ("/usr/include/nginx.h", "dev"),
                ("/usr/lib/debug/.build-id/ab/cd.debug", "debug"),
                ("/usr/lib/libngx.a", "dev"),
                ("/usr/lib/x86_64-linux-gnu/pkgconfig/ngx.pc", "dev"),
                ("/usr/share/doc/nginx/README", "doc"),
                ("/usr/share/info/nginx.info", "doc"),
                ("/usr/share/locale/de/LC_MESSAGES/nginx.mo", "locale:de"),
                (
                    "/usr/share/locale/pt_BR/LC_MESSAGES/nginx.mo",
                    "locale:pt_BR"
                ),
                ("/usr/share/man/man8/nginx.8.gz", "doc"),
                ("/usr/share/pkgconfig/ngx2.pc", "dev"),
            ]
        );
        let reasons: Vec<String> = facets
            .placements
            .iter()
            .map(|pl| pl.reason.to_string())
            .collect();
        assert_eq!(
            reasons,
            [
                "everything else",
                "under /usr/include",
                "under /usr/lib/debug",
                "a static library",
                "a pkg-config file",
                "under /usr/share/doc, man or info",
                "under /usr/share/doc, man or info",
                "under /usr/share/locale",
                "under /usr/share/locale",
                "under /usr/share/doc, man or info",
                "a pkg-config file",
            ]
        );
        let names: Vec<&str> = facets.facets.keys().map(Facet::as_str).collect();
        assert_eq!(
            names,
            [
                "debug",
                "dev",
                "doc",
                "locale:de",
                "locale:pt_BR",
                "runtime"
            ]
        );
        assert!(facets.notes.is_empty());
    }

    #[test]
    fn earlier_rules_win() {
        let facets = split(vec![
            file("/usr/lib/debug/libx.a", 1),
            file("/usr/share/doc/x/libexample.a", 1),
            file("/usr/share/man/de/man1/x.1", 1),
            file("/usr/include/x.pc", 1),
            file("/usr/share/doc/pkgconfig/x.pc", 1),
        ]);
        assert_eq!(
            placed(&facets),
            [
                ("/usr/include/x.pc", "dev"),
                ("/usr/lib/debug/libx.a", "debug"),
                ("/usr/share/doc/pkgconfig/x.pc", "doc"),
                ("/usr/share/doc/x/libexample.a", "doc"),
                ("/usr/share/man/de/man1/x.1", "doc"),
            ]
        );
    }

    #[test]
    fn rules_match_whole_names() {
        // Neighbours with the same start, and names that only look alike.
        let facets = split(vec![
            file("/usr/lib/debugger", 1),
            file("/usr/share/docs/x", 1),
            file("/usr/share/manual", 1),
            file("/usr/include2/x.h", 1),
            file("/usr/lib/x.a.1", 1),
            file("/usr/lib/x.pc", 1),
            file("/usr/lib/mypkgconfig/x.pc", 1),
            file("/usr/share/locales/de/x", 1),
        ]);
        assert!(
            facets
                .placements
                .iter()
                .all(|pl| pl.facet == Facet::runtime())
        );
        assert_eq!(facets.facets.len(), 1);
    }

    #[test]
    fn locale_names_are_directories() {
        let facets = split(vec![
            file("/usr/share/locale/locale.alias", 1),
            symlink("/usr/share/locale/en", "en_US"),
            dir("/usr/share/locale/fr"),
            file("/usr/share/locale/ca@valencia/LC_MESSAGES/x.mo", 1),
        ]);
        assert_eq!(
            placed(&facets),
            [
                (
                    "/usr/share/locale/ca@valencia/LC_MESSAGES/x.mo",
                    "locale:ca@valencia"
                ),
                ("/usr/share/locale/en", "runtime"),
                ("/usr/share/locale/fr", "locale:fr"),
                ("/usr/share/locale/locale.alias", "runtime"),
            ]
        );
        // An empty locale directory is its own facet's only entry, below
        // the directories above it.
        assert_eq!(
            paths_in(&facets, "locale:fr"),
            [
                "/usr",
                "/usr/share",
                "/usr/share/locale",
                "/usr/share/locale/fr"
            ]
        );
    }

    #[test]
    fn a_locale_name_a_facet_cant_hold_stays_in_runtime() {
        let facets = split(vec![
            file("/usr/share/locale/no way/a.mo", 1),
            file("/usr/share/locale/no way/b.mo", 1),
            dir("/usr/share/locale/x:y"),
        ]);
        assert!(
            facets
                .placements
                .iter()
                .all(|pl| pl.facet == Facet::runtime())
        );
        assert_eq!(
            facets.notes,
            [
                FacetNote::BadLocale {
                    path: "/usr/share/locale/no way".into()
                },
                FacetNote::BadLocale {
                    path: "/usr/share/locale/x:y".into()
                },
            ]
        );
        assert_eq!(
            facets.notes[0].to_string(),
            "/usr/share/locale/no way: not a locale name a facet can hold, so it stays in runtime"
        );
    }

    #[test]
    fn directories_are_not_dev_by_name() {
        let facets = split(vec![dir("/usr/lib/x.a"), dir("/usr/lib/pkgconfig/y.pc")]);
        assert_eq!(
            placed(&facets),
            [
                ("/usr/lib/pkgconfig/y.pc", "runtime"),
                ("/usr/lib/x.a", "runtime")
            ]
        );
        // A link named like a static library is dev.
        let facets = split(vec![symlink("/usr/lib/libx.a", "libx.a.1")]);
        assert_eq!(placed(&facets), [("/usr/lib/libx.a", "dev")]);
    }

    #[test]
    fn each_facet_holds_the_directories_above_its_entries() {
        let facets = split(vec![
            dir_as("/usr/share/doc", "0700"),
            file("/usr/share/doc/x/README", 10),
            file("/usr/share/x/data", 20),
            file("/usr/bin/x", 30),
        ]);
        assert_eq!(
            paths_in(&facets, "doc"),
            [
                "/usr",
                "/usr/share",
                "/usr/share/doc",
                "/usr/share/doc/x",
                "/usr/share/doc/x/README"
            ]
        );
        assert_eq!(
            paths_in(&facets, "runtime"),
            [
                "/usr",
                "/usr/bin",
                "/usr/bin/x",
                "/usr/share",
                "/usr/share/x",
                "/usr/share/x/data"
            ]
        );
        // Directories keep their metadata in every facet.
        let doc = &facets.facets[&f("doc")].tree;
        assert_eq!(
            doc.get("/usr/share/doc").unwrap().kind,
            dir_as("/x", "0700").kind
        );
        assert_eq!(facets.facets[&f("doc")].size, 10);
        assert_eq!(facets.facets[&Facet::runtime()].size, 50);
        // Directories with entries below them aren't placements.
        assert!(
            facets
                .placements
                .iter()
                .all(|pl| !pl.path.as_str().ends_with("/doc"))
        );
    }

    #[test]
    fn runtime_is_always_there() {
        let facets = split(vec![file("/usr/share/doc/x", 1)]);
        let runtime = &facets.facets[&Facet::runtime()];
        assert!(runtime.tree.entries().is_empty());
        assert_eq!(runtime.size, 0);
        let empty = classify(&tree(vec![]), &[]).unwrap();
        assert_eq!(empty.facets.len(), 1);
        assert!(empty.placements.is_empty());
    }

    #[test]
    fn hard_links_in_one_facet_stay_links() {
        let facets = split(vec![
            file("/usr/bin/a", 9),
            hardlink("/usr/bin/b", "/usr/bin/a"),
        ]);
        let runtime = &facets.facets[&Facet::runtime()];
        assert_eq!(
            runtime.tree.get("/usr/bin/b").unwrap().kind,
            Kind::HardLink(p("/usr/bin/a"))
        );
        assert_eq!(runtime.size, 9);
        assert!(facets.notes.is_empty());
    }

    #[test]
    fn a_hard_link_to_another_facet_becomes_a_copy() {
        let facets = split(vec![
            file("/usr/bin/a", 9),
            hardlink("/usr/share/doc/x/a", "/usr/bin/a"),
            hardlink("/usr/share/doc/x/b", "/usr/bin/a"),
        ]);
        let doc = &facets.facets[&f("doc")];
        // The first link is a copy of the file, the second a link to it.
        assert_eq!(
            doc.tree.get("/usr/share/doc/x/a").unwrap().kind,
            file("/usr/bin/a", 9).kind
        );
        assert_eq!(
            doc.tree.get("/usr/share/doc/x/b").unwrap().kind,
            Kind::HardLink(p("/usr/share/doc/x/a"))
        );
        assert_eq!(doc.size, 9);
        assert_eq!(facets.facets[&Facet::runtime()].size, 9);
        assert_eq!(
            facets.notes,
            [FacetNote::Copied {
                path: p("/usr/share/doc/x/a"),
                target: p("/usr/bin/a"),
            }]
        );
        assert_eq!(
            facets.notes[0].to_string(),
            "/usr/share/doc/x/a: a hard link to /usr/bin/a, which is in another facet, so it's a copy here"
        );
    }

    #[test]
    fn notes_are_in_path_order() {
        // The copy note is made after the locale notes are found, and
        // sorts between them.
        let facets = split(vec![
            file("/usr/bin/a", 1),
            file("/usr/share/locale/a b/x", 1),
            hardlink("/usr/share/doc/a", "/usr/bin/a"),
            file("/usr/share/locale/z z/x", 1),
        ]);
        let paths: Vec<String> = facets
            .notes
            .iter()
            .map(|n| n.to_string().split(':').next().unwrap().to_owned())
            .collect();
        assert_eq!(
            paths,
            [
                "/usr/share/doc/a",
                "/usr/share/locale/a b",
                "/usr/share/locale/z z"
            ]
        );
    }

    #[test]
    fn overrides_move_a_path_and_everything_below_it() {
        let facets = overridden(
            vec![
                file("/usr/lib/libx.so", 1),
                file("/usr/lib/cmake/x/XConfig.cmake", 1),
                file("/usr/lib/cmake/x/keep/runtime.cmake", 1),
                file("/usr/share/doc/x/needed-at-runtime", 1),
                file("/usr/lib/payload/bin/x", 1),
            ],
            &[
                ("/usr/lib/libx.so", "dev"),
                ("/usr/lib/cmake", "dev"),
                ("/usr/lib/cmake/x/keep", "runtime"),
                ("/usr/share/doc/x/needed-at-runtime", "runtime"),
                ("/usr/lib/payload", "payload"),
            ],
        )
        .unwrap();
        assert_eq!(
            placed(&facets),
            [
                ("/usr/lib/cmake/x/XConfig.cmake", "dev"),
                ("/usr/lib/cmake/x/keep/runtime.cmake", "runtime"),
                ("/usr/lib/libx.so", "dev"),
                ("/usr/lib/payload/bin/x", "payload"),
                ("/usr/share/doc/x/needed-at-runtime", "runtime"),
            ]
        );
        let reason = |path: &str| {
            facets
                .placements
                .iter()
                .find(|pl| pl.path.as_str() == path)
                .map(|pl| pl.reason.clone())
                .unwrap()
        };
        assert_eq!(
            reason("/usr/lib/cmake/x/XConfig.cmake"),
            Reason::Override(p("/usr/lib/cmake"))
        );
        assert_eq!(
            reason("/usr/lib/cmake/x/keep/runtime.cmake").to_string(),
            "overridden at /usr/lib/cmake/x/keep"
        );
    }

    #[test]
    fn an_override_must_match_something() {
        let error = overridden(vec![file("/usr/bin/x", 1)], &[("/usr/bin/y", "doc")]).unwrap_err();
        assert_eq!(error.path, "/usr/bin/y");
        assert!(matches!(error.kind, FacetErrorKind::UnusedOverride));
        assert_eq!(
            error.to_string(),
            "/usr/bin/y: the facet override matches nothing in the tree"
        );
        // A directory with nothing but itself still matches.
        overridden(
            vec![dir("/usr/share/empty")],
            &[("/usr/share/empty", "doc")],
        )
        .unwrap();
        // So does a directory whose entries are all overridden more
        // specifically.
        overridden(
            vec![file("/usr/a/b", 1)],
            &[("/usr/a", "doc"), ("/usr/a/b", "dev")],
        )
        .unwrap();
    }

    #[test]
    fn two_overrides_for_one_path_are_refused() {
        let error = overridden(
            vec![file("/usr/bin/x", 1)],
            &[("/usr/bin/x", "doc"), ("/usr/bin/x", "dev")],
        )
        .unwrap_err();
        assert!(matches!(error.kind, FacetErrorKind::DuplicateOverride));
        assert_eq!(
            error.to_string(),
            "/usr/bin/x: the path has two facet overrides"
        );
    }

    /// Paths from a small alphabet, so rules and links meet often.
    fn spec() -> impl Strategy<Value = (Vec<&'static str>, u8)> {
        (
            prop::collection::vec(
                prop::sample::select(vec![
                    "usr",
                    "share",
                    "doc",
                    "lib",
                    "debug",
                    "include",
                    "locale",
                    "de",
                    "pkgconfig",
                    "x.a",
                    "y.pc",
                    "bin",
                ]),
                1..5,
            ),
            0u8..4,
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn every_path_lands_in_exactly_one_facet(specs in prop::collection::vec(spec(), 0..25)) {
            let mut seen: Vec<String> = Vec::new();
            let mut entries = Vec::new();
            let mut files: Vec<String> = Vec::new();
            for (names, kind) in specs {
                let path = format!("/{}", names.join("/"));
                let clash = seen.iter().any(|s| *s == path || path.starts_with(&format!("{s}/")) || s.starts_with(&format!("{path}/")));
                if clash {
                    continue;
                }
                seen.push(path.clone());
                entries.push(match kind {
                    0 => { files.push(path.clone()); file(&path, 3) }
                    1 => dir(&path),
                    2 => symlink(&path, "x"),
                    _ => match files.first() {
                        Some(target) if *target < path => hardlink(&path, target),
                        _ => file(&path, 1),
                    },
                });
            }
            let input = tree(entries);
            let facets = classify(&input, &[]).unwrap();
            // The leaves, each once.
            let leaves: Vec<&str> = input
                .entries()
                .iter()
                .filter(|e| !matches!(e.kind, Kind::Dir(_)) || !input.entries().iter().any(|c| c.path.parent() == e.path.as_str()))
                .map(|e| e.path.as_str())
                .collect();
            let placed: Vec<&str> = facets.placements.iter().map(|pl| pl.path.as_str()).collect();
            prop_assert_eq!(&placed, &leaves);
            for Placement { path, facet, .. } in &facets.placements {
                let tree = &facets.facets[facet].tree;
                prop_assert!(tree.get(path.as_str()).is_some());
                for (other, t) in &facets.facets {
                    if other != facet && !matches!(input.get(path.as_str()).unwrap().kind, Kind::Dir(_)) {
                        prop_assert!(t.tree.get(path.as_str()).is_none());
                    }
                }
            }
            // Every facet's tree holds nothing but placements and the
            // directories above them.
            for t in facets.facets.values() {
                for e in t.tree.entries() {
                    prop_assert!(input.get(e.path.as_str()).is_some());
                }
            }
            prop_assert!(facets.facets.contains_key(&Facet::runtime()));
        }
    }
}
