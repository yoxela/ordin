// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Layout normalization (ORD-111): an install root mapped into Ordin's
//! layout, on trees built in memory.

#[cfg(test)]
mod layout {
    use std::collections::BTreeSet;

    use ordin_core::{Account, Algorithm, Digest, Mode};
    use ordin_manifest::{Class, Config, Flush, Merge, Seed, StateFile, StatePath};
    use ordin_pack::{Layout, LayoutError, LayoutErrorKind, LayoutOptions, normalize};
    use ordin_tree::{
        Capabilities, DIR_MODE, Dir, Entry, FILE_MODE, File, Kind, LinuxCap, Symlink, Tree,
        TreePath, Xattrs,
    };
    use proptest::prelude::*;

    fn p(path: &str) -> TreePath {
        path.parse().unwrap()
    }

    fn account(name: &str) -> Account {
        name.parse().unwrap()
    }

    fn mode(text: &str) -> Mode {
        text.parse().unwrap()
    }

    fn dir_as(path: &str, m: &str, owner: &str, group: &str) -> Entry {
        Entry {
            path: p(path),
            kind: Kind::Dir(Dir {
                mode: mode(m),
                owner: account(owner),
                group: account(group),
                xattrs: Xattrs::new(),
            }),
        }
    }

    fn dir(path: &str) -> Entry {
        dir_as(path, "0755", "root", "root")
    }

    fn file_of(path: &str, size: u64) -> File {
        File {
            mode: FILE_MODE,
            owner: Account::root(),
            group: Account::root(),
            size,
            content: Digest::blake3(path.as_bytes()),
            fsverity: Digest::new(Algorithm::Sha256, [7; 32]),
            xattrs: Xattrs::new(),
            capabilities: None,
        }
    }

    fn file(path: &str, size: u64) -> Entry {
        Entry {
            path: p(path),
            kind: Kind::File(file_of(path, size)),
        }
    }

    fn file_as(path: &str, size: u64, m: &str, owner: &str, group: &str) -> Entry {
        let mut f = file_of(path, size);
        f.mode = mode(m);
        f.owner = account(owner);
        f.group = account(group);
        Entry {
            path: p(path),
            kind: Kind::File(f),
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

    /// A tree of these entries, with every missing parent added as a
    /// default directory.
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

    fn options(prefixes: &[&str]) -> LayoutOptions {
        LayoutOptions {
            name: "nginx".parse().unwrap(),
            prefixes: prefixes.iter().map(|x| p(x)).collect(),
        }
    }

    fn layout(entries: Vec<Entry>) -> Layout {
        normalize(&tree(entries), &options(&[])).unwrap()
    }

    fn refused(entries: Vec<Entry>) -> LayoutError {
        normalize(&tree(entries), &options(&[])).unwrap_err()
    }

    fn paths(t: &Tree) -> Vec<&str> {
        t.entries().iter().map(|e| e.path.as_str()).collect()
    }

    fn fp(path: &str) -> ordin_core::FilePath {
        path.parse().unwrap()
    }

    fn nothing_declared(l: &Layout) -> bool {
        l.config.is_empty()
            && l.state_paths.is_empty()
            && l.state_files.is_empty()
            && l.seeds.is_empty()
    }

    #[test]
    fn each_entry_records_where_it_was() {
        let l = layout(vec![
            file("/bin/x", 1),
            file("/usr/bin/y", 1),
            file("/etc/nginx.conf", 1),
            file("/var/lib/nginx/seed", 3),
            file("/var/lib/nginx/empty", 0),
        ]);
        let origin = |path: &str| l.origins.get(&p(path)).map(TreePath::as_str);
        assert_eq!(origin("/usr/bin/x"), Some("/bin/x"));
        assert_eq!(origin("/usr/bin/y"), Some("/usr/bin/y"));
        assert_eq!(
            origin("/usr/share/ordin/defaults/nginx/nginx.conf"),
            Some("/etc/nginx.conf")
        );
        assert_eq!(
            origin("/usr/share/ordin/seeds/nginx/var/lib/nginx/seed"),
            Some("/var/lib/nginx/seed")
        );
        // Directories added above entries came from nowhere.
        assert_eq!(origin("/usr/share/ordin"), None);
        // Every origin is an entry of the tree, and nothing else is.
        assert!(
            l.origins
                .keys()
                .all(|path| l.tree.get(path.as_str()).is_some())
        );
        assert!(l.tree.get("/var/lib/nginx/empty").is_none());
    }

    #[test]
    fn usr_stays_where_it_is() {
        let input = tree(vec![
            dir_as("/usr/lib/nginx", "0750", "www", "adm"),
            file_as("/usr/sbin/nginx", 10, "4755", "root", "root"),
            symlink("/usr/bin/ng", "../sbin/nginx"),
            hardlink("/usr/sbin/nginx2", "/usr/sbin/nginx"),
            dir("/usr/local/empty"),
        ]);
        let l = normalize(&input, &options(&[])).unwrap();
        assert_eq!(l.tree, input);
        assert!(nothing_declared(&l));
    }

    #[test]
    fn etc_becomes_config_defaults() {
        let l = layout(vec![
            file("/etc/nginx.conf", 5),
            dir_as("/etc/nginx", "0750", "root", "www"),
            file_as("/etc/nginx/mime.types", 9, "0640", "root", "www"),
            dir("/etc/nginx/conf.d"),
            file("/usr/sbin/nginx", 1),
        ]);
        assert_eq!(
            paths(&l.tree),
            [
                "/usr",
                "/usr/sbin",
                "/usr/sbin/nginx",
                "/usr/share",
                "/usr/share/ordin",
                "/usr/share/ordin/defaults",
                "/usr/share/ordin/defaults/nginx",
                "/usr/share/ordin/defaults/nginx/nginx",
                "/usr/share/ordin/defaults/nginx/nginx.conf",
                "/usr/share/ordin/defaults/nginx/nginx/conf.d",
                "/usr/share/ordin/defaults/nginx/nginx/mime.types",
            ]
        );
        let config = |default: &str, target: &str, merge| Config {
            default: fp(default),
            target: fp(target),
            merge,
        };
        assert_eq!(
            l.config,
            // Sorted by the bytes of the target, where '.' comes before '/'.
            [
                config(
                    "/usr/share/ordin/defaults/nginx/nginx.conf",
                    "/etc/nginx.conf",
                    Merge::ThreeWay
                ),
                config(
                    "/usr/share/ordin/defaults/nginx/nginx/conf.d",
                    "/etc/nginx/conf.d",
                    Merge::DropIn
                ),
                config(
                    "/usr/share/ordin/defaults/nginx/nginx/mime.types",
                    "/etc/nginx/mime.types",
                    Merge::ThreeWay
                ),
            ]
        );
        // The defaults keep their metadata, and the added directories are
        // root's.
        let at = |path: &str| l.tree.get(path).unwrap().kind.clone();
        assert_eq!(
            at("/usr/share/ordin/defaults/nginx/nginx"),
            dir_as("/x", "0750", "root", "www").kind
        );
        assert_eq!(
            at("/usr/share/ordin/defaults/nginx/nginx/mime.types"),
            file_as("/etc/nginx/mime.types", 9, "0640", "root", "www").kind
        );
        assert_eq!(at("/usr/share/ordin").clone(), dir("/x").kind);
        assert!(l.state_paths.is_empty() && l.seeds.is_empty());
    }

    #[test]
    fn links_under_etc_are_refused() {
        let error = refused(vec![symlink("/etc/a", "b")]);
        assert_eq!(error.path, "/etc/a");
        assert!(matches!(
            error.kind,
            LayoutErrorKind::LinkInEtc { found: "symlink" }
        ));
        let error = refused(vec![file("/etc/a", 1), hardlink("/etc/b", "/etc/a")]);
        assert_eq!(error.path, "/etc/b");
        assert!(matches!(
            error.kind,
            LayoutErrorKind::LinkInEtc { found: "hardlink" }
        ));
        assert_eq!(
            error.to_string(),
            "/etc/b: a hardlink under /etc can't be a config default; only files and empty directories can"
        );
    }

    #[test]
    fn var_becomes_state() {
        let l = layout(vec![
            dir_as("/var/lib/nginx", "0750", "www", "www"),
            dir("/var/lib/nginx/body"),
            file_as("/var/lib/nginx/body/default.db", 4, "0600", "www", "www"),
            dir("/var/cache/nginx"),
            dir_as("/var/log/nginx", "0750", "www", "adm"),
            file_as("/var/log/nginx/error.log", 0, "0640", "www", "adm"),
            dir("/var/spool/nginx"),
            dir("/var/tmp/nginx"),
        ]);
        let state = |path: &str, class, m: &str, owner: &str, group: &str| StatePath {
            path: fp(path),
            class,
            owner: account(owner),
            group: account(group),
            mode: mode(m),
            flush: Flush::Never,
            recurse: false,
            on_remove: None,
        };
        assert_eq!(
            l.state_paths,
            [
                state("/var/cache/nginx", Class::Cache, "0755", "root", "root"),
                state("/var/lib/nginx", Class::Data, "0750", "www", "www"),
                state("/var/lib/nginx/body", Class::Data, "0755", "root", "root"),
                state("/var/log/nginx", Class::Log, "0750", "www", "adm"),
                state("/var/spool/nginx", Class::Spool, "0755", "root", "root"),
                state("/var/tmp/nginx", Class::Tmp, "0755", "root", "root"),
            ]
        );
        assert_eq!(
            l.state_files,
            [StateFile {
                path: fp("/var/log/nginx/error.log"),
                owner: account("www"),
                group: account("adm"),
                mode: mode("0640"),
            }]
        );
        let from = "/usr/share/ordin/seeds/nginx/var/lib/nginx/body/default.db";
        assert_eq!(
            l.seeds,
            [Seed {
                path: fp("/var/lib/nginx/body/default.db"),
                from: fp(from),
            }]
        );
        // Only the seed is in the tree, with its own metadata.
        assert_eq!(
            l.tree.get(from).unwrap().kind,
            file_as("/var/lib/nginx/body/default.db", 4, "0600", "www", "www").kind
        );
        assert!(paths(&l.tree).iter().all(|x| x.starts_with("/usr")));
        assert!(l.config.is_empty());
    }

    #[test]
    fn an_empty_file_with_attributes_is_a_seed() {
        let mut with_xattr = file_of("/var/lib/a/x", 0);
        with_xattr
            .xattrs
            .insert("user.note".parse().unwrap(), b"hi".to_vec());
        let mut with_caps = file_of("/var/lib/a/y", 0);
        with_caps.capabilities = Some(Capabilities {
            permitted: ["cap_net_raw".parse::<LinuxCap>().unwrap()].into(),
            inheritable: BTreeSet::new(),
            effective: true,
        });
        let l = layout(vec![
            Entry {
                path: p("/var/lib/a/x"),
                kind: Kind::File(with_xattr),
            },
            Entry {
                path: p("/var/lib/a/y"),
                kind: Kind::File(with_caps),
            },
            file("/var/lib/a/z", 0),
        ]);
        let seeded: Vec<&str> = l.seeds.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(seeded, ["/var/lib/a/x", "/var/lib/a/y"]);
        assert_eq!(l.state_files.len(), 1);
        assert_eq!(l.state_files[0].path.as_str(), "/var/lib/a/z");
    }

    #[test]
    fn var_outside_the_known_classes_is_refused() {
        for (entries, at) in [
            (vec![dir("/var/www/site")], "/var/www"),
            (vec![file("/var/x", 1)], "/var/x"),
        ] {
            let error = refused(entries);
            assert_eq!(error.path, at);
            assert!(
                matches!(error.kind, LayoutErrorKind::UnknownState),
                "{error}"
            );
        }
        for (entries, at) in [
            (vec![dir("/var/run/nginx")], "/var/run"),
            (vec![dir("/run/nginx")], "/run"),
        ] {
            let error = refused(entries);
            assert_eq!(error.path, at);
            assert!(matches!(error.kind, LayoutErrorKind::Runtime), "{error}");
        }
    }

    #[test]
    fn links_and_attributes_under_var_are_refused() {
        let error = refused(vec![symlink("/var/lib/a", "b")]);
        assert!(matches!(
            error.kind,
            LayoutErrorKind::LinkInVar { found: "symlink" }
        ));
        let error = refused(vec![
            file("/var/lib/a", 1),
            hardlink("/var/lib/b", "/var/lib/a"),
        ]);
        assert_eq!(error.path, "/var/lib/b");
        assert!(matches!(
            error.kind,
            LayoutErrorKind::LinkInVar { found: "hardlink" }
        ));
        let mut d = Dir {
            mode: DIR_MODE,
            owner: Account::root(),
            group: Account::root(),
            xattrs: Xattrs::new(),
        };
        d.xattrs.insert("user.a".parse().unwrap(), vec![1]);
        let error = refused(vec![Entry {
            path: p("/var/lib/a"),
            kind: Kind::Dir(d),
        }]);
        assert!(matches!(error.kind, LayoutErrorKind::StateXattrs));
    }

    #[test]
    fn a_hard_link_to_a_state_file_is_refused() {
        // The walker names a link group by its smallest path, so this
        // needs a tree built by hand.
        let error = refused(vec![
            file("/var/lib/a/e", 0),
            hardlink("/usr/a", "/var/lib/a/e"),
        ]);
        assert_eq!(error.path, "/usr/a");
        assert!(
            matches!(&error.kind, LayoutErrorKind::LinkToState { target } if target == "/var/lib/a/e")
        );
    }

    #[test]
    fn hard_links_follow_their_files() {
        let l = layout(vec![file("/etc/a", 3), hardlink("/usr/a", "/etc/a")]);
        assert_eq!(
            l.tree.get("/usr/a").unwrap().kind,
            Kind::HardLink(p("/usr/share/ordin/defaults/nginx/a"))
        );
        let input = tree(vec![
            file("/opt/foo/bin/x", 3),
            hardlink("/opt/foo/bin/y", "/opt/foo/bin/x"),
        ]);
        let l = normalize(&input, &options(&["/opt/foo"])).unwrap();
        assert_eq!(
            l.tree.get("/usr/bin/y").unwrap().kind,
            Kind::HardLink(p("/usr/bin/x"))
        );
    }

    #[test]
    fn a_directory_ordin_provides_must_be_one() {
        for top in ["/etc", "/var", "/var/lib"] {
            let error = refused(vec![file(top, 1)]);
            assert_eq!(error.path, top);
            assert!(
                matches!(error.kind, LayoutErrorKind::NotADirectory { found: "file" }),
                "{error}"
            );
        }
    }

    #[test]
    fn anything_else_is_refused_with_a_hint() {
        for (entries, at) in [
            (vec![file("/opt/foo/bin/x", 1)], "/opt"),
            (vec![dir("/srv/www")], "/srv"),
            (vec![dir("/home")], "/home"),
            (vec![file("/README", 1)], "/README"),
            (vec![dir("/boot")], "/boot"),
        ] {
            let error = refused(entries);
            assert_eq!(error.path, at);
            assert!(
                matches!(error.kind, LayoutErrorKind::OutsideLayout),
                "{error}"
            );
        }
        assert_eq!(
            refused(vec![dir("/srv")]).to_string(),
            "/srv: outside Ordin's layout, which packages usr/, etc/ and var/; if the software was installed with a prefix here, pass it with --prefix to move it under /usr"
        );
    }

    #[test]
    fn usr_share_ordin_is_reserved() {
        for path in ["/usr/share/ordin", "/usr/share/ordin/defaults/x"] {
            let error = refused(vec![dir(path)]);
            assert_eq!(error.path, "/usr/share/ordin");
            assert!(matches!(error.kind, LayoutErrorKind::Reserved));
        }
        // A neighbour with the same start isn't.
        let l = layout(vec![file("/usr/share/ordinal", 1)]);
        assert!(l.tree.get("/usr/share/ordinal").is_some());
    }

    #[test]
    fn the_merged_directories_move_under_usr() {
        let l = layout(vec![
            file("/bin/a", 1),
            file("/sbin/b", 1),
            file("/lib/c", 1),
            file("/lib64/d", 1),
            file("/usr/bin/e", 1),
        ]);
        assert_eq!(
            paths(&l.tree),
            [
                "/usr",
                "/usr/bin",
                "/usr/bin/a",
                "/usr/bin/e",
                "/usr/lib",
                "/usr/lib/c",
                "/usr/lib64",
                "/usr/lib64/d",
                "/usr/sbin",
                "/usr/sbin/b",
            ]
        );
        assert!(nothing_declared(&l));
    }

    #[test]
    fn merged_links_are_dropped_and_other_links_move() {
        let l = layout(vec![
            symlink("/bin", "usr/bin"),
            symlink("/lib", "/usr/lib"),
            symlink("/sbin", "usr/bin"),
            dir("/usr/bin"),
        ]);
        assert_eq!(paths(&l.tree), ["/usr", "/usr/bin", "/usr/sbin"]);
        assert_eq!(
            l.tree.get("/usr/sbin").unwrap().kind,
            symlink("/x", "usr/bin").kind
        );
        // A symlink below the top level is kept, whatever it points at.
        let l = layout(vec![symlink("/bin/sh", "usr/bin")]);
        assert!(l.tree.get("/usr/bin/sh").is_some());
    }

    #[test]
    fn paths_that_meet_must_be_identical_directories() {
        let error = refused(vec![file("/bin/a", 1), file("/usr/bin/a", 1)]);
        assert_eq!(error.path, "/usr/bin/a");
        assert!(matches!(
            &error.kind,
            LayoutErrorKind::Collision { destination, other }
                if destination == "/usr/bin/a" && other == "/bin/a"
        ));
        assert_eq!(
            error.to_string(),
            "/usr/bin/a: it moves to /usr/bin/a, where /bin/a is too"
        );
        let error = refused(vec![
            dir_as("/bin", "0700", "root", "root"),
            dir("/usr/bin"),
        ]);
        assert!(matches!(error.kind, LayoutErrorKind::Collision { .. }));
        // A file meeting a directory collides even with the same metadata.
        let error = refused(vec![dir("/bin/a"), file("/usr/bin/a", 1)]);
        assert!(matches!(error.kind, LayoutErrorKind::Collision { .. }));
        let error = refused(vec![file("/bin/a", 1), dir("/usr/bin/a")]);
        assert!(matches!(error.kind, LayoutErrorKind::Collision { .. }));
    }

    #[test]
    fn a_prefix_moves_its_contents_to_usr() {
        let input = tree(vec![
            dir_as("/opt/foo", "0700", "root", "root"),
            file("/opt/foo/bin/foo", 1),
            dir_as("/opt/foo/lib", "0750", "root", "adm"),
            file("/srv/data/x", 1),
        ]);
        let l = normalize(&input, &options(&["/opt/foo", "/srv/data"])).unwrap();
        assert_eq!(
            paths(&l.tree),
            ["/usr", "/usr/bin", "/usr/bin/foo", "/usr/lib", "/usr/x"]
        );
        assert_eq!(
            l.tree.get("/usr/lib").unwrap().kind,
            dir_as("/x", "0750", "root", "adm").kind
        );
        // Outside the prefix is still refused.
        let input = tree(vec![file("/opt/foo/a", 1), file("/opt/bar/b", 1)]);
        let error = normalize(&input, &options(&["/opt/foo"])).unwrap_err();
        assert_eq!(error.path, "/opt/bar");
        assert!(matches!(error.kind, LayoutErrorKind::OutsideLayout));
        // A neighbour with the same start isn't under the prefix.
        let input = tree(vec![file("/opt/foo/a", 1), file("/opt/foobar/b", 1)]);
        let error = normalize(&input, &options(&["/opt/foo"])).unwrap_err();
        assert_eq!(error.path, "/opt/foobar");
    }

    #[test]
    fn a_prefix_must_be_usable() {
        let input = tree(vec![
            file("/opt/foo/a", 1),
            file("/usr/b", 1),
            file("/etc/c", 1),
        ]);
        let bad = |prefixes: &[&str]| normalize(&input, &options(prefixes)).unwrap_err();
        for prefix in ["/usr", "/etc", "/var/lib", "/run", "/bin", "/lib64/x"] {
            let error = bad(&[prefix]);
            assert_eq!(error.path, prefix);
            assert!(
                matches!(error.kind, LayoutErrorKind::BadPrefix(_)),
                "{error}"
            );
        }
        let error = bad(&["/opt/foo", "/opt"]);
        assert_eq!(error.path, "/opt");
        assert!(matches!(
            error.kind,
            LayoutErrorKind::BadPrefix("prefixes can't be inside one another")
        ));
        let error = bad(&["/opt/foo", "/opt/foo"]);
        assert!(matches!(error.kind, LayoutErrorKind::BadPrefix(_)));
        let error = bad(&["/opt/nothing"]);
        assert!(matches!(error.kind, LayoutErrorKind::UnusedPrefix));
        assert_eq!(
            error.to_string(),
            "/opt/nothing: --prefix names nothing in the tree"
        );
        let error = bad(&["/opt/foo/a"]);
        assert!(matches!(
            error.kind,
            LayoutErrorKind::BadPrefix("a prefix is a directory")
        ));
        // Two prefixes side by side are fine.
        let input = tree(vec![file("/opt/a/x", 1), file("/opt/b/y", 1)]);
        normalize(&input, &options(&["/opt/b", "/opt/a"])).unwrap();
    }

    #[test]
    fn paths_the_manifest_cant_declare_are_refused() {
        for entries in [
            vec![file("/etc/a b", 1)],
            vec![dir("/etc/x~")],
            vec![dir("/var/lib/a b")],
            vec![file("/var/log/a,b", 0)],
            vec![file("/var/lib/a[1]", 4)],
        ] {
            let error = refused(entries);
            assert!(
                matches!(error.kind, LayoutErrorKind::NotDeclarable(_)),
                "{error}"
            );
        }
    }

    #[test]
    fn a_destination_too_long_for_a_tree_is_refused() {
        // 20 names of 200 bytes and /bin: 4,024 bytes, which fits. Under
        // /usr it would be 4,028; one more name of 70 bytes makes it too
        // long only once it moves.
        let long = "x".repeat(200);
        let mut path = String::from("/bin");
        for _ in 0..20 {
            path.push('/');
            path.push_str(&long);
        }
        path.push('/');
        path.push_str(&"y".repeat(67));
        assert_eq!(path.len(), 4092);
        let error = refused(vec![file(&path, 1)]);
        assert!(
            matches!(error.kind, LayoutErrorKind::BadDestination(_)),
            "{error}"
        );
    }

    #[test]
    fn a_result_that_breaks_a_tree_rule_is_refused() {
        // A tree at its entry limit, all under /etc: moving it adds the
        // directories above the defaults, one more than a tree may hold.
        let mut entries: Vec<Entry> = (0..ordin_tree::MAX_ENTRIES - 1)
            .map(|i| file(&format!("/etc/{i:06}"), 1))
            .collect();
        entries.push(dir("/etc"));
        let input = Tree::new(entries).unwrap();
        let error = normalize(&input, &options(&[])).unwrap_err();
        assert_eq!(error.path, "the normalized tree");
        assert!(matches!(error.kind, LayoutErrorKind::Tree(_)));
    }

    fn usr_entry() -> impl Strategy<Value = (Vec<String>, u8)> {
        (
            prop::collection::vec(prop::sample::select(vec!["a", "b", "lib", "x.so"]), 1..4),
            0u8..3,
        )
            .prop_map(|(names, kind)| (names.into_iter().map(String::from).collect(), kind))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn a_usr_only_tree_is_unchanged(specs in prop::collection::vec(usr_entry(), 0..20)) {
            let mut seen = BTreeSet::new();
            let mut entries = Vec::new();
            for (names, kind) in specs {
                let path = format!("/usr/{}", names.join("/"));
                // Each path once, and nothing below a file or symlink.
                if seen.iter().any(|s: &String| path.starts_with(&format!("{s}/")) || s.starts_with(&format!("{path}/")) || *s == path) {
                    continue;
                }
                seen.insert(path.clone());
                entries.push(match kind {
                    0 => file(&path, 1),
                    1 => dir(&path),
                    _ => symlink(&path, "a"),
                });
            }
            let input = tree(entries);
            let l = normalize(&input, &options(&[])).unwrap();
            prop_assert_eq!(&l.tree, &input);
            prop_assert!(nothing_declared(&l));
        }
    }
}
