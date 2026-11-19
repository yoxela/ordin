// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Walking real directories. Each test builds its own, with explicit
//! modes so the result doesn't depend on the umask.

#[cfg(test)]
mod walking {
    use std::collections::BTreeSet;
    use std::ffi::OsStr;
    use std::fs::{self, File, FileTimes, Permissions};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::{Duration, SystemTime};

    use ordin_pack::{Options, OwnerOverride, Walk, WalkError, WalkErrorKind, walk};
    use ordin_tree::{Entry, Kind, Tree, file_digests};
    use rustix::fs::{FileType, Mode, XattrFlags, mknodat, setxattr};
    use tempfile::TempDir;

    fn temp() -> TempDir {
        tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap()
    }

    fn chmod(path: &Path, mode: u32) {
        fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
    }

    fn dir(root: &Path, name: &str, mode: u32) -> PathBuf {
        let path = root.join(name);
        fs::create_dir(&path).unwrap();
        chmod(&path, mode);
        path
    }

    fn file(root: &Path, name: &str, content: &[u8], mode: u32) -> PathBuf {
        let path = root.join(name);
        fs::write(&path, content).unwrap();
        chmod(&path, mode);
        path
    }

    fn xattr(path: &Path, name: &str, value: &[u8]) {
        setxattr(path, name, value, XattrFlags::empty()).unwrap();
    }

    fn walked(root: &Path) -> Walk {
        walk(root, &Options::default()).unwrap()
    }

    fn refused(root: &Path) -> WalkError {
        walk(root, &Options::default()).unwrap_err()
    }

    fn with_owners(overrides: &[&str]) -> Options {
        Options {
            owners: overrides.iter().map(|o| o.parse().unwrap()).collect(),
            setuid: BTreeSet::new(),
        }
    }

    fn get<'a>(tree: &'a Tree, path: &str) -> &'a Kind {
        match tree.get(path) {
            Some(Entry { kind, .. }) => kind,
            None => panic!("{path} is missing"),
        }
    }

    fn get_file<'a>(tree: &'a Tree, path: &str) -> &'a ordin_tree::File {
        match get(tree, path) {
            Kind::File(f) => f,
            other => panic!("{path} is a {}", other.type_name()),
        }
    }

    fn get_dir<'a>(tree: &'a Tree, path: &str) -> &'a ordin_tree::Dir {
        match get(tree, path) {
            Kind::Dir(d) => d,
            other => panic!("{path} is a {}", other.type_name()),
        }
    }

    fn paths(tree: &Tree) -> Vec<&str> {
        tree.entries().iter().map(|e| e.path.as_str()).collect()
    }

    /// A small tree with one of everything a walk records.
    fn sample(root: &Path) {
        let usr = dir(root, "usr", 0o755);
        let bin = dir(&usr, "bin", 0o755);
        file(&bin, "rg", b"ripgrep", 0o755);
        symlink("rg", bin.join("ripgrep")).unwrap();
        let share = dir(&usr, "share", 0o2775);
        let doc = file(&share, "README", b"read me", 0o640);
        xattr(&doc, "user.note", b"hello");
        xattr(&share, "user.kind", b"docs");
        dir(&share, "empty", 0o700);
    }

    #[test]
    fn every_kind_of_entry_is_recorded() {
        let root = temp();
        sample(root.path());
        let Walk { tree, warnings } = walked(root.path());
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(
            paths(&tree),
            [
                "/usr",
                "/usr/bin",
                "/usr/bin/rg",
                "/usr/bin/ripgrep",
                "/usr/share",
                "/usr/share/README",
                "/usr/share/empty",
            ]
        );

        let rg = get_file(&tree, "/usr/bin/rg");
        let digests = file_digests(&b"ripgrep"[..]).unwrap();
        assert_eq!(rg.mode.value(), 0o755);
        assert_eq!(rg.size, 7);
        assert_eq!(rg.content, digests.content);
        assert_eq!(rg.fsverity, digests.fsverity);
        assert!(rg.xattrs.is_empty());
        assert_eq!(rg.capabilities, None);

        let Kind::Symlink(link) = get(&tree, "/usr/bin/ripgrep") else {
            panic!("not a symlink");
        };
        assert_eq!(link.target.as_str(), "rg");

        let share = get_dir(&tree, "/usr/share");
        assert_eq!(share.mode.value(), 0o2775);
        let values: Vec<_> = share
            .xattrs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_slice()))
            .collect();
        assert_eq!(values, [("user.kind", &b"docs"[..])]);

        let readme = get_file(&tree, "/usr/share/README");
        assert_eq!(readme.mode.value(), 0o640);
        let values: Vec<_> = readme
            .xattrs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_slice()))
            .collect();
        assert_eq!(values, [("user.note", &b"hello"[..])]);
        assert_eq!(get_dir(&tree, "/usr/share/empty").mode.value(), 0o700);
    }

    #[test]
    fn an_empty_directory_is_an_empty_tree() {
        let root = temp();
        assert!(walked(root.path()).tree.entries().is_empty());
    }

    #[test]
    fn a_file_larger_than_one_read_is_digested_whole() {
        let root = temp();
        let content = vec![7u8; 300_000];
        file(root.path(), "big", &content, 0o644);
        let tree = walked(root.path()).tree;
        let big = get_file(&tree, "/big");
        assert_eq!(big.size, 300_000);
        assert_eq!(big.content, file_digests(&content[..]).unwrap().content);
    }

    #[test]
    fn owners_never_come_from_the_disk() {
        // These files belong to whoever runs the test, and that doesn't
        // show: everything is root's. An override is the only way to
        // change that, and it reaches every kind of entry below it.
        let root = temp();
        sample(root.path());
        let plain = walked(root.path()).tree;
        assert_eq!(get_file(&plain, "/usr/bin/rg").owner.as_str(), "root");
        assert_eq!(get_dir(&plain, "/usr").group.as_str(), "root");

        let options = with_owners(&["/usr/bin=app:adm", "/usr/share/README=doc:staff"]);
        let tree = walk(root.path(), &options).unwrap().tree;
        let usr_bin = get_dir(&tree, "/usr/bin");
        assert_eq!(
            (usr_bin.owner.as_str(), usr_bin.group.as_str()),
            ("app", "adm")
        );
        let rg = get_file(&tree, "/usr/bin/rg");
        assert_eq!((rg.owner.as_str(), rg.group.as_str()), ("app", "adm"));
        let Kind::Symlink(link) = get(&tree, "/usr/bin/ripgrep") else {
            panic!("not a symlink");
        };
        assert_eq!((link.owner.as_str(), link.group.as_str()), ("app", "adm"));
        let readme = get_file(&tree, "/usr/share/README");
        assert_eq!(
            (readme.owner.as_str(), readme.group.as_str()),
            ("doc", "staff")
        );
        assert_eq!(get_dir(&tree, "/usr").owner.as_str(), "root");
    }

    #[test]
    fn an_override_matching_nothing_is_refused() {
        let root = temp();
        sample(root.path());
        let e = walk(root.path(), &with_owners(&["/usr/bni=app:app"])).unwrap_err();
        assert_eq!(e.path, "/usr/bni");
        assert!(matches!(e.kind, WalkErrorKind::UnusedOwner), "{e}");
        let repeated = with_owners(&["/usr=a:a", "/usr=b:b"]);
        let e = walk(root.path(), &repeated).unwrap_err();
        assert!(matches!(e.kind, WalkErrorKind::DuplicateOwner), "{e}");
    }

    #[test]
    fn timestamps_and_creation_order_do_not_matter() {
        let first = temp();
        sample(first.path());
        let second = temp();
        // The same tree, made in another order, with other timestamps.
        let usr = dir(second.path(), "usr", 0o755);
        let share = dir(&usr, "share", 0o2775);
        dir(&share, "empty", 0o700);
        xattr(&share, "user.kind", b"docs");
        let doc = file(&share, "README", b"read me", 0o640);
        xattr(&doc, "user.note", b"hello");
        let bin = dir(&usr, "bin", 0o755);
        symlink("rg", bin.join("ripgrep")).unwrap();
        let rg = file(&bin, "rg", b"ripgrep", 0o755);
        let long_ago = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        File::open(&rg)
            .unwrap()
            .set_times(FileTimes::new().set_modified(long_ago))
            .unwrap();
        assert_eq!(
            walked(first.path()).tree.digest().unwrap(),
            walked(second.path()).tree.digest().unwrap()
        );
    }

    #[test]
    fn hard_links_become_links_to_the_first_name_in_sort_order() {
        let root = temp();
        // A walk reaches a/z before a.b, but "/a.b" sorts first, because
        // '.' comes before '/'.
        let a = dir(root.path(), "a", 0o755);
        let original = file(&a, "z", b"shared", 0o750);
        xattr(&original, "user.k", b"v");
        fs::hard_link(&original, root.path().join("a.b")).unwrap();
        fs::hard_link(&original, root.path().join("b")).unwrap();
        file(root.path(), "other", b"shared", 0o750);
        let options = with_owners(&["/a.b=app:adm"]);
        let tree = walk(root.path(), &options).unwrap().tree;
        let first = get_file(&tree, "/a.b");
        assert_eq!(first.mode.value(), 0o750);
        assert_eq!(first.owner.as_str(), "app");
        assert_eq!(first.xattrs.len(), 1);
        for alias in ["/a/z", "/b"] {
            let Kind::HardLink(target) = get(&tree, alias) else {
                panic!("{alias} isn't a hard link");
            };
            assert_eq!(target.as_str(), "/a.b");
        }
        // The same content in a separate file is a separate file.
        assert_eq!(get(&tree, "/other").type_name(), "file");
    }

    #[test]
    fn symlinks_are_recorded_and_never_followed() {
        let root = temp();
        let outside = temp();
        let secret = dir(outside.path(), "secret", 0o755);
        file(&secret, "key", b"private", 0o644);
        // Absolute, dangling, and leading out of the tree: kept as written.
        let target = secret.to_str().unwrap();
        symlink(target, root.path().join("out")).unwrap();
        symlink("no/such/file", root.path().join("dangling")).unwrap();
        symlink("../..", root.path().join("up")).unwrap();
        let tree = walked(root.path()).tree;
        assert_eq!(paths(&tree), ["/dangling", "/out", "/up"]);
        let Kind::Symlink(out) = get(&tree, "/out") else {
            panic!("not a symlink");
        };
        assert_eq!(out.target.as_str(), target);
    }

    #[test]
    fn the_root_may_be_reached_through_a_symlink() {
        let real = temp();
        file(real.path(), "f", b"x", 0o644);
        let holder = temp();
        let link = holder.path().join("root");
        symlink(real.path(), &link).unwrap();
        assert_eq!(paths(&walked(&link).tree), ["/f"]);
    }

    #[test]
    fn a_missing_or_wrong_root_is_named() {
        let holder = temp();
        let missing = holder.path().join("missing");
        let e = refused(&missing);
        assert!(e.path.ends_with("/missing"), "{e}");
        assert!(matches!(e.kind, WalkErrorKind::Io { .. }), "{e}");
        let plain = file(holder.path(), "plain", b"x", 0o644);
        let e = refused(&plain);
        assert!(e.to_string().contains("can't open the directory"), "{e}");
    }

    #[test]
    fn fifos_and_sockets_are_refused() {
        let root = temp();
        let sub = dir(root.path(), "sub", 0o755);
        let fd = rustix::fs::open(
            &sub,
            rustix::fs::OFlags::RDONLY.union(rustix::fs::OFlags::DIRECTORY),
            Mode::empty(),
        )
        .unwrap();
        mknodat(&fd, "pipe", FileType::Fifo, Mode::RUSR.union(Mode::WUSR), 0).unwrap();
        let e = refused(root.path());
        assert_eq!(e.path, "/sub/pipe");
        assert_eq!(e.to_string(), "/sub/pipe: a FIFO can't be packaged");
        fs::remove_file(sub.join("pipe")).unwrap();

        let _socket = UnixListener::bind(sub.join("sock")).unwrap();
        let e = refused(root.path());
        assert_eq!(e.to_string(), "/sub/sock: a socket can't be packaged");
    }

    #[test]
    fn names_a_tree_cannot_hold_are_refused_safely() {
        let root = temp();
        let bad = root.path().join(OsStr::from_bytes(b"bad\xff\x1b[31m"));
        fs::write(&bad, b"x").unwrap();
        let e = refused(root.path());
        assert!(matches!(e.kind, WalkErrorKind::NotUtf8), "{e}");
        assert_eq!(e.path, "/bad\u{fffd}\\u{1b}[31m");
        fs::remove_file(&bad).unwrap();

        let control = root.path().join("tab\there");
        fs::write(&control, b"x").unwrap();
        let e = refused(root.path());
        assert!(matches!(e.kind, WalkErrorKind::BadPath(_)), "{e}");
        assert_eq!(e.path, "/tab\\there");
    }

    #[test]
    fn symlink_targets_a_tree_cannot_hold_are_refused() {
        let root = temp();
        let link = root.path().join("l");
        symlink(OsStr::from_bytes(b"bad\xff"), &link).unwrap();
        assert!(matches!(
            refused(root.path()).kind,
            WalkErrorKind::TargetNotUtf8
        ));
        fs::remove_file(&link).unwrap();
        symlink("tab\there", &link).unwrap();
        let e = refused(root.path());
        assert!(matches!(e.kind, WalkErrorKind::BadTarget(_)), "{e}");
    }

    #[test]
    fn what_a_tree_refuses_stops_the_walk() {
        let root = temp();
        let f = file(root.path(), "f", b"x", 0o644);
        // One more than a tree's limit of 16.
        for n in 0..17 {
            xattr(&f, &format!("user.k{n}"), b"v");
        }
        let e = refused(root.path());
        assert!(matches!(e.kind, WalkErrorKind::Tree(_)), "{e}");
        assert_eq!(e.path, "/");
    }

    #[test]
    fn attribute_names_a_tree_cannot_hold_are_refused() {
        // The kernel allows a space here, and a tree doesn't.
        let root = temp();
        let f = file(root.path(), "f", b"x", 0o644);
        xattr(&f, "user.a b", b"v");
        let e = refused(root.path());
        assert_eq!(e.path, "/f");
        assert!(matches!(e.kind, WalkErrorKind::BadAttribute(_)), "{e}");
    }

    #[test]
    fn unreadable_things_are_named() {
        let root = temp();
        if fs::metadata(root.path()).unwrap().uid() == 0 {
            return; // Root reads everything.
        }
        let locked = file(root.path(), "locked", b"x", 0o000);
        let e = refused(root.path());
        assert_eq!(e.path, "/locked");
        assert!(e.to_string().contains("can't open the file"), "{e}");
        fs::remove_file(locked).unwrap();

        let closed = dir(root.path(), "closed", 0o000);
        let e = refused(root.path());
        assert_eq!(e.path, "/closed");
        assert!(e.to_string().contains("can't open the directory"), "{e}");
        chmod(&closed, 0o755);
    }

    fn setuid_sample(root: &Path) {
        let bin = dir(root, "bin", 0o2755);
        file(&bin, "su", b"su", 0o4755);
        file(&bin, "wall", b"wall", 0o2755);
        file(&bin, "both", b"both", 0o6755);
        file(&bin, "plain", b"plain", 0o755);
        file(&bin, "sticky", b"sticky", 0o1755);
    }

    #[test]
    fn undeclared_setuid_and_setgid_files_are_warned_about() {
        let root = temp();
        setuid_sample(root.path());
        let warnings = walked(root.path()).warnings;
        let text: Vec<String> = warnings.iter().map(ToString::to_string).collect();
        // A setgid directory is ordinary, and draws nothing.
        assert_eq!(
            text,
            [
                "/bin/both: not declared: setuid, so it runs as root, the default \
                 (--owner sets another); setgid, so it runs with group root, the default \
                 (--owner sets another)",
                "/bin/su: not declared: setuid, so it runs as root, the default \
                 (--owner sets another)",
                "/bin/wall: not declared: setgid, so it runs with group root, the default \
                 (--owner sets another)",
            ]
        );
    }

    #[test]
    fn a_chosen_owner_is_reported_as_chosen() {
        let root = temp();
        setuid_sample(root.path());
        let warnings = walk(root.path(), &with_owners(&["/bin/su=app:adm", "/bin=x:y"]))
            .unwrap()
            .warnings;
        let su = warnings
            .iter()
            .find(|w| w.path.as_str() == "/bin/su")
            .unwrap();
        assert_eq!(su.setuid.as_ref().unwrap().as_str(), "app");
        assert_eq!(su.setgid, None);
        assert!(!su.default_owner);
        let wall = warnings
            .iter()
            .find(|w| w.path.as_str() == "/bin/wall")
            .unwrap();
        assert_eq!(wall.setgid.as_ref().unwrap().as_str(), "y");
        assert_eq!(wall.setuid, None);
    }

    #[test]
    fn declared_files_draw_no_warning_under_any_of_their_names() {
        let root = temp();
        let bin = dir(root.path(), "bin", 0o755);
        let su = file(&bin, "su", b"su", 0o4755);
        fs::hard_link(&su, bin.join("zu")).unwrap();
        file(&bin, "other", b"other", 0o4755);
        for declared in ["/bin/su", "/bin/zu"] {
            let options = Options {
                owners: Vec::new(),
                setuid: [declared.parse().unwrap()].into(),
            };
            let warnings = walk(root.path(), &options).unwrap().warnings;
            let warned: Vec<_> = warnings.iter().map(|w| w.path.as_str()).collect();
            assert_eq!(warned, ["/bin/other"], "declaring {declared}");
        }
    }

    /// Keeps doing `change` on another thread and expects a walk to notice.
    fn noticed_while(root: &Path, change: impl Fn(u64) + Send + 'static) {
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let mut round = 0;
            while !stopping.load(Ordering::Relaxed) {
                change(round);
                round += 1;
            }
        });
        let mut noticed = None;
        for _ in 0..2000 {
            if let Err(e) = walk(root, &Options::default()) {
                noticed = Some(e);
                break;
            }
        }
        stop.store(true, Ordering::Relaxed);
        worker.join().unwrap();
        let e = noticed.expect("the walk never noticed");
        assert!(
            matches!(e.kind, WalkErrorKind::Changed | WalkErrorKind::Io { .. }),
            "{e}"
        );
    }

    #[test]
    fn a_file_being_written_is_noticed() {
        let root = temp();
        let path = file(root.path(), "log", &[1; 1 << 20], 0o644);
        noticed_while(root.path(), move |round| {
            let size = 1_000 + round % 1_000;
            fs::write(&path, vec![2; usize::try_from(size).unwrap()]).unwrap();
        });
    }

    #[test]
    fn a_directory_being_changed_is_noticed() {
        let root = temp();
        let sub = dir(root.path(), "sub", 0o755);
        file(&sub, "f", b"x", 0o644);
        let extra = sub.join("extra");
        noticed_while(root.path(), move |round| {
            if round % 2 == 0 {
                fs::write(&extra, b"x").unwrap();
            } else {
                fs::remove_file(&extra).unwrap();
            }
        });
    }

    #[test]
    fn overrides_print_as_they_are_read() {
        let o: OwnerOverride = "/srv/www=www-data:adm".parse().unwrap();
        assert_eq!(o.to_string(), "/srv/www=www-data:adm");
    }
}
