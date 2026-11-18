// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Integration tests: every rule of tree format 1, at the field it applies
//! to, against a fixture that uses every field.

#[cfg(test)]
mod rules {
    use ordin_core::json;
    use ordin_core::{Account, Algorithm, Digest, Mode};
    use ordin_tree::{
        Capabilities, Dir, Entry, Error, ErrorKind, File, Kind, MAX_ENTRIES, MAX_SIZE, Symlink,
        Tree, XATTR_VALUE_MAX, XATTRS_MAX, Xattrs,
    };
    use serde_json::{Value, json};

    const EVERYTHING: &[u8] = include_bytes!("data/everything.json");

    fn digest(seed: &str) -> Digest {
        Digest::blake3(seed.as_bytes())
    }

    fn verity(seed: &str) -> Digest {
        Digest::new(Algorithm::Sha256, *Digest::blake3(seed.as_bytes()).bytes())
    }

    fn dir(path: &str) -> Entry {
        Entry {
            path: path.parse().unwrap(),
            kind: Kind::Dir(Dir {
                mode: Mode::DIR,
                owner: Account::root(),
                group: Account::root(),
                xattrs: Xattrs::new(),
            }),
        }
    }

    fn file(path: &str, size: u64) -> Entry {
        Entry {
            path: path.parse().unwrap(),
            kind: Kind::File(File {
                mode: Mode::FILE,
                owner: Account::root(),
                group: Account::root(),
                size,
                content: digest(path),
                fsverity: verity(path),
                xattrs: Xattrs::new(),
                capabilities: None,
            }),
        }
    }

    fn symlink(path: &str, target: &str) -> Entry {
        Entry {
            path: path.parse().unwrap(),
            kind: Kind::Symlink(Symlink {
                target: target.parse().unwrap(),
                owner: Account::root(),
                group: Account::root(),
            }),
        }
    }

    fn hardlink(path: &str, target: &str) -> Entry {
        Entry {
            path: path.parse().unwrap(),
            kind: Kind::HardLink(target.parse().unwrap()),
        }
    }

    fn caps(names: &[&str]) -> std::collections::BTreeSet<ordin_tree::LinuxCap> {
        names.iter().map(|c| c.parse().unwrap()).collect()
    }

    /// Every field, each set away from its default at least once, and
    /// each entry type more than once.
    fn everything() -> Vec<Entry> {
        let mut ping = file("/usr/bin/ping", 90312);
        if let Kind::File(f) = &mut ping.kind {
            f.mode = Mode::new(0o755).unwrap();
            f.capabilities = Some(Capabilities {
                permitted: caps(&["cap_net_admin", "cap_net_raw"]),
                inheritable: caps(&["cap_net_raw"]),
                effective: true,
            });
        }
        let mut tagged = file("/usr/share/doc/Third Party~1.txt", 0);
        if let Kind::File(f) = &mut tagged.kind {
            f.owner = "_apt".parse().unwrap();
            f.group = "adm".parse().unwrap();
            f.xattrs
                .insert("user.mime_type".parse().unwrap(), b"text/plain".to_vec());
            f.xattrs.insert("user.a".parse().unwrap(), vec![0, 255]);
        }
        let mut mail = dir("/usr/share/mail");
        if let Kind::Dir(d) = &mut mail.kind {
            d.mode = Mode::new(0o2775).unwrap();
            d.owner = "Debian-exim".parse().unwrap();
            d.group = "mail".parse().unwrap();
            d.xattrs
                .insert("user.note".parse().unwrap(), b"spool".to_vec());
        }
        let mut owned_link = symlink("/usr/share/mail/current", "../doc");
        if let Kind::Symlink(l) = &mut owned_link.kind {
            l.owner = "nobody".parse().unwrap();
            l.group = "nogroup".parse().unwrap();
        }
        vec![
            dir("/usr"),
            dir("/usr/bin"),
            ping,
            file("/usr/bin/rg", 5_123_456),
            hardlink("/usr/bin/rg-again", "/usr/bin/rg"),
            hardlink("/usr/bin/ping6", "/usr/bin/ping"),
            symlink("/usr/bin/ripgrep", "rg"),
            dir("/usr/share"),
            dir("/usr/share/doc"),
            tagged,
            file("/usr/share/doc/\u{de}main.go", 12),
            mail,
            owned_link,
            symlink("/usr/share/mail/abs", "/usr/bin/rg"),
        ]
    }

    /// The fixture as a JSON value to edit.
    fn fixture() -> Value {
        serde_json::from_slice(EVERYTHING).unwrap()
    }

    /// Reads a JSON value as a tree, after encoding it canonically.
    fn read(v: &Value) -> Result<Tree, Error> {
        let canonical = json::canonical(&json::parse(&v.to_string()).unwrap());
        Tree::from_canonical_bytes(canonical.as_bytes()).map(|(t, _)| t)
    }

    /// The fixture after `f` changes it, read as a tree.
    fn edited(f: impl FnOnce(&mut Value)) -> Result<Tree, Error> {
        let mut v = fixture();
        f(&mut v);
        read(&v)
    }

    /// Sets the value at a JSON pointer, adding the field if it is
    /// missing.
    fn set(pointer: &str, value: Value) -> impl FnOnce(&mut Value) + use<> {
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        let (parent, key) = (parent.to_owned(), key.to_owned());
        move |v| match v.pointer_mut(&parent).unwrap() {
            Value::Object(map) => {
                map.insert(key, value);
            }
            Value::Array(items) => items[key.parse::<usize>().unwrap()] = value,
            other => panic!("can't set {key} in {other}"),
        }
    }

    /// Removes the field at a JSON pointer.
    fn remove(pointer: &str) -> impl FnOnce(&mut Value) + use<> {
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        let (parent, key) = (parent.to_owned(), key.to_owned());
        move |v| {
            v.pointer_mut(&parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(&key)
                .unwrap();
        }
    }

    /// The entry index of each fixture path, so the tests read well.
    const PING: usize = 2;
    const PING6: usize = 3;
    const RG: usize = 4;
    const RG_AGAIN: usize = 5;
    const RIPGREP: usize = 6;
    const TAGGED: usize = 9;
    const MAIL: usize = 11;
    const ABS: usize = 12;

    fn at(index: usize) -> String {
        format!("/entries/{index}")
    }

    /// Asserts where an error is and what kind it is.
    fn is(e: &Error, entry: Option<usize>, field: Option<&str>, kind: &ErrorKind) {
        assert_eq!(e.at.entry.as_ref().map(|(i, _)| *i), entry, "{e}");
        assert_eq!(e.at.field.as_deref(), field, "{e}");
        assert_eq!(&e.kind, kind, "{e}");
    }

    #[test]
    fn the_fixture_is_everything_encoded() {
        let t = Tree::new(everything()).unwrap();
        assert_eq!(t.to_canonical_bytes().unwrap(), EVERYTHING);
        let (read, id) = Tree::from_canonical_bytes(EVERYTHING).unwrap();
        assert_eq!(read, t);
        assert_eq!(id, Digest::blake3(EVERYTHING));
        assert_eq!(t.digest().unwrap(), id);
        assert_eq!(read.entries().len(), 14);
        // Every field is used, so nothing the reader accepts goes untested.
        let text = std::str::from_utf8(EVERYTHING).unwrap();
        for field in [
            "capabilities",
            "content",
            "effective",
            "fsverity",
            "group",
            "inheritable",
            "mode",
            "owner",
            "path",
            "permitted",
            "size",
            "target",
            "type",
            "xattrs",
        ] {
            assert!(text.contains(&format!("\"{field}\":")), "{field}");
        }
    }

    #[test]
    fn new_sorts_entries_and_get_finds_them() {
        let mut shuffled = everything();
        shuffled.reverse();
        shuffled.swap(3, 9);
        let t = Tree::new(shuffled).unwrap();
        assert_eq!(t.to_canonical_bytes().unwrap(), EVERYTHING);
        for e in t.entries() {
            assert_eq!(t.get(e.path.as_str()), Some(e));
        }
        assert_eq!(t.get("/usr/bin/nothing"), None);
        assert_eq!(t.get("/"), None);
        let empty = Tree::new(vec![]).unwrap();
        assert_eq!(
            empty.to_canonical_bytes().unwrap(),
            br#"{"entries":[],"ordin-tree":1}"#
        );
    }

    #[test]
    fn bytes_must_be_canonical_utf8_json_within_the_size_limit() {
        let e = Tree::from_canonical_bytes(&vec![b' '; MAX_SIZE + 1]).unwrap_err();
        is(
            &e,
            None,
            None,
            &ErrorKind::TooLarge {
                max: MAX_SIZE,
                len: MAX_SIZE + 1,
            },
        );
        // Exactly the limit is read (and is not JSON).
        let e = Tree::from_canonical_bytes(&vec![b' '; MAX_SIZE]).unwrap_err();
        assert!(matches!(e.kind, ErrorKind::Json(_)), "{e}");
        let e = Tree::from_canonical_bytes(b"\xff").unwrap_err();
        is(&e, None, None, &ErrorKind::NotUtf8);
        let e = Tree::from_canonical_bytes(br#"{"a":1,"a":2}"#).unwrap_err();
        assert!(
            matches!(&e.kind, ErrorKind::Json(m) if m.contains("twice")),
            "{e}"
        );
        let spaced = String::from_utf8(EVERYTHING.to_vec())
            .unwrap()
            .replacen(':', ": ", 1);
        let e = Tree::from_canonical_bytes(spaced.as_bytes()).unwrap_err();
        is(&e, None, None, &ErrorKind::NotCanonical { at: 11 });
        assert!(e.to_string().contains("first difference is at byte 11"));
    }

    #[test]
    fn the_top_level_has_a_known_format_and_entries() {
        let wrong = |expected, found| ErrorKind::WrongType { expected, found };
        is(
            &read(&json!([])).unwrap_err(),
            None,
            None,
            &wrong("an object", "an array"),
        );
        let e = edited(remove("/ordin-tree")).unwrap_err();
        is(&e, None, Some("ordin-tree"), &ErrorKind::Missing);
        for (version, shown) in [(json!(2), "2"), (json!("1"), "\"1\""), (json!(0), "0")] {
            let e = edited(set("/ordin-tree", version)).unwrap_err();
            is(
                &e,
                None,
                Some("ordin-tree"),
                &ErrorKind::UnknownFormat(shown.into()),
            );
        }
        // The format is checked before any other field, so a newer tree
        // says so instead of naming a field.
        let e = read(&json!({"ordin-tree": 2, "facet": "doc"})).unwrap_err();
        assert_eq!(e.kind, ErrorKind::UnknownFormat("2".into()));
        let e = edited(set("/facet", json!("doc"))).unwrap_err();
        is(&e, None, Some("facet"), &ErrorKind::UnknownField);
        let e = edited(remove("/entries")).unwrap_err();
        is(&e, None, Some("entries"), &ErrorKind::Missing);
        let e = edited(set("/entries", json!({}))).unwrap_err();
        is(&e, None, Some("entries"), &wrong("an array", "an object"));
    }

    #[test]
    fn the_entry_count_is_limited() {
        let names = |n: usize| {
            (0..n)
                .map(|i| dir(&format!("/d{i:06}")))
                .collect::<Vec<_>>()
        };
        let t = Tree::new(names(MAX_ENTRIES)).unwrap();
        let bytes = t.to_canonical_bytes().unwrap();
        assert_eq!(
            Tree::from_canonical_bytes(&bytes)
                .unwrap()
                .0
                .entries()
                .len(),
            MAX_ENTRIES
        );
        let too_many = ErrorKind::TooManyEntries {
            max: MAX_ENTRIES,
            len: MAX_ENTRIES + 1,
        };
        let e = Tree::new(names(MAX_ENTRIES + 1)).unwrap_err();
        is(&e, None, Some("entries"), &too_many);
        let entries: Vec<Value> = (0..=MAX_ENTRIES)
            .map(|i| json!({"path": format!("/d{i:06}"), "type": "dir"}))
            .collect();
        let e = read(&json!({"ordin-tree": 1, "entries": entries})).unwrap_err();
        is(&e, None, Some("entries"), &too_many);
    }

    #[test]
    fn every_entry_is_an_object_with_a_path_and_a_known_type() {
        let e = edited(set(&at(RG), json!("/usr/bin/rg"))).unwrap_err();
        is(
            &e,
            Some(RG),
            None,
            &ErrorKind::WrongType {
                expected: "an object",
                found: "a string",
            },
        );
        assert_eq!(e.at.entry, Some((RG, None)));
        let e = edited(remove(&format!("{}/path", at(RG)))).unwrap_err();
        is(&e, Some(RG), Some("path"), &ErrorKind::Missing);
        let e = edited(set(&format!("{}/path", at(RG)), json!(7))).unwrap_err();
        is(
            &e,
            Some(RG),
            Some("path"),
            &ErrorKind::WrongType {
                expected: "a string",
                found: "an integer",
            },
        );
        let e = edited(set(&format!("{}/path", at(RG)), json!("usr/bin/rg"))).unwrap_err();
        assert!(
            matches!(&e.kind, ErrorKind::Invalid(m) if m.contains("absolute")),
            "{e}"
        );
        assert_eq!(e.at.entry, Some((RG, None)));
        let e = edited(remove(&format!("{}/type", at(RG)))).unwrap_err();
        is(&e, Some(RG), Some("type"), &ErrorKind::Missing);
        assert_eq!(e.at.entry, Some((RG, Some("/usr/bin/rg".into()))));
        for other in ["fifo", "socket", "char-device", "block-device", "File"] {
            let e = edited(set(&format!("{}/type", at(RG)), json!(other))).unwrap_err();
            is(
                &e,
                Some(RG),
                Some("type"),
                &ErrorKind::UnknownType(other.into()),
            );
            assert!(
                e.to_string()
                    .contains("device nodes, sockets and FIFOs can't be packaged")
            );
        }
    }

    #[test]
    fn each_type_has_only_its_own_fields() {
        for (index, field, value) in [
            (RG, "target", json!("x")),
            (MAIL, "size", json!(1)),
            (MAIL, "content", json!("x")),
            (RIPGREP, "mode", json!("0777")),
            (RIPGREP, "xattrs", json!({})),
            (RG_AGAIN, "owner", json!("nobody")),
            (RG_AGAIN, "mode", json!("0755")),
            (RG, "mtime", json!(0)),
        ] {
            let e = edited(set(&format!("{}/{field}", at(index)), value)).unwrap_err();
            is(&e, Some(index), Some(field), &ErrorKind::UnknownField);
        }
    }

    #[test]
    fn modes_owners_and_groups_leave_out_their_defaults() {
        for (index, mode) in [(RG, "0644"), (MAIL, "0755")] {
            let e = edited(set(&format!("{}/mode", at(index)), json!(mode))).unwrap_err();
            is(&e, Some(index), Some("mode"), &ErrorKind::DefaultValue);
        }
        // The other type's default is an ordinary value.
        assert!(edited(set(&format!("{}/mode", at(RG)), json!("0755"))).is_ok());
        assert!(edited(set(&format!("{}/mode", at(MAIL)), json!("0644"))).is_ok());
        let e = edited(set(&format!("{}/mode", at(RG)), json!("0999"))).unwrap_err();
        assert!(
            matches!(&e.kind, ErrorKind::Invalid(m) if m.contains("four octal digits")),
            "{e}"
        );
        for (index, field) in [
            (TAGGED, "owner"),
            (TAGGED, "group"),
            (MAIL, "owner"),
            (ABS, "group"),
        ] {
            let e = edited(set(&format!("{}/{field}", at(index)), json!("root"))).unwrap_err();
            is(&e, Some(index), Some(field), &ErrorKind::DefaultValue);
            let e = edited(set(&format!("{}/{field}", at(index)), json!("9x"))).unwrap_err();
            assert!(
                matches!(&e.kind, ErrorKind::Invalid(m) if m.contains("account name")),
                "{e}"
            );
        }
    }

    #[test]
    fn files_record_a_size_and_both_digests() {
        let e = edited(remove(&format!("{}/size", at(RG)))).unwrap_err();
        is(&e, Some(RG), Some("size"), &ErrorKind::Missing);
        let e = edited(set(&format!("{}/size", at(RG)), json!(-1))).unwrap_err();
        assert!(
            matches!(&e.kind, ErrorKind::Invalid(m) if m.contains("negative")),
            "{e}"
        );
        let e = edited(set(&format!("{}/size", at(RG)), json!("1"))).unwrap_err();
        is(
            &e,
            Some(RG),
            Some("size"),
            &ErrorKind::WrongType {
                expected: "an integer",
                found: "a string",
            },
        );
        assert!(edited(set(&format!("{}/size", at(RG)), json!(json::MAX_INT))).is_ok());
        for field in ["content", "fsverity"] {
            let e = edited(remove(&format!("{}/{field}", at(RG)))).unwrap_err();
            is(&e, Some(RG), Some(field), &ErrorKind::Missing);
            let e = edited(set(&format!("{}/{field}", at(RG)), json!("md5:00"))).unwrap_err();
            assert!(
                matches!(&e.kind, ErrorKind::Invalid(m) if m.contains("digest")),
                "{e}"
            );
        }
        let swapped = |field: &str, digest: Digest| {
            set(&format!("{}/{field}", at(RG)), json!(digest.to_string()))
        };
        let e = edited(swapped("content", verity("x"))).unwrap_err();
        is(
            &e,
            Some(RG),
            Some("content"),
            &ErrorKind::WrongAlgorithm {
                expected: Algorithm::Blake3,
            },
        );
        let e = edited(swapped("fsverity", digest("x"))).unwrap_err();
        is(
            &e,
            Some(RG),
            Some("fsverity"),
            &ErrorKind::WrongAlgorithm {
                expected: Algorithm::Sha256,
            },
        );
    }

    /// The file at `path` in `entries`.
    fn file_mut<'a>(entries: &'a mut [Entry], path: &str) -> &'a mut File {
        match entries
            .iter_mut()
            .find(|e| e.path.as_str() == path)
            .map(|e| &mut e.kind)
        {
            Some(Kind::File(f)) => f,
            _ => panic!("no file at {path}"),
        }
    }

    #[test]
    fn struct_built_trees_are_held_to_the_same_rules() {
        let with = |f: &dyn Fn(&mut File)| {
            let mut entries = everything();
            f(file_mut(&mut entries, "/usr/bin/rg"));
            Tree::new(entries).unwrap_err()
        };
        let max = json::MAX_INT.unsigned_abs();
        let e = with(&|f| f.size = max + 1);
        is(
            &e,
            Some(RG),
            Some("size"),
            &ErrorKind::OutOfRange {
                max,
                value: max + 1,
            },
        );
        let e = with(&|f| f.content = verity("x"));
        is(
            &e,
            Some(RG),
            Some("content"),
            &ErrorKind::WrongAlgorithm {
                expected: Algorithm::Blake3,
            },
        );
        let e = with(&|f| f.fsverity = digest("x"));
        is(
            &e,
            Some(RG),
            Some("fsverity"),
            &ErrorKind::WrongAlgorithm {
                expected: Algorithm::Sha256,
            },
        );
        let e = with(&|f| {
            f.capabilities = Some(Capabilities {
                permitted: caps(&[]),
                inheritable: caps(&[]),
                effective: true,
            });
        });
        is(
            &e,
            Some(RG),
            Some("capabilities"),
            &ErrorKind::EmptyCapabilities,
        );
        // At the limit, a size is fine.
        let mut entries = everything();
        file_mut(&mut entries, "/usr/bin/rg").size = max;
        assert!(Tree::new(entries).unwrap().to_canonical_bytes().is_ok());
    }

    #[test]
    fn xattrs_are_user_attributes_in_canonical_base64() {
        let x = |name: &str| format!("{}/xattrs/{name}", at(TAGGED));
        let e = edited(set(&format!("{}/xattrs", at(TAGGED)), json!({}))).unwrap_err();
        is(&e, Some(TAGGED), Some("xattrs"), &ErrorKind::DefaultValue);
        let e = edited(set(&format!("{}/xattrs", at(TAGGED)), json!([]))).unwrap_err();
        is(
            &e,
            Some(TAGGED),
            Some("xattrs"),
            &ErrorKind::WrongType {
                expected: "an object",
                found: "an array",
            },
        );
        for name in [
            "trusted.overlay.redirect",
            "security.capability",
            "security.selinux",
            "system.posix_acl_access",
        ] {
            let e = edited(set(&x(name), json!("AA=="))).unwrap_err();
            assert!(
                matches!(&e.kind, ErrorKind::Invalid(m) if m.contains("only user.*")),
                "{e}"
            );
            assert_eq!(
                e.at.field.as_deref(),
                Some(format!("xattrs.{name}").as_str())
            );
        }
        let e = edited(set(&x("user.a"), json!(1))).unwrap_err();
        is(
            &e,
            Some(TAGGED),
            Some("xattrs.user.a"),
            &ErrorKind::WrongType {
                expected: "a string",
                found: "an integer",
            },
        );
        let e = edited(set(&x("user.a"), json!("AP9="))).unwrap_err();
        assert!(
            matches!(&e.kind, ErrorKind::Invalid(m) if m.contains("canonical base64")),
            "{e}"
        );
        // Directories carry them too.
        let e = edited(set(
            &format!("{}/xattrs/user.note", at(MAIL)),
            json!("c3Bvb2w"),
        ))
        .unwrap_err();
        is(
            &e,
            Some(MAIL),
            Some("xattrs.user.note"),
            &ErrorKind::Invalid("\"c3Bvb2w\" isn't canonical base64 (RFC 4648, padded)".into()),
        );
    }

    #[test]
    fn xattrs_have_count_and_size_limits() {
        let many = |n: usize| {
            let map: serde_json::Map<String, Value> = (0..n)
                .map(|i| (format!("user.k{i:02}"), json!("AA==")))
                .collect();
            set(&format!("{}/xattrs", at(TAGGED)), Value::Object(map))
        };
        assert!(edited(many(XATTRS_MAX)).is_ok());
        let e = edited(many(XATTRS_MAX + 1)).unwrap_err();
        is(
            &e,
            Some(TAGGED),
            Some("xattrs"),
            &ErrorKind::TooManyXattrs {
                max: XATTRS_MAX,
                len: XATTRS_MAX + 1,
            },
        );
        let value = |len: usize| {
            set(
                &format!("{}/xattrs/user.a", at(TAGGED)),
                json!(ordin_tree::base64_encode(&vec![7; len])),
            )
        };
        assert!(edited(value(XATTR_VALUE_MAX)).is_ok());
        let e = edited(value(XATTR_VALUE_MAX + 1)).unwrap_err();
        is(
            &e,
            Some(TAGGED),
            Some("xattrs.user.a"),
            &ErrorKind::XattrTooLarge {
                max: XATTR_VALUE_MAX,
                len: XATTR_VALUE_MAX + 1,
            },
        );
        // The limits hold on directories as well.
        let e = edited(|v| {
            let map: serde_json::Map<String, Value> = (0..=XATTRS_MAX)
                .map(|i| (format!("user.k{i:02}"), json!("AA==")))
                .collect();
            *v.pointer_mut(&format!("{}/xattrs", at(MAIL))).unwrap() = Value::Object(map);
        })
        .unwrap_err();
        is(
            &e,
            Some(MAIL),
            Some("xattrs"),
            &ErrorKind::TooManyXattrs {
                max: XATTRS_MAX,
                len: XATTRS_MAX + 1,
            },
        );
    }

    #[test]
    fn capabilities_are_named_sorted_sets() {
        let c = |key: &str| format!("{}/capabilities/{key}", at(PING));
        let e = edited(set(
            &format!("{}/capabilities", at(PING)),
            json!(["cap_net_raw"]),
        ))
        .unwrap_err();
        is(
            &e,
            Some(PING),
            Some("capabilities"),
            &ErrorKind::WrongType {
                expected: "an object",
                found: "an array",
            },
        );
        let e = edited(set(&c("ambient"), json!(["cap_net_raw"]))).unwrap_err();
        is(
            &e,
            Some(PING),
            Some("capabilities.ambient"),
            &ErrorKind::UnknownField,
        );
        let e = edited(set(&c("effective"), json!(false))).unwrap_err();
        is(
            &e,
            Some(PING),
            Some("capabilities.effective"),
            &ErrorKind::DefaultValue,
        );
        let e = edited(set(&c("effective"), json!(1))).unwrap_err();
        is(
            &e,
            Some(PING),
            Some("capabilities.effective"),
            &ErrorKind::WrongType {
                expected: "a boolean",
                found: "an integer",
            },
        );
        assert!(edited(remove(&c("effective"))).is_ok());
        for key in ["permitted", "inheritable"] {
            let field = format!("capabilities.{key}");
            let e = edited(set(&c(key), json!([]))).unwrap_err();
            is(&e, Some(PING), Some(&field), &ErrorKind::DefaultValue);
            let e = edited(set(&c(key), json!("cap_net_raw"))).unwrap_err();
            is(
                &e,
                Some(PING),
                Some(&field),
                &ErrorKind::WrongType {
                    expected: "an array",
                    found: "a string",
                },
            );
            let e = edited(set(&c(key), json!(["CAP_NET_RAW"]))).unwrap_err();
            assert!(
                matches!(&e.kind, ErrorKind::Invalid(m) if m.contains("isn't a Linux capability")),
                "{e}"
            );
            for bad in [
                json!(["cap_net_raw", "cap_net_admin"]),
                json!(["cap_net_raw", "cap_net_raw"]),
            ] {
                let e = edited(set(&c(key), bad)).unwrap_err();
                assert!(
                    matches!(&e.kind, ErrorKind::Invalid(m) if m.contains("sorted by name, without repeats")),
                    "{e}"
                );
            }
            assert!(
                edited(set(
                    &c(key),
                    json!(["cap_chown", "cap_net_raw", "cap_sys_admin"])
                ))
                .is_ok()
            );
            // Either set alone is enough.
            assert!(edited(remove(&c(key))).is_ok());
        }
        let e = edited(|v| {
            remove(&c("permitted"))(v);
            remove(&c("inheritable"))(v);
        })
        .unwrap_err();
        is(
            &e,
            Some(PING),
            Some("capabilities"),
            &ErrorKind::EmptyCapabilities,
        );
    }

    #[test]
    fn symlinks_and_hard_links_need_a_target() {
        for index in [RIPGREP, RG_AGAIN] {
            let e = edited(remove(&format!("{}/target", at(index)))).unwrap_err();
            is(&e, Some(index), Some("target"), &ErrorKind::Missing);
        }
        let e = edited(set(&format!("{}/target", at(RIPGREP)), json!(""))).unwrap_err();
        assert!(
            matches!(&e.kind, ErrorKind::Invalid(m) if m.contains("can't be empty")),
            "{e}"
        );
        let e = edited(set(&format!("{}/target", at(RG_AGAIN)), json!("rg"))).unwrap_err();
        assert!(
            matches!(&e.kind, ErrorKind::Invalid(m) if m.contains("absolute")),
            "{e}"
        );
    }

    #[test]
    fn entries_are_sorted_and_unique() {
        let e = edited(|v| v["entries"].as_array_mut().unwrap().swap(RG, RG_AGAIN)).unwrap_err();
        is(
            &e,
            Some(RG_AGAIN),
            None,
            &ErrorKind::NotSorted {
                previous: "/usr/bin/rg-again".into(),
            },
        );
        let e = edited(|v| {
            let copy = v["entries"][RG].clone();
            v["entries"].as_array_mut().unwrap().insert(RG, copy);
        })
        .unwrap_err();
        is(&e, Some(RG + 1), None, &ErrorKind::Duplicate);
        let mut twice = everything();
        twice.push(file("/usr/bin/rg", 1));
        let e = Tree::new(twice).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Duplicate);
    }

    #[test]
    fn every_parent_is_a_directory_in_the_tree() {
        let mut entries = everything();
        entries.push(file("/usr/lib/x.so", 1));
        let e = Tree::new(entries).unwrap_err();
        is(
            &e,
            Some(7),
            None,
            &ErrorKind::NoParent {
                parent: "/usr/lib".into(),
            },
        );
        for (parent, found) in [
            ("/usr/bin/rg", "file"),
            ("/usr/bin/ripgrep", "symlink"),
            ("/usr/bin/rg-again", "hardlink"),
        ] {
            let mut entries = everything();
            entries.push(file(&format!("{parent}/x"), 1));
            let e = Tree::new(entries).unwrap_err();
            assert_eq!(
                e.kind,
                ErrorKind::ParentNotDir {
                    parent: parent.into(),
                    found
                },
                "{e}"
            );
        }
        // Top-level entries need no parent entry.
        assert!(Tree::new(vec![file("/top", 1)]).is_ok());
        let e = edited(|v| {
            v["entries"].as_array_mut().unwrap().remove(1);
        })
        .unwrap_err();
        is(
            &e,
            Some(1),
            None,
            &ErrorKind::NoParent {
                parent: "/usr/bin".into(),
            },
        );
    }

    #[test]
    fn hard_links_point_at_files_in_the_tree() {
        let link = |target: &str| {
            let mut entries = everything();
            entries.push(hardlink("/usr/bin/zz", target));
            Tree::new(entries).unwrap_err()
        };
        let e = link("/usr/bin/missing");
        assert_eq!(
            e.kind,
            ErrorKind::LinkTargetMissing {
                target: "/usr/bin/missing".into()
            }
        );
        assert_eq!(e.at.field.as_deref(), Some("target"));
        for (target, found) in [
            ("/usr/bin", "dir"),
            ("/usr/bin/ripgrep", "symlink"),
            ("/usr/bin/ping6", "hardlink"),
        ] {
            let e = link(target);
            assert_eq!(
                e.kind,
                ErrorKind::LinkTargetNotFile {
                    target: target.into(),
                    found
                },
                "{e}"
            );
        }
        // Both fixture links point at different files, and both are fine.
        let t = Tree::new(everything()).unwrap();
        for (index, target) in [(PING6, "/usr/bin/ping"), (RG_AGAIN, "/usr/bin/rg")] {
            assert_eq!(
                t.entries()[index].kind,
                Kind::HardLink(target.parse().unwrap())
            );
        }
    }

    #[test]
    fn errors_say_where_they_are() {
        let e = edited(set(&format!("{}/mode", at(RG)), json!("0644"))).unwrap_err();
        assert_eq!(
            e.to_string(),
            "entry 4 (\"/usr/bin/rg\"), field \"mode\": written with its default value, which must be left out"
        );
        let mut entries = everything();
        entries.push(file("/usr/lib/x.so", 1));
        assert_eq!(
            Tree::new(entries).unwrap_err().to_string(),
            "entry 7 (\"/usr/lib/x.so\"): its parent \"/usr/lib\" isn't in the tree; every parent must be a dir entry"
        );
    }
}
