// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Manifests end to end: reading, canonical bytes, identity, and every
//! rule of SCHEMA.md refusing what it should, at the right field.

use ordin_manifest::{ErrorKind, MAX_SIZE, Manifest};
use serde_json::Value;

type R<T> = Result<T, Box<dyn std::error::Error>>;

const EVERYTHING: &str = include_str!("data/everything.json");
const MINIMAL: &str = include_str!("data/minimal.json");
const UPDATE: &str = include_str!("data/update.json");

/// `text` with the value at JSON pointer `at` replaced by `new` (JSON), or
/// removed when `new` is `None`. Missing parents are not created.
fn edit(text: &str, at: &str, new: Option<&str>) -> R<String> {
    let mut v: Value = serde_json::from_str(text)?;
    let (parent, key) = at.rsplit_once('/').ok_or("pointer without '/'")?;
    let target = v
        .pointer_mut(parent)
        .ok_or_else(|| format!("no {parent}"))?;
    match (target, new) {
        (Value::Object(m), Some(new)) => {
            m.insert(key.to_owned(), serde_json::from_str(new)?);
        }
        (Value::Object(m), None) => {
            m.remove(key).ok_or_else(|| format!("no {at}"))?;
        }
        (Value::Array(a), Some(new)) => {
            let i: usize = key.parse()?;
            *a.get_mut(i).ok_or("no index")? = serde_json::from_str(new)?;
        }
        (Value::Array(a), None) => {
            a.remove(key.parse()?);
        }
        _ => return Err(format!("{parent} isn't a container").into()),
    }
    Ok(serde_json::to_string(&v)?)
}

/// Expects `text` to be refused at `path` with a message containing
/// `message`.
fn refused(text: &str, path: &str, message: &str) -> R<()> {
    match Manifest::from_json(text) {
        Ok(_) => Err(format!("accepted, expected {path}: {message}").into()),
        Err(e) => {
            let shown = e.to_string();
            if e.path.to_string() == path && shown.contains(message) {
                Ok(())
            } else {
                Err(format!("expected {path}: …{message}…, got {shown}").into())
            }
        }
    }
}

fn try_check(base: &str, at: &str, new: Option<&str>, path: &str, message: &str) -> R<()> {
    let text = edit(base, at, new).map_err(|e| format!("{at}: {e}"))?;
    refused(&text, path, message).map_err(|e| format!("{at} = {new:?}: {e}").into())
}

/// Edits one field of a fixture and expects the error at `path`.
macro_rules! check {
    ($($arg:expr),+ $(,)?) => {
        try_check($($arg),+).unwrap()
    };
}

#[test]
fn the_fixtures_read_and_round_trip_byte_for_byte() {
    for (name, text) in [
        ("everything", EVERYTHING),
        ("minimal", MINIMAL),
        ("update", UPDATE),
    ] {
        let m = Manifest::from_json(text).unwrap_or_else(|e| panic!("{name}: {e}"));
        let bytes = m
            .to_canonical_bytes()
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let (again, digest) =
            Manifest::from_signed_bytes(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(again, m, "{name}");
        assert_eq!(again.to_canonical_bytes().unwrap(), bytes, "{name}");
        assert_eq!(m.digest().unwrap(), digest, "{name}");
    }
}

#[test]
fn ignorable_fields_are_kept_in_place_and_counted_in_the_identity() {
    let m = Manifest::from_json(EVERYTHING).unwrap();
    let bytes = String::from_utf8(m.to_canonical_bytes().unwrap()).unwrap();
    assert!(bytes.contains(r#""digest-v2":"future""#), "{bytes}");
    assert!(bytes.contains(r#""uid":33"#), "{bytes}");
    // Changing an ignored value changes the identity.
    let changed = edit(EVERYTHING, "/declares/users/0/uid", Some("34")).unwrap();
    let other = Manifest::from_json(&changed).unwrap();
    assert_ne!(other.digest().unwrap(), m.digest().unwrap());
}

#[test]
fn the_identity_is_the_blake3_of_the_canonical_bytes() {
    let m = Manifest::from_json(MINIMAL).unwrap();
    let bytes = m.to_canonical_bytes().unwrap();
    assert_eq!(
        String::from_utf8(bytes.clone()).unwrap(),
        concat!(
            r#"{"arch":"x86_64","facets":{"runtime":{"size":4096,"tree":"blake3:"#,
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            r#""}},"kind":"base","license":{"spdx":"GPL-3.0-or-later","texts":{"GPL-3.0-or-later":"blake3:"#,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            r#""}},"name":"hello","ordin":1,"summary":"Prints a friendly greeting","version":{"release":"1","upstream":"2.12"}}"#
        )
    );
    assert_eq!(m.digest().unwrap(), ordin_core::Digest::blake3(&bytes));
    // One changed character, a different package.
    let other = Manifest::from_json(
        &edit(MINIMAL, "/summary", Some(r#""Prints a friendly greetinG""#)).unwrap(),
    )
    .unwrap();
    assert_ne!(other.digest().unwrap(), m.digest().unwrap());
}

#[test]
fn signed_bytes_must_already_be_canonical() {
    let canonical = Manifest::from_json(MINIMAL)
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
    assert!(Manifest::from_signed_bytes(&canonical).is_ok());
    let not = |bytes: &[u8], at: usize| {
        let e = Manifest::from_signed_bytes(bytes).unwrap_err();
        assert_eq!(e.kind, ErrorKind::NotCanonical { at }, "{e}");
    };
    // Pretty-printed, a trailing newline, a key out of order.
    not(MINIMAL.as_bytes(), 1);
    let mut newline = canonical.clone();
    newline.push(b'\n');
    not(&newline, canonical.len());
    let swapped = String::from_utf8(canonical.clone()).unwrap().replacen(
        r#""arch":"x86_64","facets""#,
        r#""facets""#,
        1,
    );
    let swapped = swapped.replacen(r#""kind":"base""#, r#""arch":"x86_64","kind":"base""#, 1);
    not(swapped.as_bytes(), 2);
    // An escape that RFC 8785 doesn't use.
    let escaped = String::from_utf8(canonical)
        .unwrap()
        .replacen("hello", "hell\\u006f", 1);
    assert!(matches!(
        Manifest::from_signed_bytes(escaped.as_bytes())
            .unwrap_err()
            .kind,
        ErrorKind::NotCanonical { .. }
    ));
}

#[test]
fn malformed_input_is_refused() {
    let kind = |bytes: &[u8]| Manifest::from_signed_bytes(bytes).unwrap_err().kind;
    assert_eq!(
        kind(&vec![b' '; MAX_SIZE + 1]),
        ErrorKind::TooLarge {
            max: MAX_SIZE,
            len: MAX_SIZE + 1
        }
    );
    // Exactly the limit is read (and then refused for what it contains).
    assert!(matches!(kind(&vec![b' '; MAX_SIZE]), ErrorKind::Json(_)));
    assert_eq!(kind(&[0xff, 0xfe]), ErrorKind::NotUtf8);
    assert!(
        matches!(kind(br#"{"ordin":1,"ordin":1}"#), ErrorKind::Json(m) if m.contains("appears twice"))
    );
    assert!(matches!(kind(br#"{"ordin":1.0}"#), ErrorKind::Json(m) if m.contains("integers")));
    assert!(matches!(
        kind(b"[]"),
        ErrorKind::WrongType {
            expected: "an object",
            ..
        }
    ));
    assert!(matches!(kind(b"{}"), ErrorKind::Empty));
    assert!(Manifest::from_json("{").is_err());
}

#[test]
fn the_format_version_and_unknown_fields() {
    check!(
        MINIMAL,
        "/ordin",
        Some("2"),
        "ordin",
        "format 2; Ordin reads format 1",
    );
    check!(
        MINIMAL,
        "/ordin",
        None,
        "the manifest",
        "\"ordin\" is required",
    );
    check!(
        MINIMAL,
        "/ordin",
        Some("\"1\""),
        "ordin",
        "expected an integer",
    );
    check!(
        MINIMAL,
        "/flavor",
        Some("\"x\""),
        "flavor",
        "unknown field \"flavor\"",
    );
    check!(
        MINIMAL,
        "/facets/runtime/digest-v2",
        Some("\"x\""),
        "facets.runtime.digest-v2",
        "unknown field",
    );
    // Ignorable may name only fields the format doesn't define, as paths.
    check!(
        MINIMAL,
        "/ignorable",
        Some(r#"["summary"]"#),
        "ignorable[0]",
        "is a field of this format",
    );
    check!(
        MINIMAL,
        "/ignorable",
        Some(r#"["declares.users.name"]"#),
        "ignorable[0]",
        "is a field of this format",
    );
    check!(
        MINIMAL,
        "/ignorable",
        Some(r#"["a..b"]"#),
        "ignorable[0]",
        "isn't a dotted path",
    );
    check!(
        MINIMAL,
        "/ignorable",
        Some(r#"["b", "a"]"#),
        "ignorable[1]",
        "\"a\" must come before \"b\"",
    );
    check!(
        MINIMAL,
        "/ignorable",
        Some("[]"),
        "ignorable",
        "empty, so it must be left out",
    );
    // A listed path covers the field in every array element and map entry.
    let listed = edit(MINIMAL, "/ignorable", Some(r#"["facets.*.digest-v2"]"#)).unwrap();
    let with = edit(&listed, "/facets/runtime/digest-v2", Some("\"x\"")).unwrap();
    assert!(Manifest::from_json(&with).is_ok());
    // Unknown values are refused even where unknown fields could be ignored.
    check!(
        MINIMAL,
        "/kind",
        Some("\"kmod\""),
        "kind",
        "isn't one of base, update or system-base",
    );
    check!(
        MINIMAL,
        "/arch",
        Some("\"riscv64\""),
        "arch",
        "unknown architecture",
    );
}

#[test]
fn defaults_must_be_left_out() {
    for (at, value, path) in [
        ("/version/epoch", "0", "version.epoch"),
        ("/version/update", "0", "version.update"),
        ("/facets/runtime/default", "true", "facets.runtime.default"),
        (
            "/license/presentation",
            "\"informational\"",
            "license.presentation",
        ),
    ] {
        check!(MINIMAL, at, Some(value), path, "the default value");
    }
    for (at, value, path) in [
        (
            "/declares/users/0/system",
            "true",
            "declares.users[0].system",
        ),
        (
            "/declares/config/1/merge",
            "\"drop-in\"",
            "declares.config[1].merge",
        ),
        ("/state/paths/1/mode", "\"0755\"", "state.paths[1].mode"),
        ("/state/paths/1/owner", "\"root\"", "state.paths[1].owner"),
        ("/state/version", "0", "state.version"),
        ("/state/migration", "\"none\"", "state.migration"),
        ("/hooks/check/0/timeout", "300", "hooks.check[0].timeout"),
        ("/tests/0/timeout", "60", "tests[0].timeout"),
        ("/switch/live-apply", "false", "switch.live-apply"),
        (
            "/delegated/payload-on-upgrade",
            "\"keep-newer\"",
            "delegated.payload-on-upgrade",
        ),
        (
            "/security/selinux/fcontexts/0/file-type",
            "\"all\"",
            "security.selinux.fcontexts[0].file-type",
        ),
        ("/state/files/0/mode", "\"0644\"", "state.files[0].mode"),
    ] {
        check!(EVERYTHING, at, Some(value), path, "the default value");
    }
    check!(MINIMAL, "/provides", Some("[]"), "provides", "empty");
    check!(MINIMAL, "/declares", Some("{}"), "declares", "empty");
    check!(MINIMAL, "/facets", Some("{}"), "facets", "empty");
    check!(
        MINIMAL,
        "/license/texts",
        Some("{}"),
        "license.texts",
        "empty"
    );
}

#[test]
fn sets_and_sorted_arrays_are_in_order() {
    check!(
        EVERYTHING,
        "/requires",
        Some(r#"["so:libc.so.6", "cap:zlib"]"#),
        "requires[1]",
        "\"cap:zlib\" must come before",
    );
    check!(
        EVERYTHING,
        "/fixes",
        Some(r#"["a", "a"]"#),
        "fixes[1]",
        "\"a\" appears twice",
    );
    check!(
        EVERYTHING,
        "/declares/groups",
        Some(r#"[{"name": "z"}, {"name": "a"}]"#),
        "declares.groups[1]",
        "\"a\" must come before \"z\"",
    );
    check!(
        EVERYTHING,
        "/state/migrations",
        Some(
            r#"[{"from": 2, "to": 3, "run": "/a", "reversibility": "irreversible"}, {"from": 1, "to": 2, "run": "/b", "reversibility": "irreversible"}]"#,
        ),
        "state.migrations[1]",
        "must come before",
    );
    check!(
        EVERYTHING,
        "/settings/1/name",
        Some(r#""cluster-name""#),
        "settings[1]",
        "appears twice",
    );
}

#[test]
fn text_must_be_in_canonical_form() {
    check!(
        EVERYTHING,
        "/requires",
        Some(r#"["cap:zlib or zlib-ng-compat", "openssl>=3"]"#),
        "requires[1]",
        "write it as \"openssl >= 3\"",
    );
    check!(
        EVERYTHING,
        "/provides",
        Some(r#"["cap:go=1.23"]"#),
        "provides[0]",
        "write it as \"cap:go = 1.23\"",
    );
    check!(
        EVERYTHING,
        "/provides",
        Some(r#"["so:libx.so.1 = 2"]"#),
        "provides[0]",
        "only package and cap: atoms can provide a version",
    );
    check!(
        EVERYTHING,
        "/license/spdx",
        Some(r#""(BSD-2-Clause OR MIT)""#),
        "license.spdx",
        "write it as \"BSD-2-Clause OR MIT\"",
    );
    check!(
        EVERYTHING,
        "/license/spdx",
        Some(r#""BSD-2-Clause or MIT""#),
        "license.spdx",
        "unexpected",
    );
    check!(
        EVERYTHING,
        "/replaces",
        Some(r#"["foo[doc] < 2"]"#),
        "replaces[0]",
        "one package",
    );
    check!(
        EVERYTHING,
        "/replaces",
        Some(r#"["foo or bar"]"#),
        "replaces[0]",
        "one package",
    );
    check!(
        EVERYTHING,
        "/obsoletes",
        Some(r#"["cap:old"]"#),
        "obsoletes[0]",
        "packages only",
    );
    check!(
        EVERYTHING,
        "/declares/units/1/if",
        Some(r#""setting.start-on-boot=true""#),
        "declares.units[1].if",
        "write it as \"setting.start-on-boot = true\"",
    );
    check!(
        EVERYTHING,
        "/declares/units/1/if",
        Some(r#""start-on-boot""#),
        "declares.units[1].if",
        "setting.<name>",
    );
    check!(
        EVERYTHING,
        "/conflicts",
        Some(r#"["and"]"#),
        "conflicts[0]",
        "found 'and'",
    );
}

#[test]
fn grammars_are_checked_where_they_apply() {
    for (at, value, path, message) in [
        ("/name", r#""Nginx""#, "name", "can't contain 'N'"),
        ("/summary", r#""""#, "summary", "1 to 120"),
        ("/summary", r#""two\nlines""#, "summary", "one line"),
        (
            "/description",
            r#""tab\there""#,
            "description",
            "only '\\n'",
        ),
        ("/homepage", r#""http://nginx.org""#, "homepage", "https://"),
        (
            "/facets/runtime/tree",
            &format!("\"sha256:{}\"", "9".repeat(64)),
            "facets.runtime.tree",
            "must be BLAKE3",
        ),
        (
            "/facets/runtime/tree",
            r#""blake3:xyz""#,
            "facets.runtime.tree",
            "isn't a digest",
        ),
        (
            "/facets/runtime/size",
            "-1",
            "facets.runtime.size",
            "negative",
        ),
        (
            "/facets/Doc",
            r#"{"tree": "x", "size": 1}"#,
            "facets.Doc",
            "lowercase letter",
        ),
        ("/source/rev", r#""a b""#, "source.rev", "printable ASCII"),
        (
            "/provenance/commit",
            &format!("\"{}\"", "A".repeat(40)),
            "provenance.commit",
            "40 or 64 lowercase hex digits",
        ),
        (
            "/provenance/commit",
            &format!("\"{}\"", "a".repeat(39)),
            "provenance.commit",
            "40 or 64 lowercase hex digits",
        ),
        (
            "/provenance/commit",
            &format!("\"{}\"", "a".repeat(41)),
            "provenance.commit",
            "40 or 64 lowercase hex digits",
        ),
        (
            "/provenance/commit",
            &format!("\"{}g\"", "a".repeat(39)),
            "provenance.commit",
            "40 or 64 lowercase hex digits",
        ),
        (
            "/abi/libngx.so.1@V1",
            &format!("\"blake3:{}\"", "a".repeat(64)),
            "abi.libngx.so.1@V1",
            "without a version node",
        ),
        (
            "/declares/users/0/name",
            r#""us.er""#,
            "declares.users[0].name",
            "account name",
        ),
        (
            "/declares/users/0/comment",
            r#""a:b""#,
            "declares.users[0].comment",
            "':'",
        ),
        (
            "/declares/units/0/name",
            r#""nginx""#,
            "declares.units[0].name",
            "suffix",
        ),
        (
            "/declares/units/0/preset",
            r#""masked""#,
            "declares.units[0].preset",
            "enable or disable",
        ),
        (
            "/declares/alternatives/0/name",
            r#""a b""#,
            "declares.alternatives[0].name",
            "alternative name",
        ),
        (
            "/declares/triggers/0/action",
            r#""LdConfig""#,
            "declares.triggers[0].action",
            "trigger action",
        ),
        (
            "/declares/config/0/target",
            r#""/usr/etc/x""#,
            "declares.config[0].target",
            "under /etc",
        ),
        (
            "/state/paths/0/class",
            r#""scratch""#,
            "state.paths[0].class",
            "isn't one of data",
        ),
        (
            "/state/paths/0/path",
            r#""/srv/cache""#,
            "state.paths[0].path",
            "under /var or /run",
        ),
        (
            "/state/paths/1/recurse",
            "true",
            "state.paths[1]",
            "only for cache and log",
        ),
        (
            "/state/paths/1/mode",
            r#""750""#,
            "state.paths[1].mode",
            "four octal digits",
        ),
        (
            "/state/seeds/0/path",
            r#""/etc/x""#,
            "state.seeds[0].path",
            "under /var or /run",
        ),
        (
            "/state/files/0/path",
            r#""/tmp/x""#,
            "state.files[0].path",
            "under /var or /run",
        ),
        (
            "/support/security-until",
            r#""2027-01-01""#,
            "support.security-until",
            "before active-until",
        ),
        (
            "/support/active-until",
            r#""2027-02-30""#,
            "support.active-until",
            "real calendar date",
        ),
        ("/notices/0/id", r#""Config""#, "notices[0].id", "lowercase"),
        (
            "/hooks/sometimes",
            "[]",
            "hooks.sometimes",
            "isn't one of check",
        ),
        (
            "/hooks/check/0/exec",
            r#"["relative/path"]"#,
            "hooks.check[0].exec[0]",
            "absolute",
        ),
        (
            "/hooks/check/0/timeout",
            "0",
            "hooks.check[0].timeout",
            "1 to 86400",
        ),
        (
            "/security/selinux/ports/0/port",
            "0",
            "security.selinux.ports[0].port",
            "1 to 65535",
        ),
        (
            "/security/selinux/ports/0/proto",
            r#""sctp""#,
            "security.selinux.ports[0].proto",
            "tcp or udp",
        ),
        (
            "/security/selinux/booleans/HTTPD",
            "true",
            "security.selinux.booleans.HTTPD",
            "SELinux boolean",
        ),
        (
            "/security/selinux/fcontexts/0/pattern",
            r#""srv/www""#,
            "security.selinux.fcontexts[0].pattern",
            "starts with '/'",
        ),
        (
            "/delegated/authority/kind",
            r#""vendor""#,
            "delegated.authority.kind",
            "isn't one of self",
        ),
        (
            "/delegated/paths",
            r#"["../x"]"#,
            "delegated.paths[0]",
            "stays inside",
        ),
        (
            "/delegated/initial",
            r#""runtime""#,
            "delegated.initial",
            "facet:<facet>",
        ),
        (
            "/delegated/identify/0/method",
            r#""magic""#,
            "delegated.identify[0].method",
            "isn't one of signature",
        ),
        (
            "/delegated/identify/0/issuer",
            r#""not a url""#,
            "delegated.identify[0].issuer",
            "https://",
        ),
        (
            "/delegated/require",
            r#""trusted""#,
            "delegated.require",
            "isn't one of signed",
        ),
    ] {
        check!(EVERYTHING, at, Some(value), path, message);
    }
    check!(
        EVERYTHING,
        "/delegated/identify/1/url",
        None,
        "delegated.identify[1]",
        "\"url\" is required",
    );
}

#[test]
fn rules_that_link_fields() {
    // Kinds and update levels.
    check!(
        MINIMAL,
        "/version/update",
        Some("1"),
        "version.update",
        "only update packages have an update level",
    );
    check!(
        UPDATE,
        "/version/update",
        None,
        "version",
        "update level of 1 or more",
    );
    check!(
        MINIMAL,
        "/updates",
        Some(r#"{"removes": {"runtime": ["/usr/x"]}}"#),
        "updates",
        "only update packages",
    );
    check!(
        MINIMAL,
        "/facets",
        Some(&format!(
            r#"{{"doc": {{"tree": "blake3:{}", "size": 1, "default": false}}}}"#,
            "c".repeat(64)
        )),
        "facets",
        "runtime facet",
    );
    check!(
        EVERYTHING,
        "/facets/debug/default",
        None,
        "facets.debug",
        "\"default\": false",
    );
    // License texts match the expression.
    check!(
        EVERYTHING,
        "/license/texts/MIT",
        None,
        "license.texts",
        "missing [\"MIT\"]",
    );
    check!(
        EVERYTHING,
        "/license/texts/ISC",
        Some(&format!("\"blake3:{}\"", "1".repeat(64))),
        "license.texts",
        "not in spdx [\"ISC\"]",
    );
    // Unit conditions name a setting.
    check!(
        EVERYTHING,
        "/declares/units/1/if",
        Some(r#""setting.missing""#),
        "declares.units[1].if",
        "no setting is named missing",
    );
    check!(
        EVERYTHING,
        "/declares/units/1/if",
        Some(r#""setting.workers""#),
        "declares.units[1].if",
        "needs a bool setting",
    );
    // Migrations.
    check!(
        EVERYTHING,
        "/state/migrations/0/to",
        Some("3"),
        "state.migrations[0].to",
        "to = from + 1",
    );
    check!(
        EVERYTHING,
        "/state/migrations/0/ops",
        Some(r#"[{"remove": "/var/x"}]"#),
        "state.migrations[0]",
        "either ops or run",
    );
    check!(
        EVERYTHING,
        "/state/migrations/0/reversibility",
        None,
        "state.migrations[0]",
        "\"reversibility\" is required",
    );
    check!(
        EVERYTHING,
        "/state/migrations/2/reverse",
        None,
        "state.migrations[2]",
        "\"reverse\" is required",
    );
    check!(
        EVERYTHING,
        "/state/migrations/0/reverse",
        Some(r#""/x""#),
        "state.migrations[0].reverse",
        "no reverse",
    );
    check!(
        EVERYTHING,
        "/state/migrations/0/reversibility",
        Some(r#""maybe""#),
        "state.migrations[0].reversibility",
        "reversible or irreversible",
    );
    check!(
        EVERYTHING,
        "/state/migrations/1/reversibility",
        Some(r#""reversible""#),
        "state.migrations[1].ops",
        "reversible by construction",
    );
    check!(
        EVERYTHING,
        "/state/migrations/1/ops/0",
        Some(r#"{"rename": "/var/a", "remove": "/var/b"}"#),
        "state.migrations[1].ops[0]",
        "exactly one of",
    );
    check!(
        EVERYTHING,
        "/state/migrations/1/ops/4",
        Some(r#"{"chown": "/var/a"}"#),
        "state.migrations[1].ops[4]",
        "an owner, a group or both",
    );
}

#[test]
fn settings_are_typed() {
    let s = |i: usize, value: &str, path: &str, message: &str| {
        check!(
            EVERYTHING,
            &format!("/settings/{i}"),
            Some(value),
            path,
            message,
        );
    };
    s(
        0,
        r#"{"name": "cluster-name", "type": "string", "required": true, "default": "x"}"#,
        "settings[0]",
        "no default",
    );
    s(
        0,
        r#"{"name": "cluster-name", "type": "string", "pattern": "([a-z"}"#,
        "settings[0].pattern",
        "regular expression",
    );
    // On one line: what is wrong, and where, for the parser's mistakes
    // and the translator's.
    for (pattern, why) in [
        (
            "[a0X--9z-+",
            "not a valid regular expression: invalid character class range, \
             the start must be <= the end, at byte 7 of the pattern",
        ),
        (
            "(?-u)\\xFF",
            "not a valid regular expression: pattern can match invalid UTF-8, \
             at byte 5 of the pattern",
        ),
    ] {
        let text = format!(
            r#"{{"name": "cluster-name", "type": "string", "pattern": {}}}"#,
            serde_json::to_string(pattern).unwrap()
        );
        s(0, &text, "settings[0].pattern", why);
    }
    s(
        0,
        r#"{"name": "cluster-name", "type": "string", "min": 1}"#,
        "settings[0].min",
        "only for int",
    );
    s(
        0,
        r#"{"name": "cluster-name", "type": "string", "default": "{host.nope}"}"#,
        "settings[0].default",
        "only placeholders",
    );
    s(
        0,
        r#"{"name": "cluster-name", "type": "string", "choices": ["a"]}"#,
        "settings[0].choices",
        "only for choice",
    );
    s(
        1,
        r#"{"name": "listen-port", "type": "port", "default": 70000}"#,
        "settings[1].default",
        "1 to 65535",
    );
    s(
        3,
        r#"{"name": "modules", "type": "multichoice", "choices": ["a", "b"], "default": ["b", "a"]}"#,
        "settings[3].default[1]",
        "must come before",
    );
    s(
        3,
        r#"{"name": "modules", "type": "multichoice", "choices": ["a", "b"], "default": ["c"]}"#,
        "settings[3].default",
        "isn't one of the choices",
    );
    s(
        4,
        r#"{"name": "mpm", "type": "choice", "default": "event"}"#,
        "settings[4]",
        "\"choices\" is required",
    );
    s(
        4,
        r#"{"name": "mpm", "type": "choice", "choices": ["event"], "default": "worker"}"#,
        "settings[4].default",
        "isn't one of the choices",
    );
    s(
        4,
        r#"{"name": "mpm", "type": "choice", "choices": ["{host.fqdn}"], "default": "{host.fqdn}"}"#,
        "settings[4].default",
        "only string settings",
    );
    s(
        5,
        r#"{"name": "server-names", "type": "list", "default": ["{host.fqdn}"]}"#,
        "settings[5].default",
        "only string settings",
    );
    s(
        6,
        r#"{"name": "start-on-boot", "type": "bool", "default": "yes"}"#,
        "settings[6].default",
        "expected a boolean",
    );
    s(
        7,
        r#"{"name": "web-root", "type": "path", "default": "srv"}"#,
        "settings[7].default",
        "absolute",
    );
    s(
        8,
        r#"{"name": "workers", "type": "int", "min": 10, "max": 5}"#,
        "settings[8].max",
        "below min",
    );
    s(
        8,
        r#"{"name": "workers", "type": "int", "min": 1, "max": 4, "default": 9}"#,
        "settings[8].default",
        "outside min and max",
    );
    s(
        8,
        r#"{"name": "workers", "type": "int", "min": 1, "default": -1}"#,
        "settings[8].default",
        "outside min and max",
    );
    s(
        8,
        r#"{"name": "workers", "type": "integer"}"#,
        "settings[8].type",
        "isn't one of bool",
    );
}

#[test]
fn wrong_types_and_lengths_are_named() {
    check!(
        MINIMAL,
        "/facets",
        Some("[]"),
        "facets",
        "expected an object, found an array"
    );
    check!(
        MINIMAL,
        "/provides",
        Some(r#""cap:x""#),
        "provides",
        "expected an array, found a string"
    );
    check!(
        MINIMAL,
        "/name",
        Some("1"),
        "name",
        "expected a string, found an integer"
    );
    check!(
        MINIMAL,
        "/facets/runtime/size",
        Some("true"),
        "facets.runtime.size",
        "expected an integer, found a boolean"
    );
    check!(
        MINIMAL,
        "/switch",
        Some(r#"{"live-apply": 1}"#),
        "switch.live-apply",
        "expected a boolean"
    );
    check!(
        EVERYTHING,
        "/fixes",
        Some(r#"[""]"#),
        "fixes[0]",
        "1 to 64 bytes"
    );
    check!(
        EVERYTHING,
        "/settings/0/pattern",
        Some(&format!("\"{}\"", "a".repeat(257))),
        "settings[0].pattern",
        "1 to 256 bytes"
    );
    check!(
        EVERYTHING,
        "/settings/8/pattern",
        Some(r#""[0-9]+""#),
        "settings[8].pattern",
        "only for string settings"
    );
    check!(
        EVERYTHING,
        "/declares/units/2/if",
        Some(r#""setting.mpm = ""#),
        "declares.units[2].if",
        "can't be empty"
    );
}

/// `text` edited at `at`, expected to be accepted.
fn try_accepted(text: &str, at: &str, value: &str) -> R<()> {
    let edited = edit(text, at, Some(value)).map_err(|e| format!("{at}: {e}"))?;
    Manifest::from_json(&edited).map_err(|e| format!("{at} = {value}: {e}"))?;
    Ok(())
}

/// Edits one field of a fixture and expects it to be accepted.
macro_rules! accepted {
    ($($arg:expr),+ $(,)?) => {
        try_accepted($($arg),+).unwrap()
    };
}

#[test]
fn limits_are_inclusive() {
    let long = |n: usize| format!("\"{}\"", "a".repeat(n));
    // Exactly the limit is accepted; one more is refused.
    accepted!(EVERYTHING, "/fixes", &format!("[{}]", long(64)));
    check!(
        EVERYTHING,
        "/fixes",
        Some(&format!("[{}]", long(65))),
        "fixes[0]",
        "1 to 64 bytes"
    );
    accepted!(EVERYTHING, "/settings/0/pattern", &long(256));
    accepted!(EVERYTHING, "/declares/alternatives/0/name", &long(255));
    check!(
        EVERYTHING,
        "/declares/alternatives/0/name",
        Some(&long(256)),
        "declares.alternatives[0].name",
        "isn't valid"
    );
    accepted!(EVERYTHING, "/hooks/check/0/timeout", "86400");
    check!(
        EVERYTHING,
        "/hooks/check/0/timeout",
        Some("86401"),
        "hooks.check[0].timeout",
        "1 to 86400"
    );
    accepted!(
        EVERYTHING,
        "/settings/8",
        r#"{"name": "workers", "type": "int", "min": 4, "max": 4, "default": 4}"#,
    );
    accepted!(
        EVERYTHING,
        "/settings/8",
        r#"{"name": "workers", "type": "int", "min": 1, "default": 1}"#,
    );
    accepted!(EVERYTHING, "/support/security-until", r#""2027-06-30""#);
    // Other edges.
    check!(
        EVERYTHING,
        "/declares/triggers/0/action",
        Some(r#""""#),
        "declares.triggers[0].action",
        "isn't valid"
    );
    accepted!(
        EVERYTHING,
        "/state/migrations/1/ops/4",
        r#"{"chown": "/var/lib/nginx/data", "group": "nginx"}"#,
    );
    accepted!(
        EVERYTHING,
        "/settings/2/aliases",
        r#"{"deb-conf": "nginx/mailname"}"#,
    );
    check!(
        EVERYTHING,
        "/settings/2/aliases",
        Some(r#"{"Debconf": "x"}"#),
        "settings[2].aliases.Debconf",
        "alias system"
    );
    check!(
        EVERYTHING,
        "/settings/5/default",
        Some(r#"["closing}"]"#),
        "settings[5].default",
        "only string settings"
    );
    check!(
        EVERYTHING,
        "/settings/2/default",
        Some(r#""a}b""#),
        "settings[2].default",
        "only placeholders"
    );
}

#[test]
fn encoding_sorts_what_code_builds_out_of_order() {
    let mut m = Manifest::from_json(EVERYTHING).unwrap();
    let modules = m
        .settings
        .iter_mut()
        .find(|s| s.name.as_str() == "modules")
        .unwrap();
    modules.default = Some(ordin_manifest::SettingValue::List(vec![
        "xslt".into(),
        "geoip".into(),
    ]));
    m.fixes.reverse();
    let bytes = String::from_utf8(m.to_canonical_bytes().unwrap()).unwrap();
    assert!(bytes.contains(r#""default":["geoip","xslt"]"#), "{bytes}");
    assert!(
        bytes.contains(r#""fixes":["CVE-2026-1234","fix-1234"]"#),
        "{bytes}"
    );
}

#[test]
fn small_objects_with_only_some_parts_round_trip() {
    for (at, value) in [
        ("/state", r#"{"migration": "irreversible"}"#),
        ("/state", r#"{"obsolete": ["/var/lib/hello/old"]}"#),
        (
            "/security",
            r#"{"apparmor": {"tunables": {"root": "/srv"}}}"#,
        ),
        ("/security", r#"{"selinux": {"booleans": {"x_y": false}}}"#),
        ("/declares", r#"{"boot": {"uki": true}}"#),
        ("/declares", r#"{"setuid": ["/usr/bin/passwd"]}"#),
        (
            "/provenance",
            &format!(r#"{{"sbom": "blake3:{}"}}"#, "e".repeat(64)),
        ),
        // A commit alone, of either length.
        (
            "/provenance",
            &format!(r#"{{"commit": "{}"}}"#, "0a".repeat(20)),
        ),
        (
            "/provenance",
            &format!(r#"{{"commit": "{}"}}"#, "9f".repeat(32)),
        ),
    ] {
        let text = edit(MINIMAL, at, Some(value)).unwrap();
        let m = Manifest::from_json(&text).unwrap_or_else(|e| panic!("{at}: {e}"));
        let bytes = m.to_canonical_bytes().unwrap();
        assert_eq!(Manifest::from_signed_bytes(&bytes).unwrap().0, m, "{at}");
    }
}

#[test]
fn the_reader_never_panics_on_damaged_bytes() {
    let canonical = Manifest::from_json(EVERYTHING)
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
    // Flip each of many positions to a few different bytes.
    for i in (0..canonical.len()).step_by(7) {
        for b in [b'"', b'0', b'{', 0x80] {
            let mut bytes = canonical.clone();
            bytes[i] = b;
            if let Ok((m, _)) = Manifest::from_signed_bytes(&bytes) {
                assert_eq!(m.to_canonical_bytes().unwrap(), bytes);
            }
        }
    }
}

#[test]
fn noassertion_and_none_stand_alone_without_texts() -> R<()> {
    for value in ["NOASSERTION", "NONE"] {
        let text = edit(
            MINIMAL,
            "/license",
            Some(&format!(r#"{{"spdx":"{value}"}}"#)),
        )?;
        let m = Manifest::from_json(&text)?;
        assert_eq!(m.license.spdx, value);
        assert!(m.license.texts.is_empty());
        let bytes = m.to_canonical_bytes()?;
        let shown = String::from_utf8(bytes.clone())?;
        assert!(shown.contains(&format!(r#""license":{{"spdx":"{value}"}}"#)));
        assert_eq!(Manifest::from_signed_bytes(&bytes)?.0, m);

        // Any text is refused, and so is an empty object.
        let with = edit(
            MINIMAL,
            "/license",
            Some(&format!(
                r#"{{"spdx":"{value}","texts":{{"{value}":"blake3:{}"}}}}"#,
                "b".repeat(64)
            )),
        )?;
        refused(
            &with,
            "license.texts",
            &format!("{value} has no license texts"),
        )?;
        let empty = edit(
            MINIMAL,
            "/license",
            Some(&format!(r#"{{"spdx":"{value}","texts":{{}}}}"#)),
        )?;
        refused(&empty, "license.texts", "has no license texts")?;
    }
    // Combined, with + or WITH, they are refused.
    for spdx in [
        "MIT AND NONE",
        "NOASSERTION OR MIT",
        "NONE+",
        "NOASSERTION WITH Classpath-exception-2.0",
        "MIT WITH NONE",
        "(NONE)",
    ] {
        let text = edit(MINIMAL, "/license/spdx", Some(&format!("\"{spdx}\"")))?;
        if spdx == "(NONE)" {
            refused(&text, "license.spdx", "canonical")?;
        } else {
            refused(&text, "license.spdx", "stands alone")?;
        }
    }
    // Other licenses still need their texts.
    let text = edit(MINIMAL, "/license/texts", None)?;
    refused(&text, "license", "the field \"texts\" is required")?;
    Ok(())
}

#[test]
fn a_manifest_built_in_code_equals_the_one_read() -> R<()> {
    let read = Manifest::from_json(MINIMAL)?;
    let built = Manifest::new(
        read.name.clone(),
        read.version.clone(),
        read.kind,
        read.arch,
        read.summary.clone(),
        read.license.clone(),
        read.facets.clone(),
    );
    assert_eq!(built, read);
    assert_eq!(built.to_canonical_bytes()?, read.to_canonical_bytes()?);
    Ok(())
}
