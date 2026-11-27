// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Rung-1 recipes (ORD-121): what each key reads as, and where and why
//! each mistake is refused.

#[cfg(test)]
mod recipe {
    use std::collections::BTreeMap;

    use ordin_core::{Account, Arch, Facet, FilePath, Mode};
    use ordin_manifest::{
        Class, Condition, Flush, Group, OnRemove, Presentation, Preset, Provide, Seed, Setting,
        SettingType, SettingValue, StateFile, StatePath, Unit, User,
    };
    use ordin_recipe::{
        Allow, Check, DeclaredState, Error, FacetMove, LicenseFiles, MAX_SIZE, Package, REASON_MAX,
        Recipe, RelativePath, parse,
    };

    const FULL: &str = r#"format = 1

[package]
name = "nginx"
version = "1:1.26.2"
release = 3
arch = "x86_64"
summary = "A web server"
description = "Serves the web."
homepage = "https://nginx.org"
license = "BSD-2-Clause"
requires = ["file:/bin/sh", "so:libssl.so.3 or so:libssl.so.1"]
provides = ["cap:httpd = 2.4", "so:libnginx.so.1"]
conflicts = ["apache2"]

[license]
presentation = "display"
files = { BSD-2-Clause = "docs/LICENSE" }

[[user]]
name = "nginx"
home = "/var/lib/nginx"
shell = "/usr/sbin/nologin"
groups = ["adm"]
comment = "nginx web server"

[[user]]
name = "person"
system = false

[[group]]
name = "nginx"

[[group]]
name = "staff"
system = false

[[unit]]
name = "nginx.service"
preset = "enable"
if = "setting.autostart"

[[unit]]
name = "nginx-reload.timer"
preset = "disable"
if = "setting.mpm = event"

[[setting]]
name = "autostart"
type = "bool"
default = true

[[setting]]
name = "listen-port"
type = "port"
default = 80
description = "Port the default site listens on"

[[setting]]
name = "workers"
type = "int"
min = 1
max = 64

[[setting]]
name = "mpm"
type = "choice"
choices = ["event", "worker"]
default = "event"

[[setting]]
name = "modules"
type = "multichoice"
choices = ["ssl", "gzip"]
default = ["gzip"]

[[setting]]
name = "cluster-name"
type = "string"
required = true
pattern = "[a-z0-9-]+"
aliases = { debconf = "nginx/cluster" }

[state]
version = 2
obsolete = ["/var/lib/nginx/old-index"]

[[state.path]]
path = "/var/lib/nginx"
class = "data"
owner = "nginx:nginx"
mode = "0750"

[[state.path]]
path = "/var/cache/nginx"
class = "cache"
flush = "on-upgrade"
recurse = true
on-remove = "purge"

[[state.file]]
path = "/var/log/nginx/error.log"
owner = "nginx:adm"
mode = "0640"

[[state.seed]]
path = "/var/lib/nginx/default.db"
from = "/usr/share/nginx/default.db"

[facets.dev]
extra = ["/usr/lib/nginx/sdk", "/usr/share/nginx/headers/**"]

[facets.doc]
extra = ["/usr/share/nginx/examples"]
"#;

    fn account(s: &str) -> Account {
        s.parse().unwrap()
    }

    fn path(s: &str) -> FilePath {
        s.parse().unwrap()
    }

    #[test]
    fn every_key_reads_as_what_it_declares() {
        let r = parse(FULL).unwrap();
        assert_eq!(
            r.package,
            Package {
                name: Some("nginx".parse().unwrap()),
                version: Some("1:1.26.2".to_owned()),
                release: Some("3".to_owned()),
                arch: Some(Arch::X86_64),
                summary: Some("A web server".to_owned()),
                description: Some("Serves the web.".to_owned()),
                homepage: Some("https://nginx.org".parse().unwrap()),
                license: Some("BSD-2-Clause".to_owned()),
            }
        );
        assert_eq!(
            r.license,
            LicenseFiles {
                presentation: Some(Presentation::Display),
                files: BTreeMap::from([(
                    "BSD-2-Clause".to_owned(),
                    "docs/LICENSE".parse().unwrap()
                )]),
            }
        );
        let d = &r.declared;
        let texts = |v: &[_]| {
            v.iter()
                .map(|x: &ordin_depexpr::Expr| x.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            texts(&d.requires),
            ["file:/bin/sh", "so:libssl.so.3 or so:libssl.so.1"]
        );
        assert_eq!(texts(&d.conflicts), ["apache2"]);
        assert_eq!(
            d.provides,
            [
                "cap:httpd = 2.4".parse::<Provide>().unwrap(),
                "so:libnginx.so.1".parse().unwrap()
            ]
        );
        assert_eq!(
            d.users,
            [
                User {
                    name: account("nginx"),
                    system: true,
                    home: Some(path("/var/lib/nginx")),
                    shell: Some(path("/usr/sbin/nologin")),
                    groups: vec![account("adm")],
                    comment: Some("nginx web server".to_owned()),
                },
                User {
                    name: account("person"),
                    system: false,
                    home: None,
                    shell: None,
                    groups: vec![],
                    comment: None,
                }
            ]
        );
        assert_eq!(
            d.groups,
            [
                Group {
                    name: account("nginx"),
                    system: true
                },
                Group {
                    name: account("staff"),
                    system: false
                }
            ]
        );
        assert_eq!(
            d.units,
            [
                Unit {
                    name: "nginx.service".parse().unwrap(),
                    preset: Preset::Enable,
                    condition: Some("setting.autostart".parse::<Condition>().unwrap()),
                },
                Unit {
                    name: "nginx-reload.timer".parse().unwrap(),
                    preset: Preset::Disable,
                    condition: Some("setting.mpm = event".parse().unwrap()),
                }
            ]
        );
        let setting = |name: &str, kind| Setting {
            name: name.parse().unwrap(),
            kind,
            default: None,
            required: false,
            description: None,
            min: None,
            max: None,
            pattern: None,
            choices: vec![],
            aliases: BTreeMap::new(),
        };
        assert_eq!(
            d.settings,
            [
                Setting {
                    default: Some(SettingValue::Bool(true)),
                    ..setting("autostart", SettingType::Bool)
                },
                Setting {
                    default: Some(SettingValue::Int(80)),
                    description: Some("Port the default site listens on".to_owned()),
                    ..setting("listen-port", SettingType::Port)
                },
                Setting {
                    min: Some(1),
                    max: Some(64),
                    ..setting("workers", SettingType::Int)
                },
                Setting {
                    choices: vec!["event".to_owned(), "worker".to_owned()],
                    default: Some(SettingValue::Str("event".to_owned())),
                    ..setting("mpm", SettingType::Choice)
                },
                Setting {
                    choices: vec!["ssl".to_owned(), "gzip".to_owned()],
                    default: Some(SettingValue::List(vec!["gzip".to_owned()])),
                    ..setting("modules", SettingType::Multichoice)
                },
                Setting {
                    required: true,
                    pattern: Some("[a-z0-9-]+".to_owned()),
                    aliases: BTreeMap::from([("debconf".to_owned(), "nginx/cluster".to_owned())]),
                    ..setting("cluster-name", SettingType::String)
                },
            ]
        );
        assert_eq!(
            d.state,
            DeclaredState {
                version: 2,
                obsolete: vec![path("/var/lib/nginx/old-index")],
                paths: vec![
                    StatePath {
                        path: path("/var/lib/nginx"),
                        class: Class::Data,
                        owner: account("nginx"),
                        group: account("nginx"),
                        mode: "0750".parse().unwrap(),
                        flush: Flush::Never,
                        recurse: false,
                        on_remove: None,
                    },
                    StatePath {
                        path: path("/var/cache/nginx"),
                        class: Class::Cache,
                        owner: Account::root(),
                        group: Account::root(),
                        mode: Mode::DIR,
                        flush: Flush::OnUpgrade,
                        recurse: true,
                        on_remove: Some(OnRemove::Purge),
                    }
                ],
                files: vec![StateFile {
                    path: path("/var/log/nginx/error.log"),
                    owner: account("nginx"),
                    group: account("adm"),
                    mode: "0640".parse().unwrap(),
                }],
                seeds: vec![Seed {
                    path: path("/var/lib/nginx/default.db"),
                    from: path("/usr/share/nginx/default.db"),
                }],
            }
        );
        let facet = |f: &str, p: &str| FacetMove {
            facet: f.parse::<Facet>().unwrap(),
            path: p.parse().unwrap(),
        };
        // A trailing /** is the directory itself.
        assert_eq!(
            d.facets,
            [
                facet("dev", "/usr/lib/nginx/sdk"),
                facet("dev", "/usr/share/nginx/headers"),
                facet("doc", "/usr/share/nginx/examples"),
            ]
        );
    }

    #[test]
    fn a_recipe_may_be_just_its_format() {
        assert_eq!(parse("format = 1\n").unwrap(), Recipe::default());
        assert!(parse("format = 1\n").unwrap().declared.state.is_empty());
        // A release may be a string too, and a state declaring only a
        // version isn't empty.
        let r = parse("format = 1\n[package]\nrelease = \"2\"\n[state]\nversion = 1\n").unwrap();
        assert_eq!(r.package.release.as_deref(), Some("2"));
        assert!(!r.declared.state.is_empty());
        // An empty facet table moves nothing.
        let r = parse("format = 1\n[facets.dev]\n").unwrap();
        assert!(r.declared.facets.is_empty());
    }

    /// Where a recipe is refused, and why.
    fn fails(text: &str) -> (usize, usize, String) {
        match parse(text) {
            Err(Error {
                line,
                column,
                message,
            }) => (line, column, message),
            Ok(r) => panic!("accepted: {r:?}"),
        }
    }

    /// A recipe with `body` after its format line, refused at `line` and
    /// `column` with a message containing `why`.
    fn refused(body: &str, line: usize, column: usize, why: &str) {
        let text = format!("format = 1\n{body}");
        let (l, c, message) = fails(&text);
        assert!(
            message.contains(why),
            "{message:?} lacks {why:?} in:\n{text}"
        );
        assert_eq!((l, c), (line, column), "{message} in:\n{text}");
    }

    #[test]
    fn the_format_comes_first_and_must_be_known() {
        assert_eq!(
            fails("[package]\nname = \"x\"\n"),
            (1, 1, "a recipe starts with format = 1".to_owned())
        );
        assert_eq!(
            fails("format = 2\n"),
            (
                1,
                10,
                "this is recipe format 2; Ordin reads format 1".to_owned()
            )
        );
        assert_eq!(
            fails("format = \"1\"\n"),
            (1, 10, "expected an integer, found a string".to_owned())
        );
        assert_eq!(
            fails("format = 99999999999999999999\n").2,
            "an integer here is at most 2^63 - 1"
        );
    }

    #[test]
    fn toml_mistakes_are_refused_where_they_are() {
        let (line, column, message) = fails("format = 1\n[package\n");
        assert_eq!((line, column), (2, 9), "{message}");
        assert!(message.starts_with("not valid TOML: "), "{message}");
        assert!(!message.contains('\n'), "{message}");
        // A key given twice.
        let (line, _, message) = fails("format = 1\nformat = 1\n");
        assert_eq!(line, 2, "{message}");
    }

    #[test]
    fn a_recipe_too_large_is_refused_before_it_is_read() {
        let text = format!("format = 1\n#{}\n", "x".repeat(MAX_SIZE));
        assert_eq!(
            fails(&text).2,
            format!(
                "a recipe is at most {MAX_SIZE} bytes; this one is {}",
                text.len()
            )
        );
        // Just under the limit is read.
        let text = format!("format = 1\n#{}\n", "x".repeat(MAX_SIZE - 13));
        assert_eq!(text.len(), MAX_SIZE);
        assert!(parse(&text).is_ok());
    }

    #[test]
    fn unknown_keys_are_refused_with_what_is_known() {
        refused(
            "sumary = \"x\"\n",
            2,
            1,
            "a recipe has no key \"sumary\"; expected facets, format, group, license, lint, package, setting, state, unit or user",
        );
        refused(
            "[package]\nsumary = \"x\"\n",
            3,
            1,
            "[package] has no key \"sumary\"; expected arch, conflicts, description, homepage, license, name, provides, release, requires, summary or version",
        );
        refused(
            "[license]\ntext = 1\n",
            3,
            1,
            "[license] has no key \"text\"",
        );
        refused(
            "[[user]]\nname = \"a\"\nuid = 5\n",
            4,
            1,
            "[[user]] has no key \"uid\"",
        );
        refused("[[group]]\ngid = 5\n", 3, 1, "[[group]] has no key \"gid\"");
        refused(
            "[[unit]]\nwanted = 1\n",
            3,
            1,
            "[[unit]] has no key \"wanted\"",
        );
        refused(
            "[[setting]]\nkind = 1\n",
            3,
            1,
            "[[setting]] has no key \"kind\"",
        );
        refused(
            "[state]\nmigrate = 1\n",
            3,
            1,
            "[state] has no key \"migrate\"",
        );
        refused(
            "[[state.path]]\nuser = 1\n",
            3,
            1,
            "[[state.path]] has no key \"user\"",
        );
        refused(
            "[[state.file]]\nclass = 1\n",
            3,
            1,
            "[[state.file]] has no key \"class\"",
        );
        refused(
            "[[state.seed]]\nmode = 1\n",
            3,
            1,
            "[[state.seed]] has no key \"mode\"",
        );
        refused(
            "[facets.dev]\npaths = []\n",
            3,
            1,
            "[facets.dev] has no key \"paths\"",
        );
    }

    #[test]
    fn tables_and_arrays_are_what_they_must_be() {
        refused(
            "package = 1\n",
            2,
            11,
            "expected a table for [package], found an integer",
        );
        refused(
            "user = 1\n",
            2,
            8,
            "expected an array of tables, written [[user]], found an integer",
        );
        refused(
            "user = [1]\n",
            2,
            9,
            "expected a table for [[user]], found an integer",
        );
        refused(
            "facets = 1\n",
            2,
            10,
            "expected a table of facets, written [facets.NAME], found an integer",
        );
        refused(
            "[facets]\ndev = 1\n",
            3,
            7,
            "expected a table for [facets.dev], found an integer",
        );
        refused(
            "[facets.dev]\nextra = \"/usr\"\n",
            3,
            9,
            "expected an array of paths, found a string",
        );
        refused(
            "[facets.dev]\nextra = [1]\n",
            3,
            10,
            "expected a string, found an integer",
        );
        refused(
            "[package]\nrequires = \"x\"\n",
            3,
            12,
            "expected an array of strings, each a requirement",
        );
        refused(
            "[package]\nrequires = [1]\n",
            3,
            13,
            "expected a requirement such as \"libfoo >= 1.2\", found an integer",
        );
        refused(
            "[package]\nsummary = 1\n",
            3,
            11,
            "expected a string, found an integer",
        );
        refused(
            "[package]\ndescription = true\n",
            3,
            15,
            "expected a string, found a boolean",
        );
        for (value, found) in [
            ("2026-11-26", "a date"),
            ("[]", "an array"),
            ("{}", "a table"),
        ] {
            refused(
                &format!("[package]\nsummary = {value}\n"),
                3,
                11,
                &format!("expected a string, found {found}"),
            );
        }
        refused(
            "[license]\nfiles = 1\n",
            3,
            9,
            "expected a table of license IDs and paths",
        );
        refused(
            "[license]\nfiles = { MIT = 1 }\n",
            3,
            17,
            "expected a path relative to the recipe's directory, found an integer",
        );
        refused(
            "[[user]]\nname = \"a\"\nsystem = 1\n",
            4,
            10,
            "expected true or false, found an integer",
        );
        refused(
            "[[user]]\nname = \"a\"\ncomment = 1\n",
            4,
            11,
            "expected a string",
        );
        refused(
            "[[setting]]\nname = \"a\"\ntype = \"list\"\nchoices = [1]\n",
            5,
            12,
            "expected a string, found an integer",
        );
        refused(
            "[[setting]]\nname = \"a\"\ntype = \"list\"\naliases = 1\n",
            5,
            11,
            "expected a table of former names",
        );
        refused(
            "[[setting]]\nname = \"a\"\ntype = \"list\"\naliases = { d = 1 }\n",
            5,
            17,
            "expected a string",
        );
        refused(
            "[[setting]]\nname = \"a\"\ntype = \"int\"\nmin = \"1\"\n",
            5,
            7,
            "expected an integer, found a string",
        );
        refused(
            "[state]\nversion = -1\n",
            3,
            11,
            "expected 0 or more, found -1",
        );
        refused(
            "[state]\nobsolete = [\"var/x\"]\n",
            3,
            13,
            "expected an absolute path",
        );
        refused(
            "[[state.path]]\npath = \"/var/lib/x\"\nclass = \"data\"\nrecurse = \"yes\"\n",
            5,
            11,
            "expected true or false",
        );
    }

    #[test]
    fn a_table_missing_what_it_needs_says_so() {
        refused("[[user]]\nhome = \"/x\"\n", 2, 1, "[[user]] needs name");
        refused("[[group]]\nsystem = true\n", 2, 1, "[[group]] needs name");
        refused(
            "[[unit]]\nname = \"a.service\"\n",
            2,
            1,
            "[[unit]] needs preset",
        );
        refused(
            "[[unit]]\npreset = \"enable\"\n",
            2,
            1,
            "[[unit]] needs name",
        );
        refused(
            "[[setting]]\nname = \"a\"\n",
            2,
            1,
            "[[setting]] needs type",
        );
        refused(
            "[[state.path]]\npath = \"/var/lib/x\"\n",
            2,
            1,
            "[[state.path]] needs class",
        );
        refused(
            "[[state.file]]\nmode = \"0644\"\n",
            2,
            1,
            "[[state.file]] needs path",
        );
        refused(
            "[[state.seed]]\npath = \"/var/lib/x\"\n",
            2,
            1,
            "[[state.seed]] needs from",
        );
    }

    #[test]
    fn each_value_is_read_by_its_own_parser() {
        let pkg = |key: &str, value: &str, column: usize, why: &str| {
            refused(&format!("[package]\n{key} = {value}\n"), 3, column, why);
        };
        pkg("name", "\"Nginx\"", 8, "expected a package name: ");
        pkg(
            "version",
            "\"\"",
            11,
            "expected an upstream version such as \"2.12\": ",
        );
        pkg("version", "1", 11, "expected a string, found an integer");
        pkg(
            "release",
            "\"a b\"",
            11,
            "expected a release such as \"1\": ",
        );
        pkg("release", "-1", 11, "expected 0 or more, found -1");
        pkg("release", "true", 11, "expected a string, found a boolean");
        pkg(
            "arch",
            "\"sparc\"",
            8,
            "expected x86_64, aarch64 or noarch: ",
        );
        pkg("homepage", "\"ftp://x\"", 12, "expected an https URL: ");
        pkg(
            "license",
            "\"MIT OR\"",
            11,
            "expected an SPDX license expression: ",
        );
        pkg("license", "1", 11, "expected a string");
        pkg(
            "requires",
            "[\"ok\", \"a >\"]",
            19,
            "expected a requirement such as \"libfoo >= 1.2\": ",
        );
        pkg("conflicts", "[\"a >\"]", 14, "expected a requirement");
        pkg(
            "provides",
            "[\"so:libc.so.6 = 2\"]",
            13,
            "expected a provide such as \"cap:foo = 1.0\": only package and cap: atoms can provide a version",
        );
        // A version, then a release that makes it unreadable.
        refused(
            "[package]\nrelease = \"1+u2\"\n",
            3,
            11,
            "doesn't read back as given",
        );
        refused(
            "[package]\nversion = \"1.0\"\nrelease = \"1+u2\"\n",
            4,
            11,
            "doesn't read back as given",
        );

        refused(
            "[license]\npresentation = \"shown\"\n",
            3,
            16,
            "expected informational, display or accept, found \"shown\"",
        );
        for (path, why) in [
            ("/etc/x", "not absolute"),
            ("", "can't be empty"),
            ("a//b", "an empty name"),
            ("a/", "an empty name"),
            ("../x", "stays below the recipe's directory"),
            ("a/./b", "stays below the recipe's directory"),
        ] {
            refused(
                &format!("[license]\nfiles = {{ MIT = {path:?} }}\n"),
                3,
                17,
                why,
            );
        }
        refused(
            &format!("[license]\nfiles = {{ MIT = \"{}\" }}\n", "a".repeat(4097)),
            3,
            17,
            "a path is at most 4096 bytes",
        );
        refused("[license]\nfiles = { MIT = \"a\\u0000b\" }\n", 3, 17, "NUL");

        let user = |line: &str, column: usize, why: &str| {
            refused(&format!("[[user]]\nname = \"a\"\n{line}\n"), 4, column, why);
        };
        user("home = \"var/x\"", 8, "expected an absolute path: ");
        user("shell = \"bin/sh\"", 9, "expected an absolute path: ");
        user("groups = [\"Bad Group\"]", 11, "expected a group name: ");
        refused("[[user]]\nname = \"-x\"\n", 3, 8, "expected a user name: ");
        refused(
            "[[group]]\nname = \"-x\"\n",
            3,
            8,
            "expected a group name: ",
        );
        refused(
            "[[group]]\nname = \"g\"\nsystem = \"no\"\n",
            4,
            10,
            "expected true or false",
        );

        let unit = |line: &str, column: usize, why: &str| {
            refused(&format!("[[unit]]\n{line}\n"), 3, column, why);
        };
        unit(
            "name = \"nginx\"\npreset = \"enable\"",
            8,
            "expected a unit name such as \"foo.service\": ",
        );
        refused(
            "[[unit]]\nname = \"a.service\"\npreset = \"on\"\n",
            4,
            10,
            "expected enable or disable, found \"on\"",
        );
        refused(
            "[[unit]]\nname = \"a.service\"\npreset = \"enable\"\nif = \"tls\"\n",
            5,
            6,
            "expected a condition such as \"setting.tls\": ",
        );

        let setting = |kind: &str, line: &str, why: &str| {
            refused(
                &format!("[[setting]]\nname = \"s\"\ntype = \"{kind}\"\n{line}\n"),
                5,
                11,
                why,
            );
        };
        setting(
            "bool",
            "default = 1",
            "expected true or false, since the setting's type is bool, found an integer",
        );
        setting(
            "int",
            "default = \"1\"",
            "expected an integer, since the setting's type is int, found a string",
        );
        setting(
            "port",
            "default = 1.5",
            "expected an integer, since the setting's type is port, found a float",
        );
        setting(
            "int",
            "default = 99999999999999999999",
            "an integer here is at most 2^63 - 1",
        );
        setting(
            "path",
            "default = 1",
            "expected a string, since the setting's type is path, found an integer",
        );
        setting(
            "list",
            "default = \"a\"",
            "expected an array of strings, since the setting's type is list, found a string",
        );
        refused(
            "[[setting]]\nname = \"s\"\ntype = \"list\"\ndefault = [1]\n",
            5,
            12,
            "expected a string, found an integer",
        );
        refused(
            "[[setting]]\nname = \"s\"\ntype = \"text\"\n",
            4,
            8,
            "expected bool, int, port, string, choice, multichoice, path or list, found \"text\"",
        );
        refused(
            "[[setting]]\nname = \"Bad Name\"\ntype = \"bool\"\n",
            3,
            8,
            "expected a setting name such as \"listen-port\": ",
        );

        let path = |line: &str, column: usize, why: &str| {
            refused(
                &format!("[[state.path]]\npath = \"/var/lib/x\"\nclass = \"data\"\n{line}\n"),
                5,
                column,
                why,
            );
        };
        path(
            "owner = \"nginx\"",
            9,
            "expected USER:GROUP: \"nginx\" has no ':'",
        );
        path("owner = \"-a:b\"", 9, "expected USER:GROUP: ");
        path("owner = \"a:-b\"", 9, "expected USER:GROUP: ");
        path(
            "mode = \"750\"",
            8,
            "expected a mode of four octal digits, such as \"0750\": ",
        );
        path(
            "flush = \"always\"",
            9,
            "expected never or on-upgrade, found \"always\"",
        );
        path(
            "on-remove = \"delete\"",
            13,
            "expected keep, purge or archive, found \"delete\"",
        );
        refused(
            "[[state.path]]\npath = \"var/lib/x\"\nclass = \"data\"\n",
            3,
            8,
            "expected an absolute path: ",
        );
        refused(
            "[[state.path]]\npath = \"/var/lib/x\"\nclass = \"logs\"\n",
            4,
            9,
            "expected data, spool, log, cache, tmp or runtime, found \"logs\"",
        );
        refused(
            "[[state.seed]]\npath = \"/var/lib/x\"\nfrom = \"x\"\n",
            4,
            8,
            "expected an absolute path in the package: ",
        );

        refused("[facets.\"Dev Stuff\"]\n", 2, 9, "expected a facet name: ");
        refused(
            "[facets.dev]\nextra = [\"usr/x\"]\n",
            3,
            10,
            "expected an absolute path: ",
        );
        refused(
            "[facets.dev]\nextra = [\"/usr/*.h\"]\n",
            3,
            10,
            "other patterns aren't supported",
        );
        refused(
            "[facets.dev]\nextra = [\"/usr/**/x\"]\n",
            3,
            10,
            "other patterns aren't supported",
        );
        refused(
            "[facets.dev]\nextra = [\"/usr/x\"]\n[facets.doc]\nextra = [\"/usr/x/**\"]\n",
            5,
            10,
            "/usr/x is moved to a facet twice",
        );
    }

    #[test]
    fn the_manifests_rules_are_refused_where_the_recipe_broke_them() {
        // A pattern that isn't a regular expression, told on one line
        // (found by fuzzing).
        refused(
            "[[setting]]\nname = \"s\"\ntype = \"string\"\npattern = \"[z-a\"\n",
            5,
            11,
            "not a valid regular expression: invalid character class range, the start must be <= the end, at byte 1 of the pattern",
        );
        // Two users with one name: the second is refused.
        refused(
            "[[user]]\nname = \"a\"\n[[user]]\nname = \"b\"\n[[user]]\nname = \"a\"\n",
            6,
            1,
            "\"a\" appears twice",
        );
        refused(
            "[[group]]\nname = \"a\"\n[[group]]\nname = \"a\"\n",
            4,
            1,
            "\"a\" appears twice",
        );
        refused(
            "[[unit]]\nname = \"b.service\"\npreset = \"enable\"\n[[unit]]\nname = \"a.service\"\npreset = \"disable\"\nif = \"setting.tls\"\n",
            8,
            6,
            "no setting is named tls",
        );
        // A field's own rule points at the field.
        refused(
            "[[user]]\nname = \"a\"\ncomment = \"a:b\"\n",
            4,
            11,
            "a user comment can't contain ':'",
        );
        refused(
            "[[setting]]\nname = \"b\"\ntype = \"bool\"\n[[setting]]\nname = \"a\"\ntype = \"string\"\nrequired = true\ndefault = \"x\"\n",
            5,
            1,
            "a required setting has no default",
        );
        refused(
            "[[setting]]\nname = \"b\"\ntype = \"bool\"\n[[setting]]\nname = \"b\"\ntype = \"int\"\n",
            5,
            1,
            "\"b\" appears twice",
        );
        // State: a path outside /var and /run, and a rule about the whole
        // path, each found in the recipe's order.
        refused(
            "[[state.path]]\npath = \"/var/lib/b\"\nclass = \"data\"\n[[state.path]]\npath = \"/opt/a\"\nclass = \"data\"\n",
            6,
            8,
            "state paths are under /var or /run",
        );
        refused(
            "[[state.path]]\npath = \"/var/lib/x\"\nclass = \"data\"\nrecurse = true\n",
            2,
            1,
            "recurse is only for cache and log paths",
        );
        refused(
            "[[state.file]]\npath = \"/etc/x\"\n",
            3,
            8,
            "state paths are under /var or /run",
        );
        refused(
            "[[state.file]]\npath = \"/var/log/b\"\n[[state.file]]\npath = \"/var/log/b\"\n",
            4,
            1,
            "appears twice",
        );
        refused(
            "[[state.seed]]\npath = \"/etc/x\"\nfrom = \"/usr/share/x\"\n",
            3,
            8,
            "state paths are under /var or /run",
        );
        refused(
            "[package]\nsummary = \"\"\n",
            3,
            11,
            "this text is 1 to 120 characters; it is 0",
        );
        refused(
            &format!("[package]\ndescription = \"{}\"\n", "x".repeat(4001)),
            3,
            15,
            "this text is 1 to 4000 characters; it is 4001",
        );
    }

    #[test]
    fn relative_paths_keep_their_names() {
        let p: RelativePath = "docs/legal/COPYING".parse().unwrap();
        assert_eq!(p.as_str(), "docs/legal/COPYING");
        assert_eq!(p.to_string(), "docs/legal/COPYING");
        // The longest path accepted.
        let longest = format!("{}/x", "a".repeat(RelativePath::MAX_LEN - 2));
        assert_eq!(longest.parse::<RelativePath>().unwrap().as_str(), longest);
    }

    #[test]
    fn lint_allows_are_read_with_their_lines() {
        let text = "format = 1\n\
                    [[lint.allow]]\n\
                    id = \"world-writable\"\n\
                    reason = \"a shared drop directory\"\n\
                    paths = [\"/usr/share/foo/drop\", \"/usr/share/foo/spool\"]\n\
                    \n\
                    [[lint.allow]]\n\
                    id = \"world-writable\"\n\
                    reason = \"another\"\n\
                    paths = [\"/usr/share/bar\"]\n\
                    \n\
                    [[lint.allow]]\n\
                    id = \"license-unknown\"\n\
                    reason = \"upstream is clarifying it\"\n";
        let r = parse(text).unwrap();
        let path = |p: &str| p.parse().unwrap();
        assert_eq!(
            r.lint,
            [
                Allow {
                    check: Check::WorldWritable,
                    reason: "a shared drop directory".to_owned(),
                    paths: vec![path("/usr/share/foo/drop"), path("/usr/share/foo/spool")],
                    line: 2,
                },
                Allow {
                    check: Check::WorldWritable,
                    reason: "another".to_owned(),
                    paths: vec![path("/usr/share/bar")],
                    line: 7,
                },
                Allow {
                    check: Check::LicenseUnknown,
                    reason: "upstream is clarifying it".to_owned(),
                    paths: Vec::new(),
                    line: 12,
                },
            ]
        );
        // [lint] alone allows nothing.
        assert!(parse("format = 1\n[lint]\n").unwrap().lint.is_empty());
        // The longest reason is accepted.
        let longest = "x".repeat(REASON_MAX);
        let text =
            format!("format = 1\n[[lint.allow]]\nid = \"facet-empty\"\nreason = \"{longest}\"\n");
        assert_eq!(parse(&text).unwrap().lint[0].reason, longest);
    }

    #[test]
    fn lint_allows_are_refused_where_they_are_wrong() {
        let allow = "[[lint.allow]]\n";
        refused(
            "[lint]\ndeny = []\n",
            3,
            1,
            "[lint] has no key \"deny\"; expected allow",
        );
        refused(
            "lint = 1\n",
            2,
            8,
            "expected a table for [lint], found an integer",
        );
        refused(
            &format!("{allow}id = \"world-writable\"\nreason = \"x\"\nwhy = \"x\"\n"),
            5,
            1,
            "[[lint.allow]] has no key \"why\"; expected id, paths or reason",
        );
        refused(
            &format!("{allow}reason = \"x\"\n"),
            2,
            1,
            "[[lint.allow]] needs id",
        );
        refused(
            &format!("{allow}id = \"world-writable\"\n"),
            2,
            1,
            "[[lint.allow]] needs reason",
        );
        refused(
            &format!("{allow}id = \"world_writable\"\nreason = \"x\"\n"),
            3,
            6,
            "expected a check: license-unknown, setuid-undeclared, world-writable, \
             so-private-version, so-bad-name, so-unversioned, so-unneeded, elf-unreadable, \
             shebang-unusual, interpreter-unknown, facet-empty or facet-misclassified; \
             found \"world_writable\"",
        );
        refused(
            &format!("{allow}id = 3\nreason = \"x\"\n"),
            3,
            6,
            "expected a string, found an integer",
        );
        refused(
            &format!("{allow}id = \"unused-allow\"\nreason = \"x\"\n"),
            3,
            6,
            "unused-allow can't be allowed; remove the allow that matches nothing",
        );
        let reason = |r: &str| format!("{allow}id = \"facet-empty\"\nreason = {r}\n");
        refused(
            &reason("\" \\t \""),
            4,
            10,
            "expected a reason: an allow says why the warning is accepted",
        );
        refused(
            &reason("\"two\\nlines\""),
            4,
            10,
            "expected a reason: one line, without control characters",
        );
        refused(
            &reason("\"tab\\there\""),
            4,
            10,
            "without control characters",
        );
        refused(
            &reason(&format!("\"{}\"", "x".repeat(REASON_MAX + 1))),
            4,
            10,
            "expected a reason: at most 200 characters",
        );
        refused(&reason("[]"), 4, 10, "expected a string, found an array");
        let paths =
            |id: &str, p: &str| format!("{allow}id = \"{id}\"\nreason = \"x\"\npaths = {p}\n");
        refused(
            &paths("license-unknown", "[\"/usr/a\"]"),
            5,
            9,
            "license-unknown warnings name no path, so its allow takes no paths",
        );
        refused(
            &paths("world-writable", "[]"),
            5,
            9,
            "expected at least one path; leave paths out to allow it for the whole package",
        );
        refused(
            &paths("world-writable", "\"/usr/a\""),
            5,
            9,
            "expected an array of paths, found a string",
        );
        refused(
            &paths("world-writable", "[\"usr/a\"]"),
            5,
            10,
            "expected an absolute path",
        );
        refused(
            &paths("world-writable", "[\"/usr/a\", \"/usr/a\"]"),
            5,
            20,
            "/usr/a is already allowed for world-writable",
        );
        // A path allowed by an earlier entry for the same check, but not
        // for another check.
        let two = |first: &str, second: &str| {
            format!(
                "{allow}id = \"world-writable\"\nreason = \"x\"\n{first}\n\
                 {allow}id = \"world-writable\"\nreason = \"y\"\n{second}\n"
            )
        };
        refused(
            &two("paths = [\"/usr/a\"]", "paths = [\"/usr/b\", \"/usr/a\"]"),
            9,
            20,
            "/usr/a is already allowed for world-writable",
        );
        let other = format!(
            "format = 1\n{allow}id = \"world-writable\"\nreason = \"x\"\npaths = [\"/usr/a\"]\n\
             {allow}id = \"setuid-undeclared\"\nreason = \"y\"\npaths = [\"/usr/a\"]\n"
        );
        assert_eq!(parse(&other).unwrap().lint.len(), 2);
        // An allow for the whole package is the only one for its check,
        // whichever comes first.
        let whole = "world-writable is already allowed at line 2; one allow for the whole \
                     package is the only one for its check";
        refused(&two("", ""), 6, 1, whole);
        refused(&two("paths = [\"/usr/a\"]", ""), 6, 1, whole);
        refused(&two("", "paths = [\"/usr/a\"]"), 6, 1, whole);
        // An allow for the whole package of another check is no conflict.
        let text = format!(
            "format = 1\n{allow}id = \"world-writable\"\nreason = \"x\"\n\
             {allow}id = \"setuid-undeclared\"\nreason = \"y\"\n"
        );
        assert_eq!(parse(&text).unwrap().lint.len(), 2);
        refused(
            "[lint]\nallow = 1\n",
            3,
            9,
            "expected an array of tables, written [[lint.allow]], found an integer",
        );
    }
}
