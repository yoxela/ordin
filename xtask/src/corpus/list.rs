// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Reading `corpus/corpus.toml`: the packages, where their files come from
//! and how those files are laid out as an install root.
//!
//! Every key is checked, and any other key is refused, so a misspelt key
//! never quietly changes what is packed.

use std::collections::{BTreeMap, BTreeSet};

use toml::{Table, Value};

use crate::release::Error;

/// The format `corpus.toml` must declare.
pub const FORMAT: i64 = 1;

/// The largest download a source may declare: 512 MiB.
pub const MAX_SIZE: u64 = 512 << 20;

/// The most leading components a source may strip.
pub const MAX_STRIP: i64 = 8;

/// What a source is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// A gzip-compressed tar file.
    TarGz,
    /// A Debian binary package, read with `dpkg-deb --fsys-tarfile`.
    Deb,
}

/// Where the entries below `from` in an archive go in the install root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Place {
    /// A path in the archive, after stripping; empty for all of it.
    pub from: String,
    /// The path in the install root; empty for the root itself.
    pub to: String,
}

/// A path in an archive that is left out on purpose, with everything
/// below it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exclude {
    /// The path in the archive, after stripping.
    pub path: String,
    /// Why it is left out.
    pub reason: String,
}

/// A symlink added to the install root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    /// Its path in the install root.
    pub path: String,
    /// What it points to.
    pub target: String,
}

/// One downloaded file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    /// Where it is downloaded from: an `https` URL.
    pub url: String,
    /// Its size in bytes.
    pub size: u64,
    /// Its SHA-256, in lowercase hex.
    pub sha256: String,
    /// What it is.
    pub format: Format,
    /// How many leading path components every entry loses.
    pub strip: usize,
    /// Where its entries go; the most specific `from` wins.
    pub place: Vec<Place>,
    /// What is left out.
    pub exclude: Vec<Exclude>,
}

/// One corpus package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    /// Its name in the corpus, and its directory under `corpus/`.
    pub name: String,
    /// What it stands for in the corpus.
    pub about: String,
    /// Each license ID mapped to its text's path in the install root.
    pub licenses: BTreeMap<String, String>,
    /// Symlinks added to the install root.
    pub links: Vec<Link>,
    /// Its downloads, laid out in this order.
    pub sources: Vec<Source>,
}

impl Package {
    /// Every SHA-256 it downloads.
    pub fn hashes(&self) -> impl Iterator<Item = &str> {
        self.sources.iter().map(|s| s.sha256.as_str())
    }
}

/// Parses `corpus.toml`.
///
/// # Errors
///
/// Returns an error if it isn't valid TOML, a key is missing, unknown or
/// wrong, or two packages share a name.
pub fn parse(text: &str) -> Result<Vec<Package>, Error> {
    let table: Table = text.parse().map_err(|e| Error::parse(WHAT, e))?;
    keys(&table, &["format", "package"], "the file")?;
    match table.get("format") {
        Some(Value::Integer(FORMAT)) => {}
        Some(other) => return Err(wrong("the file", format!("format {other} isn't {FORMAT}"))),
        None => return Err(wrong("the file", "format is missing")),
    }
    let mut names = BTreeSet::new();
    let mut packages = Vec::new();
    for value in tables(&table, "package", "the file")? {
        let package = package(value)?;
        if !names.insert(package.name.clone()) {
            return Err(wrong(&package.name, "two packages have this name"));
        }
        packages.push(package);
    }
    if packages.is_empty() {
        return Err(wrong("the file", "it lists no packages"));
    }
    Ok(packages)
}

const WHAT: &str = "corpus/corpus.toml";

fn wrong(context: &str, error: impl Into<String>) -> Error {
    Error::parse(WHAT, format!("{context}: {}", error.into()))
}

/// Refuses any key of `table` not in `allowed`.
fn keys(table: &Table, allowed: &[&str], context: &str) -> Result<(), Error> {
    match table.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(key) => Err(wrong(
            context,
            format!("unknown key {key}; expected one of {}", allowed.join(", ")),
        )),
        None => Ok(()),
    }
}

/// The array of tables at `key`, or none if it is missing.
fn tables<'a>(table: &'a Table, key: &str, context: &str) -> Result<Vec<&'a Table>, Error> {
    match table.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_table()
                    .ok_or_else(|| wrong(context, format!("each {key} must be a table")))
            })
            .collect(),
        Some(_) => Err(wrong(context, format!("{key} must be an array of tables"))),
    }
}

fn string<'a>(table: &'a Table, key: &str, context: &str) -> Result<&'a str, Error> {
    match table.get(key) {
        Some(Value::String(s)) => Ok(s),
        Some(_) => Err(wrong(context, format!("{key} must be a string"))),
        None => Err(wrong(context, format!("{key} is missing"))),
    }
}

/// A line of text: not empty, no control characters.
fn line<'a>(table: &'a Table, key: &str, context: &str) -> Result<&'a str, Error> {
    let s = string(table, key, context)?;
    if s.trim().is_empty() || s.chars().any(char::is_control) {
        return Err(wrong(
            context,
            format!("{key} must be one line of text, not empty"),
        ));
    }
    Ok(s)
}

/// A relative path: names separated by single `/`, none of them `.` or
/// `..`, and no control characters. Empty only if `empty` allows it.
fn path(s: &str, empty: bool, what: &str, context: &str) -> Result<String, Error> {
    let bad = if s.is_empty() {
        !empty
    } else {
        s.split('/').any(|c| c.is_empty() || c == "." || c == "..")
            || s.chars().any(char::is_control)
    };
    if bad {
        return Err(wrong(
            context,
            format!(
                "{what} {s:?} must be a relative path of names separated by single /, none of them . or ..{}",
                if empty { ", or empty" } else { "" }
            ),
        ));
    }
    Ok(s.to_owned())
}

fn package(table: &Table) -> Result<Package, Error> {
    let name = string(table, "name", "a package")?;
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        && !name.starts_with('-');
    if !valid {
        return Err(wrong(
            "a package",
            format!(
                "name {name:?} must be 1 to 64 lowercase letters, digits, - and _, not starting with -"
            ),
        ));
    }
    keys(
        table,
        &["name", "about", "licenses", "links", "source"],
        name,
    )?;
    let about = line(table, "about", name)?.to_owned();
    let licenses = match table.get("licenses") {
        None => BTreeMap::new(),
        Some(Value::Table(t)) => t
            .iter()
            .map(|(id, value)| {
                let id_ok = !id.is_empty()
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'+');
                if !id_ok {
                    return Err(wrong(name, format!("license ID {id:?} isn't an SPDX ID")));
                }
                let text = value
                    .as_str()
                    .ok_or_else(|| wrong(name, format!("license {id} must be a path")))?;
                Ok((id.clone(), path(text, false, "license text", name)?))
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return Err(wrong(name, "licenses must be a table")),
    };
    let mut links = Vec::new();
    for t in tables(table, "links", name)? {
        keys(t, &["path", "target"], name)?;
        let target = string(t, "target", name)?;
        if target.is_empty() || target.chars().any(char::is_control) {
            return Err(wrong(name, "a link's target must be a path"));
        }
        links.push(Link {
            path: path(string(t, "path", name)?, false, "link path", name)?,
            target: target.to_owned(),
        });
    }
    let sources = tables(table, "source", name)?
        .into_iter()
        .map(|t| source(t, name))
        .collect::<Result<Vec<_>, _>>()?;
    if sources.is_empty() {
        return Err(wrong(name, "it has no source"));
    }
    Ok(Package {
        name: name.to_owned(),
        about,
        licenses,
        links,
        sources,
    })
}

fn source(table: &Table, name: &str) -> Result<Source, Error> {
    keys(
        table,
        &[
            "url", "size", "sha256", "format", "strip", "place", "exclude",
        ],
        name,
    )?;
    let url = string(table, "url", name)?;
    if !url.starts_with("https://") || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(wrong(name, format!("url {url:?} must be an https URL")));
    }
    let context = format!("{name}: {url}");
    let size = match table.get("size") {
        Some(Value::Integer(n)) => u64::try_from(*n)
            .ok()
            .filter(|n| (1..=MAX_SIZE).contains(n))
            .ok_or_else(|| wrong(&context, format!("size must be 1 to {MAX_SIZE} bytes")))?,
        _ => return Err(wrong(&context, "size must be an integer")),
    };
    let sha256 = string(table, "sha256", &context)?;
    if sha256.len() != 64
        || !sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(wrong(&context, "sha256 must be 64 lowercase hex digits"));
    }
    let format = match string(table, "format", &context)? {
        "tar.gz" => Format::TarGz,
        "deb" => Format::Deb,
        other => {
            return Err(wrong(
                &context,
                format!("format {other:?} must be \"tar.gz\" or \"deb\""),
            ));
        }
    };
    let strip = match (table.get("strip"), format) {
        (None, _) => 0,
        (Some(_), Format::Deb) => {
            return Err(wrong(
                &context,
                "a deb's paths start at the root, so it takes no strip",
            ));
        }
        (Some(Value::Integer(n)), Format::TarGz) if (0..=MAX_STRIP).contains(n) => {
            usize::try_from(*n).map_err(|_| wrong(&context, "strip is too large"))?
        }
        (Some(_), Format::TarGz) => {
            return Err(wrong(&context, format!("strip must be 0 to {MAX_STRIP}")));
        }
    };
    let mut place = Vec::new();
    for t in tables(table, "place", &context)? {
        keys(t, &["from", "to"], &context)?;
        let from = path(string(t, "from", &context)?, true, "from", &context)?;
        if place.iter().any(|p: &Place| p.from == from) {
            return Err(wrong(&context, format!("from {from:?} is placed twice")));
        }
        place.push(Place {
            from,
            to: path(string(t, "to", &context)?, true, "to", &context)?,
        });
    }
    if table.get("place").is_none() {
        place.push(Place {
            from: String::new(),
            to: String::new(),
        });
    } else if place.is_empty() {
        return Err(wrong(
            &context,
            "place is empty, so nothing would be laid out",
        ));
    }
    let mut exclude = Vec::new();
    for t in tables(table, "exclude", &context)? {
        keys(t, &["path", "reason"], &context)?;
        let p = path(
            string(t, "path", &context)?,
            false,
            "exclude path",
            &context,
        )?;
        if exclude.iter().any(|e: &Exclude| e.path == p) {
            return Err(wrong(&context, format!("{p:?} is excluded twice")));
        }
        exclude.push(Exclude {
            path: p,
            reason: line(t, "reason", &context)?.to_owned(),
        });
    }
    Ok(Source {
        url: url.to_owned(),
        size,
        sha256: sha256.to_owned(),
        format,
        strip,
        place,
        exclude,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "54268ab4643c00a290a29b0086066d64b3f56236dd805ec64629a86f9bd29fd0";

    fn one(source: &str) -> String {
        format!(
            "format = 1\n[[package]]\nname = \"p\"\nabout = \"a test\"\n[[package.source]]\nurl = \"https://example.org/p.tar.gz\"\nsize = 10\nsha256 = \"{HASH}\"\n{source}\n"
        )
    }

    fn error(text: &str) -> String {
        parse(text).unwrap_err().to_string()
    }

    #[test]
    fn a_full_list_is_read() {
        let text = format!(
            "format = 1
[[package]]
name = \"go-1\"
about = \"a toolchain\"
licenses = {{ \"BSD-3-Clause\" = \"usr/lib/go/LICENSE\" }}
links = [{{ path = \"usr/bin/go\", target = \"../lib/go/bin/go\" }}]
[[package.source]]
url = \"https://example.org/go.tar.gz\"
size = 70
sha256 = \"{HASH}\"
format = \"tar.gz\"
strip = 1
place = [{{ from = \"go\", to = \"usr/lib/go\" }}, {{ from = \"\", to = \"usr/share/doc/go\" }}]
exclude = [{{ path = \"go/test\", reason = \"tests\" }}]
[[package.source]]
url = \"https://example.org/x.deb\"
size = 5
sha256 = \"{HASH}\"
format = \"deb\"
[[package]]
name = \"b\"
about = \"another\"
[[package.source]]
url = \"https://example.org/b.deb\"
size = 1
sha256 = \"{HASH}\"
format = \"deb\"
"
        );
        let packages = parse(&text).unwrap();
        assert_eq!(packages.len(), 2);
        let go = &packages[0];
        assert_eq!(go.name, "go-1");
        assert_eq!(go.about, "a toolchain");
        assert_eq!(
            go.licenses,
            BTreeMap::from([("BSD-3-Clause".to_owned(), "usr/lib/go/LICENSE".to_owned())])
        );
        assert_eq!(
            go.links,
            [Link {
                path: "usr/bin/go".to_owned(),
                target: "../lib/go/bin/go".to_owned()
            }]
        );
        assert_eq!(
            go.sources[0],
            Source {
                url: "https://example.org/go.tar.gz".to_owned(),
                size: 70,
                sha256: HASH.to_owned(),
                format: Format::TarGz,
                strip: 1,
                place: vec![
                    Place {
                        from: "go".to_owned(),
                        to: "usr/lib/go".to_owned()
                    },
                    Place {
                        from: String::new(),
                        to: "usr/share/doc/go".to_owned()
                    },
                ],
                exclude: vec![Exclude {
                    path: "go/test".to_owned(),
                    reason: "tests".to_owned()
                }],
            }
        );
        // A source with no place is laid out where it is.
        assert_eq!(go.sources[1].format, Format::Deb);
        assert_eq!(go.sources[1].strip, 0);
        assert_eq!(
            go.sources[1].place,
            [Place {
                from: String::new(),
                to: String::new()
            }]
        );
        assert_eq!(go.hashes().collect::<Vec<_>>(), [HASH, HASH]);
        assert!(packages[1].licenses.is_empty() && packages[1].links.is_empty());
    }

    #[test]
    fn the_file_must_be_format_1_with_packages() {
        assert!(error("format = [").starts_with("can't parse corpus/corpus.toml: "));
        assert_eq!(
            error("format = 2"),
            "can't parse corpus/corpus.toml: the file: format 2 isn't 1"
        );
        assert_eq!(
            error("package = []"),
            "can't parse corpus/corpus.toml: the file: format is missing"
        );
        assert_eq!(
            error("format = 1"),
            "can't parse corpus/corpus.toml: the file: it lists no packages"
        );
        assert_eq!(
            error("format = 1\nother = 1"),
            "can't parse corpus/corpus.toml: the file: unknown key other; expected one of format, package"
        );
        assert_eq!(
            error("format = 1\npackage = 1"),
            "can't parse corpus/corpus.toml: the file: package must be an array of tables"
        );
        assert_eq!(
            error("format = 1\npackage = [1]"),
            "can't parse corpus/corpus.toml: the file: each package must be a table"
        );
        let twice = format!(
            "{}{}",
            one("format = \"deb\""),
            &one("format = \"deb\"")[11..]
        );
        assert_eq!(
            error(&twice),
            "can't parse corpus/corpus.toml: p: two packages have this name"
        );
    }

    #[test]
    fn a_package_is_checked() {
        let base = one("format = \"deb\"");
        let with = |from: &str, to: &str| base.replacen(from, to, 1);
        let cases = [
            (
                with("name = \"p\"", "name = \"P\""),
                "a package: name \"P\" must be 1 to 64 lowercase letters, digits, - and _, not starting with -",
            ),
            (
                with("name = \"p\"", "name = \"-p\""),
                "a package: name \"-p\" must be 1 to 64 lowercase letters, digits, - and _, not starting with -",
            ),
            (
                with("name = \"p\"", &format!("name = \"{}\"", "a".repeat(65))),
                &format!(
                    "a package: name \"{}\" must be 1 to 64 lowercase letters, digits, - and _, not starting with -",
                    "a".repeat(65)
                ),
            ),
            (
                with("name = \"p\"", "name = \"\""),
                "a package: name \"\" must be 1 to 64 lowercase letters, digits, - and _, not starting with -",
            ),
            (
                with("name = \"p\"", "name = 1"),
                "a package: name must be a string",
            ),
            (with("name = \"p\"\n", ""), "a package: name is missing"),
            (
                with("about = \"a test\"", "about = \" \""),
                "p: about must be one line of text, not empty",
            ),
            (
                with("about = \"a test\"", "about = \"a\\nb\""),
                "p: about must be one line of text, not empty",
            ),
            (
                with("about = \"a test\"", "about = \"a\"\nmore = 1"),
                "p: unknown key more; expected one of name, about, licenses, links, source",
            ),
            (
                with("about = \"a test\"", "about = \"a\"\nlicenses = 1"),
                "p: licenses must be a table",
            ),
            (
                with(
                    "about = \"a test\"",
                    "about = \"a\"\nlicenses = { \"MIT=x\" = \"a\" }",
                ),
                "p: license ID \"MIT=x\" isn't an SPDX ID",
            ),
            (
                with(
                    "about = \"a test\"",
                    "about = \"a\"\nlicenses = { \"\" = \"a\" }",
                ),
                "p: license ID \"\" isn't an SPDX ID",
            ),
            (
                with(
                    "about = \"a test\"",
                    "about = \"a\"\nlicenses = { MIT = 1 }",
                ),
                "p: license MIT must be a path",
            ),
            (
                with(
                    "about = \"a test\"",
                    "about = \"a\"\nlicenses = { MIT = \"/COPYING\" }",
                ),
                "p: license text \"/COPYING\" must be a relative path of names separated by single /, none of them . or ..",
            ),
            (
                with(
                    "about = \"a test\"",
                    "about = \"a\"\nlinks = [{ path = \"a\", target = \"\" }]",
                ),
                "p: a link's target must be a path",
            ),
            (
                with(
                    "about = \"a test\"",
                    "about = \"a\"\nlinks = [{ path = \"a\", target = \"b\\u0007\" }]",
                ),
                "p: a link's target must be a path",
            ),
            (
                with(
                    "about = \"a test\"",
                    "about = \"a\"\nlinks = [{ path = \"../a\", target = \"b\" }]",
                ),
                "p: link path \"../a\" must be a relative path of names separated by single /, none of them . or ..",
            ),
            (
                with(
                    "about = \"a test\"",
                    "about = \"a\"\nlinks = [{ path = \"a\", target = \"b\", x = 1 }]",
                ),
                "p: unknown key x; expected one of path, target",
            ),
        ];
        for (text, expected) in cases {
            assert_eq!(
                error(&text),
                format!("can't parse corpus/corpus.toml: {expected}"),
                "{text}"
            );
        }
        let none = "format = 1\n[[package]]\nname = \"p\"\nabout = \"a\"\n";
        assert_eq!(
            error(none),
            "can't parse corpus/corpus.toml: p: it has no source"
        );
    }

    #[test]
    fn a_source_is_checked() {
        let url = "p: https://example.org/p.tar.gz";
        let cases = [
            ("format = \"zip\"", format!("{url}: format \"zip\" must be \"tar.gz\" or \"deb\"")),
            ("format = \"deb\"\nstrip = 1", format!("{url}: a deb's paths start at the root, so it takes no strip")),
            ("format = \"tar.gz\"\nstrip = 9", format!("{url}: strip must be 0 to 8")),
            ("format = \"tar.gz\"\nstrip = -1", format!("{url}: strip must be 0 to 8")),
            ("format = \"tar.gz\"\nstrip = \"1\"", format!("{url}: strip must be 0 to 8")),
            ("format = \"deb\"\nplace = []", format!("{url}: place is empty, so nothing would be laid out")),
            ("format = \"deb\"\nplace = [{ from = \"a\", to = \"b\" }, { from = \"a\", to = \"c\" }]", format!("{url}: from \"a\" is placed twice")),
            ("format = \"deb\"\nplace = [{ from = \"a/\", to = \"b\" }]", format!("{url}: from \"a/\" must be a relative path of names separated by single /, none of them . or .., or empty")),
            ("format = \"deb\"\nplace = [{ from = \"a\", to = \"b//c\" }]", format!("{url}: to \"b//c\" must be a relative path of names separated by single /, none of them . or .., or empty")),
            ("format = \"deb\"\nplace = [{ from = \"a\", to = \"./b\" }]", format!("{url}: to \"./b\" must be a relative path of names separated by single /, none of them . or .., or empty")),
            ("format = \"deb\"\nplace = [{ from = \"a\" }]", format!("{url}: to is missing")),
            ("format = \"deb\"\nplace = [{ from = \"a\", to = \"b\", x = 1 }]", format!("{url}: unknown key x; expected one of from, to")),
            ("format = \"deb\"\nexclude = [{ path = \"\", reason = \"r\" }]", format!("{url}: exclude path \"\" must be a relative path of names separated by single /, none of them . or ..")),
            ("format = \"deb\"\nexclude = [{ path = \"a\", reason = \"r\" }, { path = \"a\", reason = \"s\" }]", format!("{url}: \"a\" is excluded twice")),
            ("format = \"deb\"\nexclude = [{ path = \"a\", reason = \"\" }]", format!("{url}: reason must be one line of text, not empty")),
            ("format = \"deb\"\nexclude = [{ path = \"a\" }]", format!("{url}: reason is missing")),
            ("format = \"deb\"\nexclude = [{ path = \"a\", reason = \"r\", x = 1 }]", format!("{url}: unknown key x; expected one of path, reason")),
            ("format = \"deb\"\nmirror = 1", "p: unknown key mirror; expected one of url, size, sha256, format, strip, place, exclude".to_owned()),
        ];
        for (source, expected) in cases {
            assert_eq!(
                error(&one(source)),
                format!("can't parse corpus/corpus.toml: {expected}"),
                "{source}"
            );
        }
        let base = one("format = \"deb\"");
        let with = |from: &str, to: &str| base.replacen(from, to, 1);
        let cases = [
            (
                with("https://example.org", "http://example.org"),
                "p: url \"http://example.org/p.tar.gz\" must be an https URL".to_owned(),
            ),
            (
                with("https://example.org/p", "https://example.org/ p"),
                "p: url \"https://example.org/ p.tar.gz\" must be an https URL".to_owned(),
            ),
            (
                with("size = 10", "size = 0"),
                format!("{url}: size must be 1 to {MAX_SIZE} bytes"),
            ),
            (
                with("size = 10", &format!("size = {}", MAX_SIZE + 1)),
                format!("{url}: size must be 1 to {MAX_SIZE} bytes"),
            ),
            (
                with("size = 10", "size = \"10\""),
                format!("{url}: size must be an integer"),
            ),
            (
                with(HASH, &HASH.to_uppercase()),
                format!("{url}: sha256 must be 64 lowercase hex digits"),
            ),
            (
                with(HASH, &HASH[1..]),
                format!("{url}: sha256 must be 64 lowercase hex digits"),
            ),
            (
                with(HASH, &format!("{}g", &HASH[1..])),
                format!("{url}: sha256 must be 64 lowercase hex digits"),
            ),
        ];
        for (text, expected) in cases {
            assert_eq!(
                error(&text),
                format!("can't parse corpus/corpus.toml: {expected}"),
                "{text}"
            );
        }
        // The largest size and strip are allowed.
        let max = with("size = 10", &format!("size = {MAX_SIZE}"));
        assert_eq!(parse(&max).unwrap()[0].sources[0].size, MAX_SIZE);
        let strip = parse(&one("format = \"tar.gz\"\nstrip = 8")).unwrap();
        assert_eq!(strip[0].sources[0].strip, 8);
    }

    #[test]
    fn this_repositorys_corpus_reads() {
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../corpus/corpus.toml"),
        )
        .unwrap();
        let packages = parse(&text).unwrap();
        assert!(packages.len() >= 5);
    }
}
