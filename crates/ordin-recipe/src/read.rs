// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Reading a recipe's TOML: every table, key and value, with where each
//! one is, so an error names the line and column.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::ops::Range;
use std::str::FromStr;

use ordin_core::{Account, Facet, FilePath, Mode, PackageName};
use ordin_depexpr::Expr;
use ordin_manifest::{
    Class, Condition, Flush, Group, Id, InferenceSkip, OnRemove, Presentation, Preset, Provide,
    Seed, Setting, SettingType, SettingValue, StateFile, StatePath, Unit, UnitName, Url, User,
};
use ordin_tree::TreePath;
use ordin_version::Version;
use toml::Spanned;
use toml::de::{DeArray, DeTable, DeValue};

use crate::{
    Allow, Check, DeclaredState, Error, FORMAT, FacetMove, LicenseFiles, REASON_MAX, Recipe,
    RelativePath, below,
};

/// A byte range in the recipe.
pub(crate) type Span = Range<usize>;

type Value<'i> = Spanned<DeValue<'i>>;

/// Where one table in an array of tables is, and each of its values.
#[derive(Clone, Debug, Default)]
pub(crate) struct Item {
    /// The table.
    pub span: Span,
    /// Each key's value.
    pub fields: BTreeMap<String, Span>,
}

/// Where each part of a recipe is, in the same order as the recipe's
/// lists.
#[derive(Clone, Debug, Default)]
pub(crate) struct Locations {
    /// Each `[package]` value, by key.
    pub package: BTreeMap<&'static str, Span>,
    pub users: Vec<Item>,
    pub groups: Vec<Item>,
    pub units: Vec<Item>,
    pub settings: Vec<Item>,
    pub state_version: Option<Span>,
    pub state_paths: Vec<Item>,
    pub state_files: Vec<Item>,
    pub seeds: Vec<Item>,
}

/// The line and column, from 1, of a byte offset; the column counts
/// characters.
pub(crate) fn position(text: &str, offset: usize) -> (usize, usize) {
    let before = &text[..text.floor_char_boundary(offset)];
    let line = before.matches('\n').count() + 1;
    let column = before.rsplit('\n').next().unwrap_or("").chars().count() + 1;
    (line, column)
}

/// An error at a span of `text`.
pub(crate) fn error(text: &str, span: &Span, message: impl Display) -> Error {
    let (line, column) = position(text, span.start);
    Error {
        line,
        column,
        message: message.to_string(),
    }
}

/// A value's type, for messages.
fn kind(v: &DeValue<'_>) -> &'static str {
    match v {
        DeValue::String(_) => "a string",
        DeValue::Integer(_) => "an integer",
        DeValue::Float(_) => "a float",
        DeValue::Boolean(_) => "a boolean",
        DeValue::Datetime(_) => "a date",
        DeValue::Array(_) => "an array",
        DeValue::Table(_) => "a table",
    }
}

/// The values `allowed` lists, for messages: `a, b or c`.
fn one_of(allowed: &[&str]) -> String {
    match allowed.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} or {last}", rest.join(", ")),
        _ => allowed.join(""),
    }
}

/// One TOML table, and what it is called in messages.
struct Table<'a, 'i> {
    entries: &'a DeTable<'i>,
    span: Span,
    name: String,
}

struct Reader<'t> {
    text: &'t str,
}

impl Reader<'_> {
    fn error(&self, span: &Span, message: impl Display) -> Error {
        error(self.text, span, message)
    }

    fn wrong(&self, v: &Value<'_>, expected: &str) -> Error {
        self.error(
            &v.span(),
            format!("expected {expected}, found {}", kind(v.get_ref())),
        )
    }

    fn table<'a, 'i>(
        &self,
        v: &'a Value<'i>,
        name: String,
        allowed: &[&str],
    ) -> Result<Table<'a, 'i>, Error> {
        let DeValue::Table(entries) = v.get_ref() else {
            return Err(self.wrong(v, &format!("a table for {name}")));
        };
        let t = Table {
            entries,
            span: v.span(),
            name,
        };
        self.keys(&t, allowed)?;
        Ok(t)
    }

    /// Refuses every key `allowed` doesn't list.
    fn keys(&self, t: &Table<'_, '_>, allowed: &[&str]) -> Result<(), Error> {
        for (key, _) in t.entries.iter() {
            let k: &str = key.get_ref();
            if !allowed.contains(&k) {
                return Err(self.error(
                    &key.span(),
                    format!("{} has no key {k:?}; expected {}", t.name, one_of(allowed)),
                ));
            }
        }
        Ok(())
    }

    fn string<'a>(&self, v: &'a Value<'_>) -> Result<&'a str, Error> {
        match v.get_ref() {
            DeValue::String(s) => Ok(s),
            _ => Err(self.wrong(v, "a string")),
        }
    }

    fn integer(&self, v: &Value<'_>) -> Result<i64, Error> {
        match v.get_ref() {
            DeValue::Integer(i) => i64::from_str_radix(i.as_str(), i.radix())
                .map_err(|_| self.error(&v.span(), "an integer here is at most 2^63 - 1")),
            _ => Err(self.wrong(v, "an integer")),
        }
    }

    fn count(&self, v: &Value<'_>) -> Result<u64, Error> {
        let i = self.integer(v)?;
        u64::try_from(i)
            .map_err(|_| self.error(&v.span(), format!("expected 0 or more, found {i}")))
    }

    fn boolean(&self, v: &Value<'_>) -> Result<bool, Error> {
        match v.get_ref() {
            DeValue::Boolean(b) => Ok(*b),
            _ => Err(self.wrong(v, "true or false")),
        }
    }

    fn array<'a, 'i>(&self, v: &'a Value<'i>, what: &str) -> Result<&'a DeArray<'i>, Error> {
        match v.get_ref() {
            DeValue::Array(a) => Ok(a),
            _ => Err(self.wrong(v, &format!("an array of {what}"))),
        }
    }

    /// A string read by `T`'s parser; `what` says what was expected.
    fn parsed<T>(&self, v: &Value<'_>, what: &str) -> Result<T, Error>
    where
        T: FromStr,
        T::Err: Display,
    {
        let s = match v.get_ref() {
            DeValue::String(s) => s,
            _ => return Err(self.wrong(v, what)),
        };
        s.parse()
            .map_err(|e| self.error(&v.span(), format!("expected {what}: {e}")))
    }

    /// One of a fixed set of strings.
    fn choice<T: Copy>(
        &self,
        v: &Value<'_>,
        from_text: fn(&str) -> Option<T>,
        allowed: fn() -> String,
    ) -> Result<T, Error> {
        let s = self.string(v)?;
        from_text(s)
            .ok_or_else(|| self.error(&v.span(), format!("expected {}, found {s:?}", allowed())))
    }

    /// Every item of an array, read by `T`'s parser.
    fn parsed_list<T>(&self, v: &Value<'_>, what: &str) -> Result<Vec<T>, Error>
    where
        T: FromStr,
        T::Err: Display,
    {
        let items = self.array(v, &format!("strings, each {what}"))?;
        items.iter().map(|item| self.parsed(item, what)).collect()
    }

    /// Every item of an array of strings.
    fn strings(&self, v: &Value<'_>) -> Result<Vec<String>, Error> {
        let items = self.array(v, "strings")?;
        items
            .iter()
            .map(|item| Ok(self.string(item)?.to_owned()))
            .collect()
    }

    /// The tables of an array of tables, such as `[[user]]`.
    fn tables<'a, 'i>(
        &self,
        v: &'a Value<'i>,
        name: &str,
        allowed: &[&str],
    ) -> Result<Vec<(Table<'a, 'i>, Item)>, Error> {
        let items = self.array(v, &format!("tables, written [[{name}]]"))?;
        items
            .iter()
            .map(|item| {
                let t = self.table(item, format!("[[{name}]]"), allowed)?;
                let fields = t
                    .entries
                    .iter()
                    .map(|(k, v)| (k.get_ref().to_string(), v.span()))
                    .collect();
                let at = Item {
                    span: t.span.clone(),
                    fields,
                };
                Ok((t, at))
            })
            .collect()
    }

    /// A key the table must have.
    fn need<'a, 'i>(&self, t: &Table<'a, 'i>, key: &str) -> Result<&'a Value<'i>, Error> {
        get(t, key).ok_or_else(|| self.error(&t.span, format!("{} needs {key}", t.name)))
    }
}

fn get<'a, 'i>(t: &Table<'a, 'i>, key: &str) -> Option<&'a Value<'i>> {
    t.entries
        .iter()
        .find(|(k, _)| {
            let k: &str = k.get_ref();
            k == key
        })
        .map(|(_, v)| v)
}

/// Reads `owner = "USER:GROUP"`.
fn owner(r: &Reader<'_>, v: &Value<'_>) -> Result<(Account, Account), Error> {
    let s = r.string(v)?;
    let bad = |why: String| r.error(&v.span(), format!("expected USER:GROUP: {why}"));
    let Some((user, group)) = s.split_once(':') else {
        return Err(bad(format!("{s:?} has no ':'")));
    };
    let user: Account = user
        .parse()
        .map_err(|e: ordin_core::Error| bad(e.to_string()))?;
    let group: Account = group
        .parse()
        .map_err(|e: ordin_core::Error| bad(e.to_string()))?;
    Ok((user, group))
}

/// Checks the version as the command line does: the upstream version,
/// then the release, must read back as given.
fn check_version(text: &str, release: &str) -> Result<(), String> {
    let full: Version = format!("{text}-{release}")
        .parse()
        .map_err(|e: ordin_version::Error| e.to_string())?;
    if full.release() == Some(release) {
        Ok(())
    } else {
        Err(format!(
            "{text:?} with release {release:?} doesn't read back as given"
        ))
    }
}

const TOP: &[&str] = &[
    "facets", "format", "group", "infer", "license", "lint", "package", "setting", "state", "unit",
    "user",
];
const PACKAGE: &[&str] = &[
    "arch",
    "conflicts",
    "description",
    "homepage",
    "license",
    "name",
    "provides",
    "release",
    "requires",
    "summary",
    "version",
];

/// Reads a recipe's text, and where each part of it is.
pub(crate) fn recipe(text: &str) -> Result<(Recipe, Locations), Error> {
    let r = Reader { text };
    let doc = DeTable::parse(text).map_err(|e| {
        let span = e.span().unwrap_or(0..0);
        // One line, like every other error.
        let message: Vec<&str> = e.message().lines().map(str::trim).collect();
        r.error(&span, format!("not valid TOML: {}", message.join("; ")))
    })?;
    let top = Table {
        entries: doc.get_ref(),
        span: doc.span(),
        name: "a recipe".to_owned(),
    };
    r.keys(&top, TOP)?;
    let format = get(&top, "format")
        .ok_or_else(|| r.error(&(0..0), format!("a recipe starts with format = {FORMAT}")))?;
    let n = r.integer(format)?;
    if n != FORMAT {
        return Err(r.error(
            &format.span(),
            format!("this is recipe format {n}; Ordin reads format {FORMAT}"),
        ));
    }

    let mut at = Locations::default();
    let mut recipe = Recipe::default();
    if let Some(v) = get(&top, "package") {
        package(&r, v, &mut recipe, &mut at)?;
    }
    if let Some(v) = get(&top, "license") {
        recipe.license = license(&r, v)?;
    }
    if let Some(v) = get(&top, "user") {
        for (t, item) in r.tables(
            v,
            "user",
            &["comment", "groups", "home", "name", "shell", "system"],
        )? {
            recipe.declared.users.push(user(&r, &t)?);
            at.users.push(item);
        }
    }
    if let Some(v) = get(&top, "group") {
        for (t, item) in r.tables(v, "group", &["name", "system"])? {
            let name = r.parsed(r.need(&t, "name")?, "a group name")?;
            let system = get(&t, "system").map(|v| r.boolean(v)).transpose()?;
            recipe.declared.groups.push(Group {
                name,
                system: system.unwrap_or(true),
            });
            at.groups.push(item);
        }
    }
    if let Some(v) = get(&top, "unit") {
        for (t, item) in r.tables(v, "unit", &["if", "name", "preset"])? {
            let name: UnitName =
                r.parsed(r.need(&t, "name")?, "a unit name such as \"foo.service\"")?;
            let preset = r.choice(r.need(&t, "preset")?, Preset::from_text, Preset::allowed)?;
            let condition = get(&t, "if")
                .map(|v| r.parsed::<Condition>(v, "a condition such as \"setting.tls\""))
                .transpose()?;
            recipe.declared.units.push(Unit {
                name,
                preset,
                condition,
            });
            at.units.push(item);
        }
    }
    if let Some(v) = get(&top, "setting") {
        for (t, item) in r.tables(v, "setting", SETTING)? {
            recipe.declared.settings.push(setting(&r, &t)?);
            at.settings.push(item);
        }
    }
    if let Some(v) = get(&top, "state") {
        recipe.declared.state = state(&r, v, &mut at)?;
    }
    if let Some(v) = get(&top, "facets") {
        recipe.declared.facets = facets(&r, v)?;
    }
    if let Some(v) = get(&top, "infer") {
        recipe.declared.inference_skip = infer(&r, v)?;
    }
    if let Some(v) = get(&top, "lint") {
        recipe.lint = lint(&r, v)?;
    }
    Ok((recipe, at))
}

fn package(
    r: &Reader<'_>,
    v: &Value<'_>,
    recipe: &mut Recipe,
    at: &mut Locations,
) -> Result<(), Error> {
    let t = r.table(v, "[package]".to_owned(), PACKAGE)?;
    for key in PACKAGE {
        if let Some(v) = get(&t, key) {
            at.package.insert(key, v.span());
        }
    }
    let p = &mut recipe.package;
    p.name = get(&t, "name")
        .map(|v| r.parsed::<PackageName>(v, "a package name"))
        .transpose()?;
    p.release = get(&t, "release")
        .map(|v| match v.get_ref() {
            DeValue::Integer(_) => r.count(v).map(|n| n.to_string()),
            _ => r.string(v).map(str::to_owned),
        })
        .transpose()?;
    if let (Some(v), Some(release)) = (get(&t, "release"), &p.release) {
        check_version("0", release)
            .map_err(|e| r.error(&v.span(), format!("expected a release such as \"1\": {e}")))?;
    }
    if let Some(v) = get(&t, "version") {
        let text = r.string(v)?;
        check_version(text, p.release.as_deref().unwrap_or("1")).map_err(|e| {
            r.error(
                &v.span(),
                format!("expected an upstream version such as \"2.12\": {e}"),
            )
        })?;
        p.version = Some(text.to_owned());
    }
    p.arch = get(&t, "arch")
        .map(|v| r.parsed(v, "x86_64, aarch64 or noarch"))
        .transpose()?;
    p.summary = get(&t, "summary")
        .map(|v| r.string(v).map(str::to_owned))
        .transpose()?;
    p.description = get(&t, "description")
        .map(|v| r.string(v).map(str::to_owned))
        .transpose()?;
    p.homepage = get(&t, "homepage")
        .map(|v| r.parsed::<Url>(v, "an https URL"))
        .transpose()?;
    if let Some(v) = get(&t, "license") {
        let text = r.string(v)?;
        ordin_manifest::spdx::parse(text).map_err(|e| {
            r.error(
                &v.span(),
                format!("expected an SPDX license expression: {e}"),
            )
        })?;
        p.license = Some(text.to_owned());
    }
    let d = &mut recipe.declared;
    let list = |key: &str| -> Result<Vec<Expr>, Error> {
        get(&t, key)
            .map(|v| r.parsed_list(v, "a requirement such as \"libfoo >= 1.2\""))
            .transpose()
            .map(Option::unwrap_or_default)
    };
    d.requires = list("requires")?;
    d.conflicts = list("conflicts")?;
    d.provides = get(&t, "provides")
        .map(|v| r.parsed_list::<Provide>(v, "a provide such as \"cap:foo = 1.0\""))
        .transpose()?
        .unwrap_or_default();
    Ok(())
}

fn license(r: &Reader<'_>, v: &Value<'_>) -> Result<LicenseFiles, Error> {
    let t = r.table(v, "[license]".to_owned(), &["files", "presentation"])?;
    let presentation = get(&t, "presentation")
        .map(|v| r.choice(v, Presentation::from_text, Presentation::allowed))
        .transpose()?;
    let mut files = BTreeMap::new();
    if let Some(v) = get(&t, "files") {
        let DeValue::Table(entries) = v.get_ref() else {
            return Err(r.wrong(
                v,
                "a table of license IDs and paths, such as { MIT = \"COPYING\" }",
            ));
        };
        for (id, path) in entries.iter() {
            let path: RelativePath = r.parsed(path, "a path relative to the recipe's directory")?;
            files.insert(id.get_ref().to_string(), path);
        }
    }
    Ok(LicenseFiles {
        presentation,
        files,
    })
}

fn user(r: &Reader<'_>, t: &Table<'_, '_>) -> Result<User, Error> {
    let opt_path = |key: &str| {
        get(t, key)
            .map(|v| r.parsed::<FilePath>(v, "an absolute path"))
            .transpose()
    };
    Ok(User {
        name: r.parsed(r.need(t, "name")?, "a user name")?,
        system: get(t, "system")
            .map(|v| r.boolean(v))
            .transpose()?
            .unwrap_or(true),
        home: opt_path("home")?,
        shell: opt_path("shell")?,
        groups: get(t, "groups")
            .map(|v| r.parsed_list(v, "a group name"))
            .transpose()?
            .unwrap_or_default(),
        comment: get(t, "comment")
            .map(|v| r.string(v).map(str::to_owned))
            .transpose()?,
    })
}

const SETTING: &[&str] = &[
    "aliases",
    "choices",
    "default",
    "description",
    "max",
    "min",
    "name",
    "pattern",
    "required",
    "type",
];

fn setting(r: &Reader<'_>, t: &Table<'_, '_>) -> Result<Setting, Error> {
    let name: Id = r.parsed(r.need(t, "name")?, "a setting name such as \"listen-port\"")?;
    let kind = r.choice(
        r.need(t, "type")?,
        SettingType::from_text,
        SettingType::allowed,
    )?;
    let default = get(t, "default")
        .map(|v| -> Result<SettingValue, Error> {
            let because = |what: &str| format!("{what}, since the setting's type is {kind}");
            Ok(match kind {
                SettingType::Bool => SettingValue::Bool(
                    r.boolean(v)
                        .map_err(|_| r.wrong(v, &because("true or false")))?,
                ),
                SettingType::Int | SettingType::Port => {
                    SettingValue::Int(r.integer(v).map_err(|e| match v.get_ref() {
                        DeValue::Integer(_) => e,
                        _ => r.wrong(v, &because("an integer")),
                    })?)
                }
                SettingType::String | SettingType::Choice | SettingType::Path => SettingValue::Str(
                    r.string(v)
                        .map_err(|_| r.wrong(v, &because("a string")))?
                        .to_owned(),
                ),
                SettingType::Multichoice | SettingType::List => {
                    SettingValue::List(r.strings(v).map_err(|e| match v.get_ref() {
                        DeValue::Array(_) => e,
                        _ => r.wrong(v, &because("an array of strings")),
                    })?)
                }
            })
        })
        .transpose()?;
    let int = |key: &str| get(t, key).map(|v| r.integer(v)).transpose();
    let mut aliases = BTreeMap::new();
    if let Some(v) = get(t, "aliases") {
        let DeValue::Table(entries) = v.get_ref() else {
            return Err(r.wrong(
                v,
                "a table of former names, such as { debconf = \"foo/bar\" }",
            ));
        };
        for (system, former) in entries.iter() {
            aliases.insert(system.get_ref().to_string(), r.string(former)?.to_owned());
        }
    }
    Ok(Setting {
        name,
        kind,
        default,
        required: get(t, "required")
            .map(|v| r.boolean(v))
            .transpose()?
            .unwrap_or(false),
        description: get(t, "description")
            .map(|v| r.string(v).map(str::to_owned))
            .transpose()?,
        min: int("min")?,
        max: int("max")?,
        pattern: get(t, "pattern")
            .map(|v| r.string(v).map(str::to_owned))
            .transpose()?,
        choices: get(t, "choices")
            .map(|v| r.strings(v))
            .transpose()?
            .unwrap_or_default(),
        aliases,
    })
}

fn state(r: &Reader<'_>, v: &Value<'_>, at: &mut Locations) -> Result<DeclaredState, Error> {
    let t = r.table(
        v,
        "[state]".to_owned(),
        &["file", "obsolete", "path", "seed", "version"],
    )?;
    let mut state = DeclaredState::default();
    if let Some(v) = get(&t, "version") {
        state.version = r.count(v)?;
        at.state_version = Some(v.span());
    }
    if let Some(v) = get(&t, "obsolete") {
        state.obsolete = r.parsed_list::<FilePath>(v, "an absolute path")?;
    }
    let path = |t: &Table<'_, '_>| r.parsed::<FilePath>(r.need(t, "path")?, "an absolute path");
    let owner = |t: &Table<'_, '_>| {
        get(t, "owner")
            .map(|v| owner(r, v))
            .transpose()
            .map(|o| o.unwrap_or((Account::root(), Account::root())))
    };
    let mode = |t: &Table<'_, '_>, default: Mode| -> Result<Mode, Error> {
        get(t, "mode").map_or(Ok(default), |v| {
            r.parsed(v, "a mode of four octal digits, such as \"0750\"")
        })
    };
    if let Some(v) = get(&t, "path") {
        let allowed = &[
            "class",
            "flush",
            "mode",
            "on-remove",
            "owner",
            "path",
            "recurse",
        ];
        for (t, item) in r.tables(v, "state.path", allowed)? {
            let (owner, group) = owner(&t)?;
            state.paths.push(StatePath {
                path: path(&t)?,
                class: r.choice(r.need(&t, "class")?, Class::from_text, Class::allowed)?,
                owner,
                group,
                mode: mode(&t, Mode::DIR)?,
                flush: get(&t, "flush")
                    .map(|v| r.choice(v, Flush::from_text, Flush::allowed))
                    .transpose()?
                    .unwrap_or(Flush::Never),
                recurse: get(&t, "recurse")
                    .map(|v| r.boolean(v))
                    .transpose()?
                    .unwrap_or(false),
                on_remove: get(&t, "on-remove")
                    .map(|v| r.choice(v, OnRemove::from_text, OnRemove::allowed))
                    .transpose()?,
            });
            at.state_paths.push(item);
        }
    }
    if let Some(v) = get(&t, "file") {
        for (t, item) in r.tables(v, "state.file", &["mode", "owner", "path"])? {
            let (owner, group) = owner(&t)?;
            state.files.push(StateFile {
                path: path(&t)?,
                owner,
                group,
                mode: mode(&t, Mode::FILE)?,
            });
            at.state_files.push(item);
        }
    }
    if let Some(v) = get(&t, "seed") {
        for (t, item) in r.tables(v, "state.seed", &["from", "path"])? {
            state.seeds.push(Seed {
                path: path(&t)?,
                from: r.parsed(r.need(&t, "from")?, "an absolute path in the package")?,
            });
            at.seeds.push(item);
        }
    }
    Ok(state)
}

/// Characters that would make a path a pattern.
const PATTERN: &[char] = &['*', '?', '[', ']', '{', '}'];

fn facets(r: &Reader<'_>, v: &Value<'_>) -> Result<Vec<FacetMove>, Error> {
    let DeValue::Table(entries) = v.get_ref() else {
        return Err(r.wrong(v, "a table of facets, written [facets.NAME]"));
    };
    let mut moves = Vec::new();
    let mut seen = BTreeSet::new();
    for (name, v) in entries.iter() {
        let facet: Facet = name.get_ref().parse().map_err(|e: ordin_core::Error| {
            r.error(&name.span(), format!("expected a facet name: {e}"))
        })?;
        let t = r.table(v, format!("[facets.{facet}]"), &["extra"])?;
        let Some(extra) = get(&t, "extra") else {
            continue;
        };
        let items = r.array(extra, "paths")?;
        for item in items.iter() {
            let path = package_path(r, item)?;
            if !seen.insert(path.clone()) {
                return Err(r.error(&item.span(), format!("{path} is moved to a facet twice")));
            }
            moves.push(FacetMove {
                facet: facet.clone(),
                path,
            });
        }
    }
    Ok(moves)
}

/// A package path for a facet move or an inference skip: absolute, with a
/// trailing `/**` meaning the same as the directory, and no other pattern.
fn package_path(r: &Reader<'_>, item: &Value<'_>) -> Result<TreePath, Error> {
    let s = r.string(item)?;
    let path = s.strip_suffix("/**").unwrap_or(s);
    if path.contains(PATTERN) {
        return Err(r.error(
            &item.span(),
            format!("expected a path, or a directory ending in /**; other patterns aren't supported: {s:?}"),
        ));
    }
    path.parse()
        .map_err(|e: String| r.error(&item.span(), format!("expected an absolute path: {e}")))
}

/// Reads `[infer]`: its `[[infer.skip]]` entries, one per path.
fn infer(r: &Reader<'_>, v: &Value<'_>) -> Result<Vec<InferenceSkip>, Error> {
    let t = r.table(v, "[infer]".to_owned(), &["skip"])?;
    let Some(v) = get(&t, "skip") else {
        return Ok(Vec::new());
    };
    let mut skips: Vec<InferenceSkip> = Vec::new();
    for (t, _) in r.tables(v, "infer.skip", &["paths", "reason"])? {
        let reason = reason(
            r,
            r.need(&t, "reason")?,
            "a skip says why its files aren't read",
        )?;
        let v = r.need(&t, "paths")?;
        let items = r.array(v, "paths")?;
        if items.is_empty() {
            return Err(r.error(&v.span(), "expected at least one path"));
        }
        for item in items.iter() {
            let path = package_path(r, item)?;
            if !path.as_str().starts_with("/usr/") {
                return Err(r.error(
                    &item.span(),
                    format!(
                        "{path} isn't under /usr, where a package's files are after its layout"
                    ),
                ));
            }
            let path: FilePath = path.as_str().parse().map_err(|e: ordin_core::Error| {
                r.error(&item.span(), format!("expected an absolute path: {e}"))
            })?;
            for earlier in &skips {
                let (a, b) = (earlier.path.as_str(), path.as_str());
                let message = if a == b {
                    format!("{path} is skipped twice")
                } else if below(b, a) {
                    format!("{path} is below {a}, which is skipped already")
                } else if below(a, b) {
                    format!("{a}, skipped already, is below {path}; skip only {path}")
                } else {
                    continue;
                };
                return Err(r.error(&item.span(), message));
            }
            skips.push(InferenceSkip {
                path,
                reason: reason.clone(),
            });
        }
    }
    Ok(skips)
}

/// Reads `[lint]`: its `[[lint.allow]]` entries.
fn lint(r: &Reader<'_>, v: &Value<'_>) -> Result<Vec<Allow>, Error> {
    let t = r.table(v, "[lint]".to_owned(), &["allow"])?;
    let Some(v) = get(&t, "allow") else {
        return Ok(Vec::new());
    };
    let mut allows: Vec<Allow> = Vec::new();
    for (t, _) in r.tables(v, "lint.allow", &["id", "paths", "reason"])? {
        let check = allowed_check(r, r.need(&t, "id")?)?;
        let reason = reason(
            r,
            r.need(&t, "reason")?,
            "an allow says why the warning is accepted",
        )?;
        let line = position(r.text, t.span.start).0;
        let mut paths: Vec<TreePath> = Vec::new();
        if let Some(v) = get(&t, "paths") {
            if !check.has_paths() {
                return Err(r.error(
                    &v.span(),
                    format!("{check} warnings name no path, so its allow takes no paths"),
                ));
            }
            let items = r.array(v, "paths")?;
            if items.is_empty() {
                return Err(r.error(
                    &v.span(),
                    "expected at least one path; leave paths out to allow it for the whole package",
                ));
            }
            for item in items.iter() {
                let path: TreePath = r.parsed(item, "an absolute path")?;
                let earlier = allows
                    .iter()
                    .filter(|a| a.check == check)
                    .any(|a| a.paths.contains(&path));
                if earlier || paths.contains(&path) {
                    return Err(r.error(
                        &item.span(),
                        format!("{path} is already allowed for {check}"),
                    ));
                }
                paths.push(path);
            }
        }
        if let Some(earlier) = allows
            .iter()
            .find(|a| a.check == check && (a.paths.is_empty() || paths.is_empty()))
        {
            return Err(r.error(
                &t.span,
                format!(
                    "{check} is already allowed at line {}; one allow for the whole package \
                     is the only one for its check",
                    earlier.line
                ),
            ));
        }
        allows.push(Allow {
            check,
            reason,
            paths,
            line,
        });
    }
    Ok(allows)
}

/// The check an allow names.
fn allowed_check(r: &Reader<'_>, v: &Value<'_>) -> Result<Check, Error> {
    let id = r.string(v)?;
    match Check::from_id(id) {
        Some(Check::UnusedAllow) => Err(r.error(
            &v.span(),
            "unused-allow can't be allowed; remove the allow that matches nothing",
        )),
        Some(check) => Ok(check),
        None => {
            let ids: Vec<&str> = Check::ALL
                .into_iter()
                .filter(|c| *c != Check::UnusedAllow)
                .map(Check::id)
                .collect();
            Err(r.error(
                &v.span(),
                format!("expected a check: {}; found {id:?}", one_of(&ids)),
            ))
        }
    }
}

/// An allow's or a skip's reason: one line of text. `empty` says what an
/// empty one is missing.
fn reason(r: &Reader<'_>, v: &Value<'_>, empty: &str) -> Result<String, Error> {
    let reason = r.string(v)?;
    let bad = |why: &str| r.error(&v.span(), format!("expected a reason: {why}"));
    if reason.trim().is_empty() {
        return Err(bad(empty));
    }
    if reason.chars().any(char::is_control) {
        return Err(bad("one line, without control characters"));
    }
    if reason.chars().count() > REASON_MAX {
        return Err(bad(&format!("at most {REASON_MAX} characters")));
    }
    Ok(reason.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_count_lines_and_characters() {
        let text = "ab\ncdé f\n";
        assert_eq!(position(text, 0), (1, 1));
        assert_eq!(position(text, 2), (1, 3));
        assert_eq!(position(text, 3), (2, 1));
        // é is two bytes and one character; inside it counts as before it.
        assert_eq!(position(text, 6), (2, 3));
        assert_eq!(position(text, 7), (2, 4));
        assert_eq!(position(text, 8), (2, 5));
        assert_eq!(position(text, 99), (3, 1));
    }

    #[test]
    fn allowed_values_are_listed_for_people() {
        assert_eq!(one_of(&["a"]), "a");
        assert_eq!(one_of(&["a", "b"]), "a or b");
        assert_eq!(one_of(&["a", "b", "c"]), "a, b or c");
        assert_eq!(one_of(&[]), "");
    }

    #[test]
    fn a_version_reads_back_as_given_or_is_refused() {
        assert!(check_version("2.12", "1").is_ok());
        assert!(check_version("1:2.0", "3").is_ok());
        assert!(check_version("2.12", "").is_err());
        // An update level would make the release read back shorter.
        assert!(check_version("2.12", "1+u2").is_err());
    }
}
