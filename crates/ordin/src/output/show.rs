// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! What `ordin show` prints.
//!
//! Text is for people: every section that has something in it, and every
//! string escaped so a package can't send control sequences to a
//! terminal. JSON is for programs: the manifest exactly as signed, with
//! what the file adds beside it.

use std::fmt::{Display, Write as _};
use std::path::Path;

use ordin_core::json::{self, Value};
use ordin_core::{Digest, Facet};
use ordin_manifest::{
    Condition, Flush, Manifest, MigrationAction, Presentation, Setting, SettingValue, Step,
};
use ordin_sign::Signature;
use ordin_tree::{Capabilities, Entry, Kind, Tree, Xattrs};

/// What is shown about a package besides its manifest.
#[derive(Clone, Copy, Debug)]
pub struct Package<'a> {
    /// The file it was read from.
    pub file: &'a Path,
    /// Its manifest.
    pub manifest: &'a Manifest,
    /// Its identity: the BLAKE3 digest of the manifest.
    pub package: Digest,
    /// The OCI image manifest's digest.
    pub image: Digest,
    /// Its signatures, each checked to verify, by key.
    pub signatures: &'a [Signature],
}

/// Whether `c` reorders text: the bidirectional formatting characters,
/// which can make a terminal show something other than what is there.
fn reorders(c: char) -> bool {
    matches!(
        c,
        '\u{61c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

/// `text`, safe to print on a terminal: control characters and the
/// bidirectional formatting characters are written as `\u{…}`.
#[must_use]
pub fn safe(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() || reorders(c) {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

/// Anything shown, made safe.
fn t(x: impl Display) -> String {
    safe(&x.to_string())
}

/// A size for people: bytes below 1 KiB, then KiB, MiB, GiB or TiB with
/// one decimal.
#[must_use]
pub fn size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS.get(unit).copied().unwrap_or("TiB"))
}

/// A mode as `ls -l` shows it, after the type letter.
#[must_use]
pub fn mode_string(kind: char, mode: u16) -> String {
    let mut s = String::from(kind);
    for (shift, special, mark) in [(6, 0o4000, 's'), (3, 0o2000, 's'), (0, 0o1000, 't')] {
        let bits = (mode >> shift) & 0o7;
        s.push(if bits & 0o4 == 0 { '-' } else { 'r' });
        s.push(if bits & 0o2 == 0 { '-' } else { 'w' });
        s.push(match (bits & 0o1 != 0, mode & special != 0) {
            (true, true) => mark,
            (false, true) => mark.to_ascii_uppercase(),
            (true, false) => 'x',
            (false, false) => '-',
        });
    }
    s
}

/// Lines of text, in sections.
#[derive(Default)]
struct Text(String);

impl Text {
    fn line(&mut self, line: &str) {
        self.0.push_str(line);
        self.0.push('\n');
    }

    /// A section: its title, then each item indented. Nothing if there
    /// are no items.
    fn section(&mut self, title: &str, items: &[String]) {
        if items.is_empty() {
            return;
        }
        self.line("");
        self.line(&format!("{title}:"));
        for item in items {
            self.line(&format!("  {item}"));
        }
    }
}

fn all<T: Display>(items: &[T]) -> Vec<String> {
    items.iter().map(t).collect()
}

fn joined<T: Display>(items: impl IntoIterator<Item = T>) -> String {
    items.into_iter().map(t).collect::<Vec<_>>().join(", ")
}

fn condition(c: &Condition) -> String {
    match &c.value {
        None => format!("setting.{}", t(&c.setting)),
        Some(v) => format!("setting.{} = {}", t(&c.setting), t(v)),
    }
}

fn value(v: &SettingValue) -> String {
    match v {
        SettingValue::Bool(b) => b.to_string(),
        SettingValue::Int(n) => n.to_string(),
        SettingValue::Str(s) => format!("{:?}", safe(s)),
        SettingValue::List(items) => format!("[{}]", joined(items)),
    }
}

fn setting(s: &Setting) -> String {
    let mut what = vec![t(s.kind)];
    if s.required {
        what.push("required".to_owned());
    }
    if let Some(d) = &s.default {
        what.push(format!("default {}", value(d)));
    }
    let mut line = format!("{} ({})", t(&s.name), what.join(", "));
    if let Some(d) = &s.description {
        let _ = write!(line, ": {}", t(d));
    }
    line
}

/// A command line: each argument made safe, and quoted if it is empty or
/// holds a space.
fn command(args: &[String]) -> String {
    args.iter()
        .map(|a| {
            if a.is_empty() || a.contains(char::is_whitespace) {
                format!("{:?}", safe(a))
            } else {
                safe(a)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn step(phase: impl Display, s: &Step) -> String {
    let mut how = vec![format!("timeout {} s", s.timeout)];
    if s.network {
        how.push("network".to_owned());
    }
    if !s.writes.is_empty() {
        how.push(format!("writes {}", joined(&s.writes)));
    }
    if !s.execs.is_empty() {
        how.push(format!("may run {}", joined(&s.execs)));
    }
    if s.legacy {
        how.push("legacy".to_owned());
    }
    format!("{}: {} ({})", t(phase), command(&s.exec), how.join(", "))
}

/// Free text that may hold line breaks, as lines of its own.
fn paragraph(text: &str) -> Vec<String> {
    text.split('\n').map(safe).collect()
}

/// The package's header and the fields that are one line each.
fn header(out: &mut Text, p: &Package<'_>, files: Option<&[(Facet, usize)]>) {
    let m = p.manifest;
    out.line(&format!(
        "{} {} ({}, {})",
        t(&m.name),
        t(&m.version),
        t(m.arch),
        t(m.kind)
    ));
    out.line(&t(&m.summary));
    if let Some(d) = &m.description {
        out.line("");
        for line in paragraph(d) {
            out.line(&format!("  {line}"));
        }
    }
    out.line("");
    if let Some(h) = &m.homepage {
        out.line(&format!("homepage: {}", t(h)));
    }
    let mut license = t(&m.license.spdx);
    if !m.license.texts.is_empty() {
        let _ = write!(license, " (texts: {})", joined(m.license.texts.keys()));
    }
    out.line(&format!("license: {license}"));
    if m.license.presentation != Presentation::Informational {
        out.line(&format!(
            "license presentation: {}",
            t(m.license.presentation)
        ));
    }
    if let Some(s) = &m.source {
        out.line(&format!("source: {} at {}", t(&s.repo), t(&s.rev)));
    }
    if let Some(p) = &m.provenance {
        if let Some(commit) = &p.commit {
            out.line(&format!("commit: {}", t(commit)));
        }
        if let Some(d) = p.slsa {
            out.line(&format!("SLSA attestation: {d}"));
        }
        if let Some(d) = p.sbom {
            out.line(&format!("SBOM: {d}"));
        }
    }
    if m.live_apply {
        out.line("applies live: yes");
    }
    if m.boot_critical {
        out.line("needs a reboot: yes");
    }
    if let Some(s) = &m.support {
        let mut line = format!(
            "support: active until {}, security fixes until {}",
            t(s.active_until),
            t(s.security_until)
        );
        if let Some(next) = &s.successor {
            let _ = write!(line, ", then {}", t(next));
        }
        out.line(&line);
    }
    out.line(&format!("package: {}", p.package));
    out.line(&format!("image: {}", p.image));
    if p.signatures.is_empty() {
        out.line("signature: not signed");
    }
    for signature in p.signatures {
        out.line(&format!("signed by {}", signature.key()));
    }
    let names = m
        .facets
        .keys()
        .map(|f| t(f).chars().count())
        .max()
        .unwrap_or(0);
    let facets: Vec<String> = m
        .facets
        .iter()
        .map(|(facet, entry)| {
            let mut line = format!("{:<names$}  {}", t(facet), size(entry.size));
            let count = files
                .and_then(|f| f.iter().find(|(name, _)| name == facet))
                .map(|(_, n)| *n);
            if let Some(n) = count {
                let _ = write!(line, ", {n} {}", if n == 1 { "entry" } else { "entries" });
            }
            if !entry.default {
                line.push_str(", not installed by default");
            }
            line
        })
        .collect();
    out.section("facets", &facets);
}

/// The relations to other packages.
fn relations(out: &mut Text, m: &Manifest) {
    out.section("requires", &all(&m.requires));
    out.section("requires while applying", &all(&m.requires_apply));
    out.section("requires at boot", &all(&m.requires_boot));
    out.section("provides", &all(&m.provides));
    out.section("conflicts", &all(&m.conflicts));
    out.section("recommends", &all(&m.recommends));
    out.section("supplements", &all(&m.supplements));
    out.section("obsoletes", &all(&m.obsoletes));
    out.section("replaces", &all(&m.replaces));
    let removes: Vec<String> = m
        .removes
        .iter()
        .flat_map(|(facet, paths)| paths.iter().map(move |p| format!("{}: {}", t(facet), t(p))))
        .collect();
    out.section("removes", &removes);
}

/// What Ordin applies to a host for the package.
fn declarations(out: &mut Text, m: &Manifest) {
    let d = &m.declares;
    let users: Vec<String> = d
        .users
        .iter()
        .map(|u| {
            let mut what = Vec::new();
            if u.system {
                what.push("system".to_owned());
            }
            if let Some(h) = &u.home {
                what.push(format!("home {}", t(h)));
            }
            if let Some(s) = &u.shell {
                what.push(format!("shell {}", t(s)));
            }
            if !u.groups.is_empty() {
                what.push(format!("groups {}", joined(&u.groups)));
            }
            if let Some(c) = &u.comment {
                what.push(format!("{:?}", safe(c)));
            }
            if what.is_empty() {
                t(&u.name)
            } else {
                format!("{} ({})", t(&u.name), what.join(", "))
            }
        })
        .collect();
    out.section("users", &users);
    let groups: Vec<String> = d
        .groups
        .iter()
        .map(|g| {
            if g.system {
                format!("{} (system)", t(&g.name))
            } else {
                t(&g.name)
            }
        })
        .collect();
    out.section("groups", &groups);
    let units: Vec<String> = d
        .units
        .iter()
        .map(|u| match &u.condition {
            None => format!("{}: {}", t(&u.name), t(u.preset)),
            Some(c) => format!("{}: {}, if {}", t(&u.name), t(u.preset), condition(c)),
        })
        .collect();
    out.section("units", &units);
    let config: Vec<String> = d
        .config
        .iter()
        .map(|c| format!("{} from {} ({})", t(&c.target), t(&c.default), t(c.merge)))
        .collect();
    out.section("config", &config);
    let mut alternatives = Vec::new();
    for a in &d.alternatives {
        alternatives.push(format!(
            "{}: {} -> {}, priority {}",
            t(&a.name),
            t(&a.link),
            t(&a.target),
            a.priority
        ));
        for f in &a.followers {
            alternatives.push(format!("  {} -> {}", t(&f.link), t(&f.target)));
        }
    }
    out.section("alternatives", &alternatives);
    let triggers: Vec<String> = d
        .triggers
        .iter()
        .map(|tr| format!("{} on {}", t(&tr.action), joined(&tr.paths)))
        .collect();
    out.section("triggers", &triggers);
    out.section("setuid files", &all(&d.setuid));
    let mut boot = Vec::new();
    if let Some(b) = &d.boot {
        if let Some(k) = &b.kernel {
            boot.push(format!("kernel {}", t(k)));
        }
        if b.uki {
            boot.push("a unified kernel image".to_owned());
        }
        boot.extend(
            b.initrd_extensions
                .iter()
                .map(|e| format!("initrd extension {}", t(e))),
        );
    }
    out.section("boot", &boot);
}

/// The state under `/var` and `/run`.
fn state(out: &mut Text, m: &Manifest) {
    let Some(s) = &m.state else {
        return;
    };
    let mut lines = vec![format!(
        "version {}, migration {}",
        s.version,
        t(s.migration)
    )];
    for p in &s.paths {
        let mut line = format!(
            "{}: {}, {}:{} {}",
            t(&p.path),
            t(p.class),
            t(&p.owner),
            t(&p.group),
            p.mode
        );
        if p.flush == Flush::OnUpgrade {
            line.push_str(", emptied on upgrade");
        }
        if p.recurse {
            line.push_str(", owners fixed recursively");
        }
        if let Some(r) = p.on_remove {
            let _ = write!(line, ", on remove: {}", t(r));
        }
        lines.push(line);
    }
    for f in &s.files {
        lines.push(format!(
            "{}: created if missing, {}:{} {}",
            t(&f.path),
            t(&f.owner),
            t(&f.group),
            f.mode
        ));
    }
    for seed in &s.seeds {
        lines.push(format!(
            "{}: copied once from {}",
            t(&seed.path),
            t(&seed.from)
        ));
    }
    for o in &s.obsolete {
        lines.push(format!("{}: removed on upgrade", t(o)));
    }
    for migration in &s.migrations {
        let how = match &migration.action {
            MigrationAction::Ops(ops) => format!("{} operations", ops.len()),
            MigrationAction::Run { run, reverse: None } => format!("runs {}", t(run)),
            MigrationAction::Run {
                run,
                reverse: Some(back),
            } => format!("runs {}, undone by {}", t(run), t(back)),
        };
        lines.push(format!(
            "migration from {} to {}: {how}",
            migration.from, migration.to
        ));
    }
    out.section("state", &lines);
}

/// Settings, programs run, policy, notices, and the paths inference didn't
/// read.
fn the_rest(out: &mut Text, m: &Manifest) {
    out.section(
        "settings",
        &m.settings.iter().map(setting).collect::<Vec<_>>(),
    );
    let hooks: Vec<String> = m
        .hooks
        .iter()
        .flat_map(|(phase, steps)| steps.iter().map(move |s| step(phase, s)))
        .collect();
    out.section("programs run", &hooks);
    let tests: Vec<String> = m
        .tests
        .iter()
        .map(|test| {
            format!(
                "{}: {} (timeout {} s)",
                t(&test.name),
                command(&test.exec),
                test.timeout
            )
        })
        .collect();
    out.section("tests", &tests);
    let mut policy = Vec::new();
    if let Some(s) = &m.security {
        if let Some(se) = &s.selinux {
            policy.extend(
                se.modules
                    .iter()
                    .map(|x| format!("SELinux module {}", t(x))),
            );
            policy.extend(
                se.booleans
                    .iter()
                    .map(|(k, v)| format!("SELinux boolean {} = {v}", t(k))),
            );
            policy.extend(
                se.ports
                    .iter()
                    .map(|p| format!("SELinux port {} {} {}", t(&p.kind), t(p.proto), p.port)),
            );
            policy.extend(se.fcontexts.iter().map(|f| {
                format!(
                    "SELinux file context {} {} ({})",
                    t(&f.pattern),
                    t(&f.kind),
                    t(f.file_type)
                )
            }));
        }
        if let Some(aa) = &s.apparmor {
            policy.extend(
                aa.profiles
                    .iter()
                    .map(|x| format!("AppArmor profile {}", t(x))),
            );
            policy.extend(
                aa.tunables
                    .iter()
                    .map(|(k, v)| format!("AppArmor tunable {} = {}", t(k), t(v))),
            );
        }
    }
    out.section("security policy", &policy);
    let mut delegated = Vec::new();
    if let Some(d) = &m.delegated {
        delegated.push(format!(
            "updated by {} {}, from facet {}",
            t(&d.authority.0),
            t(&d.authority.1),
            t(&d.initial)
        ));
        delegated.push(format!(
            "requires {} evidence, {} if not, {} on upgrade",
            t(d.require),
            t(d.on_insufficient),
            t(d.payload_on_upgrade)
        ));
        delegated.extend(d.paths.iter().map(|p| format!("path {}", t(p))));
    }
    out.section("delegated payload", &delegated);
    out.section("fixes", &all(&m.fixes));
    let mut notices = Vec::new();
    for n in &m.notices {
        notices.push(format!("{}:", t(&n.id)));
        notices.extend(paragraph(&n.text).into_iter().map(|l| format!("  {l}")));
    }
    out.section("notices", &notices);
    let skipped: Vec<String> = m
        .inference_skip
        .iter()
        .map(|s| format!("{}: {}", t(&s.path), t(&s.reason)))
        .collect();
    out.section("not inferred from", &skipped);
}

/// The package as text. `files` holds each facet's entry count when the
/// trees were read.
#[must_use]
pub fn text(p: &Package<'_>, files: Option<&[(Facet, usize)]>) -> String {
    let mut out = Text::default();
    header(&mut out, p, files);
    relations(&mut out, p.manifest);
    declarations(&mut out, p.manifest);
    state(&mut out, p.manifest);
    the_rest(&mut out, p.manifest);
    out.0
}

fn capabilities(c: &Capabilities) -> String {
    let mut parts = Vec::new();
    if !c.permitted.is_empty() {
        parts.push(format!("permitted {}", joined(&c.permitted)));
    }
    if !c.inheritable.is_empty() {
        parts.push(format!("inheritable {}", joined(&c.inheritable)));
    }
    if c.effective {
        parts.push("effective".to_owned());
    }
    format!("capabilities: {}", parts.join("; "))
}

fn xattrs(x: &Xattrs) -> Option<String> {
    (!x.is_empty()).then(|| format!("xattrs: {}", joined(x.keys())))
}

/// One entry's columns: type and mode, owner, size, and the path with
/// what it points at and anything unusual about it.
fn columns(tree: &Tree, e: &Entry) -> [String; 4] {
    let owner = |o, g| format!("{}:{}", t(o), t(g));
    let mut extra = Vec::new();
    let (mode, who, size_text, path) = match &e.kind {
        Kind::File(f) => {
            if let Some(c) = &f.capabilities {
                extra.push(capabilities(c));
            }
            extra.extend(xattrs(&f.xattrs));
            (
                mode_string('-', f.mode.value()),
                owner(&f.owner, &f.group),
                size(f.size),
                t(&e.path),
            )
        }
        Kind::Dir(d) => {
            extra.extend(xattrs(&d.xattrs));
            (
                mode_string('d', d.mode.value()),
                owner(&d.owner, &d.group),
                "-".to_owned(),
                t(&e.path),
            )
        }
        Kind::Symlink(l) => (
            mode_string('l', 0o777),
            owner(&l.owner, &l.group),
            "-".to_owned(),
            format!("{} -> {}", t(&e.path), t(&l.target)),
        ),
        Kind::HardLink(target) => {
            // A tree's hard links point at files in it, so this is the
            // file's mode, owner and size.
            let file = tree.get(target.as_str()).and_then(|e| match &e.kind {
                Kind::File(f) => Some(f),
                _ => None,
            });
            let (mode, who, size_text) = file.map_or_else(
                || ("h?????????".to_owned(), "?".to_owned(), "?".to_owned()),
                |f| {
                    (
                        mode_string('h', f.mode.value()),
                        owner(&f.owner, &f.group),
                        size(f.size),
                    )
                },
            );
            (
                mode,
                who,
                size_text,
                format!("{} => {}", t(&e.path), t(target)),
            )
        }
    };
    let path = if extra.is_empty() {
        path
    } else {
        format!("{path} [{}]", extra.join("; "))
    };
    [mode, who, size_text, path]
}

/// One facet's entries, as `ls -l` would list them, with a heading.
#[must_use]
pub fn facet_text(facet: &Facet, tree: &Tree) -> String {
    let rows: Vec<[String; 4]> = tree.entries().iter().map(|e| columns(tree, e)).collect();
    let width = |i: usize| {
        rows.iter()
            .map(|r| r.get(i).map_or(0, |c| c.chars().count()))
            .max()
            .unwrap_or(0)
    };
    let (owners, sizes) = (width(1), width(2));
    let mut out = format!("\nentries in {}:\n", t(facet));
    for [mode, who, size_text, path] in rows {
        let _ = writeln!(out, "  {mode} {who:<owners$} {size_text:>sizes$} {path}");
    }
    out
}

fn string(s: impl Display) -> String {
    json::canonical(&Value::Str(s.to_string()))
}

/// The package as one canonical JSON object: `file`, `files` (each
/// facet's tree entries, as the tree records them, when they were read),
/// `image`, `manifest` (exactly as signed), `package` and `signatures`
/// (each with its `key`).
///
/// `manifest` must be the manifest's canonical bytes, and each entries
/// text a tree's canonical entries array, so the whole is canonical.
#[must_use]
pub fn json(p: &Package<'_>, manifest: &str, files: Option<&[(Facet, String)]>) -> String {
    let mut out = format!("{{\"file\":{}", string(p.file.display()));
    if let Some(files) = files {
        out.push_str(",\"files\":{");
        for (i, (facet, entries)) in files.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(out, "{}:{entries}", string(facet));
        }
        out.push('}');
    }
    let _ = write!(
        out,
        ",\"image\":{},\"manifest\":{manifest},\"package\":{},\"signatures\":[",
        string(p.image),
        string(p.package)
    );
    for (i, signature) in p.signatures.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "{{\"key\":{}}}", string(signature.key()));
    }
    out.push_str("]}");
    out
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ordin_core::{Account, Algorithm, Mode};
    use ordin_tree::{Dir, File, Symlink};

    use super::*;

    const EVERYTHING: &str = include_str!("../../../ordin-manifest/tests/data/everything.json");

    fn digest(n: u8) -> Digest {
        Digest::new(Algorithm::Blake3, [n; 32])
    }

    fn package(m: &Manifest) -> Package<'_> {
        Package {
            file: Path::new("nginx.ordin"),
            manifest: m,
            package: digest(1),
            image: Digest::new(Algorithm::Sha256, [2; 32]),
            signatures: &[],
        }
    }

    fn everything() -> Manifest {
        Manifest::from_json(EVERYTHING).unwrap()
    }

    #[test]
    fn text_is_made_safe_for_a_terminal() {
        assert_eq!(safe("plain ünïcode 字"), "plain ünïcode 字");
        assert_eq!(
            safe("a\u{1b}[31mb\n\t\u{7f}"),
            "a\\u{1b}[31mb\\u{a}\\u{9}\\u{7f}"
        );
        assert_eq!(
            safe("x\u{202e}y\u{2066}\u{2069}\u{200e}\u{200f}\u{61c}\u{202a}"),
            "x\\u{202e}y\\u{2066}\\u{2069}\\u{200e}\\u{200f}\\u{61c}\\u{202a}"
        );
        // Neighbours of the reordering characters are left alone.
        assert_eq!(
            safe("\u{2065}\u{206a}\u{202f}\u{2029}\u{200d}"),
            "\u{2065}\u{206a}\u{202f}\u{2029}\u{200d}"
        );
        assert_eq!(t(format_args!("{}", "\u{0}")), "\\u{0}");
    }

    #[test]
    fn sizes_are_for_people() {
        let shown: Vec<String> = [
            0,
            1023,
            1024,
            1536,
            1024 * 1024 - 1,
            1 << 20,
            5 << 30,
            3 << 40,
            u64::MAX,
        ]
        .into_iter()
        .map(size)
        .collect();
        assert_eq!(
            shown,
            [
                "0 B",
                "1023 B",
                "1.0 KiB",
                "1.5 KiB",
                "1024.0 KiB",
                "1.0 MiB",
                "5.0 GiB",
                "3.0 TiB",
                "16777216.0 TiB"
            ]
        );
    }

    #[test]
    fn modes_are_shown_as_ls_shows_them() {
        let shown: Vec<String> = [
            ('-', 0o644),
            ('d', 0o755),
            ('-', 0o4755),
            ('-', 0o4644),
            ('-', 0o2755),
            ('-', 0o2745),
            ('d', 0o1777),
            ('d', 0o1776),
            ('-', 0),
            ('l', 0o777),
        ]
        .into_iter()
        .map(|(k, m)| mode_string(k, m))
        .collect();
        assert_eq!(
            shown,
            [
                "-rw-r--r--",
                "drwxr-xr-x",
                "-rwsr-xr-x",
                "-rwSr--r--",
                "-rwxr-sr-x",
                "-rwxr-Sr-x",
                "drwxrwxrwt",
                "drwxrwxrwT",
                "----------",
                "lrwxrwxrwx"
            ]
        );
    }

    #[test]
    fn every_section_of_a_full_manifest_is_shown() {
        let m = everything();
        insta::assert_snapshot!(text(&package(&m), None));
    }

    #[test]
    fn a_small_manifest_has_only_its_own_sections() {
        let mut m = everything();
        let keep = m.clone();
        m = Manifest::new(
            keep.name,
            keep.version,
            keep.kind,
            keep.arch,
            keep.summary,
            ordin_manifest::License {
                spdx: "NOASSERTION".into(),
                presentation: Presentation::Informational,
                texts: std::collections::BTreeMap::new(),
            },
            keep.facets,
        );
        let shown = text(&package(&m), None);
        insta::assert_snapshot!(shown);
        assert!(!shown.contains("requires"));
    }

    #[test]
    fn what_isnt_there_isnt_shown() {
        let mut m = everything();
        m.declares.users = vec![ordin_manifest::User {
            name: "plain".parse().unwrap(),
            system: false,
            home: None,
            shell: None,
            groups: vec![],
            comment: None,
        }];
        let full = m.security.clone().unwrap();
        m.security = Some(ordin_manifest::Security {
            selinux: None,
            ..full.clone()
        });
        let shown = text(&package(&m), None);
        assert!(shown.contains("\nusers:\n  plain\n\n"), "{shown}");
        assert!(!shown.contains("SELinux"), "{shown}");
        assert!(shown.contains("AppArmor profile"), "{shown}");
        m.security = Some(ordin_manifest::Security {
            apparmor: None,
            ..full
        });
        let shown = text(&package(&m), None);
        assert!(shown.contains("SELinux module"), "{shown}");
        assert!(!shown.contains("AppArmor"), "{shown}");
    }

    #[test]
    fn entry_counts_are_shown_when_the_trees_were_read() {
        let m = everything();
        let counts = [("doc".parse().unwrap(), 1), ("runtime".parse().unwrap(), 3)];
        let shown = text(&package(&m), Some(&counts));
        assert!(
            shown.contains("  doc           69.3 KiB, 1 entry, not installed by default\n"),
            "{shown}"
        );
        assert!(
            shown.contains("  runtime       1.8 MiB, 3 entries\n"),
            "{shown}"
        );
        assert!(
            shown.contains("  debug         8.8 KiB, not installed by default\n"),
            "{shown}"
        );
    }

    fn file(path: &str, mode: u16, owner: &str, size: u64) -> Entry {
        Entry {
            path: path.parse().unwrap(),
            kind: Kind::File(File {
                mode: Mode::new(mode).unwrap(),
                owner: owner.parse().unwrap(),
                group: Account::root(),
                size,
                content: digest(3),
                fsverity: Digest::new(Algorithm::Sha256, [4; 32]),
                xattrs: Xattrs::new(),
                capabilities: None,
            }),
        }
    }

    fn sample() -> Tree {
        let mut ping = file("/usr/bin/ping", 0o755, "root", 90_312);
        if let Kind::File(f) = &mut ping.kind {
            f.capabilities = Some(Capabilities {
                permitted: [
                    "cap_net_admin".parse().unwrap(),
                    "cap_net_raw".parse().unwrap(),
                ]
                .into(),
                inheritable: ["cap_net_raw".parse().unwrap()].into(),
                effective: true,
            });
            f.xattrs
                .insert("user.origin".parse().unwrap(), b"x".to_vec());
        }
        let mut dir = Dir {
            mode: Mode::new(0o1777).unwrap(),
            owner: Account::root(),
            group: "adm".parse().unwrap(),
            xattrs: Xattrs::new(),
        };
        dir.xattrs.insert("user.k".parse().unwrap(), b"v".to_vec());
        let plain = |path: &str| Entry {
            path: path.parse().unwrap(),
            kind: Kind::Dir(Dir {
                mode: Mode::DIR,
                owner: Account::root(),
                group: Account::root(),
                xattrs: Xattrs::new(),
            }),
        };
        Tree::new(vec![
            plain("/usr"),
            plain("/usr/bin"),
            ping,
            Entry {
                path: "/usr/bin/ping4".parse().unwrap(),
                kind: Kind::HardLink("/usr/bin/ping".parse().unwrap()),
            },
            Entry {
                path: "/usr/bin/pong".parse().unwrap(),
                kind: Kind::Symlink(Symlink {
                    target: "ping".parse().unwrap(),
                    owner: Account::root(),
                    group: Account::root(),
                }),
            },
            file("/usr/bin/su", 0o4755, "_apt", 7),
            Entry {
                path: "/var".parse().unwrap(),
                kind: Kind::Dir(dir),
            },
        ])
        .unwrap()
    }

    #[test]
    fn a_facets_entries_are_listed_as_ls_would() {
        insta::assert_snapshot!(facet_text(&"runtime".parse().unwrap(), &sample()));
    }

    #[test]
    fn a_command_line_is_shown_as_typed() {
        assert_eq!(
            command(&[
                "/bin/x".into(),
                "a b".into(),
                String::new(),
                "\u{1b}".into()
            ]),
            "/bin/x \"a b\" \"\" \\u{1b}"
        );
    }

    #[test]
    fn json_is_one_canonical_object() {
        let m = everything();
        let p = package(&m);
        let signed = String::from_utf8(m.to_canonical_bytes().unwrap()).unwrap();
        let canonical = |text: &str| {
            let value = json::parse(text).unwrap();
            assert_eq!(json::canonical(&value), text);
            value
        };
        let Value::Object(plain) = canonical(&json(&p, &signed, None)) else {
            panic!("an object");
        };
        assert_eq!(
            plain.keys().collect::<Vec<_>>(),
            ["file", "image", "manifest", "package", "signatures"]
        );
        assert_eq!(plain["manifest"], json::parse(&signed).unwrap());
        assert_eq!(plain["signatures"], Value::Array(vec![]));
        assert_eq!(plain["file"], Value::Str("nginx.ordin".into()));
        assert_eq!(plain["package"], Value::Str(digest(1).to_string()));
        let files = [
            ("doc".parse().unwrap(), "[]".to_owned()),
            (
                "runtime".parse().unwrap(),
                r#"[{"path":"/usr","type":"dir"}]"#.to_owned(),
            ),
        ];
        let Value::Object(listed) = canonical(&json(&p, &signed, Some(&files))) else {
            panic!("an object");
        };
        assert_eq!(listed.keys().len(), 6);
        assert_eq!(
            listed["files"],
            json::parse(r#"{"doc":[],"runtime":[{"path":"/usr","type":"dir"}]}"#).unwrap()
        );
        let named = Package {
            file: &PathBuf::from("a \"b\""),
            ..p
        };
        assert!(json(&named, &signed, None).starts_with(r#"{"file":"a \"b\"","#));
    }

    #[test]
    fn signers_are_shown_by_key() {
        let m = everything();
        let keys: Vec<ordin_sign::SecretKey> = (0..2)
            .map(|_| ordin_sign::SecretKey::generate().unwrap())
            .collect();
        let mut signatures: Vec<Signature> =
            keys.iter().map(|k| k.sign(&digest(1)).unwrap()).collect();
        signatures.sort_by_key(Signature::key);
        let p = Package {
            signatures: &signatures,
            ..package(&m)
        };
        let shown = text(&p, None);
        assert!(!shown.contains("not signed"));
        let expected = format!(
            "\nsigned by {}\nsigned by {}\n",
            signatures[0].key(),
            signatures[1].key()
        );
        assert!(shown.contains(&expected), "{shown}");
        let signed = String::from_utf8(m.to_canonical_bytes().unwrap()).unwrap();
        let out = json(&p, &signed, None);
        let value = json::parse(&out).unwrap();
        assert_eq!(json::canonical(&value), out);
        let Value::Object(map) = value else {
            panic!("an object");
        };
        assert_eq!(
            map["signatures"],
            Value::Array(
                signatures
                    .iter()
                    .map(|s| Value::Object(
                        [("key".to_owned(), Value::Str(s.key().to_string()))].into()
                    ))
                    .collect()
            )
        );
    }
}
