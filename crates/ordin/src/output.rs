// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! What the commands print. Nothing else in the program prints.
//!
//! Results go to standard output, and warnings and errors to standard
//! error. With `--json`, a command prints one JSON object (RFC 8785
//! canonical form) on standard output instead, errors included, and
//! nothing on standard error.
//!
//! Warnings and errors can quote names from an install root or from inside
//! a package, so every line on standard error is made safe for a terminal:
//! control characters and bidirectional formatting characters are written
//! as `\u{…}`. JSON escapes control characters itself, and a program
//! reading it gets the exact text.

pub mod show;

use std::collections::BTreeMap;
use std::io::Write;

use ordin_core::json::{self, MAX_INT, Value};

use ordin_pack::Finding;

use crate::keys::Generated;
use crate::lint::Linted;
use crate::pack::Report;
use crate::sign::Signed;
use crate::unpack::Unpacked;
use crate::verify::{Report as Verification, Verdict};

fn text(s: impl ToString) -> Value {
    Value::Str(s.to_string())
}

fn int(n: u64) -> Value {
    Value::Int(i64::try_from(n).unwrap_or(MAX_INT))
}

fn object<const N: usize>(fields: [(&str, Value); N]) -> Value {
    Value::Object(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

/// `ordin pack`'s result as JSON.
pub fn pack_json(report: &Report) -> String {
    let m = &report.packed.manifest;
    let facets: BTreeMap<String, Value> = m
        .facets
        .iter()
        .map(|(facet, entry)| {
            (
                facet.to_string(),
                object([("size", int(entry.size)), ("tree", text(entry.tree))]),
            )
        })
        .collect();
    let commit = m
        .provenance
        .as_ref()
        .and_then(|p| p.commit.as_ref())
        .map_or(Value::Null, text);
    let value = object([
        ("arch", text(m.arch)),
        ("commit", commit),
        ("facets", Value::Object(facets)),
        ("file", text(report.packed.out.display())),
        ("image", text(report.packed.written.image)),
        ("license", text(&m.license.spdx)),
        ("name", text(&m.name)),
        ("package", text(report.packed.written.package)),
        (
            "recipe",
            report
                .recipe
                .as_ref()
                .map_or(Value::Null, |p| text(p.display())),
        ),
        (
            "provides",
            Value::Array(m.provides.iter().map(|p| text(&p.atom)).collect()),
        ),
        (
            "requires",
            Value::Array(m.requires.iter().map(text).collect()),
        ),
        (
            "signatures",
            Value::Array(report.signer.iter().map(text).collect()),
        ),
        ("size", int(report.packed.written.size)),
        ("version", text(&m.version)),
        (
            "warnings",
            Value::Array(report.warnings.iter().map(text).collect()),
        ),
    ]);
    json::canonical(&value)
}

/// `ordin pack`'s result for people.
pub fn pack_text(report: &Report) -> String {
    let m = &report.packed.manifest;
    let facets: Vec<String> = m
        .facets
        .iter()
        .map(|(facet, entry)| format!("{facet} ({} bytes)", entry.size))
        .collect();
    let mut out = format!(
        "wrote {} ({} bytes)\npackage {}\nfacets: {}\n",
        report.packed.out.display(),
        report.packed.written.size,
        report.packed.written.package,
        facets.join(", ")
    );
    if let Some(recipe) = &report.recipe {
        out.push_str(&format!("recipe {}\n", recipe.display()));
    }
    if let Some(commit) = m.provenance.as_ref().and_then(|p| p.commit.as_ref()) {
        out.push_str(&format!("commit {commit}\n"));
    }
    if let Some(key) = &report.signer {
        out.push_str(&format!("signed by {key}\n"));
    }
    out
}

/// `ordin sign`'s result as JSON.
pub fn sign_json(signed: &Signed) -> String {
    json::canonical(&object([
        ("file", text(signed.file.display())),
        ("image", text(signed.image)),
        ("key", text(signed.key)),
        ("package", text(signed.package)),
        ("replaced", Value::Bool(signed.replaced)),
        (
            "signatures",
            Value::Array(signed.signatures.iter().map(text).collect()),
        ),
    ]))
}

/// `ordin sign`'s result for people.
pub fn sign_text(signed: &Signed) -> String {
    let again = if signed.replaced {
        ", replacing its earlier signature"
    } else {
        ""
    };
    format!(
        "signed {} with {}{again}\npackage {}\nsignatures: {}\n",
        signed.file.display(),
        signed.key,
        signed.package,
        signed.signatures.len()
    )
}

/// `ordin key generate`'s result as JSON.
pub fn key_json(made: &Generated) -> String {
    json::canonical(&object([
        ("encrypted", Value::Bool(made.encrypted)),
        ("key", text(made.key)),
        ("public", text(made.public.display())),
        ("secret", text(made.secret.display())),
    ]))
}

/// `ordin key generate`'s result for people.
pub fn key_text(made: &Generated) -> String {
    let sealed = if made.encrypted {
        "encrypted"
    } else {
        "not encrypted"
    };
    format!(
        "wrote {} (the secret key, {sealed})\nwrote {} (the public key)\nkey {}\n",
        made.secret.display(),
        made.public.display(),
        made.key
    )
}

/// What a packager should know about a new key.
pub fn key_warnings(made: &Generated) -> Vec<String> {
    if made.encrypted {
        return Vec::new();
    }
    vec![format!(
        "{} isn't encrypted: anyone who can read it can sign as this key",
        made.secret.display()
    )]
}

/// `n` and `thing`, plural unless `n` is 1.
fn count(n: usize, thing: &str) -> String {
    plural(n, thing, &format!("{thing}s"))
}

/// `n` and `one` if `n` is 1, `many` otherwise.
fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// `ordin unpack`'s result for people.
pub fn unpack_text(u: &Unpacked) -> String {
    let facets: Vec<String> = u.facets.iter().map(ToString::to_string).collect();
    format!(
        "unpacked {} into {}\npackage {}\nfacets: {}\n{}, {} ({}), {}, {}\n\
         not applied, recorded in {}: owners, setuid, setgid and sticky bits, \
         extended attributes and capabilities\n",
        u.file.display(),
        u.to.display(),
        u.package,
        facets.join(", "),
        plural(u.dirs, "directory", "directories"),
        count(u.files, "file"),
        show::size(u.size),
        count(u.symlinks, "symlink"),
        count(u.hard_links, "hard link"),
        u.meta.display()
    )
}

/// `ordin unpack`'s result as JSON.
pub fn unpack_json(u: &Unpacked) -> String {
    json::canonical(&object([
        ("dirs", int(u.dirs as u64)),
        ("facets", Value::Array(u.facets.iter().map(text).collect())),
        ("file", text(u.file.display())),
        ("files", int(u.files as u64)),
        ("hard_links", int(u.hard_links as u64)),
        ("meta", text(u.meta.display())),
        ("package", text(u.package)),
        ("size", int(u.size)),
        ("symlinks", int(u.symlinks as u64)),
        ("to", text(u.to.display())),
    ]))
}

/// A lint warning's first line: its ID, the path it is about, and what
/// is wrong.
fn finding_line(label: &str, f: &Finding) -> String {
    match &f.path {
        Some(path) => format!("{label}[{}] {path}: {}", f.check, f.message),
        None => format!("{label}[{}] {}", f.check, f.message),
    }
}

/// `ordin lint`'s result for people. Paths and names come from inside
/// the package, so every line is made safe for a terminal.
pub fn lint_text(linted: &Linted) -> String {
    let r = &linted.report;
    let mut lines = vec![format!("lint {}", linted.file.display())];
    if let Some(recipe) = &linted.recipe {
        lines.push(format!("recipe {}", recipe.display()));
    }
    for f in &r.warnings {
        lines.push(finding_line("warning", f));
        if let Some(hint) = &f.hint {
            lines.push(format!("  hint: {hint}"));
        }
    }
    let recipe = linted
        .recipe
        .as_ref()
        .map_or_else(|| "the recipe".to_owned(), |p| p.display().to_string());
    for a in &r.allowed {
        lines.push(finding_line("allowed", &a.finding));
        lines.push(format!("  reason ({recipe}:{}): {}", a.line, a.reason));
    }
    let warnings = match r.warnings.len() {
        0 => "no warnings".to_owned(),
        n => count(n, "warning"),
    };
    lines.push(if r.allowed.is_empty() {
        warnings
    } else {
        format!("{warnings}, {} allowed", r.allowed.len())
    });
    lines.iter().map(|l| show::safe(l) + "\n").collect()
}

/// A lint warning as JSON.
fn finding_json(f: &Finding) -> [(&'static str, Value); 4] {
    [
        ("hint", f.hint.as_ref().map_or(Value::Null, text)),
        ("id", text(f.check)),
        ("message", text(&f.message)),
        ("path", f.path.as_ref().map_or(Value::Null, text)),
    ]
}

/// `ordin lint`'s result as JSON.
pub fn lint_json(linted: &Linted) -> String {
    let r = &linted.report;
    let warnings = r.warnings.iter().map(|f| object(finding_json(f))).collect();
    let allowed = r
        .allowed
        .iter()
        .map(|a| {
            let mut fields = finding_json(&a.finding).to_vec();
            fields.push(("line", int(a.line as u64)));
            fields.push(("reason", text(&a.reason)));
            Value::Object(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
        })
        .collect();
    json::canonical(&object([
        ("allowed", Value::Array(allowed)),
        ("file", text(linted.file.display())),
        (
            "recipe",
            linted
                .recipe
                .as_ref()
                .map_or(Value::Null, |p| text(p.display())),
        ),
        ("warnings", Value::Array(warnings)),
    ]))
}

/// `ordin verify`'s result for people, for an intact package.
pub fn verify_text(report: &Verification) -> String {
    let facets: Vec<String> = report
        .verified
        .facets
        .iter()
        .map(|f| {
            format!(
                "{} ({} in {}, {})",
                f.facet,
                count(f.files, "file"),
                count(f.chunks, "chunk"),
                show::size(f.size)
            )
        })
        .collect();
    let mut out = format!(
        "{} is intact\npackage {}\nimage {}\nfacets: {}\n",
        report.file.display(),
        report.package,
        report.image,
        // A manifest has at least one facet.
        facets.join(", ")
    );
    if report.signers.is_empty() {
        out.push_str("not signed\n");
    }
    for (key, trusted) in &report.signers {
        let trusted = if *trusted { "trusted" } else { "not trusted" };
        out.push_str(&format!("signed by {key}, {trusted}\n"));
    }
    out
}

/// Why an intact package isn't trusted, if it isn't.
pub fn verify_failure(report: &Verification) -> Option<String> {
    let file = report.file.display();
    match report.verdict() {
        Verdict::Trusted => None,
        Verdict::Unsigned => Some(format!("{file} is intact but not signed")),
        Verdict::Untrusted if report.trust_given => Some(format!(
            "{file} is intact, but no key given with --trust signed it"
        )),
        Verdict::Untrusted => Some(format!(
            "{file} is intact, but no key is trusted; give the keys you trust with --trust"
        )),
    }
}

/// `ordin verify`'s result as JSON, for an intact package.
pub fn verify_json(report: &Verification) -> String {
    let facets = report
        .verified
        .facets
        .iter()
        .map(|f| {
            object([
                ("chunks", int(f.chunks as u64)),
                ("facet", text(&f.facet)),
                ("files", int(f.files as u64)),
                ("size", int(f.size)),
            ])
        })
        .collect();
    let signatures = report
        .signers
        .iter()
        .map(|(key, trusted)| object([("key", text(key)), ("trusted", Value::Bool(*trusted))]))
        .collect();
    json::canonical(&object([
        ("facets", Value::Array(facets)),
        ("file", text(report.file.display())),
        ("image", text(report.image)),
        ("licenses", int(report.verified.licenses as u64)),
        ("package", text(report.package)),
        ("result", text(report.verdict().name())),
        ("signatures", Value::Array(signatures)),
    ]))
}

/// `ordin verify`'s result as JSON, for a corrupt package.
pub fn corrupt_json(e: &anyhow::Error) -> String {
    json::canonical(&object([
        ("error", text(format!("{e:#}"))),
        ("result", text("corrupt")),
    ]))
}

/// An error as JSON.
pub fn error_json(e: &anyhow::Error) -> String {
    json::canonical(&object([("error", text(format!("{e:#}")))]))
}

/// The line a warning is printed as, made safe for a terminal.
fn warning_line(warning: &str) -> String {
    format!("ordin: warning: {}\n", show::safe(warning))
}

/// The line an error is printed as, made safe for a terminal.
fn error_line(message: &str) -> String {
    format!("ordin: error: {}\n", show::safe(message))
}

/// Prints a command's result: its warnings on standard error, then the
/// result on standard output.
pub fn print(result: &str, warnings: &[String]) {
    let mut err = std::io::stderr().lock();
    for w in warnings {
        // Nothing useful can be done if standard error is gone.
        let _ = err.write_all(warning_line(w).as_bytes());
    }
    let _ = std::io::stdout().lock().write_all(result.as_bytes());
}

/// Prints an error on standard error.
pub fn print_error(e: &anyhow::Error) {
    print_failure(&format!("{e:#}"));
}

/// Prints why a command failed on standard error.
pub fn print_failure(message: &str) {
    let _ = std::io::stderr()
        .lock()
        .write_all(error_line(message).as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_line_on_standard_error_is_safe_for_a_terminal() {
        assert_eq!(
            error_line("/usr/bin/\u{202e}txt.sh in facet runtime: \x1b[2Jwrong"),
            "ordin: error: /usr/bin/\\u{202e}txt.sh in facet runtime: \\u{1b}[2Jwrong\n"
        );
        assert_eq!(
            warning_line("/opt/x\u{2066}y: not declared\r"),
            "ordin: warning: /opt/x\\u{2066}y: not declared\\u{d}\n"
        );
        // Already escaped text and plain text are left as they are.
        assert_eq!(
            error_line(r"/x\u{1b}: a name: \\ é"),
            "ordin: error: /x\\u{1b}: a name: \\\\ é\n"
        );
    }

    #[test]
    fn a_corrupt_package_is_reported_exactly_in_json() {
        let e = anyhow::anyhow!("/usr/bin/\u{202e}txt.sh in facet runtime: wrong")
            .context("p.ordin is corrupt");
        assert_eq!(
            corrupt_json(&e),
            "{\"error\":\"p.ordin is corrupt: /usr/bin/\u{202e}txt.sh in facet runtime: wrong\",\
             \"result\":\"corrupt\"}"
        );
    }

    #[test]
    fn counts_are_plural_unless_one() {
        assert_eq!(count(0, "file"), "0 files");
        assert_eq!(count(1, "file"), "1 file");
        assert_eq!(count(2, "chunk"), "2 chunks");
        assert_eq!(plural(1, "directory", "directories"), "1 directory");
        assert_eq!(plural(3, "directory", "directories"), "3 directories");
    }
}
