// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! What the commands print. Nothing else in the program prints.
//!
//! Results go to standard output, and warnings and errors to standard
//! error. With `--json`, a command prints one JSON object (RFC 8785
//! canonical form) on standard output instead, errors included, and
//! nothing on standard error.

pub mod show;

use std::collections::BTreeMap;
use std::io::Write;

use ordin_core::json::{self, MAX_INT, Value};

use crate::keys::Generated;
use crate::pack::Report;
use crate::sign::Signed;

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
    let value = object([
        ("arch", text(m.arch)),
        ("facets", Value::Object(facets)),
        ("file", text(report.packed.out.display())),
        ("image", text(report.packed.written.image)),
        ("license", text(&m.license.spdx)),
        ("name", text(&m.name)),
        ("package", text(report.packed.written.package)),
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

/// An error as JSON.
pub fn error_json(e: &anyhow::Error) -> String {
    json::canonical(&object([("error", text(format!("{e:#}")))]))
}

/// Prints a command's result: its warnings on standard error, then the
/// result on standard output.
pub fn print(result: &str, warnings: &[String]) {
    let mut err = std::io::stderr().lock();
    for w in warnings {
        // Nothing useful can be done if standard error is gone.
        let _ = writeln!(err, "ordin: warning: {w}");
    }
    let _ = std::io::stdout().lock().write_all(result.as_bytes());
}

/// Prints an error on standard error.
pub fn print_error(e: &anyhow::Error) {
    let _ = writeln!(std::io::stderr().lock(), "ordin: error: {e:#}");
}
