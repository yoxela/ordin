// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! SPDX license expressions: `MIT OR Apache-2.0`,
//! `GPL-2.0-or-later WITH Classpath-exception-2.0`, `LicenseRef-acme`.
//!
//! This checks the grammar only. Whether an ID is on the SPDX license
//! list is `ordin lint`'s business, since the list changes over time.
//!
//! ```text
//! or     := and ( "OR" and )*
//! and    := with ( "AND" with )*
//! with   := simple [ "WITH" id ] | "(" or ")"
//! simple := id [ "+" ]
//! id     := [A-Za-z0-9.-]+
//! ```
//!
//! Operators are uppercase. The canonical text uses single spaces and
//! only the parentheses the tree needs.

use std::collections::BTreeSet;
use std::fmt;

/// The longest expression, in bytes.
pub const MAX_LEN: usize = 1024;
const MAX_DEPTH: usize = 16;

/// A parsed SPDX expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Spdx {
    /// A license ID, with `+` meaning "or later".
    License {
        /// The ID.
        id: String,
        /// Whether `+` follows it.
        or_later: bool,
        /// The exception after `WITH`, if any.
        exception: Option<String>,
    },
    /// Two or more, all applying.
    And(Vec<Spdx>),
    /// Two or more, any one applying.
    Or(Vec<Spdx>),
}

impl Spdx {
    /// Every license and exception ID in the expression, without `+`.
    #[must_use]
    pub fn ids(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        self.collect(&mut out);
        out
    }

    fn collect(&self, out: &mut BTreeSet<String>) {
        match self {
            Self::License { id, exception, .. } => {
                out.insert(id.clone());
                if let Some(e) = exception {
                    out.insert(e.clone());
                }
            }
            Self::And(parts) | Self::Or(parts) => parts.iter().for_each(|p| p.collect(out)),
        }
    }
}

impl fmt::Display for Spdx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::License {
                id,
                or_later,
                exception,
            } => {
                f.write_str(id)?;
                if *or_later {
                    f.write_str("+")?;
                }
                if let Some(e) = exception {
                    write!(f, " WITH {e}")?;
                }
                Ok(())
            }
            Self::And(parts) => join(f, parts, " AND ", |p| matches!(p, Self::Or(_))),
            Self::Or(parts) => join(f, parts, " OR ", |_| false),
        }
    }
}

fn join(
    f: &mut fmt::Formatter<'_>,
    parts: &[Spdx],
    word: &str,
    wrap: impl Fn(&Spdx) -> bool,
) -> fmt::Result {
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            f.write_str(word)?;
        }
        if wrap(p) {
            write!(f, "({p})")?;
        } else {
            write!(f, "{p}")?;
        }
    }
    Ok(())
}

/// Parses an SPDX expression.
///
/// # Errors
///
/// Returns why the text isn't an SPDX expression.
pub fn parse(text: &str) -> Result<Spdx, String> {
    if text.len() > MAX_LEN {
        return Err(format!("an SPDX expression is at most {MAX_LEN} bytes"));
    }
    let tokens = tokenize(text)?;
    let mut p = Parser {
        rest: &tokens,
        depth: 0,
    };
    let expr = p.or()?;
    if let Some(t) = p.peek() {
        return Err(format!("unexpected {t:?} in the SPDX expression"));
    }
    Ok(expr)
}

fn tokenize(text: &str) -> Result<Vec<&str>, String> {
    let mut tokens = Vec::new();
    let mut rest = text;
    loop {
        rest = rest.trim_start_matches(' ');
        let Some(c) = rest.chars().next() else {
            return Ok(tokens);
        };
        let len = match c {
            '(' | ')' | '+' => 1,
            c if c.is_ascii_alphanumeric() || c == '.' || c == '-' => rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
                .unwrap_or(rest.len()),
            c => return Err(format!("{c:?} isn't allowed in an SPDX expression")),
        };
        // Every token is at least one byte, so the loop always moves on.
        // Correct code never needs the `max`; it keeps a mistake here (or a
        // mutation under test) from looping forever while it allocates.
        let (token, after) = rest.split_at(len.max(1));
        tokens.push(token);
        rest = after;
    }
}

/// The parser reads from `rest`, the tokens not yet read. It only ever
/// moves forward, by taking the first token off the slice, so no mistake
/// in index arithmetic can make it read the same token forever.
struct Parser<'a> {
    rest: &'a [&'a str],
    depth: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&'a str> {
        self.rest.first().copied()
    }

    fn next(&mut self) -> Option<&'a str> {
        let (first, rest) = self.rest.split_first()?;
        self.rest = rest;
        Some(first)
    }

    /// Takes the next token if it is `token`.
    fn eat(&mut self, token: &str) -> bool {
        let found = self.peek() == Some(token);
        if found {
            self.next();
        }
        found
    }

    fn or(&mut self) -> Result<Spdx, String> {
        let mut parts = vec![self.and()?];
        while self.eat("OR") {
            parts.push(self.and()?);
        }
        Ok(if parts.len() == 1 {
            parts.remove(0)
        } else {
            Spdx::Or(parts)
        })
    }

    fn and(&mut self) -> Result<Spdx, String> {
        let mut parts = vec![self.with()?];
        while self.eat("AND") {
            parts.push(self.with()?);
        }
        Ok(if parts.len() == 1 {
            parts.remove(0)
        } else {
            Spdx::And(parts)
        })
    }

    fn with(&mut self) -> Result<Spdx, String> {
        if self.eat("(") {
            self.depth += 1;
            if self.depth > MAX_DEPTH {
                return Err("an SPDX expression nests at most 16 deep".to_owned());
            }
            let inner = self.or()?;
            if self.next() != Some(")") {
                return Err("expected ')' in the SPDX expression".to_owned());
            }
            self.depth -= 1;
            return Ok(inner);
        }
        let id = self.id()?;
        let or_later = self.eat("+");
        let exception = if self.eat("WITH") {
            Some(self.id()?)
        } else {
            None
        };
        Ok(Spdx::License {
            id,
            or_later,
            exception,
        })
    }

    fn id(&mut self) -> Result<String, String> {
        match self.next() {
            Some(t) if !matches!(t, "AND" | "OR" | "WITH" | "(" | ")" | "+") => {
                if matches!(t.to_ascii_uppercase().as_str(), "AND" | "OR" | "WITH") {
                    return Err(format!("SPDX operators are uppercase: {t:?}"));
                }
                Ok(t.to_owned())
            }
            Some(t) => Err(format!("expected a license ID, found {t:?}")),
            None => Err("expected a license ID, found the end".to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical(text: &str) -> String {
        parse(text)
            .unwrap_or_else(|e| panic!("{text}: {e}"))
            .to_string()
    }

    #[test]
    fn common_expressions_parse_and_print_canonically() {
        for text in [
            "MIT",
            "MIT OR Apache-2.0",
            "GPL-2.0+",
            "GPL-2.0-or-later WITH Classpath-exception-2.0",
            "LicenseRef-acme-eula",
            "BSD-3-Clause OR GPL-2.0-only",
            "(MIT OR Apache-2.0) AND BSD-2-Clause",
            "MIT AND Apache-2.0 AND ISC",
            "MIT OR Apache-2.0 AND BSD-2-Clause",
        ] {
            assert_eq!(canonical(text), text);
        }
        assert_eq!(canonical("( MIT )"), "MIT");
        assert_eq!(canonical("MIT  OR  Apache-2.0"), "MIT OR Apache-2.0");
        assert_eq!(canonical("(MIT AND ISC) OR Zlib"), "MIT AND ISC OR Zlib");
    }

    #[test]
    fn ids_include_exceptions_without_plus() {
        let ids = parse("(GPL-2.0+ WITH Classpath-exception-2.0) OR MIT")
            .unwrap()
            .ids();
        let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
        assert_eq!(ids, ["Classpath-exception-2.0", "GPL-2.0", "MIT"]);
    }

    #[test]
    fn the_limit_is_inclusive_and_ids_may_start_with_any_id_character() {
        assert!(parse(&"M".repeat(1024)).is_ok());
        // Exactly 16 levels nest; depth is restored after each group, so
        // siblings never add up.
        assert!(parse(&format!("{}MIT{}", "(".repeat(16), ")".repeat(16))).is_ok());
        assert!(parse(&vec!["(MIT)"; 20].join(" AND ")).is_ok());
        assert_eq!(canonical("-x OR .y"), "-x OR .y");
        assert_eq!(canonical("a.b-c"), "a.b-c");
    }

    #[test]
    fn bad_expressions_say_why() {
        let err = |t: &str| parse(t).unwrap_err();
        assert!(err("").contains("found the end"));
        assert!(err("MIT or Apache-2.0").contains("unexpected \"or\""));
        assert!(err("MIT OR").contains("found the end"));
        assert!(err("OR MIT").contains("found \"OR\""));
        assert!(err("MIT WITH").contains("found the end"));
        assert!(err("(MIT").contains("expected ')'"));
        assert!(err("MIT)").contains("unexpected \")\""));
        assert!(err("MIT/BSD").contains("'/'"));
        assert!(err("MIT OR with").contains("uppercase"));
        assert!(err(&"(".repeat(17)).contains("nests"));
        assert!(err(&"M".repeat(1025)).contains("at most"));
        assert!(err("MIT + +").contains("unexpected \"+\""));
    }
}
