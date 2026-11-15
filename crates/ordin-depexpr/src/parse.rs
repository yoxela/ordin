// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The parser: recursive descent over the text, with limits on length,
//! nesting and atoms, so no input can exhaust the stack or take long.
//!
//! ```text
//! expr        := chain [ "if" chain ]
//! chain       := unary ( ("and" unary)+ | ("or" unary)+ )?
//! unary       := "not" unary | "(" expr ")" | requirement
//! requirement := atom [ facets ] [ op version ] [ facets ]
//! facets      := "[" facet ( "," facet )* "]"
//! op          := "=" | "!=" | "<" | "<=" | ">" | ">=" | "~"
//! ```
//!
//! Facets may follow the atom or the version, but not both. Mixing `and`
//! and `or` in one chain, and a second `if` in one group, are refused.

use std::collections::BTreeSet;
use std::str::FromStr;

use ordin_core::{Atom, Facet};
use ordin_version::Version;

use crate::error::{Error, ErrorKind};
use crate::expr::{Expr, Op, Requirement};
use crate::{MAX_ATOMS, MAX_DEPTH, MAX_LEN};

/// Characters that end a word: whitespace, brackets, `,` and the operators.
fn ends_word(c: u8) -> bool {
    c.is_ascii_whitespace() || b"()[],=!<>~".contains(&c)
}

/// Characters that end a version or a facet: whitespace, brackets and `,`.
fn ends_value(c: u8) -> bool {
    c.is_ascii_whitespace() || b"()[],".contains(&c)
}

struct Parser<'a> {
    text: &'a str,
    pos: usize,
    depth: usize,
    atoms: usize,
}

impl FromStr for Expr {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        if text.len() > MAX_LEN {
            return Err(Error {
                at: MAX_LEN,
                kind: ErrorKind::TooLong {
                    max: MAX_LEN,
                    len: text.len(),
                },
            });
        }
        let mut p = Parser {
            text,
            pos: 0,
            depth: 0,
            atoms: 0,
        };
        p.skip_space();
        if p.pos == text.len() {
            return Err(p.error(ErrorKind::Empty));
        }
        let expr = p.expr()?;
        p.skip_space();
        if p.pos < text.len() {
            return Err(p.expected("'and', 'or', 'if' or the end"));
        }
        // The canonical text adds spaces around operators, so it can be
        // longer than the input. It must fit the limit too, or it couldn't
        // be read back.
        let len = expr.to_string().len();
        if len > MAX_LEN {
            return Err(Error {
                at: 0,
                kind: ErrorKind::CanonicalTooLong { max: MAX_LEN, len },
            });
        }
        Ok(expr)
    }
}

impl Parser<'_> {
    fn error(&self, kind: ErrorKind) -> Error {
        Error { at: self.pos, kind }
    }

    fn expected(&self, expected: &'static str) -> Error {
        self.error(ErrorKind::Expected {
            expected,
            found: self.describe_next(),
        })
    }

    /// What comes next, for an error message.
    fn describe_next(&self) -> String {
        let rest = self.rest();
        match rest.bytes().next() {
            None => "the end".to_owned(),
            Some(c) if ends_word(c) && !c.is_ascii_whitespace() => {
                let len = match rest.as_bytes() {
                    [b'!' | b'<' | b'>', b'=', ..] => 2,
                    _ => 1,
                };
                format!("'{}'", rest.get(..len).unwrap_or(rest))
            }
            Some(_) => {
                let word = self.peek_word();
                let shown: String = word.chars().take(40).collect();
                format!("'{shown}'")
            }
        }
    }

    fn rest(&self) -> &str {
        self.text.get(self.pos..).unwrap_or_default()
    }

    fn skip_space(&mut self) {
        let n = self
            .rest()
            .bytes()
            .take_while(u8::is_ascii_whitespace)
            .count();
        self.pos += n;
    }

    fn peek_byte(&self) -> Option<u8> {
        self.rest().bytes().next()
    }

    /// The word at the current position, without moving.
    fn peek_word(&self) -> &str {
        self.take_while(|c| !ends_word(c))
    }

    fn take_while(&self, keep: impl Fn(u8) -> bool) -> &str {
        let rest = self.rest();
        let len = rest.bytes().take_while(|&c| keep(c)).count();
        rest.get(..len).unwrap_or_default()
    }

    /// Consumes `word` if it is the next word.
    fn eat_keyword(&mut self, word: &str) -> bool {
        self.skip_space();
        if self.peek_word() == word {
            self.pos += word.len();
            true
        } else {
            false
        }
    }

    fn enter(&mut self) -> Result<(), Error> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(self.error(ErrorKind::TooDeep(MAX_DEPTH)));
        }
        Ok(())
    }

    fn expr(&mut self) -> Result<Expr, Error> {
        let then = self.chain()?;
        if !self.eat_keyword("if") {
            return Ok(then);
        }
        let cond = self.chain()?;
        self.skip_space();
        let at = self.pos;
        if self.eat_keyword("if") {
            return Err(Error {
                at,
                kind: ErrorKind::ChainedIf,
            });
        }
        Ok(Expr::If {
            then: Box::new(then),
            cond: Box::new(cond),
        })
    }

    fn chain(&mut self) -> Result<Expr, Error> {
        let first = self.unary()?;
        self.skip_space();
        let word = match self.peek_word() {
            "and" => "and",
            "or" => "or",
            _ => return Ok(first),
        };
        let mut parts = vec![first];
        loop {
            self.skip_space();
            let at = self.pos;
            let next = self.peek_word();
            if next == word {
                self.pos += word.len();
                parts.push(self.unary()?);
            } else if next == "and" || next == "or" {
                return Err(Error {
                    at,
                    kind: ErrorKind::MixedAndOr,
                });
            } else {
                break;
            }
        }
        Ok(if word == "and" {
            Expr::And(parts)
        } else {
            Expr::Or(parts)
        })
    }

    fn unary(&mut self) -> Result<Expr, Error> {
        self.skip_space();
        if self.eat_keyword("not") {
            self.enter()?;
            let inner = self.unary()?;
            self.depth -= 1;
            return Ok(Expr::Not(Box::new(inner)));
        }
        if self.peek_byte() == Some(b'(') {
            self.enter()?;
            self.pos += 1;
            let inner = self.expr()?;
            self.skip_space();
            if self.peek_byte() != Some(b')') {
                return Err(self.expected("')'"));
            }
            self.pos += 1;
            self.depth -= 1;
            return Ok(inner);
        }
        self.requirement().map(Expr::Req)
    }

    fn requirement(&mut self) -> Result<Requirement, Error> {
        self.skip_space();
        let at = self.pos;
        let word = self.peek_word();
        if word.is_empty() || matches!(word, "and" | "or" | "not" | "if") {
            return Err(self.expected("an atom, 'not' or '('"));
        }
        let len = word.len();
        let atom: Atom = word.parse().map_err(|e| Error {
            at,
            kind: ErrorKind::Atom(e),
        })?;
        self.atoms += 1;
        if self.atoms > MAX_ATOMS {
            return Err(Error {
                at,
                kind: ErrorKind::TooManyAtoms(MAX_ATOMS),
            });
        }
        self.pos += len;
        let mut req = Requirement::new(atom);
        let facets_first = self.facets(&mut req)?;
        self.skip_space();
        let op_at = self.pos;
        if let Some(op) = self.op() {
            if !matches!(req.atom, Atom::Package(_) | Atom::Cap(_)) {
                return Err(Error {
                    at: op_at,
                    kind: ErrorKind::VersionNotAllowed,
                });
            }
            self.skip_space();
            let version_at = self.pos;
            let text = self.take_while(|c| !ends_value(c));
            if text.is_empty() {
                return Err(self.expected("a version"));
            }
            let version: Version = text.parse().map_err(|e| Error {
                at: version_at,
                kind: ErrorKind::Version(e),
            })?;
            self.pos += text.len();
            req.constraint = Some((op, version));
            if facets_first {
                let before = self.pos;
                self.skip_space();
                if self.peek_byte() == Some(b'[') {
                    return Err(self.error(ErrorKind::FacetsTwice));
                }
                self.pos = before;
            } else {
                self.facets(&mut req)?;
            }
        }
        Ok(req)
    }

    /// Reads an operator, if one is next.
    fn op(&mut self) -> Option<Op> {
        let (op, len) = match self.rest().as_bytes() {
            [b'!', b'=', ..] => (Op::Ne, 2),
            [b'<', b'=', ..] => (Op::Le, 2),
            [b'>', b'=', ..] => (Op::Ge, 2),
            [b'=', ..] => (Op::Eq, 1),
            [b'<', ..] => (Op::Lt, 1),
            [b'>', ..] => (Op::Gt, 1),
            [b'~', ..] => (Op::Compatible, 1),
            _ => return None,
        };
        self.pos += len;
        Some(op)
    }

    /// Reads a `[facet, ...]` selector into `req`, if one is next (allowing
    /// space before it). Returns whether there was one.
    fn facets(&mut self, req: &mut Requirement) -> Result<bool, Error> {
        let before = self.pos;
        self.skip_space();
        if self.peek_byte() != Some(b'[') {
            self.pos = before;
            return Ok(false);
        }
        if !matches!(req.atom, Atom::Package(_)) {
            return Err(self.error(ErrorKind::FacetsNotAllowed));
        }
        self.pos += 1;
        let mut facets = BTreeSet::new();
        loop {
            self.skip_space();
            let at = self.pos;
            let text = self.take_while(|c| !ends_value(c));
            if text.is_empty() {
                return Err(self.expected("a facet"));
            }
            let facet: Facet = text.parse().map_err(|e| Error {
                at,
                kind: ErrorKind::Facet(e),
            })?;
            self.pos += text.len();
            if facets.contains(&facet) {
                return Err(Error {
                    at,
                    kind: ErrorKind::DuplicateFacet(facet),
                });
            }
            facets.insert(facet);
            self.skip_space();
            match self.peek_byte() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(self.expected("',' or ']'")),
            }
        }
        req.facets = facets;
        Ok(true)
    }
}
