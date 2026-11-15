// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The syntax tree, its canonical text, and evaluation against a set of
//! provides.

use std::collections::BTreeSet;
use std::fmt;

use ordin_core::{Atom, Facet};
use ordin_version::Version;

/// A version comparison in a requirement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    /// `=`
    Eq,
    /// `!=`
    Ne,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
    /// `~`, compatible with: at least the version, and below its
    /// [compatible bound](Version::compatible_bound).
    Compatible,
}

impl Op {
    /// The operator as written.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::Compatible => "~",
        }
    }

    /// Whether `version` satisfies `self` `wanted`.
    #[must_use]
    pub fn holds(self, version: &Version, wanted: &Version) -> bool {
        match self {
            Self::Eq => version == wanted,
            Self::Ne => version != wanted,
            Self::Lt => version < wanted,
            Self::Le => version <= wanted,
            Self::Gt => version > wanted,
            Self::Ge => version >= wanted,
            Self::Compatible => version.is_compatible_with(wanted),
        }
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One atom with an optional version constraint and, for a package, the
/// facets it needs: `nginx[doc] >= 1.27`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requirement {
    /// What is required.
    pub atom: Atom,
    /// The version constraint, if any. Only package and `cap:` atoms have
    /// one.
    pub constraint: Option<(Op, Version)>,
    /// The facets needed. Only package atoms have any.
    pub facets: BTreeSet<Facet>,
}

impl Requirement {
    /// A requirement on `atom` with no constraint or facets.
    #[must_use]
    pub fn new(atom: Atom) -> Self {
        Self {
            atom,
            constraint: None,
            facets: BTreeSet::new(),
        }
    }

    /// Whether some provide in `provides` satisfies this requirement: the
    /// same atom, a version that meets the constraint (a provide without a
    /// version meets none), and every facet needed.
    #[must_use]
    pub fn is_satisfied_by(&self, provides: &[Provide]) -> bool {
        provides.iter().any(|p| {
            p.atom == self.atom
                && self.facets.is_subset(&p.facets)
                && self.constraint.as_ref().is_none_or(|(op, wanted)| {
                    p.version.as_ref().is_some_and(|v| op.holds(v, wanted))
                })
        })
    }
}

impl fmt::Display for Requirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.atom)?;
        if !self.facets.is_empty() {
            let facets: Vec<&str> = self.facets.iter().map(Facet::as_str).collect();
            write!(f, "[{}]", facets.join(","))?;
        }
        if let Some((op, version)) = &self.constraint {
            write!(f, " {op} {version}")?;
        }
        Ok(())
    }
}

/// A dependency expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    /// One requirement.
    Req(Requirement),
    /// `not a`: satisfied when `a` isn't.
    Not(Box<Expr>),
    /// `a and b and …`: two or more, all satisfied.
    And(Vec<Expr>),
    /// `a or b or …`: two or more, at least one satisfied.
    Or(Vec<Expr>),
    /// `then if cond`: `then` is required only when `cond` holds, so it is
    /// satisfied when `cond` isn't or `then` is.
    If {
        /// What is required.
        then: Box<Expr>,
        /// When it is required.
        cond: Box<Expr>,
    },
}

impl Expr {
    /// Whether the expression is satisfied by `provides`.
    #[must_use]
    pub fn is_satisfied_by(&self, provides: &[Provide]) -> bool {
        match self {
            Self::Req(r) => r.is_satisfied_by(provides),
            Self::Not(e) => !e.is_satisfied_by(provides),
            Self::And(es) => es.iter().all(|e| e.is_satisfied_by(provides)),
            Self::Or(es) => es.iter().any(|e| e.is_satisfied_by(provides)),
            Self::If { then, cond } => {
                !cond.is_satisfied_by(provides) || then.is_satisfied_by(provides)
            }
        }
    }

    /// Every requirement in the expression, in order.
    #[must_use]
    pub fn requirements(&self) -> Vec<&Requirement> {
        let mut out = Vec::new();
        self.collect(&mut out);
        out
    }

    fn collect<'a>(&'a self, out: &mut Vec<&'a Requirement>) {
        match self {
            Self::Req(r) => out.push(r),
            Self::Not(e) => e.collect(out),
            Self::And(es) | Self::Or(es) => es.iter().for_each(|e| e.collect(out)),
            Self::If { then, cond } => {
                then.collect(out);
                cond.collect(out);
            }
        }
    }

    fn is_group(&self) -> bool {
        matches!(self, Self::And(_) | Self::Or(_) | Self::If { .. })
    }
}

/// Writes `e`, in parentheses if `wrap`.
fn write_part(f: &mut fmt::Formatter<'_>, e: &Expr, wrap: bool) -> fmt::Result {
    if wrap {
        write!(f, "({e})")
    } else {
        write!(f, "{e}")
    }
}

/// The canonical text: single spaces around keywords and operators, and
/// only the parentheses the tree needs, so parsing it gives the same tree.
impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Req(r) => write!(f, "{r}"),
            Self::Not(e) => {
                f.write_str("not ")?;
                write_part(f, e, e.is_group())
            }
            Self::And(es) | Self::Or(es) => {
                let word = if matches!(self, Self::And(_)) {
                    " and "
                } else {
                    " or "
                };
                for (i, e) in es.iter().enumerate() {
                    if i > 0 {
                        f.write_str(word)?;
                    }
                    write_part(f, e, e.is_group())?;
                }
                Ok(())
            }
            Self::If { then, cond } => {
                let nested = |e: &Expr| matches!(e, Self::If { .. });
                write_part(f, then, nested(then))?;
                f.write_str(" if ")?;
                write_part(f, cond, nested(cond))
            }
        }
    }
}

/// Something present that requirements are checked against: an installed
/// or candidate package, or a capability, soname or file it provides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provide {
    /// What is provided.
    pub atom: Atom,
    /// Its version, if it has one.
    pub version: Option<Version>,
    /// For a package, the facets selected.
    pub facets: BTreeSet<Facet>,
}

impl Provide {
    /// A provide of `atom` with no version or facets.
    #[must_use]
    pub fn new(atom: Atom) -> Self {
        Self {
            atom,
            version: None,
            facets: BTreeSet::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        text.parse().unwrap()
    }

    #[test]
    fn operators_compare_versions() {
        let (one, two) = (v("1.0"), v("2.0"));
        let cases = [
            (Op::Eq, [false, true, false]),
            (Op::Ne, [true, false, true]),
            (Op::Lt, [true, false, false]),
            (Op::Le, [true, true, false]),
            (Op::Gt, [false, false, true]),
            (Op::Ge, [false, true, true]),
        ];
        for (op, expected) in cases {
            for (have, want) in [&v("0.9"), &one, &two].into_iter().zip(expected) {
                assert_eq!(op.holds(have, &one), want, "{have} {op} {one}");
            }
        }
        assert!(Op::Compatible.holds(&v("1.5"), &one));
        assert!(!Op::Compatible.holds(&two, &one));
        assert!(!Op::Compatible.holds(&v("0.9"), &one));
        let shown: Vec<&str> = [
            Op::Eq,
            Op::Ne,
            Op::Lt,
            Op::Le,
            Op::Gt,
            Op::Ge,
            Op::Compatible,
        ]
        .iter()
        .map(|o| o.as_str())
        .collect();
        assert_eq!(shown, ["=", "!=", "<", "<=", ">", ">=", "~"]);
        assert_eq!(Op::Ge.to_string(), ">=");
    }
}
