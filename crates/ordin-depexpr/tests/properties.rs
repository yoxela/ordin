// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Property tests: printing and parsing give back the same tree, and the
//! evaluator follows the laws of logic.

use std::collections::BTreeSet;

use ordin_core::{Atom, Facet};
use ordin_depexpr::{Expr, Op, Provide, Requirement};
use ordin_version::Version;
use proptest::prelude::*;

const ATOMS: [&str; 6] = [
    "aa",
    "bb",
    "cap:cc",
    "cap:and",
    "so:libd.so.1",
    "file:/usr/bin/e",
];
const FACETS: [&str; 3] = ["doc", "runtime", "locale:pt_BR"];
const VERSIONS: [&str; 4] = ["1", "1.2", "2.0~rc1", "1:0.5-1"];
const OPS: [Op; 7] = [
    Op::Eq,
    Op::Ne,
    Op::Lt,
    Op::Le,
    Op::Gt,
    Op::Ge,
    Op::Compatible,
];

fn atom(i: usize) -> Atom {
    ATOMS[i % ATOMS.len()]
        .parse()
        .unwrap_or_else(|_| unreachable!())
}

fn facet(i: usize) -> Facet {
    FACETS[i % FACETS.len()]
        .parse()
        .unwrap_or_else(|_| unreachable!())
}

fn version(i: usize) -> Version {
    VERSIONS[i % VERSIONS.len()]
        .parse()
        .unwrap_or_else(|_| unreachable!())
}

/// A valid requirement: constraints only on packages and capabilities,
/// facets only on packages.
fn requirement() -> impl Strategy<Value = Requirement> {
    (
        0..ATOMS.len(),
        prop::option::of((0..OPS.len(), 0..VERSIONS.len())),
        prop::collection::btree_set(0..FACETS.len(), 0..3),
    )
        .prop_map(|(a, constraint, facets)| {
            let atom = atom(a);
            let mut r = Requirement::new(atom.clone());
            if matches!(atom, Atom::Package(_) | Atom::Cap(_)) {
                r.constraint = constraint.map(|(o, v)| (OPS[o], version(v)));
            }
            if matches!(atom, Atom::Package(_)) {
                r.facets = facets.into_iter().map(facet).collect();
            }
            r
        })
}

fn expr() -> impl Strategy<Value = Expr> {
    requirement()
        .prop_map(Expr::Req)
        .prop_recursive(5, 48, 4, |inner| {
            prop_oneof![
                inner.clone().prop_map(|e| Expr::Not(Box::new(e))),
                prop::collection::vec(inner.clone(), 2..4).prop_map(Expr::And),
                prop::collection::vec(inner.clone(), 2..4).prop_map(Expr::Or),
                (inner.clone(), inner).prop_map(|(then, cond)| Expr::If {
                    then: Box::new(then),
                    cond: Box::new(cond)
                }),
            ]
        })
}

/// A set of provides drawn from the same atoms, versions and facets.
fn provides() -> impl Strategy<Value = Vec<Provide>> {
    prop::collection::vec(
        (
            0..ATOMS.len(),
            prop::option::of(0..VERSIONS.len()),
            prop::collection::btree_set(0..FACETS.len(), 0..3),
        ),
        0..5,
    )
    .prop_map(|items| {
        items
            .into_iter()
            .map(|(a, v, f)| Provide {
                atom: atom(a),
                version: v.map(version),
                facets: f.into_iter().map(facet).collect::<BTreeSet<_>>(),
            })
            .collect()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn printing_then_parsing_gives_the_same_tree(e in expr()) {
        let text = e.to_string();
        let back: Expr = text.parse().map_err(|err| TestCaseError::fail(format!("{text}: {err}")))?;
        prop_assert_eq!(&back, &e, "{}", text);
        prop_assert_eq!(back.to_string(), text);
    }

    #[test]
    fn any_text_fails_or_round_trips(text in "[a-z :~^().,\\[\\]=!<>0-9/-]{0,40}") {
        if let Ok(e) = text.parse::<Expr>() {
            let shown = e.to_string();
            let again: Expr = shown.parse().map_err(|err| TestCaseError::fail(format!("{shown}: {err}")))?;
            prop_assert_eq!(&again, &e);
            prop_assert_eq!(again.to_string(), shown);
        }
    }

    #[test]
    fn any_input_is_parsed_or_refused_without_panicking(text in "\\PC{0,80}") {
        let _ = text.parse::<Expr>();
    }

    #[test]
    fn the_evaluator_follows_the_laws_of_logic(a in expr(), b in expr(), p in provides()) {
        let not = |e: &Expr| Expr::Not(Box::new(e.clone()));
        let sat = |e: &Expr| e.is_satisfied_by(&p);
        // `a if b` is `not b or a`.
        let cond = Expr::If { then: Box::new(a.clone()), cond: Box::new(b.clone()) };
        prop_assert_eq!(sat(&cond), sat(&Expr::Or(vec![not(&b), a.clone()])));
        // Double negation and De Morgan.
        prop_assert_eq!(sat(&not(&not(&a))), sat(&a));
        prop_assert_eq!(sat(&not(&Expr::And(vec![a.clone(), b.clone()]))), sat(&Expr::Or(vec![not(&a), not(&b)])));
        prop_assert_eq!(sat(&not(&Expr::Or(vec![a.clone(), b.clone()]))), sat(&Expr::And(vec![not(&a), not(&b)])));
        // Order doesn't matter.
        prop_assert_eq!(sat(&Expr::And(vec![a.clone(), b.clone()])), sat(&Expr::And(vec![b.clone(), a.clone()])));
        prop_assert_eq!(sat(&Expr::Or(vec![a.clone(), b.clone()])), sat(&Expr::Or(vec![b, a])));
    }

    #[test]
    fn a_requirement_matches_exactly_when_a_provide_meets_it(r in requirement(), p in provides()) {
        let expected = p.iter().any(|pr| {
            pr.atom == r.atom
                && r.facets.iter().all(|f| pr.facets.contains(f))
                && match &r.constraint {
                    None => true,
                    Some((op, want)) => match &pr.version {
                        None => false,
                        Some(have) => match op {
                            Op::Eq => have == want,
                            Op::Ne => have != want,
                            Op::Lt => have < want,
                            Op::Le => have <= want,
                            Op::Gt => have > want,
                            Op::Ge => have >= want,
                            Op::Compatible => have >= want && *have < want.compatible_bound(),
                        },
                    },
                }
        });
        prop_assert_eq!(r.is_satisfied_by(&p), expected);
    }
}
