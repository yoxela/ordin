// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Dependency expression parsing (ORD-012). Any input either fails to
//! parse, or gives a tree whose canonical text parses back to the same
//! tree and prints the same again. Evaluation must not panic either.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ordin_depexpr::{Expr, Provide};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(expr) = text.parse::<Expr>() else {
        return;
    };
    let shown = expr.to_string();
    let again: Expr = match shown.parse() {
        Ok(again) => again,
        Err(e) => panic!("{shown:?} (from {text:?}) doesn't parse back: {e}"),
    };
    assert_eq!(again, expr);
    assert_eq!(again.to_string(), shown);
    // Evaluate against the requirements' own atoms, with and without
    // versions, so constraints and facets are exercised.
    let provides: Vec<Provide> = expr
        .requirements()
        .iter()
        .map(|r| {
            let mut p = Provide::new(r.atom.clone());
            p.version = r.constraint.as_ref().map(|(_, v)| v.clone());
            p.facets = r.facets.clone();
            p
        })
        .collect();
    let _ = expr.is_satisfied_by(&provides);
    let _ = expr.is_satisfied_by(&[]);
});
