// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Parsing, canonical printing, errors with positions, and evaluation.

use ordin_depexpr::{ErrorKind, Expr, MAX_ATOMS, MAX_DEPTH, MAX_LEN, Op, Provide};

type R<T> = Result<T, Box<dyn std::error::Error>>;

/// Parses `text` and returns its canonical form.
fn canonical(text: &str) -> R<String> {
    Ok(text.parse::<Expr>()?.to_string())
}

/// Parses `text`, expecting an error; returns its offset and kind.
fn error(text: &str) -> R<(usize, ErrorKind)> {
    match text.parse::<Expr>() {
        Ok(e) => Err(format!("{text:?} parsed as {e}").into()),
        Err(e) => Ok((e.at, e.kind)),
    }
}

/// A provide of a package or capability with a version, and facets.
fn provide(atom: &str, version: Option<&str>, facets: &[&str]) -> R<Provide> {
    let mut p = Provide::new(atom.parse()?);
    p.version = version.map(str::parse).transpose()?;
    for f in facets {
        p.facets.insert(f.parse()?);
    }
    Ok(p)
}

fn satisfied(expr: &str, provides: &[Provide]) -> R<bool> {
    Ok(expr.parse::<Expr>()?.is_satisfied_by(provides))
}

#[test]
fn the_spec_examples_parse_and_print_canonically() {
    for text in [
        "so:libssl.so.3 and so:libpcre2-8.so.0 and (cap:zlib or zlib-ng-compat)",
        "nginx-legacy < 1.20",
        "B or C or (D and E)",
    ]
    .map(|t| t.replace("B or C or (D and E)", "bb or cc or (dd and ee)"))
    {
        assert_eq!(canonical(&text).unwrap(), text);
    }
}

#[test]
fn spacing_is_normalized() {
    for (input, shown) in [
        ("cap:go>=1.21", "cap:go >= 1.21"),
        ("  nginx  ", "nginx"),
        ("aa\tand\nbb", "aa and bb"),
        ("foo~1.27", "foo ~ 1.27"),
        ("foo!=2", "foo != 2"),
        ("foo<=2 or foo>3", "foo <= 2 or foo > 3"),
        ("foo=1", "foo = 1"),
        ("foo<1", "foo < 1"),
        ("nginx [ doc , runtime ]", "nginx[doc,runtime]"),
        ("nginx[runtime,doc]", "nginx[doc,runtime]"),
        ("nginx >= 1.27 [doc]", "nginx[doc] >= 1.27"),
        ("nginx[doc]>=1.27", "nginx[doc] >= 1.27"),
        ("foo >= 0:1.0-1+u0", "foo >= 1.0-1"),
        ("((aa))", "aa"),
        ("(aa and bb) and cc", "(aa and bb) and cc"),
        ("not(aa)", "not aa"),
        ("not (aa or bb)", "not (aa or bb)"),
        ("not not aa", "not not aa"),
        ("aa and not bb", "aa and not bb"),
        ("aa and bb if cc or dd", "aa and bb if cc or dd"),
        ("(aa if bb) and cc", "(aa if bb) and cc"),
        ("(aa if bb) if cc", "(aa if bb) if cc"),
        ("aa if (bb if cc)", "aa if (bb if cc)"),
        ("not (aa if bb)", "not (aa if bb)"),
        (
            "nothing and android and iff and order",
            "nothing and android and iff and order",
        ),
        (
            "file:/usr/bin/python3 or cap:python",
            "file:/usr/bin/python3 or cap:python",
        ),
    ] {
        assert_eq!(canonical(input).unwrap(), shown, "{input:?}");
        // The canonical text is itself canonical.
        assert_eq!(canonical(shown).unwrap(), shown);
    }
}

#[test]
fn the_tree_has_the_expected_shape() {
    let e: Expr = "aa and bb if cc".parse().unwrap();
    let Expr::If { then, cond } = e else {
        panic!("not an if")
    };
    assert!(matches!(*then, Expr::And(ref parts) if parts.len() == 2));
    assert!(matches!(*cond, Expr::Req(_)));
    let e: Expr = "nginx[doc] ~ 1.27".parse().unwrap();
    let reqs = e.requirements();
    assert_eq!(reqs.len(), 1);
    let (op, version) = reqs[0].constraint.as_ref().unwrap();
    assert_eq!(*op, Op::Compatible);
    assert_eq!(version.to_string(), "1.27");
    assert_eq!(reqs[0].facets.len(), 1);
    let e: Expr = "aa or (bb and not cc) or (dd if ee)".parse().unwrap();
    let names: Vec<String> = e
        .requirements()
        .iter()
        .map(|r| r.atom.to_string())
        .collect();
    assert_eq!(names, ["aa", "bb", "cc", "dd", "ee"]);
}

#[test]
fn errors_say_what_and_where() {
    let cases: Vec<(&str, usize, &str)> = vec![
        ("", 0, "the expression is empty"),
        ("   ", 3, "the expression is empty"),
        ("aa and", 6, "expected an atom, 'not' or '(', found the end"),
        ("aa and bb or cc", 10, "'and' and 'or' can't be mixed"),
        ("aa or bb and cc", 9, "'and' and 'or' can't be mixed"),
        ("aa if bb if cc", 9, "only one 'if' per group"),
        ("(aa", 3, "expected ')', found the end"),
        ("aa)", 2, "expected 'and', 'or', 'if' or the end, found ')'"),
        (
            "aa bb",
            3,
            "expected 'and', 'or', 'if' or the end, found 'bb'",
        ),
        (")", 0, "expected an atom, 'not' or '(', found ')'"),
        ("and", 0, "expected an atom, 'not' or '(', found 'and'"),
        ("not", 3, "expected an atom, 'not' or '(', found the end"),
        ("aa and >= 1", 7, "found '>='"),
        ("aa and != 1", 7, "found '!='"),
        ("aa and <= 1", 7, "found '<='"),
        ("aa and = 1", 7, "found '='"),
        ("Nginx", 0, "can't contain 'N'"),
        ("pkg:x", 0, "isn't an atom"),
        ("aa >=", 5, "expected a version, found the end"),
        ("aa >= )", 6, "expected a version, found ')'"),
        ("aa >= x1", 6, "must start with a digit"),
        (
            "aa ! 1",
            3,
            "expected 'and', 'or', 'if' or the end, found '!'",
        ),
        (
            "so:libc.so.6 >= 1",
            13,
            "only packages and cap: atoms can have a version constraint",
        ),
        ("file:/bin/sh = 1", 13, "only packages and cap: atoms"),
        ("cap:mta[doc]", 7, "only package atoms can select facets"),
        (
            "so:libc.so.6 [doc]",
            13,
            "only package atoms can select facets",
        ),
        (
            "aa[doc] >= 1 [dev]",
            13,
            "facets can be given once per atom",
        ),
        ("aa[]", 3, "expected a facet, found ']'"),
        ("aa[doc,]", 7, "expected a facet, found ']'"),
        ("aa[doc", 6, "expected ',' or ']', found the end"),
        ("aa[doc dev]", 7, "expected ',' or ']', found 'dev'"),
        ("aa[doc,doc]", 7, "the facet doc is listed twice"),
        ("aa[Doc]", 3, "must start with a lowercase letter"),
        ("aa[locale:]", 3, "nothing after ':'"),
    ];
    for (text, at, message) in cases {
        let e = text.parse::<Expr>().unwrap_err();
        assert_eq!(e.at, at, "{text:?}: {e}");
        assert!(e.to_string().contains(message), "{text:?}: {e}");
        assert!(e.to_string().starts_with(&format!("at byte {at}: ")));
    }
}

#[test]
fn the_limits_hold() {
    // Length.
    let long = format!("aa{}", " ".repeat(MAX_LEN - 2));
    assert!(long.parse::<Expr>().is_ok());
    let (at, kind) = error(&format!("{long} ")).unwrap();
    assert_eq!(at, MAX_LEN);
    assert_eq!(
        kind,
        ErrorKind::TooLong {
            max: MAX_LEN,
            len: MAX_LEN + 1
        }
    );
    // The canonical text must fit too: unspaced operators get spaces.
    let tight = vec!["aa!=1111111111"; 220].join(" or ");
    assert!(tight.len() <= MAX_LEN);
    let (at, kind) = error(&tight).unwrap();
    assert_eq!(at, 0);
    assert_eq!(
        kind,
        ErrorKind::CanonicalTooLong {
            max: MAX_LEN,
            len: 220 * 20 - 4
        }
    );
    // Exactly the limit, in canonical form, is accepted.
    let mut names = vec!["a".repeat(124); 31];
    names.push("a".repeat(128));
    let exact = names.join(" or ");
    assert_eq!(exact.len(), MAX_LEN);
    assert_eq!(exact.parse::<Expr>().unwrap().to_string().len(), MAX_LEN);
    let fits = vec!["aa!=1111111111"; 200].join(" or ");
    assert!(fits.parse::<Expr>().unwrap().to_string().len() <= MAX_LEN);
    // Depth, through parentheses and through `not`.
    let deep = |n: usize| format!("{}aa{}", "(".repeat(n), ")".repeat(n));
    assert!(deep(MAX_DEPTH).parse::<Expr>().is_ok());
    assert_eq!(
        error(&deep(MAX_DEPTH + 1)).unwrap(),
        (MAX_DEPTH, ErrorKind::TooDeep(MAX_DEPTH))
    );
    let nots = |n: usize| format!("{}aa", "not ".repeat(n));
    assert!(nots(MAX_DEPTH).parse::<Expr>().is_ok());
    assert_eq!(
        error(&nots(MAX_DEPTH + 1)).unwrap(),
        (MAX_DEPTH * 4 + 3, ErrorKind::TooDeep(MAX_DEPTH))
    );
    // Depth is restored after each group, so siblings don't add up.
    let siblings = vec![deep(MAX_DEPTH); 3].join(" and ");
    assert!(siblings.parse::<Expr>().is_ok());
    let negations = vec!["not aa"; MAX_DEPTH + 8].join(" and ");
    assert!(negations.parse::<Expr>().is_ok());
    // Atoms.
    let atoms = |n: usize| vec!["aa"; n].join(" or ");
    assert!(atoms(MAX_ATOMS).parse::<Expr>().is_ok());
    let (at, kind) = error(&atoms(MAX_ATOMS + 1)).unwrap();
    assert_eq!(kind, ErrorKind::TooManyAtoms(MAX_ATOMS));
    assert_eq!(at, MAX_ATOMS * 6);
}

#[test]
fn requirements_match_atoms_versions_and_facets() {
    let nginx = provide("nginx", Some("1.27.3-2"), &["runtime", "doc"]).unwrap();
    let go = provide("cap:go", Some("1.23"), &[]).unwrap();
    let mta = provide("cap:mta", None, &[]).unwrap();
    let ssl = provide("so:libssl.so.3", None, &[]).unwrap();
    let all = [nginx, go, mta, ssl];
    for (expr, expected) in [
        ("nginx", true),
        ("nginx >= 1.27", true),
        ("nginx > 1.27.3-2", false),
        ("nginx ~ 1.20", true),
        ("nginx ~ 2.0", false),
        ("nginx != 1.27.3-2", false),
        ("nginx[doc]", true),
        ("nginx[doc,runtime] = 1.27.3-2", true),
        ("nginx[dev]", false),
        ("apache2", false),
        ("cap:go >= 1.21", true),
        ("cap:go < 1.21", false),
        // A provide without a version meets no versioned requirement.
        ("cap:mta", true),
        ("cap:mta >= 1", false),
        ("cap:mta != 1", false),
        ("so:libssl.so.3", true),
        ("so:libssl.so.1.1", false),
        ("not apache2", true),
        ("not nginx", false),
        ("nginx and apache2", false),
        ("nginx and cap:mta", true),
        ("apache2 or nginx", true),
        ("apache2 or lighttpd", false),
        // `a if b`: required only when b holds.
        ("apache2 if lighttpd", true),
        ("apache2 if nginx", false),
        ("cap:mta if nginx", true),
    ] {
        assert_eq!(satisfied(expr, &all).unwrap(), expected, "{expr}");
    }
    assert!(!satisfied("nginx", &[]).unwrap());
    assert!(satisfied("not nginx", &[]).unwrap());
}
