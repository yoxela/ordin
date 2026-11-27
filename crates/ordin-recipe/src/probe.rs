// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Checking a recipe's declarations against every rule of the manifest,
//! without a copy of those rules: the declarations are put in a manifest
//! of their own, and the manifest's first error is traced back to the
//! line and column it came from.
//!
//! Requirements, provides, conflicts and the homepage are left out: the
//! manifest has no rule for them beyond the parsers that already read
//! them.

use std::collections::BTreeMap;

use ordin_core::{Arch, Digest, Facet, PackageName};
use ordin_manifest::{
    FacetEntry, Kind, License, Manifest, Migration, Presentation, Segment, State,
};
use ordin_version::Version;

use crate::read::{Item, Locations, Span, error};
use crate::{Error, Recipe};

/// The manifest a recipe's declarations make, with placeholders for
/// what the command line may still give.
fn manifest(recipe: &Recipe) -> Result<Manifest, String> {
    let p = &recipe.package;
    let name = match &p.name {
        Some(name) => name.clone(),
        None => "placeholder"
            .parse::<PackageName>()
            .map_err(|e| e.to_string())?,
    };
    let version: Version = format!(
        "{}-{}",
        p.version.as_deref().unwrap_or("0"),
        p.release.as_deref().unwrap_or("1")
    )
    .parse()
    .map_err(|e: ordin_version::Error| e.to_string())?;
    let facets = BTreeMap::from([(
        Facet::runtime(),
        FacetEntry {
            tree: Digest::blake3(b""),
            size: 0,
            default: true,
        },
    )]);
    // The license expression and its texts are checked when the package
    // is made, since the command line can change either.
    let license = License {
        spdx: "NONE".to_owned(),
        presentation: Presentation::Informational,
        texts: BTreeMap::new(),
    };
    let summary = p.summary.clone().unwrap_or_else(|| name.to_string());
    let mut m = Manifest::new(
        name,
        version,
        Kind::Base,
        p.arch.unwrap_or(Arch::Noarch),
        summary,
        license,
        facets,
    );
    let d = &recipe.declared;
    m.description.clone_from(&p.description);
    m.declares.users.clone_from(&d.users);
    m.declares.groups.clone_from(&d.groups);
    m.declares.units.clone_from(&d.units);
    m.settings.clone_from(&d.settings);
    if !d.state.is_empty() {
        m.state = Some(State {
            version: d.state.version,
            migration: Migration::None,
            paths: d.state.paths.clone(),
            files: d.state.files.clone(),
            seeds: d.state.seeds.clone(),
            obsolete: d.state.obsolete.clone(),
            migrations: Vec::new(),
        });
    }
    Ok(m)
}

/// The order the manifest lists items in: by `key`, keeping the
/// recipe's order for equal keys, as a stable sort does.
fn order<T>(items: &[T], key: impl Fn(&T) -> String) -> Vec<usize> {
    let mut order: Vec<usize> = (0..items.len()).collect();
    order.sort_by_key(|&i| key(&items[i]));
    order
}

/// A recipe key for a manifest field, where they differ.
fn recipe_key(field: &str) -> &str {
    match field {
        // `owner = "USER:GROUP"` gives both.
        "group" => "owner",
        other => other,
    }
}

/// Where in an item: the field's value, or the item when the recipe
/// doesn't write that field.
fn in_item(item: &Item, rest: &[Segment]) -> Span {
    match rest.first() {
        Some(Segment::Key(field)) => item
            .fields
            .get(recipe_key(field))
            .unwrap_or(&item.span)
            .clone(),
        _ => item.span.clone(),
    }
}

/// Where a manifest path came from in the recipe, if anywhere.
fn locate(recipe: &Recipe, at: &Locations, path: &[Segment]) -> Option<Span> {
    let key = |i: usize| match path.get(i) {
        Some(Segment::Key(k)) => Some(k.as_str()),
        _ => None,
    };
    let index = |i: usize| match path.get(i) {
        Some(Segment::Index(n)) => Some(*n),
        _ => None,
    };
    let d = &recipe.declared;
    let ordered = |items: &[Item], order: Vec<usize>, i: usize, rest: usize| {
        let item = items.get(*order.get(i)?)?;
        Some(in_item(item, path.get(rest..).unwrap_or(&[])))
    };
    match (key(0)?, key(1)) {
        ("settings", _) => ordered(
            &at.settings,
            order(&d.settings, |s| s.name.to_string()),
            index(1)?,
            2,
        ),
        ("declares", Some("users")) => ordered(
            &at.users,
            order(&d.users, |u| u.name.to_string()),
            index(2)?,
            3,
        ),
        ("declares", Some("groups")) => ordered(
            &at.groups,
            order(&d.groups, |g| g.name.to_string()),
            index(2)?,
            3,
        ),
        ("declares", Some("units")) => ordered(
            &at.units,
            order(&d.units, |u| u.name.to_string()),
            index(2)?,
            3,
        ),
        ("state", Some("version")) => at.state_version.clone(),
        ("state", Some("paths")) => ordered(
            &at.state_paths,
            order(&d.state.paths, |p| p.path.to_string()),
            index(2)?,
            3,
        ),
        ("state", Some("files")) => ordered(
            &at.state_files,
            order(&d.state.files, |f| f.path.to_string()),
            index(2)?,
            3,
        ),
        ("state", Some("seeds")) => ordered(
            &at.seeds,
            order(&d.state.seeds, |s| s.path.to_string()),
            index(2)?,
            3,
        ),
        (field, _) => at.package.get(field).cloned(),
    }
}

/// Checks the recipe's declarations against every manifest rule.
pub(crate) fn check(recipe: &Recipe, at: &Locations, text: &str) -> Result<(), Error> {
    let start = 0..0;
    let m = manifest(recipe).map_err(|e| error(text, &start, e))?;
    match m.to_canonical_bytes() {
        Ok(_) => Ok(()),
        Err(e) => Err(match locate(recipe, at, &e.path.0) {
            Some(span) => error(text, &span, &e.kind),
            // Nothing in the recipe wrote it: say where in the manifest.
            None => error(text, &start, format!("in the manifest it makes, {e}")),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stable_order_keeps_equal_keys_in_the_recipes_order() {
        assert_eq!(
            order(&["b", "a", "b", "a"], |s| (*s).to_owned()),
            [1, 3, 0, 2]
        );
    }

    #[test]
    fn a_path_the_recipe_didnt_write_is_found_nowhere() {
        let recipe = Recipe::default();
        let at = Locations::default();
        let key = |k: &str| Segment::Key(k.to_owned());
        // No index where one belongs, an index nothing has, or a field no
        // table holds.
        assert_eq!(
            locate(&recipe, &at, &[key("declares"), key("users"), key("x")]),
            None
        );
        assert_eq!(
            locate(&recipe, &at, &[key("settings"), Segment::Index(0)]),
            None
        );
        assert_eq!(locate(&recipe, &at, &[key("kind")]), None);
        assert_eq!(locate(&recipe, &at, &[Segment::Index(0)]), None);
    }

    #[test]
    fn an_item_points_at_its_field_or_at_itself() {
        let item = Item {
            span: 1..9,
            fields: BTreeMap::from([("owner".to_owned(), 3..5)]),
        };
        let key = |k: &str| [Segment::Key(k.to_owned())];
        assert_eq!(in_item(&item, &key("owner")), 3..5);
        assert_eq!(in_item(&item, &key("group")), 3..5);
        assert_eq!(in_item(&item, &key("mode")), 1..9);
        assert_eq!(in_item(&item, &[Segment::Index(0)]), 1..9);
        assert_eq!(in_item(&item, &[]), 1..9);
    }
}
