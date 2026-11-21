// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Splitting a package's tree into facets, so an admin picks what to
//! install and a packager never splits `-dev` or `-doc` packages by hand.
//!
//! Each path goes to the facet of the first rule that matches it:
//!
//! 1. under `/usr/lib/debug`: `debug`
//! 2. under `/usr/share/doc`, `/usr/share/man` or `/usr/share/info`:
//!    `doc`
//! 3. under `/usr/share/locale/<ll>/`: `locale:<ll>`
//! 4. under `/usr/include`, a file or link whose name ends in `.a`, or a
//!    `.pc` file in a `pkgconfig` directory: `dev`
//! 5. everything else: `runtime`
//!
//! An override moves a path and everything below it to another facet,
//! and the most specific override wins. Each facet's tree holds the
//! directories above its entries, and a directory with nothing below it
//! goes by its own path. A hard link whose file lands in another facet
//! becomes a copy of the file: the same content, so it takes no more
//! space.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ordin_core::Facet;
use ordin_tree::{Entry, Kind, Tree, TreePath};

/// A rule-1 override from the recipe: `path` and everything below it go
/// to `facet`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FacetOverride {
    /// The path, a file or a directory.
    pub path: TreePath,
    /// Where it goes.
    pub facet: Facet,
}

/// Why a path is in its facet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    /// A path rule, described.
    Rule(&'static str),
    /// An override of this path or a directory above it.
    Override(TreePath),
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rule(rule) => f.write_str(rule),
            Self::Override(path) => write!(f, "overridden at {path}"),
        }
    }
}

/// Where one path landed, as `ordin show --facets` lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placement {
    /// The path.
    pub path: TreePath,
    /// Its facet.
    pub facet: Facet,
    /// Why.
    pub reason: Reason,
}

/// One facet's tree and the bytes of file content in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FacetTree {
    /// The tree.
    pub tree: Tree,
    /// Bytes of file content, as the manifest records it. A hard link
    /// adds nothing; a copy made from one does.
    pub size: u64,
}

/// Something about the classification a packager should know.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FacetNote {
    /// A locale directory whose name isn't a facet qualifier, so its
    /// contents stay in `runtime`.
    BadLocale {
        /// The directory.
        path: String,
    },
    /// A hard link whose file is in another facet, made a copy.
    Copied {
        /// The link.
        path: TreePath,
        /// Its file, in the other facet.
        target: TreePath,
    },
}

impl fmt::Display for FacetNote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLocale { path } => write!(
                f,
                "{path}: not a locale name a facet can hold, so it stays in runtime"
            ),
            Self::Copied { path, target } => write!(
                f,
                "{path}: a hard link to {target}, which is in another facet, so it's a copy here"
            ),
        }
    }
}

/// A package's tree split into facets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Facets {
    /// Each facet's tree. `runtime` is always there, even empty.
    pub facets: BTreeMap<Facet, FacetTree>,
    /// Every path but the directories above others, sorted, with its facet.
    pub placements: Vec<Placement>,
    /// Notes, in path order.
    pub notes: Vec<FacetNote>,
}

/// An override that can't be used.
#[derive(Debug, thiserror::Error)]
#[error("{path}: {kind}")]
pub struct FacetError {
    /// The path.
    pub path: String,
    /// What is wrong.
    pub kind: FacetErrorKind,
}

/// What is wrong.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FacetErrorKind {
    /// An override for a path that isn't in the tree.
    #[error("the facet override matches nothing in the tree")]
    UnusedOverride,
    /// Two overrides for one path.
    #[error("the path has two facet overrides")]
    DuplicateOverride,
    /// A facet's tree breaks a tree rule.
    #[error(transparent)]
    Tree(Box<ordin_tree::Error>),
}

/// Whether `path` is `base` or inside it.
fn within(path: &str, base: &str) -> bool {
    path.strip_prefix(base)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

const DOC: [&str; 3] = ["/usr/share/doc", "/usr/share/info", "/usr/share/man"];

const LOCALE: &str = "/usr/share/locale/";

/// The facet a path's rules give, why, and a note for a locale name a
/// facet can't hold.
fn by_rule(e: &Entry) -> (Facet, &'static str, Option<FacetNote>) {
    let path = e.path.as_str();
    if within(path, "/usr/lib/debug") {
        return (Facet::debug(), "under /usr/lib/debug", None);
    }
    if DOC.iter().any(|base| within(path, base)) {
        return (Facet::doc(), "under /usr/share/doc, man or info", None);
    }
    if let Some(rest) = path.strip_prefix(LOCALE) {
        // A name directly in /usr/share/locale is a locale only when it is
        // a directory (`de/`), not a file such as `locale.alias`.
        let name = match rest.split_once('/') {
            Some((name, _)) => Some(name),
            None if matches!(e.kind, Kind::Dir(_)) => Some(rest),
            None => None,
        };
        if let Some(name) = name {
            return match format!("locale:{name}").parse() {
                Ok(locale) => (locale, "under /usr/share/locale", None),
                Err(_) => (
                    Facet::runtime(),
                    "everything else",
                    Some(FacetNote::BadLocale {
                        path: format!("{LOCALE}{name}"),
                    }),
                ),
            };
        }
    }
    if within(path, "/usr/include") {
        return (Facet::dev(), "under /usr/include", None);
    }
    let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
    if matches!(e.kind, Kind::Dir(_)) {
        return (Facet::runtime(), "everything else", None);
    }
    if name.ends_with(".a") {
        return (Facet::dev(), "a static library", None);
    }
    if name.ends_with(".pc")
        && parent
            .rsplit_once('/')
            .is_some_and(|(_, dir)| dir == "pkgconfig")
    {
        return (Facet::dev(), "a pkg-config file", None);
    }
    (Facet::runtime(), "everything else", None)
}

/// The overrides by path, each with whether it matched anything.
struct Overrides<'a>(BTreeMap<&'a str, (&'a FacetOverride, bool)>);

impl<'a> Overrides<'a> {
    fn new(overrides: &'a [FacetOverride]) -> Result<Self, FacetError> {
        let mut map = BTreeMap::new();
        for o in overrides {
            if map.insert(o.path.as_str(), (o, false)).is_some() {
                return Err(FacetError {
                    path: o.path.to_string(),
                    kind: FacetErrorKind::DuplicateOverride,
                });
            }
        }
        Ok(Self(map))
    }

    /// The most specific override covering `path`.
    fn of(&mut self, path: &str) -> Option<&'a FacetOverride> {
        let mut at = path;
        loop {
            if let Some((o, used)) = self.0.get_mut(at) {
                *used = true;
                return Some(o);
            }
            at = at
                .rsplit_once('/')
                .map(|(up, _)| up)
                .filter(|up| !up.is_empty())?;
        }
    }

    fn check_all_used(&self) -> Result<(), FacetError> {
        match self.0.iter().find(|(_, (_, used))| !used) {
            Some((path, _)) => Err(FacetError {
                path: (*path).to_owned(),
                kind: FacetErrorKind::UnusedOverride,
            }),
            None => Ok(()),
        }
    }
}

/// Splits a tree into facets by path rules and overrides.
///
/// # Errors
///
/// An override that matches nothing, or two for one path.
pub fn classify(tree: &Tree, overrides: &[FacetOverride]) -> Result<Facets, FacetError> {
    let mut overrides = Overrides::new(overrides)?;
    let has_children: BTreeSet<&str> = tree.entries().iter().map(|e| e.path.parent()).collect();
    let mut placements = Vec::new();
    let mut notes = Vec::new();
    // Each path's facet, for every entry including directories.
    let mut placed: BTreeMap<&str, Facet> = BTreeMap::new();
    for e in tree.entries() {
        let path = e.path.as_str();
        let (facet, reason) = match overrides.of(path) {
            Some(o) => (o.facet.clone(), Reason::Override(o.path.clone())),
            None => {
                let (facet, rule, note) = by_rule(e);
                notes.extend(note);
                (facet, Reason::Rule(rule))
            }
        };
        let leaf = !(matches!(e.kind, Kind::Dir(_)) && has_children.contains(path));
        if leaf {
            placements.push(Placement {
                path: e.path.clone(),
                facet: facet.clone(),
                reason,
            });
            placed.insert(path, facet);
        }
    }
    overrides.check_all_used()?;
    notes.dedup();

    // Each facet's entries: its leaves, then the directories above them.
    let mut members: BTreeMap<Facet, BTreeSet<&str>> = BTreeMap::new();
    members.entry(Facet::runtime()).or_default();
    for (path, facet) in &placed {
        let set = members.entry(facet.clone()).or_default();
        set.insert(path);
        let mut at = *path;
        while let Some((up, _)) = at.rsplit_once('/').filter(|(up, _)| !up.is_empty()) {
            set.insert(up);
            at = up;
        }
    }
    let mut facets = BTreeMap::new();
    for (facet, paths) in members {
        let mut entries = Vec::with_capacity(paths.len());
        // The first copy made in this facet of each file, by the file's path.
        let mut copies: BTreeMap<&TreePath, TreePath> = BTreeMap::new();
        let mut size = 0u64;
        for e in paths.iter().filter_map(|p| tree.get(p)) {
            let kind = match &e.kind {
                Kind::HardLink(target) if !paths.contains(target.as_str()) => {
                    if let Some(first) = copies.get(target) {
                        Kind::HardLink(first.clone())
                    } else {
                        copies.insert(target, e.path.clone());
                        notes.push(FacetNote::Copied {
                            path: e.path.clone(),
                            target: target.clone(),
                        });
                        tree.get(target.as_str())
                            .map_or_else(|| e.kind.clone(), |t| t.kind.clone())
                    }
                }
                other => other.clone(),
            };
            if let Kind::File(f) = &kind {
                size = size.saturating_add(f.size);
            }
            entries.push(Entry {
                path: e.path.clone(),
                kind,
            });
        }
        let built = facet_tree(&facet, entries)?;
        facets.insert(facet, FacetTree { tree: built, size });
    }
    notes.sort_by(|a, b| note_path(a).cmp(note_path(b)));
    Ok(Facets {
        facets,
        placements,
        notes,
    })
}

/// One facet's tree. Its entries are a part of a valid tree, with every
/// directory above them and every hard link pointed inside, so the rules
/// hold by construction; they are checked anyway.
fn facet_tree(facet: &Facet, entries: Vec<Entry>) -> Result<Tree, FacetError> {
    Tree::new(entries).map_err(|error| FacetError {
        path: facet.to_string(),
        kind: FacetErrorKind::Tree(Box::new(error)),
    })
}

fn note_path(note: &FacetNote) -> &str {
    match note {
        FacetNote::BadLocale { path } => path,
        FacetNote::Copied { path, .. } => path.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_facet_tree_that_breaks_a_rule_is_refused() {
        // A link to a file that isn't there.
        let entries = vec![Entry {
            path: "/a".parse().unwrap(),
            kind: Kind::HardLink("/b".parse().unwrap()),
        }];
        let error = facet_tree(&Facet::doc(), entries).unwrap_err();
        assert_eq!(error.path, "doc");
        assert!(matches!(error.kind, FacetErrorKind::Tree(_)));
        assert!(facet_tree(&Facet::doc(), vec![]).is_ok());
    }
}
