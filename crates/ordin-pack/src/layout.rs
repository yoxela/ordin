// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Mapping an install root into Ordin's layout.
//!
//! A package's tree lives under `/usr`. The rest of an install root
//! becomes declarations instead:
//!
//! - `usr/` stays where it is. `bin/`, `sbin/`, `lib/` and `lib64/` move
//!   under `usr/`, as on a merged-`/usr` system.
//! - `etc/` moves to `/usr/share/ordin/defaults/<name>/` as the package's
//!   config defaults. Each file is merged three ways with the admin's
//!   copy, and an empty directory is a drop-in directory.
//! - Under `var/lib`, `var/cache`, `var/log`, `var/spool` and `var/tmp`,
//!   directories become state paths of that class. Empty files become
//!   state files, created if missing. Other files become seeds, kept
//!   under `/usr/share/ordin/seeds/<name>/` and copied once if missing.
//! - Anything else is refused with a hint, unless it is under a prefix
//!   the software was installed with: `--prefix /opt/foo` moves
//!   `opt/foo/bin/x` to `usr/bin/x`.

use std::collections::btree_map::Entry as Slot;
use std::collections::{BTreeMap, BTreeSet};

use ordin_core::{Account, FilePath, PackageName};
use ordin_manifest::{Class, Config, Flush, Merge, Seed, StateFile, StatePath};
use ordin_tree::{DIR_MODE, Dir, Entry, Kind, Tree, TreePath, Xattrs};

/// Ordin's own part of `/usr`.
const RESERVED: &str = "/usr/share/ordin";

/// Where config defaults go, under the package's name.
const DEFAULTS: &str = "/usr/share/ordin/defaults";

/// Where seeds go, under the package's name.
const SEEDS: &str = "/usr/share/ordin/seeds";

/// Top-level directories that a merged-`/usr` system keeps under `/usr`.
const MERGED: [&str; 4] = ["bin", "lib", "lib64", "sbin"];

/// The directories under `/var` whose contents are state, and its class.
const STATE_ROOTS: [(&str, Class); 5] = [
    ("cache", Class::Cache),
    ("lib", Class::Data),
    ("log", Class::Log),
    ("spool", Class::Spool),
    ("tmp", Class::Tmp),
];

/// What [`normalize`] needs besides the tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayoutOptions {
    /// The package's name, which config defaults and seeds are kept under.
    pub name: PackageName,
    /// Prefixes the software was installed with. Everything under one
    /// moves to `/usr`.
    pub prefixes: Vec<TreePath>,
}

/// A tree in Ordin's layout, and what the manifest declares for the rest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    /// Everything under `/usr`, including config defaults and seeds.
    pub tree: Tree,
    /// Config defaults, sorted by target.
    pub config: Vec<Config>,
    /// State directories, sorted by path.
    pub state_paths: Vec<StatePath>,
    /// Empty state files, created if missing, sorted by path.
    pub state_files: Vec<StateFile>,
    /// Files copied once if missing, sorted by path.
    pub seeds: Vec<Seed>,
}

/// A path that doesn't fit Ordin's layout, and why.
#[derive(Debug, thiserror::Error)]
#[error("{path}: {kind}")]
pub struct LayoutError {
    /// The path in the install root, or the option given.
    pub path: String,
    /// What is wrong.
    pub kind: LayoutErrorKind,
}

/// Why a path doesn't fit Ordin's layout.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LayoutErrorKind {
    /// Outside `usr/`, `etc/`, `var/` and the merged directories.
    #[error(
        "outside Ordin's layout, which packages usr/, etc/ and var/; if the software was installed with a prefix here, pass it with --prefix to move it under /usr"
    )]
    OutsideLayout,
    /// Under `/usr/share/ordin`.
    #[error("/usr/share/ordin is Ordin's own; config defaults come from etc/ and seeds from var/")]
    Reserved,
    /// Under `/run` or `/var/run`.
    #[error(
        "runtime directories are created at boot; declare them in the recipe, or with a unit's RuntimeDirectory="
    )]
    Runtime,
    /// Under `/var`, outside the directories whose class is known.
    #[error(
        "only var/lib, var/cache, var/log, var/spool and var/tmp are recognized as state; declare other state in the recipe"
    )]
    UnknownState,
    /// Something other than a directory where Ordin's layout has one.
    #[error("a {found} where Ordin's layout has a directory")]
    NotADirectory {
        /// What is there.
        found: &'static str,
    },
    /// A symlink or hard link under `/etc`.
    #[error("a {found} under /etc can't be a config default; only files and empty directories can")]
    LinkInEtc {
        /// What is there.
        found: &'static str,
    },
    /// A symlink or hard link under `/var`.
    #[error("a {found} under /var can't be state; only directories and files can")]
    LinkInVar {
        /// What is there.
        found: &'static str,
    },
    /// A state directory with extended attributes, which a state
    /// declaration can't carry.
    #[error("a state directory can't carry extended attributes; declare it in the recipe instead")]
    StateXattrs,
    /// A path the manifest's grammar can't declare.
    #[error("the manifest can't declare this path: {0}")]
    NotDeclarable(String),
    /// A destination a tree can't hold.
    #[error("moving it gives a path a tree can't hold: {0}")]
    BadDestination(String),
    /// Two paths that move to the same place.
    #[error("it moves to {destination}, where {other} is too")]
    Collision {
        /// Where both would be.
        destination: String,
        /// The other path in the install root.
        other: String,
    },
    /// A hard link to a file that becomes state, and so leaves the tree.
    #[error("a hard link to {target}, which becomes a state file and isn't packaged")]
    LinkToState {
        /// The file it links to.
        target: String,
    },
    /// A prefix that can't be used.
    #[error("not a usable --prefix: {0}")]
    BadPrefix(&'static str),
    /// A prefix with nothing at it.
    #[error("--prefix names nothing in the tree")]
    UnusedPrefix,
    /// The result breaks a tree rule.
    #[error(transparent)]
    Tree(Box<ordin_tree::Error>),
}

fn refused(path: &str, kind: LayoutErrorKind) -> LayoutError {
    LayoutError {
        path: path.to_owned(),
        kind,
    }
}

/// The first name of a path, and the rest if there is any.
fn split(path: &str) -> (&str, Option<&str>) {
    let path = path.strip_prefix('/').unwrap_or(path);
    match path.split_once('/') {
        Some((first, rest)) => (first, Some(rest)),
        None => (path, None),
    }
}

/// Whether `path` is `base` or inside it.
fn within(path: &str, base: &str) -> bool {
    path.strip_prefix(base)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Checks the prefixes against the tree.
fn check_prefixes<'a>(tree: &Tree, prefixes: &'a [TreePath]) -> Result<Vec<&'a str>, LayoutError> {
    let mut checked: Vec<&str> = prefixes.iter().map(TreePath::as_str).collect();
    checked.sort_unstable();
    for (index, prefix) in checked.iter().enumerate() {
        let (top, _) = split(prefix);
        let reason = if ["usr", "etc", "var", "run"].contains(&top) || MERGED.contains(&top) {
            Some("usr/, etc/, var/, run/, bin/, sbin/, lib/ and lib64/ have their own rules")
        } else if checked
            .get(index + 1)
            .is_some_and(|next| within(next, prefix))
        {
            Some("prefixes can't be inside one another")
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(refused(prefix, LayoutErrorKind::BadPrefix(reason)));
        }
        match tree.get(prefix) {
            None => return Err(refused(prefix, LayoutErrorKind::UnusedPrefix)),
            Some(e) if !matches!(e.kind, Kind::Dir(_)) => {
                return Err(refused(
                    prefix,
                    LayoutErrorKind::BadPrefix("a prefix is a directory"),
                ));
            }
            Some(_) => {}
        }
    }
    Ok(checked)
}

/// Where a path goes.
enum Route<'a> {
    /// To this path under `/usr`.
    Usr(String),
    /// Nowhere: a directory Ordin's layout already has.
    Drop,
    /// Into the config defaults.
    Etc(&'a str),
    /// Into state of this class.
    Var(Class),
}

fn route<'a>(path: &'a str, prefixes: &[&str]) -> Result<Route<'a>, LayoutErrorKind> {
    for prefix in prefixes {
        if path == *prefix || within(prefix, path) {
            return Ok(Route::Drop);
        }
        if let Some(rest) = path.strip_prefix(prefix).filter(|r| r.starts_with('/')) {
            return Ok(Route::Usr(format!("/usr{rest}")));
        }
    }
    let (top, rest) = split(path);
    match (top, rest) {
        ("usr", _) if within(path, RESERVED) => Err(LayoutErrorKind::Reserved),
        ("usr", _) => Ok(Route::Usr(path.to_owned())),
        (merged, _) if MERGED.contains(&merged) => Ok(Route::Usr(format!("/usr{path}"))),
        ("etc", None) | ("var", None) => Ok(Route::Drop),
        ("etc", Some(rest)) => Ok(Route::Etc(rest)),
        ("var", Some(rest)) => {
            let (root, below) = split(rest);
            match STATE_ROOTS.iter().find(|(name, _)| *name == root) {
                Some(_) if below.is_none() => Ok(Route::Drop),
                Some((_, class)) => Ok(Route::Var(*class)),
                None if root == "run" => Err(LayoutErrorKind::Runtime),
                None => Err(LayoutErrorKind::UnknownState),
            }
        }
        ("run", _) => Err(LayoutErrorKind::Runtime),
        _ => Err(LayoutErrorKind::OutsideLayout),
    }
}

/// A top-level symlink such as `bin -> usr/bin`, which a merged-`/usr`
/// layout already has.
fn merged_link(path: &str, kind: &Kind) -> bool {
    let Kind::Symlink(link) = kind else {
        return false;
    };
    let (top, rest) = split(path);
    rest.is_none()
        && MERGED.contains(&top)
        && [format!("usr/{top}"), format!("/usr/{top}")].contains(&link.target.to_string())
}

fn declarable(path: &str) -> Result<FilePath, LayoutErrorKind> {
    path.parse()
        .map_err(|e: ordin_core::Error| LayoutErrorKind::NotDeclarable(e.to_string()))
}

/// The layout being built.
struct Building {
    name: String,
    /// The new tree's entries by path, with the path each came from.
    entries: BTreeMap<TreePath, (String, Kind)>,
    /// Where each path that stays in the tree went.
    moved: BTreeMap<String, TreePath>,
    config: Vec<Config>,
    state_paths: Vec<StatePath>,
    state_files: Vec<StateFile>,
    seeds: Vec<Seed>,
}

impl Building {
    /// Puts an entry at `destination`. Two identical directories may meet
    /// there; anything else is a collision.
    fn add(
        &mut self,
        source: &str,
        destination: String,
        kind: &Kind,
    ) -> Result<(), LayoutErrorKind> {
        let destination: TreePath = destination
            .parse()
            .map_err(LayoutErrorKind::BadDestination)?;
        match self.entries.entry(destination.clone()) {
            Slot::Vacant(slot) => {
                slot.insert((source.to_owned(), kind.clone()));
            }
            Slot::Occupied(slot) => {
                let (other, existing) = slot.get();
                if !(matches!(kind, Kind::Dir(_)) && existing == kind) {
                    return Err(LayoutErrorKind::Collision {
                        destination: destination.to_string(),
                        other: other.clone(),
                    });
                }
            }
        }
        self.moved.insert(source.to_owned(), destination);
        Ok(())
    }

    fn etc(&mut self, e: &Entry, rest: &str, has_children: bool) -> Result<(), LayoutErrorKind> {
        let path = e.path.as_str();
        let default = format!("{DEFAULTS}/{}/{rest}", self.name);
        let merge = match &e.kind {
            Kind::File(_) => Some(Merge::ThreeWay),
            Kind::Dir(_) if has_children => None,
            Kind::Dir(_) => Some(Merge::DropIn),
            other => {
                return Err(LayoutErrorKind::LinkInEtc {
                    found: other.type_name(),
                });
            }
        };
        if let Some(merge) = merge {
            self.config.push(Config {
                default: declarable(&default)?,
                target: declarable(path)?,
                merge,
            });
        }
        self.add(path, default, &e.kind)
    }

    fn var(&mut self, e: &Entry, class: Class) -> Result<(), LayoutErrorKind> {
        let path = e.path.as_str();
        match &e.kind {
            Kind::Dir(d) if !d.xattrs.is_empty() => Err(LayoutErrorKind::StateXattrs),
            Kind::Dir(d) => {
                self.state_paths.push(StatePath {
                    path: declarable(path)?,
                    class,
                    owner: d.owner.clone(),
                    group: d.group.clone(),
                    mode: d.mode,
                    flush: Flush::Never,
                    recurse: false,
                    on_remove: None,
                });
                Ok(())
            }
            Kind::File(f) if f.size == 0 && f.xattrs.is_empty() && f.capabilities.is_none() => {
                self.state_files.push(StateFile {
                    path: declarable(path)?,
                    owner: f.owner.clone(),
                    group: f.group.clone(),
                    mode: f.mode,
                });
                Ok(())
            }
            Kind::File(_) => {
                let from = format!("{SEEDS}/{}{path}", self.name);
                self.seeds.push(Seed {
                    path: declarable(path)?,
                    from: declarable(&from)?,
                });
                self.add(path, from, &e.kind)
            }
            other => Err(LayoutErrorKind::LinkInVar {
                found: other.type_name(),
            }),
        }
    }

    fn place(
        &mut self,
        e: &Entry,
        prefixes: &[&str],
        has_children: bool,
    ) -> Result<(), LayoutErrorKind> {
        let path = e.path.as_str();
        match route(path, prefixes)? {
            Route::Drop if matches!(e.kind, Kind::Dir(_)) => Ok(()),
            Route::Drop => Err(LayoutErrorKind::NotADirectory {
                found: e.kind.type_name(),
            }),
            Route::Usr(_) if merged_link(path, &e.kind) => Ok(()),
            Route::Usr(destination) => self.add(path, destination, &e.kind),
            Route::Etc(rest) => self.etc(e, rest, has_children),
            Route::Var(class) => self.var(e, class),
        }
    }

    /// The new tree: hard links pointed at where their files went, and
    /// every missing directory above an entry added as `root:root 0755`.
    fn finish(mut self) -> Result<Layout, LayoutError> {
        let mut entries = Vec::with_capacity(self.entries.len());
        let mut parents = BTreeSet::new();
        for (destination, (source, kind)) in std::mem::take(&mut self.entries) {
            let kind = match kind {
                Kind::HardLink(target) => {
                    let moved = self.moved.get(target.as_str()).ok_or_else(|| {
                        refused(
                            &source,
                            LayoutErrorKind::LinkToState {
                                target: target.to_string(),
                            },
                        )
                    })?;
                    Kind::HardLink(moved.clone())
                }
                other => other,
            };
            let mut parent = destination.as_str();
            while let Some((up, _)) = parent.rsplit_once('/').filter(|(up, _)| !up.is_empty()) {
                parents.insert(up.to_owned());
                parent = up;
            }
            entries.push(Entry {
                path: destination,
                kind,
            });
        }
        let present: BTreeSet<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        // Every parent of a valid path is a valid path.
        let missing: Vec<TreePath> = parents
            .iter()
            .filter(|p| !present.contains(p.as_str()))
            .filter_map(|p| p.parse().ok())
            .collect();
        entries.extend(missing.into_iter().map(|path| Entry {
            path,
            kind: Kind::Dir(Dir {
                mode: DIR_MODE,
                owner: Account::root(),
                group: Account::root(),
                xattrs: Xattrs::new(),
            }),
        }));
        let tree = Tree::new(entries)
            .map_err(|e| refused("the normalized tree", LayoutErrorKind::Tree(Box::new(e))))?;
        Ok(Layout {
            tree,
            config: self.config,
            state_paths: self.state_paths,
            state_files: self.state_files,
            seeds: self.seeds,
        })
    }
}

/// Maps a walked install root into Ordin's layout.
///
/// # Errors
///
/// The first path that doesn't fit, with a hint, or a prefix that can't
/// be used.
pub fn normalize(tree: &Tree, options: &LayoutOptions) -> Result<Layout, LayoutError> {
    let prefixes = check_prefixes(tree, &options.prefixes)?;
    let parents: BTreeSet<&str> = tree.entries().iter().map(|e| e.path.parent()).collect();
    let mut building = Building {
        name: options.name.to_string(),
        entries: BTreeMap::new(),
        moved: BTreeMap::new(),
        config: Vec::new(),
        state_paths: Vec::new(),
        state_files: Vec::new(),
        seeds: Vec::new(),
    };
    for e in tree.entries() {
        let path = e.path.as_str();
        building
            .place(e, &prefixes, parents.contains(path))
            .map_err(|kind| refused(path, kind))?;
    }
    building.finish()
}
