// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Who owns what in a package. Nothing comes from the files on disk,
//! because a packager usually isn't root: everything is `root:root`
//! unless an override says otherwise.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use ordin_core::Account;
use ordin_tree::TreePath;

use crate::error::{WalkError, WalkErrorKind};

/// `PATH=USER:GROUP`: the owner and group of a path and of everything
/// below it. The most specific override of a path wins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerOverride {
    /// The path it applies to.
    pub path: TreePath,
    /// The owning user.
    pub owner: Account,
    /// The owning group.
    pub group: Account,
}

impl FromStr for OwnerOverride {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let form = || format!("an owner override is PATH=USER:GROUP: {text:?}");
        // Account names have no '=' or ':', and a path may.
        let (path, accounts) = text.rsplit_once('=').ok_or_else(form)?;
        let (owner, group) = accounts.split_once(':').ok_or_else(form)?;
        Ok(Self {
            path: path.parse()?,
            owner: owner.parse().map_err(|e| format!("{e}"))?,
            group: group.parse().map_err(|e| format!("{e}"))?,
        })
    }
}

impl fmt::Display for OwnerOverride {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}:{}", self.path, self.owner, self.group)
    }
}

#[derive(Debug)]
struct Slot {
    owner: Account,
    group: Account,
    used: bool,
}

/// The overrides of one walk.
#[derive(Debug)]
pub(crate) struct Owners(BTreeMap<String, Slot>);

/// Who owns a path, and whether an override said so.
#[derive(Debug)]
pub(crate) struct Ownership {
    pub owner: Account,
    pub group: Account,
    pub overridden: bool,
}

impl Owners {
    pub fn new(overrides: &[OwnerOverride]) -> Result<Self, WalkError> {
        let mut slots = BTreeMap::new();
        for o in overrides {
            let slot = Slot {
                owner: o.owner.clone(),
                group: o.group.clone(),
                used: false,
            };
            if slots.insert(o.path.to_string(), slot).is_some() {
                return Err(WalkError {
                    path: o.path.to_string(),
                    kind: WalkErrorKind::DuplicateOwner,
                });
            }
        }
        Ok(Self(slots))
    }

    /// Who owns `path`: the override of the path or its nearest parent
    /// that has one, otherwise `root:root`.
    pub fn of(&mut self, path: &TreePath) -> Ownership {
        let mut at = path.as_str();
        while !at.is_empty() {
            if let Some(slot) = self.0.get_mut(at) {
                slot.used = true;
                return Ownership {
                    owner: slot.owner.clone(),
                    group: slot.group.clone(),
                    overridden: true,
                };
            }
            at = at.rsplit_once('/').map_or("", |(parent, _)| parent);
        }
        Ownership {
            owner: Account::root(),
            group: Account::root(),
            overridden: false,
        }
    }

    /// Refuses an override nothing used.
    pub fn check_all_used(&self) -> Result<(), WalkError> {
        match self.0.iter().find(|(_, slot)| !slot.used) {
            Some((path, _)) => Err(WalkError {
                path: path.clone(),
                kind: WalkErrorKind::UnusedOwner,
            }),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn over(text: &str) -> OwnerOverride {
        text.parse().unwrap()
    }

    fn path(text: &str) -> TreePath {
        text.parse().unwrap()
    }

    #[test]
    fn overrides_read_and_print() {
        let o = over("/var/lib/app=app:adm");
        assert_eq!(o.path.as_str(), "/var/lib/app");
        assert_eq!(o.owner.as_str(), "app");
        assert_eq!(o.group.as_str(), "adm");
        assert_eq!(o.to_string(), "/var/lib/app=app:adm");
        // Only the last '=' separates, because a path may hold one.
        assert_eq!(over("/a=b=app:adm").path.as_str(), "/a=b");
    }

    #[test]
    fn bad_overrides_say_why() {
        for (text, expected) in [
            ("/a", "PATH=USER:GROUP"),
            ("/a=app", "PATH=USER:GROUP"),
            ("a=app:adm", "absolute"),
            ("/a=:adm", "account name"),
            ("/a=app:", "account name"),
            ("/a=a.b:adm", "account name"),
            ("/a=app:a:b", "account name"),
        ] {
            let e = text.parse::<OwnerOverride>().unwrap_err();
            assert!(e.contains(expected), "{text}: {e}");
        }
    }

    #[test]
    fn the_nearest_override_wins_and_others_get_root() {
        let mut owners = Owners::new(&[over("/a=one:one"), over("/a/b/c=two:adm")]).unwrap();
        let of = |owners: &mut Owners, p: &str| {
            let o = owners.of(&path(p));
            (o.owner.to_string(), o.group.to_string(), o.overridden)
        };
        let one = ("one".to_owned(), "one".to_owned(), true);
        let two = ("two".to_owned(), "adm".to_owned(), true);
        let root = ("root".to_owned(), "root".to_owned(), false);
        assert_eq!(of(&mut owners, "/a"), one);
        assert_eq!(of(&mut owners, "/a/b"), one);
        assert_eq!(of(&mut owners, "/a/b/c"), two);
        assert_eq!(of(&mut owners, "/a/b/c/d"), two);
        // Sharing a prefix of letters isn't being below.
        assert_eq!(of(&mut owners, "/ab"), root);
        assert_eq!(of(&mut owners, "/a/b/cd"), one);
    }

    #[test]
    fn unused_and_repeated_overrides_are_refused() {
        let mut owners = Owners::new(&[over("/used=a:a"), over("/typo=a:a")]).unwrap();
        owners.of(&path("/used/x"));
        let e = owners.check_all_used().unwrap_err();
        assert_eq!(e.path, "/typo");
        assert!(matches!(e.kind, WalkErrorKind::UnusedOwner));
        owners.of(&path("/typo"));
        owners.check_all_used().unwrap();

        let e = Owners::new(&[over("/a=x:x"), over("/a=y:y")]).unwrap_err();
        assert_eq!(e.path, "/a");
        assert!(matches!(e.kind, WalkErrorKind::DuplicateOwner));
    }
}
