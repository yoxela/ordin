// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The manifest's types, one per object in `SCHEMA.md`. Fields are public
//! so tools can build manifests; encoding checks every rule again.

use std::collections::BTreeMap;

use ordin_core::{Arch, Atom, Digest, Facet, FilePath, PackageName, Soname};
use ordin_depexpr::{Expr, Requirement};
use ordin_version::Version;

use crate::json::Value;
use crate::text::{Date, Id, UnitName, Url};
use ordin_core::{Account, Mode};

/// Defines an enum written as fixed strings, with its list of values.
macro_rules! str_enum {
    ($(#[$doc:meta])* $name:ident { $($(#[$vdoc:meta])* $var:ident = $s:literal),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $($(#[$vdoc])* $var),+
        }

        impl $name {
            /// Every value, in the order the schema lists them.
            pub const ALL: &[Self] = &[$(Self::$var),+];

            /// The value as written in a manifest.
            #[must_use]
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$var => $s),+
                }
            }

            /// The value written `text`, if it is one.
            #[must_use]
            pub fn from_text(text: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|v| v.as_str() == text)
            }

            /// The allowed values, for messages: `a, b or c`.
            #[must_use]
            pub fn allowed() -> String {
                let all: Vec<&str> = Self::ALL.iter().map(|v| v.as_str()).collect();
                match all.split_last() {
                    Some((last, rest)) if !rest.is_empty() => format!("{} or {last}", rest.join(", ")),
                    _ => all.join(""),
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

str_enum!(
    /// What a package is.
    Kind {
        /// Installs a product at a version.
        Base = "base",
        /// Applies on top of one exact base.
        Update = "update",
        /// A closure that must boot to a login prompt.
        SystemBase = "system-base",
    }
);

str_enum!(
    /// How a license is shown.
    Presentation {
        /// Recorded and queryable, never shown during install.
        Informational = "informational",
        /// Shown interactively, logged otherwise.
        Display = "display",
        /// The transaction waits for explicit acceptance.
        Accept = "accept",
    }
);

str_enum!(
    /// A unit's preset.
    Preset {
        /// Enabled on install.
        Enable = "enable",
        /// Installed disabled.
        Disable = "disable",
    }
);

str_enum!(
    /// How a config default meets the admin's `/etc`.
    Merge {
        /// The target is a directory of drop-ins.
        DropIn = "drop-in",
        /// The target is a file, merged three ways.
        ThreeWay = "three-way",
    }
);

str_enum!(
    /// What an update does to state.
    Migration {
        /// Nothing.
        None = "none",
        /// A change that can be undone.
        Reversible = "reversible",
        /// A change that can't; Ordin snapshots first.
        Irreversible = "irreversible",
    }
);

str_enum!(
    /// A state path's class.
    Class {
        /// `/var/lib`: kept on remove.
        Data = "data",
        /// `/var/spool`: kept on remove.
        Spool = "spool",
        /// `/var/log`: kept, subject to host retention.
        Log = "log",
        /// `/var/cache`: purged on remove.
        Cache = "cache",
        /// `/var/tmp`: purged on remove.
        Tmp = "tmp",
        /// `/run`: gone at shutdown.
        Runtime = "runtime",
    }
);

str_enum!(
    /// When a state path is emptied.
    Flush {
        /// Never.
        Never = "never",
        /// Whenever the version changes.
        OnUpgrade = "on-upgrade",
    }
);

str_enum!(
    /// What happens to a state path on remove.
    OnRemove {
        /// Kept.
        Keep = "keep",
        /// Deleted.
        Purge = "purge",
        /// Archived, then deleted.
        Archive = "archive",
    }
);

str_enum!(
    /// A setting's type.
    SettingType {
        /// `true` or `false`.
        Bool = "bool",
        /// An integer, optionally within `min` and `max`.
        Int = "int",
        /// A TCP or UDP port, 1 to 65535.
        Port = "port",
        /// A string, optionally matching `pattern`.
        String = "string",
        /// One of `choices`.
        Choice = "choice",
        /// A set of `choices`.
        Multichoice = "multichoice",
        /// An absolute path.
        Path = "path",
        /// A list of strings.
        List = "list",
    }
);

str_enum!(
    /// A lifecycle phase.
    Phase {
        /// Before apply, read-only.
        Check = "check",
        /// Before staging a generation.
        PreApply = "pre-apply",
        /// After staging a generation.
        PostApply = "post-apply",
        /// Before a generation becomes permanent.
        PreCommit = "pre-commit",
        /// After a generation becomes permanent.
        PostCommit = "post-commit",
        /// When an applied generation is rejected.
        Reject = "reject",
        /// When the package's configuration is removed.
        Unconfig = "unconfig",
        /// When the package leaves the system.
        Remove = "remove",
        /// After switching into a generation.
        Health = "health",
    }
);

str_enum!(
    /// An SELinux port's protocol.
    Proto {
        /// TCP.
        Tcp = "tcp",
        /// UDP.
        Udp = "udp",
    }
);

str_enum!(
    /// An SELinux file context's file type.
    FileType {
        /// Any.
        All = "all",
        /// A regular file.
        File = "file",
        /// A directory.
        Directory = "directory",
        /// A symbolic link.
        Symlink = "symlink",
        /// A socket.
        Socket = "socket",
        /// A named pipe.
        Pipe = "pipe",
        /// A block device.
        Block = "block",
        /// A character device.
        Char = "char",
    }
);

str_enum!(
    /// How much evidence identifies an observed payload.
    Evidence {
        /// A vendor signature names the version.
        Signed = "signed",
        /// A signed release index lists the digest.
        Indexed = "indexed",
        /// Metadata compiled into the file.
        Embedded = "embedded",
        /// The program's own `--version`, sandboxed.
        Probed = "probed",
        /// The admin's word.
        Asserted = "asserted",
    }
);

str_enum!(
    /// What happens when evidence falls short.
    OnInsufficient {
        /// Report it.
        Warn = "warn",
        /// Restore the last known-good copy.
        Quarantine = "quarantine",
        /// Deny execution until an admin accepts it.
        Block = "block",
    }
);

str_enum!(
    /// What an upgrade does to a delegated payload.
    PayloadOnUpgrade {
        /// Keep the observed payload if it is newer.
        KeepNewer = "keep-newer",
        /// Always install the package's payload.
        Replace = "replace",
    }
);

/// A package manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// The package.
    pub name: PackageName,
    /// Its version; the release is required.
    pub version: Version,
    /// What it is.
    pub kind: Kind,
    /// What it runs on.
    pub arch: Arch,
    /// One line, 1 to 120 characters.
    pub summary: String,
    /// Longer text.
    pub description: Option<String>,
    /// Where users go for the software.
    pub homepage: Option<Url>,
    /// Its license.
    pub license: License,
    /// Where it was built from.
    pub source: Option<Source>,
    /// Its attestations.
    pub provenance: Option<Provenance>,
    /// Its facets.
    pub facets: BTreeMap<Facet, FacetEntry>,
    /// What it provides besides its own name.
    pub provides: Vec<Provide>,
    /// Each must hold.
    pub requires: Vec<Expr>,
    /// None may be co-installed.
    pub conflicts: Vec<Expr>,
    /// Installed if possible.
    pub recommends: Vec<Expr>,
    /// "Install me when this holds."
    pub supplements: Vec<Expr>,
    /// Requirements while applying.
    pub requires_apply: Vec<Expr>,
    /// Requirements at boot.
    pub requires_boot: Vec<Expr>,
    /// Packages this one supersedes.
    pub obsoletes: Vec<Expr>,
    /// Packages whose files this one may take over.
    pub replaces: Vec<Requirement>,
    /// For an update: files it removes, per facet.
    pub removes: BTreeMap<Facet, Vec<FilePath>>,
    /// What Ordin applies and undoes.
    pub declares: Declares,
    /// Paths under `/var` and `/run`.
    pub state: Option<State>,
    /// Typed settings.
    pub settings: Vec<Setting>,
    /// Sandboxed programs per phase.
    pub hooks: BTreeMap<Phase, Vec<Step>>,
    /// Installed tests.
    pub tests: Vec<Test>,
    /// SELinux and AppArmor policy.
    pub security: Option<Security>,
    /// A delegated payload.
    pub delegated: Option<Delegated>,
    /// May be applied live.
    pub live_apply: bool,
    /// Needs a full reboot.
    pub boot_critical: bool,
    /// Support dates.
    pub support: Option<Support>,
    /// Per shared library, its ABI digest.
    pub abi: BTreeMap<Soname, Digest>,
    /// Advisory and fix IDs contained.
    pub fixes: Vec<String>,
    /// Notices shown once.
    pub notices: Vec<Notice>,
    /// Paths whose files inference was told not to read, sorted by path.
    pub inference_skip: Vec<InferenceSkip>,
    /// Fields an older reader may skip.
    pub ignorable: Vec<String>,
    /// The ignorable fields present, with where they were, kept so the
    /// encoding is unchanged.
    pub(crate) ignored: Vec<(Vec<crate::error::Segment>, Value)>,
}

/// The license.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct License {
    /// The SPDX expression, canonical.
    pub spdx: String,
    /// How it is shown.
    pub presentation: Presentation,
    /// Each license and exception ID, with the digest of its text.
    pub texts: BTreeMap<String, Digest>,
}

/// Where the package was built from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    /// The source repository.
    pub repo: Url,
    /// The revision built.
    pub rev: String,
    /// The recipe's digest.
    pub recipe: Digest,
}

/// Where the package came from: attestations carried beside the
/// manifest, and the commit it was built from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provenance {
    /// The SLSA attestation.
    pub slsa: Option<Digest>,
    /// The SBOM.
    pub sbom: Option<Digest>,
    /// The git commit built: its full object name, 40 lowercase hex
    /// digits (SHA-1) or 64 (SHA-256).
    pub commit: Option<String>,
}

/// One facet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FacetEntry {
    /// Its tree.
    pub tree: Digest,
    /// Bytes of file content.
    pub size: u64,
    /// Installed unless the host selects otherwise.
    pub default: bool,
}

/// Something provided, optionally with a version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provide {
    /// What.
    pub atom: Atom,
    /// Its version; only on package and `cap:` atoms.
    pub version: Option<Version>,
}

impl std::fmt::Display for Provide {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.version {
            Some(v) => write!(f, "{} = {v}", self.atom),
            None => write!(f, "{}", self.atom),
        }
    }
}

impl std::str::FromStr for Provide {
    type Err = String;

    /// Reads `atom` or `atom = version`, in any spacing around the `=`.
    fn from_str(text: &str) -> Result<Self, String> {
        let (atom, version) = match text.split_once('=') {
            Some((a, ver)) => (a.trim(), Some(ver.trim())),
            None => (text, None),
        };
        let atom: Atom = atom.parse().map_err(|e: ordin_core::Error| e.to_string())?;
        let version = version
            .map(|v| v.parse::<Version>().map_err(|e| e.to_string()))
            .transpose()?;
        if version.is_some() && !matches!(atom, Atom::Package(_) | Atom::Cap(_)) {
            return Err("only package and cap: atoms can provide a version".into());
        }
        Ok(Self { atom, version })
    }
}

/// Declarations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Declares {
    /// Users.
    pub users: Vec<User>,
    /// Groups.
    pub groups: Vec<Group>,
    /// Units and presets.
    pub units: Vec<Unit>,
    /// Config defaults.
    pub config: Vec<Config>,
    /// Alternatives.
    pub alternatives: Vec<Alternative>,
    /// Triggers.
    pub triggers: Vec<Trigger>,
    /// Setuid or setgid files, on purpose.
    pub setuid: Vec<FilePath>,
    /// Boot files.
    pub boot: Option<Boot>,
}

/// A user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    /// Its name.
    pub name: Account,
    /// A system user.
    pub system: bool,
    /// Home directory.
    pub home: Option<FilePath>,
    /// Login shell.
    pub shell: Option<FilePath>,
    /// Extra groups.
    pub groups: Vec<Account>,
    /// GECOS text.
    pub comment: Option<String>,
}

/// A group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    /// Its name.
    pub name: Account,
    /// A system group.
    pub system: bool,
}

/// A unit and its preset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unit {
    /// The unit.
    pub name: UnitName,
    /// Its preset.
    pub preset: Preset,
    /// A setting condition, if any.
    pub condition: Option<Condition>,
}

/// A condition on a setting: `setting.<name>` or `setting.<name> = <value>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Condition {
    /// The setting.
    pub setting: Id,
    /// The value it must have; `None` means a `bool` setting is true.
    pub value: Option<String>,
}

impl std::fmt::Display for Condition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.value {
            Some(v) => write!(f, "setting.{} = {v}", self.setting),
            None => write!(f, "setting.{}", self.setting),
        }
    }
}

impl std::str::FromStr for Condition {
    type Err = String;

    /// Reads `setting.<name>` or `setting.<name> = <value>`, in any
    /// spacing around the `=`.
    fn from_str(text: &str) -> Result<Self, String> {
        let rest = text
            .strip_prefix("setting.")
            .ok_or("a condition is setting.<name> or setting.<name> = <value>")?;
        let (name, value) = match rest.split_once('=') {
            Some((n, val)) => (n.trim(), Some(val.trim().to_owned())),
            None => (rest, None),
        };
        let setting: Id = name.parse()?;
        if let Some(val) = &value {
            crate::text::printable_ascii(val, "a condition value")?;
            if val.is_empty() {
                return Err("a condition value can't be empty".into());
            }
        }
        Ok(Self { setting, value })
    }
}

/// A config default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Under `/usr/share/ordin/defaults/<name>/`.
    pub default: FilePath,
    /// Under `/etc`.
    pub target: FilePath,
    /// How the two meet.
    pub merge: Merge,
}

/// An alternative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alternative {
    /// The link group.
    pub name: String,
    /// The generic link.
    pub link: FilePath,
    /// This package's file.
    pub target: FilePath,
    /// Higher wins.
    pub priority: i64,
    /// Links that follow the group.
    pub followers: Vec<Follower>,
}

/// A follower link of an alternative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Follower {
    /// The generic link.
    pub link: FilePath,
    /// This package's file.
    pub target: FilePath,
}

/// A trigger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trigger {
    /// Path prefixes that fire it.
    pub paths: Vec<FilePath>,
    /// The built-in action.
    pub action: String,
}

/// Boot files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Boot {
    /// A kernel image in the tree.
    pub kernel: Option<FilePath>,
    /// A unified kernel image.
    pub uki: bool,
    /// Initrd extensions in the tree.
    pub initrd_extensions: Vec<FilePath>,
}

/// State declarations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    /// The state version expected.
    pub version: u64,
    /// What this release does to state.
    pub migration: Migration,
    /// Declared paths.
    pub paths: Vec<StatePath>,
    /// Files created if missing.
    pub files: Vec<StateFile>,
    /// Files copied once if missing.
    pub seeds: Vec<Seed>,
    /// Removed on upgrade.
    pub obsolete: Vec<FilePath>,
    /// Migrations by state version.
    pub migrations: Vec<StateMigration>,
}

/// A declared state path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatePath {
    /// Under `/var` or `/run`.
    pub path: FilePath,
    /// Its class.
    pub class: Class,
    /// Owning user.
    pub owner: Account,
    /// Owning group.
    pub group: Account,
    /// Its mode.
    pub mode: Mode,
    /// When it is emptied.
    pub flush: Flush,
    /// Fix ownership recursively.
    pub recurse: bool,
    /// What happens on remove, if not the class's default.
    pub on_remove: Option<OnRemove>,
}

/// A file created if missing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateFile {
    /// The file.
    pub path: FilePath,
    /// Owning user.
    pub owner: Account,
    /// Owning group.
    pub group: Account,
    /// Its mode.
    pub mode: Mode,
}

/// A file copied once if missing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seed {
    /// Where it goes.
    pub path: FilePath,
    /// The file in the package's tree.
    pub from: FilePath,
}

/// A migration from one state version to the next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateMigration {
    /// The state version before.
    pub from: u64,
    /// The state version after: `from` + 1.
    pub to: u64,
    /// What it does.
    pub action: MigrationAction,
}

/// What a migration does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrationAction {
    /// Declarative operations, reversible by construction.
    Ops(Vec<MigrationOp>),
    /// A program, sandboxed to the declared paths.
    Run {
        /// The program.
        run: FilePath,
        /// The program that undoes it, if it is reversible.
        reverse: Option<FilePath>,
    },
}

/// A declarative migration operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrationOp {
    /// Renames a path.
    Rename {
        /// The old path.
        path: FilePath,
        /// The new path.
        to: FilePath,
    },
    /// Moves a path.
    Move {
        /// The old path.
        path: FilePath,
        /// The new path.
        to: FilePath,
    },
    /// Creates a symbolic link.
    Link {
        /// The link.
        path: FilePath,
        /// What it points at, as written.
        to: String,
    },
    /// Removes a path.
    Remove {
        /// The path.
        path: FilePath,
    },
    /// Changes ownership.
    Chown {
        /// The path.
        path: FilePath,
        /// The new owner.
        owner: Option<Account>,
        /// The new group.
        group: Option<Account>,
    },
}

/// A setting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Setting {
    /// Its name.
    pub name: Id,
    /// Its type.
    pub kind: SettingType,
    /// Its default.
    pub default: Option<SettingValue>,
    /// No default; the plan fails until set.
    pub required: bool,
    /// One line.
    pub description: Option<String>,
    /// For `int`.
    pub min: Option<i64>,
    /// For `int`.
    pub max: Option<i64>,
    /// For `string`: a Rust `regex` pattern, anchored.
    pub pattern: Option<String>,
    /// For `choice` and `multichoice`.
    pub choices: Vec<String>,
    /// Former names by system: `{"debconf": "postfix/mailname"}`.
    pub aliases: BTreeMap<String, String>,
}

/// A setting's value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettingValue {
    /// For `bool`.
    Bool(bool),
    /// For `int` and `port`.
    Int(i64),
    /// For `string`, `choice` and `path`.
    Str(String),
    /// For `multichoice` (a set) and `list`.
    List(Vec<String>),
}

/// A sandboxed program run in a phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    /// The program and its arguments.
    pub exec: Vec<String>,
    /// Seconds.
    pub timeout: u64,
    /// The only paths it may write.
    pub writes: Vec<FilePath>,
    /// Whether it may use the network.
    pub network: bool,
    /// Other programs it may run.
    pub execs: Vec<FilePath>,
    /// Carried over from another packaging format.
    pub legacy: bool,
}

/// An installed test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Test {
    /// Its name.
    pub name: Id,
    /// The program and its arguments.
    pub exec: Vec<String>,
    /// Seconds.
    pub timeout: u64,
}

/// Security policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Security {
    /// SELinux policy.
    pub selinux: Option<SeLinux>,
    /// AppArmor policy.
    pub apparmor: Option<AppArmor>,
}

/// SELinux policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeLinux {
    /// Policy modules.
    pub modules: Vec<FilePath>,
    /// Booleans.
    pub booleans: BTreeMap<String, bool>,
    /// Port labels.
    pub ports: Vec<Port>,
    /// File contexts.
    pub fcontexts: Vec<Fcontext>,
}

/// An SELinux port label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Port {
    /// The SELinux type.
    pub kind: String,
    /// The protocol.
    pub proto: Proto,
    /// The port.
    pub port: u16,
}

/// An SELinux file context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fcontext {
    /// The file-context regular expression.
    pub pattern: String,
    /// The SELinux type.
    pub kind: String,
    /// The file type.
    pub file_type: FileType,
}

/// AppArmor policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppArmor {
    /// Profiles.
    pub profiles: Vec<FilePath>,
    /// Tunables.
    pub tunables: BTreeMap<String, String>,
}

/// A delegated payload (proposed; settled in milestone 8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delegated {
    /// Who may update it: `kind` and `exec`.
    pub authority: (String, FilePath),
    /// The delegated paths, relative to the delegated area.
    pub paths: Vec<String>,
    /// The facet holding the initial payload.
    pub initial: Facet,
    /// How new versions are identified.
    pub identify: Vec<Identify>,
    /// The minimum evidence.
    pub require: Evidence,
    /// What happens below it.
    pub on_insufficient: OnInsufficient,
    /// What an upgrade does.
    pub payload_on_upgrade: PayloadOnUpgrade,
}

/// An identify method: its name and its string fields, as written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identify {
    /// `signature`, `release-index`, `elf-note`, `go-buildinfo`,
    /// `cargo-auditable`, `string` or `exec`.
    pub method: String,
    /// The method's fields.
    pub fields: BTreeMap<String, Value>,
}

/// Support dates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Support {
    /// Active support ends.
    pub active_until: Date,
    /// Security fixes end.
    pub security_until: Date,
    /// What to move to.
    pub successor: Option<PackageName>,
}

/// A path whose files `ordin pack` and `ordin lint` don't infer
/// requirements, provides or the architecture from: data that only looks
/// like programs, such as test files built for other machines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferenceSkip {
    /// The path, with everything below it; under `/usr`.
    pub path: FilePath,
    /// Why: one line, 1 to [`SKIP_REASON_MAX`] characters.
    pub reason: String,
}

/// The longest reason an inference skip may give, in characters.
pub const SKIP_REASON_MAX: usize = 200;

/// A notice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    /// Its name.
    pub id: Id,
    /// Its text.
    pub text: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enums_list_and_name_their_values() {
        assert_eq!(Kind::allowed(), "base, update or system-base");
        assert_eq!(Preset::allowed(), "enable or disable");
        assert_eq!(Kind::from_text("system-base"), Some(Kind::SystemBase));
        assert_eq!(Kind::from_text("kmod"), None);
        for p in Phase::ALL {
            assert_eq!(Phase::from_text(p.as_str()), Some(*p));
        }
        assert_eq!(Phase::ALL.len(), 9);
        assert_eq!(Class::ALL.len(), 6);
        assert_eq!(SettingType::ALL.len(), 8);
        assert_eq!(FileType::ALL.len(), 8);
        assert_eq!(Evidence::ALL.len(), 5);
    }

    str_enum!(
        /// An enum with one value, as `allowed` must handle.
        Only {
            /// The one value.
            One = "one",
        }
    );

    #[test]
    fn a_single_value_is_listed_alone() {
        assert_eq!(Only::allowed(), "one");
        assert_eq!(Only::from_text("one"), Some(Only::One));
        assert_eq!(Only::One.to_string(), "one");
    }

    #[test]
    fn provides_show_with_their_version() {
        let p = Provide {
            atom: "cap:go".parse().unwrap(),
            version: Some("1.23".parse().unwrap()),
        };
        assert_eq!(p.to_string(), "cap:go = 1.23");
        let bare = Provide {
            atom: "cap:mta".parse().unwrap(),
            version: None,
        };
        assert_eq!(bare.to_string(), "cap:mta");
    }
}
