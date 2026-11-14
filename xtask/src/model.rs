// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! A small, testable model of the workspace's package graph, built from
//! `cargo metadata`.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// The layer a workspace crate declares in `[package.metadata.ordin] layer`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    /// One of the four architecture layers, 0 to 3.
    Level(u8),
    /// Project tooling such as `xtask`, outside the four layers.
    Tool,
}

impl Layer {
    /// Parses the `layer` value: an integer from 0 to 3, or the string `"tool"`.
    ///
    /// # Errors
    ///
    /// Returns a description of the value when it is anything else.
    pub fn parse(value: &serde_json::Value) -> Result<Self, String> {
        match value {
            serde_json::Value::Number(n) => match n.as_u64().and_then(|v| u8::try_from(v).ok()) {
                Some(level @ 0..=3) => Ok(Self::Level(level)),
                _ => Err(format!("expected 0, 1, 2, 3 or \"tool\", found {n}")),
            },
            serde_json::Value::String(s) if s == "tool" => Ok(Self::Tool),
            other => Err(format!("expected 0, 1, 2, 3 or \"tool\", found {other}")),
        }
    }
}

/// Which kinds of dependency edge connect two packages.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DepKinds {
    /// A normal (`[dependencies]`) edge.
    pub normal: bool,
    /// A build (`[build-dependencies]`) edge.
    pub build: bool,
    /// A dev (`[dev-dependencies]`) edge.
    pub dev: bool,
}

impl DepKinds {
    /// Whether the edge ends up in what a crate builds and ships: normal or
    /// build. Dev dependencies only serve the crate's own tests.
    #[must_use]
    pub fn shipped(self) -> bool {
        self.normal || self.build
    }
}

/// One package in the graph.
#[derive(Clone, Debug)]
pub struct Package {
    /// The package name.
    pub name: String,
    /// Whether the package is a member of this workspace.
    pub workspace_member: bool,
    /// The declared layer: `None` when missing, `Some(Err(_))` when invalid.
    pub layer: Option<Result<Layer, String>>,
    /// The `license` field, if any.
    pub license: Option<String>,
    /// The directory holding the package's `Cargo.toml`.
    pub manifest_dir: PathBuf,
    /// Direct dependencies, by package key, with the kinds of each edge.
    pub deps: BTreeMap<String, DepKinds>,
}

/// The package graph, keyed by cargo's unique package ID.
#[derive(Clone, Debug, Default)]
pub struct Model {
    /// Every package in the resolved graph.
    pub packages: BTreeMap<String, Package>,
}

impl Model {
    /// Builds the model from `cargo metadata` output.
    #[must_use]
    pub fn from_metadata(meta: &cargo_metadata::Metadata) -> Self {
        let mut packages = BTreeMap::new();
        for p in &meta.packages {
            let layer = p
                .metadata
                .get("ordin")
                .and_then(|o| o.get("layer"))
                .map(Layer::parse);
            let manifest_dir = p
                .manifest_path
                .parent()
                .map(|d| d.as_std_path().to_path_buf())
                .unwrap_or_default();
            packages.insert(
                p.id.repr.clone(),
                Package {
                    name: p.name.to_string(),
                    workspace_member: meta.workspace_members.contains(&p.id),
                    layer,
                    license: p.license.clone(),
                    manifest_dir,
                    deps: BTreeMap::new(),
                },
            );
        }
        if let Some(resolve) = &meta.resolve {
            for node in &resolve.nodes {
                let mut deps = BTreeMap::new();
                for dep in &node.deps {
                    let mut kinds = DepKinds::default();
                    for info in &dep.dep_kinds {
                        match info.kind {
                            cargo_metadata::DependencyKind::Development => kinds.dev = true,
                            cargo_metadata::DependencyKind::Build => kinds.build = true,
                            // Normal, and anything a newer cargo adds, counts as
                            // shipped: the stricter reading.
                            _ => kinds.normal = true,
                        }
                    }
                    deps.insert(dep.pkg.repr.clone(), kinds);
                }
                if let Some(package) = packages.get_mut(&node.id.repr) {
                    package.deps = deps;
                }
            }
        }
        Self { packages }
    }

    /// The workspace members, sorted by name.
    #[must_use]
    pub fn members(&self) -> Vec<(&String, &Package)> {
        let mut members: Vec<_> = self
            .packages
            .iter()
            .filter(|(_, p)| p.workspace_member)
            .collect();
        members.sort_by(|a, b| a.1.name.cmp(&b.1.name));
        members
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_valid_layers() {
        assert_eq!(Layer::parse(&json!(0)), Ok(Layer::Level(0)));
        assert_eq!(Layer::parse(&json!(3)), Ok(Layer::Level(3)));
        assert_eq!(Layer::parse(&json!("tool")), Ok(Layer::Tool));
    }

    #[test]
    fn rejects_invalid_layers() {
        assert!(Layer::parse(&json!(4)).is_err());
        assert!(Layer::parse(&json!(-1)).is_err());
        assert!(Layer::parse(&json!(1.5)).is_err());
        assert!(Layer::parse(&json!(300)).is_err());
        assert!(Layer::parse(&json!("engine")).is_err());
        assert!(Layer::parse(&json!(null)).is_err());
    }

    #[test]
    fn shipped_covers_normal_and_build_only() {
        let normal = DepKinds {
            normal: true,
            ..DepKinds::default()
        };
        let build = DepKinds {
            build: true,
            ..DepKinds::default()
        };
        let dev = DepKinds {
            dev: true,
            ..DepKinds::default()
        };
        assert!(normal.shipped());
        assert!(build.shipped());
        assert!(!dev.shipped());
    }

    #[test]
    fn builds_from_real_metadata() {
        let meta = cargo_metadata::MetadataCommand::new()
            .manifest_path(concat!(env!("CARGO_MANIFEST_DIR"), "/../Cargo.toml"))
            .exec()
            .expect("cargo metadata runs");
        let model = Model::from_metadata(&meta);
        let names: Vec<&str> = model
            .members()
            .iter()
            .map(|(_, p)| p.name.as_str())
            .collect();
        assert!(names.contains(&"ordin-core"));
        assert!(names.contains(&"xtask"));
        let xtask = model
            .members()
            .into_iter()
            .find(|(_, p)| p.name == "xtask")
            .map(|(_, p)| p.clone());
        let xtask = xtask.expect("xtask is a member");
        assert_eq!(xtask.layer, Some(Ok(Layer::Tool)));
        assert!(xtask.manifest_dir.ends_with("xtask"));
        // xtask depends on cargo_metadata, so the resolve graph was read.
        let has_cargo_metadata = xtask.deps.keys().any(|k| {
            model
                .packages
                .get(k)
                .is_some_and(|p| p.name == "cargo_metadata")
        });
        assert!(has_cargo_metadata);
        // Third-party packages are in the graph but are not members.
        assert!(
            model
                .packages
                .values()
                .any(|p| p.name == "serde_json" && !p.workspace_member)
        );
    }
}
