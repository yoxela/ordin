// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The rules over the package graph: layers, licenses and denylists.

use std::collections::{BTreeMap, VecDeque};

use crate::model::{Layer, Model, Package};
use crate::{Rule, Violation};

/// The license of the format and library crates.
pub const PERMISSIVE: &str = "MIT OR Apache-2.0";
/// The license of everything else.
pub const GPL: &str = "GPL-3.0-or-later";
/// Crates above layer 0 that are permissive anyway.
pub const PERMISSIVE_ABOVE_LAYER_0: &[&str] = &["ordin-archive", "ordin-sign", "ordin-api"];
/// Crates a layer-0 crate may not depend on, directly or not, because they do I/O.
pub const LAYER_0_IO_DENYLIST: &[&str] =
    &["tokio", "reqwest", "hyper", "mio", "rusqlite", "async-std"];
/// The privileged daemon.
pub const ORDIND: &str = "ordind";
/// Crates `ordind` may not depend on, directly or not: archive, decompression,
/// ELF and solver code run in `ordin-helper` instead.
pub const ORDIND_DENYLIST: &[&str] = &[
    "tar",
    "zstd",
    "flate2",
    "xz2",
    "goblin",
    "object",
    "resolvo",
    "pubgrub",
    "ordin-archive",
    "ordin-solve",
    "ordin-pack",
    "ordin-import",
];

/// The license a workspace crate must carry.
#[must_use]
pub fn expected_license(name: &str, layer: Layer) -> &'static str {
    match layer {
        Layer::Level(0) => PERMISSIVE,
        Layer::Level(_) if PERMISSIVE_ABOVE_LAYER_0.contains(&name) => PERMISSIVE,
        _ => GPL,
    }
}

/// Checks every workspace member against the graph rules.
#[must_use]
pub fn check(model: &Model) -> Vec<Violation> {
    let mut out = Vec::new();
    for (key, package) in model.members() {
        let layer = match &package.layer {
            None => {
                out.push(violation(
                    package,
                    Rule::Layer,
                    "has no [package.metadata.ordin] layer".into(),
                ));
                continue;
            }
            Some(Err(e)) => {
                out.push(violation(
                    package,
                    Rule::Layer,
                    format!("has an invalid layer: {e}"),
                ));
                continue;
            }
            Some(Ok(layer)) => *layer,
        };

        let expected = expected_license(&package.name, layer);
        if package.license.as_deref() != Some(expected) {
            out.push(violation(
                package,
                Rule::License,
                format!(
                    "is licensed {}, but its layer requires {expected}",
                    package.license.as_deref().unwrap_or("(none)")
                ),
            ));
        }

        check_direct(model, package, layer, &mut out);
        check_shipped(model, key, package, layer, &mut out);
    }
    out
}

/// Direct workspace dependencies of any kind: no upward edges, and nothing
/// may depend on a tool.
fn check_direct(model: &Model, package: &Package, layer: Layer, out: &mut Vec<Violation>) {
    for dep_key in package.deps.keys() {
        let Some(dep) = model.packages.get(dep_key).filter(|d| d.workspace_member) else {
            continue;
        };
        match (layer, &dep.layer) {
            (_, Some(Ok(Layer::Tool))) => out.push(violation(
                package,
                Rule::ToolDependency,
                format!("depends on the tool crate {}", dep.name),
            )),
            (Layer::Level(own), Some(Ok(Layer::Level(theirs)))) if *theirs > own => {
                out.push(violation(
                    package,
                    Rule::UpwardDependency,
                    format!("(layer {own}) depends on {} (layer {theirs})", dep.name),
                ))
            }
            _ => {}
        }
    }
}

/// Everything the crate ships, directly or not (normal and build edges).
fn check_shipped(
    model: &Model,
    key: &str,
    package: &Package,
    layer: Layer,
    out: &mut Vec<Violation>,
) {
    let paths = shipped_paths(model, key);
    let permissive = package.license.as_deref() == Some(PERMISSIVE);
    for (dep_key, path) in &paths {
        let Some(dep) = model.packages.get(dep_key) else {
            continue;
        };
        if permissive && dep.workspace_member && dep.license.as_deref() != Some(PERMISSIVE) {
            out.push(violation(
                package,
                Rule::PermissiveDependsOnGpl,
                format!(
                    "is permissive but depends on {} ({}): {path}",
                    dep.name,
                    dep.license.as_deref().unwrap_or("no license")
                ),
            ));
        }
        if layer == Layer::Level(0) && LAYER_0_IO_DENYLIST.contains(&dep.name.as_str()) {
            out.push(violation(
                package,
                Rule::Layer0Io,
                format!(
                    "is in layer 0 but depends on the I/O crate {}: {path}",
                    dep.name
                ),
            ));
        }
        if package.name == ORDIND && ORDIND_DENYLIST.contains(&dep.name.as_str()) {
            out.push(violation(
                package,
                Rule::OrdindDenylist,
                format!("must not link {}: {path}", dep.name),
            ));
        }
    }
}

/// Every package reachable from `start` over shipped edges, with the shortest
/// path to it written as `a -> b -> c`.
fn shipped_paths(model: &Model, start: &str) -> BTreeMap<String, String> {
    let name = |k: &str| {
        model
            .packages
            .get(k)
            .map_or_else(|| k.to_owned(), |p| p.name.clone())
    };
    let mut paths: BTreeMap<String, String> = BTreeMap::new();
    let mut queue = VecDeque::from([(start.to_owned(), name(start))]);
    while let Some((key, path)) = queue.pop_front() {
        let Some(package) = model.packages.get(&key) else {
            continue;
        };
        for (dep_key, kinds) in &package.deps {
            if !kinds.shipped() || dep_key == start || paths.contains_key(dep_key) {
                continue;
            }
            let dep_path = format!("{path} -> {}", name(dep_key));
            paths.insert(dep_key.clone(), dep_path.clone());
            queue.push_back((dep_key.clone(), dep_path));
        }
    }
    paths
}

fn violation(package: &Package, rule: Rule, message: String) -> Violation {
    Violation {
        crate_name: package.name.clone(),
        rule,
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DepKinds;
    use std::path::PathBuf;

    const NORMAL: DepKinds = DepKinds {
        normal: true,
        build: false,
        dev: false,
    };
    const BUILD: DepKinds = DepKinds {
        normal: false,
        build: true,
        dev: false,
    };
    const DEV: DepKinds = DepKinds {
        normal: false,
        build: false,
        dev: true,
    };

    /// Builds synthetic workspaces. Each test adds an allowed case beside the
    /// forbidden one, so a guard that never fires can't pass.
    #[derive(Default)]
    struct Fixture(Model);

    impl Fixture {
        fn member(
            mut self,
            name: &str,
            layer: Option<Result<Layer, String>>,
            license: Option<&str>,
        ) -> Self {
            self.0.packages.insert(
                name.to_owned(),
                Package {
                    name: name.to_owned(),
                    workspace_member: true,
                    layer,
                    license: license.map(str::to_owned),
                    manifest_dir: PathBuf::new(),
                    deps: BTreeMap::new(),
                },
            );
            self
        }

        /// A well-formed member whose license matches its layer.
        fn krate(self, name: &str, layer: Layer) -> Self {
            let license = expected_license(name, layer);
            self.member(name, Some(Ok(layer)), Some(license))
        }

        fn third_party(mut self, name: &str) -> Self {
            self.0.packages.insert(
                name.to_owned(),
                Package {
                    name: name.to_owned(),
                    workspace_member: false,
                    layer: None,
                    license: Some("MIT".to_owned()),
                    manifest_dir: PathBuf::new(),
                    deps: BTreeMap::new(),
                },
            );
            self
        }

        fn dep(mut self, from: &str, to: &str, kinds: DepKinds) -> Self {
            if let Some(p) = self.0.packages.get_mut(from) {
                p.deps.insert(to.to_owned(), kinds);
            }
            self
        }

        fn violations(&self) -> Vec<(String, Rule, String)> {
            check(&self.0)
                .into_iter()
                .map(|v| (v.crate_name, v.rule, v.message))
                .collect()
        }

        fn rules_for(&self, name: &str) -> Vec<Rule> {
            self.violations()
                .into_iter()
                .filter(|v| v.0 == name)
                .map(|v| v.1)
                .collect()
        }
    }

    #[test]
    fn a_clean_workspace_has_no_violations() {
        let f = Fixture::default()
            .krate("ordin-core", Layer::Level(0))
            .krate("ordin-archive", Layer::Level(1))
            .krate("ordin-store", Layer::Level(1))
            .krate("ordin-pack", Layer::Level(2))
            .krate("ordin", Layer::Level(3))
            .krate("xtask", Layer::Tool)
            .third_party("serde")
            .dep("ordin-archive", "ordin-core", NORMAL)
            .dep("ordin-store", "ordin-core", NORMAL)
            .dep("ordin-pack", "ordin-store", NORMAL)
            .dep("ordin-pack", "ordin-archive", NORMAL)
            .dep("ordin", "ordin-pack", NORMAL)
            .dep("ordin-core", "serde", NORMAL)
            .dep("xtask", "ordin", NORMAL);
        assert_eq!(f.violations(), vec![]);
    }

    #[test]
    fn missing_or_invalid_layers_are_reported() {
        let f = Fixture::default()
            .member("no-layer", None, Some(GPL))
            .member("bad-layer", Some(Err("found 7".into())), Some(GPL))
            .krate("good", Layer::Level(2));
        assert_eq!(f.rules_for("no-layer"), vec![Rule::Layer]);
        assert_eq!(f.rules_for("bad-layer"), vec![Rule::Layer]);
        assert_eq!(f.rules_for("good"), vec![]);
        assert!(f.violations().iter().any(|v| v.2.contains("found 7")));
    }

    #[test]
    fn expected_licenses_follow_the_layers() {
        assert_eq!(
            expected_license("ordin-version", Layer::Level(0)),
            PERMISSIVE
        );
        assert_eq!(
            expected_license("ordin-archive", Layer::Level(1)),
            PERMISSIVE
        );
        assert_eq!(expected_license("ordin-sign", Layer::Level(1)), PERMISSIVE);
        assert_eq!(expected_license("ordin-api", Layer::Level(2)), PERMISSIVE);
        assert_eq!(expected_license("ordin-store", Layer::Level(1)), GPL);
        assert_eq!(expected_license("ordin-pack", Layer::Level(2)), GPL);
        assert_eq!(expected_license("ordin", Layer::Level(3)), GPL);
        assert_eq!(expected_license("xtask", Layer::Tool), GPL);
        // The permissive exceptions only apply to their own names.
        assert_eq!(expected_license("ordin-api", Layer::Tool), GPL);
    }

    #[test]
    fn wrong_or_missing_licenses_are_reported() {
        let f = Fixture::default()
            .member("ordin-core", Some(Ok(Layer::Level(0))), Some(GPL))
            .member("ordin-pack", Some(Ok(Layer::Level(2))), Some(PERMISSIVE))
            .member("ordin-api", Some(Ok(Layer::Level(2))), Some(PERMISSIVE))
            .member("ordin", Some(Ok(Layer::Level(3))), None)
            .member("ordin-version", Some(Ok(Layer::Level(0))), Some(PERMISSIVE));
        assert_eq!(f.rules_for("ordin-core"), vec![Rule::License]);
        assert_eq!(f.rules_for("ordin-pack"), vec![Rule::License]);
        assert_eq!(f.rules_for("ordin"), vec![Rule::License]);
        assert_eq!(f.rules_for("ordin-api"), vec![]);
        assert_eq!(f.rules_for("ordin-version"), vec![]);
    }

    #[test]
    fn upward_dependencies_of_any_kind_are_reported() {
        let f = Fixture::default()
            .krate("low", Layer::Level(1))
            .krate("low-dev", Layer::Level(1))
            .krate("same", Layer::Level(1))
            .krate("high", Layer::Level(2))
            .dep("low", "high", NORMAL)
            .dep("low-dev", "high", DEV)
            .dep("same", "low", NORMAL)
            .dep("high", "low", NORMAL);
        assert_eq!(f.rules_for("low"), vec![Rule::UpwardDependency]);
        assert_eq!(f.rules_for("low-dev"), vec![Rule::UpwardDependency]);
        assert_eq!(f.rules_for("same"), vec![]);
        assert_eq!(f.rules_for("high"), vec![]);
        assert!(
            f.violations()
                .iter()
                .any(|v| v.2 == "(layer 1) depends on high (layer 2)")
        );
    }

    #[test]
    fn nothing_may_depend_on_a_tool_but_a_tool_may_depend_on_anything() {
        let f = Fixture::default()
            .krate("ordin", Layer::Level(3))
            .krate("xtask", Layer::Tool)
            .krate("other-tool", Layer::Tool)
            .dep("ordin", "xtask", DEV)
            .dep("other-tool", "xtask", NORMAL)
            .dep("xtask", "ordin", NORMAL);
        assert_eq!(f.rules_for("ordin"), vec![Rule::ToolDependency]);
        assert_eq!(f.rules_for("other-tool"), vec![Rule::ToolDependency]);
        assert_eq!(f.rules_for("xtask"), vec![]);
    }

    #[test]
    fn dependencies_on_crates_without_a_valid_layer_are_left_to_their_own_report() {
        let f = Fixture::default()
            .krate("ordin-core", Layer::Level(0))
            .member("broken", None, Some(GPL))
            .dep("ordin-core", "broken", DEV);
        assert_eq!(f.rules_for("ordin-core"), vec![]);
        assert_eq!(f.rules_for("broken"), vec![Rule::Layer]);
    }

    #[test]
    fn permissive_crates_may_not_reach_gpl_crates() {
        let f = Fixture::default()
            .krate("ordin-core", Layer::Level(0))
            .krate("ordin-manifest", Layer::Level(0))
            .krate("ordin-archive", Layer::Level(1))
            .krate("ordin-sign", Layer::Level(1))
            .krate("ordin-store", Layer::Level(1))
            .krate("ordin-pack", Layer::Level(2))
            // Forbidden: permissive -> permissive -> GPL, over a build edge.
            .dep("ordin-archive", "ordin-manifest", NORMAL)
            .dep("ordin-manifest", "ordin-store", BUILD)
            // Allowed: a dev edge is not shipped.
            .dep("ordin-sign", "ordin-store", DEV)
            // Allowed: GPL may depend on GPL and on permissive.
            .dep("ordin-pack", "ordin-store", NORMAL)
            .dep("ordin-pack", "ordin-core", NORMAL);
        let archive = f.rules_for("ordin-archive");
        assert_eq!(archive, vec![Rule::PermissiveDependsOnGpl]);
        assert!(f.violations().iter().any(|v| {
            v.2.contains("ordin-archive -> ordin-manifest -> ordin-store")
        }));
        assert!(
            f.rules_for("ordin-manifest")
                .contains(&Rule::PermissiveDependsOnGpl)
        );
        assert_eq!(f.rules_for("ordin-sign"), vec![]);
        assert_eq!(f.rules_for("ordin-pack"), vec![]);
    }

    #[test]
    fn layer_0_may_not_reach_io_crates() {
        let f = Fixture::default()
            .krate("ordin-version", Layer::Level(0))
            .krate("ordin-core", Layer::Level(0))
            .krate("ordin-plan", Layer::Level(0))
            .krate("ordin-fetch", Layer::Level(1))
            .third_party("helper-lib")
            .third_party("tokio")
            .third_party("reqwest")
            // Forbidden: transitively through a third-party crate.
            .dep("ordin-version", "helper-lib", NORMAL)
            .dep("helper-lib", "tokio", NORMAL)
            // Allowed: a dev edge in layer 0.
            .dep("ordin-core", "tokio", DEV)
            // Allowed: layer 1 may do I/O.
            .dep("ordin-fetch", "reqwest", NORMAL)
            .dep("ordin-plan", "helper-lib", DEV);
        assert_eq!(f.rules_for("ordin-version"), vec![Rule::Layer0Io]);
        assert!(
            f.violations()
                .iter()
                .any(|v| v.2.contains("ordin-version -> helper-lib -> tokio"))
        );
        assert_eq!(f.rules_for("ordin-core"), vec![]);
        assert_eq!(f.rules_for("ordin-fetch"), vec![]);
        assert_eq!(f.rules_for("ordin-plan"), vec![]);
    }

    #[test]
    fn ordind_may_not_link_parsers_but_the_helper_may() {
        let f = Fixture::default()
            .krate("ordind", Layer::Level(3))
            .krate("ordin-helper", Layer::Level(3))
            .krate("ordin-compose", Layer::Level(2))
            .krate("ordin-archive", Layer::Level(1))
            .third_party("zstd")
            .third_party("serde")
            .dep("ordind", "ordin-compose", NORMAL)
            .dep("ordin-compose", "zstd", NORMAL)
            .dep("ordind", "ordin-archive", NORMAL)
            .dep("ordind", "serde", NORMAL)
            .dep("ordin-helper", "zstd", NORMAL)
            .dep("ordin-helper", "ordin-archive", NORMAL);
        let ordind = f.rules_for("ordind");
        assert_eq!(ordind, vec![Rule::OrdindDenylist, Rule::OrdindDenylist]);
        assert!(
            f.violations()
                .iter()
                .any(|v| v.2.contains("ordind -> ordin-compose -> zstd"))
        );
        assert_eq!(f.rules_for("ordin-helper"), vec![]);
    }

    #[test]
    fn ordind_dev_dependencies_are_allowed() {
        let f = Fixture::default()
            .krate("ordind", Layer::Level(3))
            .third_party("tar")
            .dep("ordind", "tar", DEV);
        assert_eq!(f.rules_for("ordind"), vec![]);
    }

    #[test]
    fn cycles_and_dangling_edges_terminate() {
        let f = Fixture::default()
            .krate("ordin-core", Layer::Level(0))
            .third_party("a")
            .third_party("b")
            .dep("ordin-core", "a", NORMAL)
            .dep("a", "b", NORMAL)
            .dep("b", "a", NORMAL)
            .dep("b", "ordin-core", NORMAL)
            .dep("a", "missing-package", NORMAL);
        assert_eq!(f.rules_for("ordin-core"), vec![]);
    }

    #[test]
    fn shortest_paths_are_reported() {
        let f = Fixture::default()
            .krate("ordin-core", Layer::Level(0))
            .third_party("a")
            .third_party("b")
            .third_party("mio")
            .dep("ordin-core", "a", NORMAL)
            .dep("a", "b", NORMAL)
            .dep("b", "mio", NORMAL)
            .dep("ordin-core", "mio", BUILD);
        let messages: Vec<String> = f.violations().into_iter().map(|v| v.2).collect();
        assert_eq!(
            messages,
            vec!["is in layer 0 but depends on the I/O crate mio: ordin-core -> mio".to_owned()]
        );
    }
}
