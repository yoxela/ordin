// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The `allowed_signers` file (OpenSSH's format, see `ssh-keygen(1)`) and
//! the policy it must follow.
//!
//! Every key is limited to one namespace, so a key that signs tags can't
//! sign release files and the other way round. Principals are plain names,
//! never patterns, and no other options are allowed.

use super::{Error, FILE_NAMESPACE, FILE_PRINCIPAL, GIT_NAMESPACE};

/// One key in the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signer {
    /// Who the key belongs to.
    pub principal: String,
    /// The one namespace the key may sign in.
    pub namespace: String,
    /// The key type and base64 key, separated by a space.
    pub key: String,
}

/// Parses an `allowed_signers` file that follows Ordin's policy. Blank
/// lines and `#` comments are skipped.
///
/// # Errors
///
/// Returns an error naming the first line that breaks the policy.
pub fn parse(text: &str) -> Result<Vec<Signer>, Error> {
    let mut signers = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let bad = |why: &str| Error::parse("allowed_signers", format!("line {}: {why}", n + 1));
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [principal, options, key_type, key, ..] = fields.as_slice() else {
            return Err(bad(
                "expected `<principal> namespaces=\"<namespace>\" <key-type> <key>`",
            ));
        };
        let plain = principal
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
        if principal.is_empty() || !plain {
            return Err(bad(
                "the principal must be one plain name, not a list or pattern",
            ));
        }
        let namespace = options
            .strip_prefix("namespaces=\"")
            .and_then(|rest| rest.strip_suffix('"'))
            .filter(|ns| {
                !ns.is_empty()
                    && ns
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
            })
            .ok_or_else(|| bad("the only option must be namespaces=\"<one namespace>\""))?;
        if !key_type.starts_with("ssh-")
            && !key_type.starts_with("ecdsa-")
            && !key_type.starts_with("sk-")
        {
            return Err(bad("unknown key type"));
        }
        signers.push(Signer {
            principal: (*principal).to_owned(),
            namespace: namespace.to_owned(),
            key: format!("{key_type} {key}"),
        });
    }
    Ok(signers)
}

/// Checks that the signers allow at least one tag signer and exactly one
/// release-file signer, `ordin-release`, and that no key is listed twice.
///
/// # Errors
///
/// Returns what is missing or repeated.
pub fn check_policy(signers: &[Signer]) -> Result<(), Error> {
    if !signers.iter().any(|s| s.namespace == GIT_NAMESPACE) {
        return Err(Error::check(format!(
            "allowed_signers has no key for the `{GIT_NAMESPACE}` namespace (tags)"
        )));
    }
    let file_signers: Vec<&Signer> = signers
        .iter()
        .filter(|s| s.namespace == FILE_NAMESPACE)
        .collect();
    if file_signers.len() != 1 || file_signers[0].principal != FILE_PRINCIPAL {
        return Err(Error::check(format!(
            "allowed_signers must have exactly one `{FILE_NAMESPACE}` key, for the principal `{FILE_PRINCIPAL}`"
        )));
    }
    if let Some(other) = signers
        .iter()
        .find(|s| s.namespace != GIT_NAMESPACE && s.namespace != FILE_NAMESPACE)
    {
        return Err(Error::check(format!(
            "allowed_signers has a key for the unknown namespace `{}`",
            other.namespace
        )));
    }
    let mut keys: Vec<&str> = signers.iter().map(|s| s.key.as_str()).collect();
    keys.sort_unstable();
    let before = keys.len();
    keys.dedup();
    if keys.len() != before {
        return Err(Error::check(
            "allowed_signers lists the same key twice; each key gets one namespace",
        ));
    }
    Ok(())
}

/// Parses `text` and checks it against the policy.
///
/// # Errors
///
/// Returns the first problem found.
pub fn load(text: &str) -> Result<Vec<Signer>, Error> {
    let signers = parse(text)?;
    check_policy(&signers)?;
    Ok(signers)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "# Ordin's signing keys\n\n\
        barraterre namespaces=\"git\" ssh-ed25519 AAAAgit tags\n\
        ordin-release namespaces=\"ordin-release\" ssh-ed25519 AAAArel release files\n";

    #[test]
    fn a_good_file_parses() {
        assert_eq!(
            load(GOOD).unwrap(),
            vec![
                Signer {
                    principal: "barraterre".into(),
                    namespace: "git".into(),
                    key: "ssh-ed25519 AAAAgit".into(),
                },
                Signer {
                    principal: "ordin-release".into(),
                    namespace: "ordin-release".into(),
                    key: "ssh-ed25519 AAAArel".into(),
                },
            ]
        );
    }

    #[test]
    fn the_real_file_follows_the_policy() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../release/allowed_signers"
        ))
        .unwrap();
        load(&text).unwrap();
    }

    #[test]
    fn lines_that_break_the_format_are_rejected_by_number() {
        for (line, why) in [
            ("a namespaces=\"git\" ssh-ed25519", "expected"),
            ("a,b namespaces=\"git\" ssh-ed25519 K", "plain name"),
            ("* namespaces=\"git\" ssh-ed25519 K", "plain name"),
            ("a ssh-ed25519 K comment", "only option"),
            (
                "a cert-authority,namespaces=\"git\" ssh-ed25519 K",
                "only option",
            ),
            ("a namespaces=\"git,file\" ssh-ed25519 K", "only option"),
            ("a namespaces=\"\" ssh-ed25519 K", "only option"),
            ("a namespaces=\"git ssh-ed25519 K", "only option"),
            ("a namespaces=\"git\" rsa K", "unknown key type"),
        ] {
            let e = parse(&format!("# c\n{line}\n")).unwrap_err().to_string();
            assert!(e.contains("line 2:") && e.contains(why), "{line}: {e}");
        }
    }

    #[test]
    fn names_may_use_letters_digits_dashes_underscores_and_dots() {
        let s = parse("a-b_c.1 namespaces=\"x-y_z.2\" ssh-ed25519 K\n").unwrap();
        assert_eq!(
            (s[0].principal.as_str(), s[0].namespace.as_str()),
            ("a-b_c.1", "x-y_z.2")
        );
        for bad in [
            "a!b namespaces=\"git\" ssh-ed25519 K",
            "a namespaces=\"g!t\" ssh-ed25519 K",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn other_key_types_are_accepted() {
        let s = parse("a namespaces=\"git\" ecdsa-sha2-nistp256 K\nb namespaces=\"git\" sk-ssh-ed25519@openssh.com K2\n")
            .unwrap();
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn the_policy_needs_one_tag_key_and_one_release_key() {
        let git = "a namespaces=\"git\" ssh-ed25519 K1\n";
        let rel = "ordin-release namespaces=\"ordin-release\" ssh-ed25519 K2\n";
        let e = load(rel).unwrap_err().to_string();
        assert!(e.contains("no key for the `git` namespace"), "{e}");
        let e = load(git).unwrap_err().to_string();
        assert!(e.contains("exactly one `ordin-release` key"), "{e}");
        let two = format!("{git}{rel}{}", rel.replace("K2", "K3"));
        assert!(load(&two).unwrap_err().to_string().contains("exactly one"));
        let wrong = format!("{git}someone namespaces=\"ordin-release\" ssh-ed25519 K2\n");
        assert!(
            load(&wrong)
                .unwrap_err()
                .to_string()
                .contains("exactly one")
        );
        let unknown = format!("{git}{rel}x namespaces=\"file\" ssh-ed25519 K4\n");
        assert!(
            load(&unknown)
                .unwrap_err()
                .to_string()
                .contains("unknown namespace `file`")
        );
        let twice = format!("{git}{rel}b namespaces=\"git\" ssh-ed25519 K2\n");
        assert!(
            load(&twice)
                .unwrap_err()
                .to_string()
                .contains("same key twice")
        );
        assert!(load(&format!("{git}{rel}")).is_ok());
    }
}
