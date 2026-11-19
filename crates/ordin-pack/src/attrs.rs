// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! What happens to each extended attribute found on disk.
//!
//! A tree holds `user.*` attributes and capabilities. Labels that belong
//! to the machine doing the packing are left behind. Anything else is
//! refused rather than dropped, because dropping it could change what
//! the file allows: when a file has an ACL, for example, its group mode
//! bits show the ACL's mask, not what the owning group may really do.

use ordin_tree::{Capabilities, XattrName, Xattrs};

use crate::error::WalkErrorKind;

/// What a tree records from a path's attributes.
#[derive(Debug, Default)]
pub(crate) struct Attributes {
    pub xattrs: Xattrs,
    pub capabilities: Option<Capabilities>,
}

/// What to do with an attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Disposition {
    /// Record it as a `user.*` attribute.
    Keep,
    /// Decode it as the file's capabilities.
    Capabilities,
    /// Leave it behind: it describes the packing machine.
    Ignore,
}

/// Decides what to do with the attribute called `name`, which may not be
/// UTF-8. Only regular files can have capabilities.
pub(crate) fn disposition(name: &[u8], regular: bool) -> Result<Disposition, WalkErrorKind> {
    let shown = String::from_utf8_lossy(name).escape_debug().to_string();
    match name {
        b"security.capability" if regular => Ok(Disposition::Capabilities),
        b"security.selinux" | b"security.ima" | b"security.evm" => Ok(Disposition::Ignore),
        b"system.posix_acl_access" | b"system.posix_acl_default" => {
            Err(WalkErrorKind::Acl { name: shown })
        }
        _ if name.starts_with(b"user.") => Ok(Disposition::Keep),
        _ => Err(WalkErrorKind::RefusedAttribute { name: shown }),
    }
}

impl Attributes {
    /// Records one attribute, as [`disposition`] decided.
    pub fn record(
        &mut self,
        keep: Disposition,
        name: &[u8],
        value: &[u8],
    ) -> Result<(), WalkErrorKind> {
        match keep {
            Disposition::Keep => {
                let name: XattrName = String::from_utf8_lossy(name)
                    .parse()
                    .map_err(WalkErrorKind::BadAttribute)?;
                self.xattrs.insert(name, value.to_vec());
            }
            Disposition::Capabilities => {
                let decoded =
                    Capabilities::from_xattr(value).map_err(WalkErrorKind::BadCapabilities)?;
                self.capabilities = Some(decoded);
            }
            Disposition::Ignore => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_are_recorded_where_they_belong() {
        let mut attrs = Attributes::default();
        attrs
            .record(Disposition::Keep, b"user.note", b"hello")
            .unwrap();
        attrs
            .record(Disposition::Ignore, b"security.selinux", b"label")
            .unwrap();
        assert_eq!(attrs.xattrs.len(), 1);
        let (name, value) = attrs.xattrs.iter().next().unwrap();
        assert_eq!(
            (name.as_str(), value.as_slice()),
            ("user.note", &b"hello"[..])
        );
        assert_eq!(attrs.capabilities, None);

        // What `setcap cap_net_raw+ep` writes.
        let mut value = vec![1, 0, 0, 2, 0, 0x20, 0, 0];
        value.resize(20, 0);
        attrs
            .record(Disposition::Capabilities, b"security.capability", &value)
            .unwrap();
        let capabilities = attrs.capabilities.unwrap();
        assert!(capabilities.effective);
        let names: Vec<_> = capabilities.permitted.iter().map(|c| c.name()).collect();
        assert_eq!(names, ["cap_net_raw"]);
    }

    #[test]
    fn attributes_that_cannot_be_recorded_say_why() {
        let mut attrs = Attributes::default();
        let e = attrs
            .record(Disposition::Keep, b"user.\xff", b"")
            .unwrap_err();
        assert!(matches!(e, WalkErrorKind::BadAttribute(_)), "{e}");
        let e = attrs
            .record(Disposition::Capabilities, b"security.capability", b"x")
            .unwrap_err();
        assert!(matches!(e, WalkErrorKind::BadCapabilities(_)), "{e}");
    }

    #[test]
    fn each_attribute_goes_where_it_should() {
        let cases: [(&[u8], bool, Disposition); 6] = [
            (b"user.note", true, Disposition::Keep),
            (b"user.note", false, Disposition::Keep),
            (b"security.capability", true, Disposition::Capabilities),
            (b"security.selinux", false, Disposition::Ignore),
            (b"security.ima", true, Disposition::Ignore),
            (b"security.evm", true, Disposition::Ignore),
        ];
        for (name, regular, expected) in cases {
            assert_eq!(disposition(name, regular).unwrap(), expected);
        }
    }

    #[test]
    fn acls_are_refused_by_name() {
        for name in ["system.posix_acl_access", "system.posix_acl_default"] {
            let e = disposition(name.as_bytes(), false).unwrap_err();
            assert!(matches!(&e, WalkErrorKind::Acl { name: n } if n == name));
            assert!(e.to_string().contains("setfacl -b"), "{e}");
        }
    }

    #[test]
    fn everything_else_is_refused() {
        let cases: [(&[u8], bool); 5] = [
            (b"trusted.overlay.redirect", true),
            (b"security.SMACK64", true),
            (b"system.other", true),
            (b"userx", true),
            // A directory can't have capabilities.
            (b"security.capability", false),
        ];
        for (name, regular) in cases {
            let e = disposition(name, regular).unwrap_err();
            assert!(matches!(e, WalkErrorKind::RefusedAttribute { .. }), "{e}");
        }
    }

    #[test]
    fn hostile_names_are_escaped() {
        let e = disposition(b"trusted.\x1b[31m\xff", true).unwrap_err();
        let text = e.to_string();
        assert!(!text.contains('\u{1b}'), "{text:?}");
        assert!(text.contains("\\u{1b}"), "{text:?}");
    }
}
