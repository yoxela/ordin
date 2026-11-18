// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! File capabilities: what `setcap` gives a program, recorded by name
//! instead of as the kernel's `security.capability` bytes.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

/// The kernel's capabilities by number, as of Linux 6.12 (`CAP_LAST_CAP`
/// is 40, `CAP_CHECKPOINT_RESTORE`).
const NAMES: [&str; 41] = [
    "cap_chown",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_fowner",
    "cap_fsetid",
    "cap_kill",
    "cap_setgid",
    "cap_setuid",
    "cap_setpcap",
    "cap_linux_immutable",
    "cap_net_bind_service",
    "cap_net_broadcast",
    "cap_net_admin",
    "cap_net_raw",
    "cap_ipc_lock",
    "cap_ipc_owner",
    "cap_sys_module",
    "cap_sys_rawio",
    "cap_sys_chroot",
    "cap_sys_ptrace",
    "cap_sys_pacct",
    "cap_sys_admin",
    "cap_sys_boot",
    "cap_sys_nice",
    "cap_sys_resource",
    "cap_sys_time",
    "cap_sys_tty_config",
    "cap_mknod",
    "cap_lease",
    "cap_audit_write",
    "cap_audit_control",
    "cap_setfcap",
    "cap_mac_override",
    "cap_mac_admin",
    "cap_syslog",
    "cap_wake_alarm",
    "cap_block_suspend",
    "cap_audit_read",
    "cap_perfmon",
    "cap_bpf",
    "cap_checkpoint_restore",
];

/// One Linux capability, by its lowercase name (`cap_net_raw`). Sets of
/// them sort by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinuxCap(&'static str);

impl LinuxCap {
    /// The capability's name.
    #[must_use]
    pub fn name(self) -> &'static str {
        self.0
    }

    /// The capability's number in the kernel.
    #[must_use]
    pub fn number(self) -> u8 {
        let mut n = 0;
        for (i, name) in (0u8..).zip(NAMES) {
            if name == self.0 {
                n = i;
            }
        }
        n
    }

    /// The capability with this number, if the kernel defines one.
    #[must_use]
    pub fn from_number(number: u8) -> Option<Self> {
        NAMES.get(usize::from(number)).copied().map(Self)
    }
}

impl FromStr for LinuxCap {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        NAMES
            .iter()
            .find(|&&name| name == text)
            .map(|&name| Self(name))
            .ok_or_else(|| {
                format!("{text:?} isn't a Linux capability Ordin knows, such as \"cap_net_raw\"")
            })
    }
}

impl fmt::Display for LinuxCap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// A file's capabilities. At least one set is non-empty; a file with
/// none has no `Capabilities`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    /// Capabilities the program gets, whatever runs it.
    pub permitted: BTreeSet<LinuxCap>,
    /// Capabilities the program gets only if the process running it has
    /// them as inheritable.
    pub inheritable: BTreeSet<LinuxCap>,
    /// Whether the permitted capabilities are also effective from the
    /// start, for programs that don't raise them themselves.
    pub effective: bool,
}

impl Capabilities {
    /// Whether both sets are empty, which a tree refuses.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.permitted.is_empty() && self.inheritable.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_numbers_match_the_kernel() {
        assert_eq!(NAMES.len(), 41);
        for (i, name) in (0u8..).zip(NAMES) {
            let cap: LinuxCap = name.parse().unwrap();
            assert_eq!(cap.number(), i);
            assert_eq!(cap.name(), name);
            assert_eq!(cap.to_string(), name);
            assert_eq!(LinuxCap::from_number(i), Some(cap));
        }
        assert_eq!("cap_chown".parse::<LinuxCap>().unwrap().number(), 0);
        assert_eq!("cap_net_raw".parse::<LinuxCap>().unwrap().number(), 13);
        assert_eq!("cap_sys_admin".parse::<LinuxCap>().unwrap().number(), 21);
        assert_eq!(
            "cap_checkpoint_restore"
                .parse::<LinuxCap>()
                .unwrap()
                .number(),
            40
        );
        assert_eq!(LinuxCap::from_number(41), None);
    }

    #[test]
    fn unknown_names_are_refused() {
        for bad in ["CAP_NET_RAW", "net_raw", "cap_", "", "cap_net_raw "] {
            let e = bad.parse::<LinuxCap>().unwrap_err();
            assert!(e.contains("isn't a Linux capability"), "{bad:?}: {e}");
        }
    }

    #[test]
    fn sets_sort_by_name() {
        let set: BTreeSet<LinuxCap> = ["cap_sys_admin", "cap_chown", "cap_net_raw"]
            .iter()
            .map(|n| n.parse().unwrap())
            .collect();
        let names: Vec<_> = set.iter().map(|c| c.name()).collect();
        assert_eq!(names, ["cap_chown", "cap_net_raw", "cap_sys_admin"]);
    }

    #[test]
    fn empty_means_both_sets_are_empty() {
        let raw: LinuxCap = "cap_net_raw".parse().unwrap();
        let mut caps = Capabilities {
            permitted: BTreeSet::new(),
            inheritable: BTreeSet::new(),
            effective: true,
        };
        assert!(caps.is_empty());
        caps.inheritable.insert(raw);
        assert!(!caps.is_empty());
        caps.inheritable.clear();
        caps.permitted.insert(raw);
        assert!(!caps.is_empty());
    }
}
