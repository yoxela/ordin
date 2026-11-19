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

/// The capability numbers set in `bits`, by name.
fn caps_from_bits(which: &str, bits: u64) -> Result<BTreeSet<LinuxCap>, String> {
    (0u8..64)
        .filter(|number| (bits >> number) % 2 == 1)
        .map(|number| {
            LinuxCap::from_number(number).ok_or_else(|| {
                format!("the {which} set has capability {number}, which Ordin doesn't know")
            })
        })
        .collect()
}

/// A 64-bit set from its two halves.
fn wide(low: u32, high: u32) -> u64 {
    u64::from(high) * (1 << 32) + u64::from(low)
}

impl Capabilities {
    /// Reads the kernel's `security.capability` value (`struct
    /// vfs_ns_cap_data` and its older forms: versions 1 to 3, in
    /// little-endian). Everything a tree can't say exactly is refused:
    /// capabilities Ordin doesn't know, flags other than "effective", a
    /// version 3 value tied to a user namespace's root, and a value with
    /// no capabilities, which still changes how a setuid-root program
    /// runs.
    ///
    /// # Errors
    ///
    /// A message saying what is wrong with the value.
    pub fn from_xattr(value: &[u8]) -> Result<Self, String> {
        let (words, rest) = value.as_chunks::<4>();
        let words: Vec<u32> = words.iter().map(|w| u32::from_le_bytes(*w)).collect();
        let ([magic, sets @ ..], []) = (words.as_slice(), rest) else {
            return Err(format!(
                "a capability value is a whole number of 32-bit words; this one is {} bytes",
                value.len()
            ));
        };
        let (permitted, inheritable, root_id) = match (magic >> 24, sets) {
            (1, &[permitted, inheritable]) => (u64::from(permitted), u64::from(inheritable), 0),
            (2, &[pl, il, ph, ih]) => (wide(pl, ph), wide(il, ih), 0),
            (3, &[pl, il, ph, ih, root_id]) => (wide(pl, ph), wide(il, ih), root_id),
            (version @ 1..=3, _) => {
                return Err(format!(
                    "a version {version} capability value can't be {} bytes",
                    value.len()
                ));
            }
            (version, _) => return Err(format!("unknown capability version {version}")),
        };
        let effective = match magic % (1 << 24) {
            0 => false,
            1 => true,
            flags => return Err(format!("unknown capability flags {flags:#x}")),
        };
        if root_id != 0 {
            return Err(format!(
                "these capabilities apply only in a user namespace whose root is user {root_id}"
            ));
        }
        let capabilities = Self {
            permitted: caps_from_bits("permitted", permitted)?,
            inheritable: caps_from_bits("inheritable", inheritable)?,
            effective,
        };
        if capabilities.is_empty() {
            return Err("a capability value with no capabilities can't be recorded".to_owned());
        }
        Ok(capabilities)
    }

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

    /// A `security.capability` value from its 32-bit words.
    fn value(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    fn names(set: &BTreeSet<LinuxCap>) -> Vec<&'static str> {
        set.iter().map(|c| c.name()).collect()
    }

    const V1: u32 = 0x0100_0000;
    const V2: u32 = 0x0200_0000;
    const V3: u32 = 0x0300_0000;
    /// `cap_net_raw` (13) in the low word.
    const NET_RAW: u32 = 1 << 13;
    /// `cap_checkpoint_restore` (40) in the high word.
    const RESTORE: u32 = 1 << 8;

    #[test]
    fn every_version_reads_its_sets() {
        // What `setcap cap_net_raw+ep` writes.
        let caps = Capabilities::from_xattr(&value(&[V2 + 1, NET_RAW, 0, 0, 0])).unwrap();
        assert_eq!(names(&caps.permitted), ["cap_net_raw"]);
        assert!(caps.inheritable.is_empty());
        assert!(caps.effective);

        let caps = Capabilities::from_xattr(&value(&[V1, 1, NET_RAW])).unwrap();
        assert_eq!(names(&caps.permitted), ["cap_chown"]);
        assert_eq!(names(&caps.inheritable), ["cap_net_raw"]);
        assert!(!caps.effective);

        // The words alternate permitted and inheritable, low then high.
        let caps = Capabilities::from_xattr(&value(&[V3, NET_RAW, 1, RESTORE, 0, 0])).unwrap();
        assert_eq!(
            names(&caps.permitted),
            ["cap_checkpoint_restore", "cap_net_raw"]
        );
        assert_eq!(names(&caps.inheritable), ["cap_chown"]);
    }

    #[test]
    fn inheritable_high_words_count() {
        let caps = Capabilities::from_xattr(&value(&[V2, 0, 1, 0, RESTORE])).unwrap();
        assert!(caps.permitted.is_empty());
        assert_eq!(
            names(&caps.inheritable),
            ["cap_checkpoint_restore", "cap_chown"]
        );
    }

    #[test]
    fn values_a_tree_cannot_say_are_refused() {
        let cases: [(Vec<u8>, &str); 10] = [
            (Vec::new(), "whole number"),
            (vec![0; 3], "whole number"),
            (vec![0; 21], "whole number"),
            (value(&[V1, 1]), "version 1"),
            (value(&[V2, 1, 0, 0]), "version 2"),
            (value(&[V3, 1, 0, 0, 0]), "version 3"),
            (value(&[0x0400_0000, 1, 0, 0, 0]), "version 4"),
            (value(&[V2 + 2, 1, 0, 0, 0]), "flags 0x2"),
            (value(&[V3, 1, 0, 0, 0, 1000]), "user 1000"),
            (value(&[V2 + 1, 0, 0, 0, 0]), "no capabilities"),
        ];
        for (bytes, expected) in cases {
            let e = Capabilities::from_xattr(&bytes).unwrap_err();
            assert!(e.contains(expected), "{bytes:?}: {e}");
        }
    }

    #[test]
    fn capabilities_the_kernel_may_add_later_are_refused() {
        // 41 is the first number Ordin doesn't know.
        let e = Capabilities::from_xattr(&value(&[V2, 0, 0, 1 << 9, 0])).unwrap_err();
        assert!(e.contains("permitted set has capability 41"), "{e}");
        let e = Capabilities::from_xattr(&value(&[V2, 0, 0, 0, 1 << 31])).unwrap_err();
        assert!(e.contains("inheritable set has capability 63"), "{e}");
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
