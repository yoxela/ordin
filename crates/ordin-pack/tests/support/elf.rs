// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! ELF files written with `object`'s writer, for tests that need real
//! programs and libraries.

use object::Endianness;
use object::elf::{
    DT_NEEDED, DT_NULL, DT_SONAME, ELFOSABI_NONE, FileFlags, FileType, Machine as EMachine,
    VER_FLG_BASE, VER_FLG_WEAK, VersionFlags, VersionIndex,
};
use object::write::elf::{FileHeader, Verdef, Vernaux, Verneed, Writer};

/// What an ELF fixture holds.
#[derive(Clone, Default)]
pub struct Spec {
    pub machine: u16,
    pub e_type: u16,
    pub is_64: bool,
    pub big: bool,
    pub soname: Option<&'static str>,
    pub needed: Vec<&'static str>,
    /// Version definitions, and whether each is the base.
    pub defines: Vec<(&'static str, bool)>,
    /// Per library, its version needs and whether each is weak.
    pub needs: Vec<(&'static str, Vec<(&'static str, bool)>)>,
}

pub fn spec(machine: u16, e_type: u16) -> Spec {
    Spec {
        machine,
        e_type,
        is_64: true,
        ..Spec::default()
    }
}

/// An ELF file with a dynamic section and the version sections `s`
/// asks for.
pub fn build(s: &Spec) -> Vec<u8> {
    let mut buf = Vec::new();
    let endian = if s.big {
        Endianness::Big
    } else {
        Endianness::Little
    };
    let mut w = Writer::new(endian, s.is_64, &mut buf);
    w.reserve_file_header();
    let soname = s.soname.map(|n| w.add_dynamic_string(n.as_bytes()));
    let needed: Vec<_> = s
        .needed
        .iter()
        .map(|n| w.add_dynamic_string(n.as_bytes()))
        .collect();
    let defines: Vec<_> = s
        .defines
        .iter()
        .map(|(n, base)| (w.add_dynamic_string(n.as_bytes()), *base))
        .collect();
    let needs: Vec<_> = s
        .needs
        .iter()
        .map(|(lib, nodes)| {
            (
                w.add_dynamic_string(lib.as_bytes()),
                nodes
                    .iter()
                    .map(|(n, weak)| (w.add_dynamic_string(n.as_bytes()), *weak))
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    w.reserve_null_section_index();
    w.reserve_dynstr_section_index();
    w.reserve_dynamic_section_index();
    if !defines.is_empty() {
        w.reserve_gnu_verdef_section_index();
    }
    if !needs.is_empty() {
        w.reserve_gnu_verneed_section_index();
    }
    w.reserve_shstrtab_section_index();
    w.reserve_dynstr().unwrap();
    let dynamic = needed.len() + usize::from(soname.is_some()) + 1;
    w.reserve_dynamic(dynamic);
    w.reserve_gnu_verdef(defines.len() as u16, defines.len());
    let aux: usize = needs.iter().map(|(_, n)| n.len()).sum();
    w.reserve_gnu_verneed(needs.len() as u16, aux);
    w.reserve_shstrtab().unwrap();
    w.reserve_section_headers();

    w.write_file_header(&FileHeader {
        os_abi: ELFOSABI_NONE,
        abi_version: 0,
        e_type: FileType(s.e_type),
        e_machine: EMachine(s.machine),
        e_entry: 0,
        e_flags: FileFlags(0),
    })
    .unwrap();
    w.write_dynstr();
    w.write_align_dynamic();
    if let Some(id) = soname {
        w.write_dynamic_string(DT_SONAME, id).unwrap();
    }
    for id in &needed {
        w.write_dynamic_string(DT_NEEDED, *id).unwrap();
    }
    w.write_dynamic(DT_NULL, 0).unwrap();
    if !defines.is_empty() {
        w.write_align_gnu_verdef();
        for (i, (id, base)) in defines.iter().enumerate() {
            let name = w.dynamic_string_offset(Some(*id));
            w.write_gnu_verdef(&Verdef {
                version: 1,
                flags: if *base { VER_FLG_BASE } else { VersionFlags(0) },
                index: VersionIndex(i as u16 + 1),
                aux_count: 1,
                name,
                hash: 0,
            });
        }
    }
    if !needs.is_empty() {
        w.write_align_gnu_verneed();
        let mut index = 2;
        for (lib, nodes) in &needs {
            let file = w.dynamic_string_offset(Some(*lib));
            w.write_gnu_verneed(&Verneed {
                version: 1,
                aux_count: nodes.len() as u16,
                file,
            });
            for (id, weak) in nodes {
                let name = w.dynamic_string_offset(Some(*id));
                w.write_gnu_vernaux(&Vernaux {
                    flags: if *weak { VER_FLG_WEAK } else { VersionFlags(0) },
                    index: VersionIndex(index),
                    name,
                    hash: 0,
                });
                index += 1;
            }
        }
    }
    w.write_shstrtab();
    w.write_null_section_header();
    w.write_dynstr_section_header(0);
    w.write_dynamic_section_header(0);
    w.write_gnu_verdef_section_header(0);
    w.write_gnu_verneed_section_header(0);
    w.write_shstrtab_section_header();
    drop(w);
    buf
}
