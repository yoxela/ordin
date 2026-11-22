// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! What a package needs from an ELF file: its machine and type, its
//! soname, the libraries it needs, and the symbol versions it needs and
//! defines.
//!
//! The file is outside input, so every count is limited and nothing here
//! panics on bad bytes. Only 64-bit little-endian x86-64 and AArch64 files
//! are read in full; for anything else only the header is.

use object::elf::{
    DT_NEEDED, DT_SONAME, EM_AARCH64, EM_X86_64, ET_DYN, ET_EXEC, FileHeader64, VER_FLG_BASE,
    VER_FLG_WEAK,
};
use object::read::ReadRef;
use object::read::elf::{Dyn, FileHeader};
use object::{Endianness, LittleEndian};

/// The most libraries one file may need.
pub const MAX_NEEDED: usize = 4096;

/// The most version definitions, or version needs, one file may have.
/// glibc, which has the most, defines about fifty.
pub const MAX_VERSIONS: usize = 8192;

/// The ELF magic.
pub const MAGIC: &[u8; 4] = b"\x7fELF";

/// What an ELF file is built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Machine {
    /// 64-bit little-endian x86-64.
    X86_64,
    /// 64-bit little-endian AArch64.
    Aarch64,
    /// Anything else, as the header says.
    Other {
        /// 64-bit rather than 32-bit.
        class64: bool,
        /// Little-endian rather than big-endian.
        little: bool,
        /// `e_machine`.
        machine: u16,
    },
}

/// What kind of ELF file it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An executable (`ET_EXEC`).
    Executable,
    /// A shared object, which includes position-independent executables
    /// (`ET_DYN`).
    Shared,
    /// Anything else: relocatable objects, core files.
    Other,
}

/// A symbol version a file needs from a library.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionNeed {
    /// The library, as the file names it.
    pub library: Vec<u8>,
    /// The version node.
    pub node: Vec<u8>,
    /// Whether the need is weak, so the file runs without it.
    pub weak: bool,
}

/// What an ELF file says about its dependencies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Info {
    /// What it is built for.
    pub machine: Machine,
    /// What kind of file it is.
    pub kind: Kind,
    /// Its soname (`DT_SONAME`), if it has one.
    pub soname: Option<Vec<u8>>,
    /// The libraries it needs (`DT_NEEDED`), in order.
    pub needed: Vec<Vec<u8>>,
    /// The symbol versions it needs.
    pub needs: Vec<VersionNeed>,
    /// The symbol versions it defines, without the base definition.
    pub defines: Vec<Vec<u8>>,
}

/// Why an ELF file couldn't be read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ElfError(pub String);

fn bad(what: &str) -> impl Fn(object::read::Error) -> ElfError + '_ {
    move |e| ElfError(format!("{what}: {e}"))
}

fn too_many(what: &str, max: usize) -> ElfError {
    ElfError(format!("more than {max} {what}"))
}

/// Reads what a package needs from `data`, or `None` if it isn't an ELF
/// file.
///
/// # Errors
///
/// A file with the ELF magic that can't be read, or that has more than
/// [`MAX_NEEDED`] needed libraries or [`MAX_VERSIONS`] version entries.
pub fn inspect<'data, R: ReadRef<'data>>(data: R) -> Result<Option<Info>, ElfError> {
    let len = data.len().unwrap_or(0).min(16);
    let ident = data.read_bytes_at(0, len).unwrap_or_default();
    if !ident.starts_with(MAGIC) {
        return Ok(None);
    }
    if ident.len() < 16 {
        return Err(ElfError(
            "the file is too short for an ELF header".to_owned(),
        ));
    }
    let class64 = ident.get(4) == Some(&2);
    let little = ident.get(5) == Some(&1);
    if !(class64 && little) {
        return header_only(data, class64, little).map(Some);
    }
    let header = FileHeader64::<LittleEndian>::parse(data).map_err(bad("the header"))?;
    let endian = LittleEndian;
    let kind = kind_of(header.e_type(endian).0);
    let machine = match header.e_machine(endian) {
        EM_X86_64 => Machine::X86_64,
        EM_AARCH64 => Machine::Aarch64,
        other => Machine::Other {
            class64,
            little,
            machine: other.0,
        },
    };
    let mut info = Info {
        machine,
        kind,
        soname: None,
        needed: Vec::new(),
        needs: Vec::new(),
        defines: Vec::new(),
    };
    if matches!(machine, Machine::Other { .. }) || kind == Kind::Other {
        return Ok(Some(info));
    }
    let sections = header
        .sections(endian, data)
        .map_err(bad("the section headers"))?;

    if let Some((entries, link)) = sections
        .dynamic(endian, data)
        .map_err(bad("the dynamic section"))?
    {
        let strings = sections
            .strings(endian, data, link)
            .map_err(bad("the dynamic strings"))?;
        for entry in entries {
            let tag = entry.d_tag(endian);
            if tag != DT_NEEDED && tag != DT_SONAME {
                continue;
            }
            let offset = u32::try_from(entry.d_val(endian))
                .map_err(|_| ElfError("a dynamic string offset is out of range".to_owned()))?;
            let name = strings
                .get(offset)
                .map_err(|()| ElfError("a dynamic string is out of range".to_owned()))?
                .to_vec();
            if tag == DT_SONAME {
                info.soname = Some(name);
            } else {
                if info.needed.len() >= MAX_NEEDED {
                    return Err(too_many("needed libraries", MAX_NEEDED));
                }
                info.needed.push(name);
            }
        }
    }

    if let Some((defs, link)) = sections
        .gnu_verdef(endian, data)
        .map_err(bad("the version definitions"))?
    {
        let strings = sections
            .strings(endian, data, link)
            .map_err(bad("the version strings"))?;
        let mut count = 0;
        for def in defs {
            let (def, mut aux) = def.map_err(bad("a version definition"))?;
            count += 1;
            if count > MAX_VERSIONS {
                return Err(too_many("version definitions", MAX_VERSIONS));
            }
            if def.vd_flags.get(endian).0 & VER_FLG_BASE.0 != 0 {
                continue;
            }
            // The first auxiliary entry is the version's own name; any
            // others name its parents.
            if let Some(name) = aux.next().map_err(bad("a version definition"))? {
                let name = name.name(endian, strings).map_err(bad("a version name"))?;
                info.defines.push(name.to_vec());
            }
        }
    }

    if let Some((needs, link)) = sections
        .gnu_verneed(endian, data)
        .map_err(bad("the version needs"))?
    {
        let strings = sections
            .strings(endian, data, link)
            .map_err(bad("the version strings"))?;
        let mut count = 0;
        for need in needs {
            let (need, aux) = need.map_err(bad("a version need"))?;
            let library = need
                .file(endian, strings)
                .map_err(bad("a version need's library"))?;
            for entry in aux {
                let entry = entry.map_err(bad("a version need"))?;
                count += 1;
                if count > MAX_VERSIONS {
                    return Err(too_many("version needs", MAX_VERSIONS));
                }
                let node = entry.name(endian, strings).map_err(bad("a version name"))?;
                info.needs.push(VersionNeed {
                    library: library.to_vec(),
                    node: node.to_vec(),
                    weak: entry.vna_flags.get(endian).0 & VER_FLG_WEAK.0 != 0,
                });
            }
        }
    }
    Ok(Some(info))
}

fn kind_of(e_type: u16) -> Kind {
    match e_type {
        t if t == ET_EXEC.0 => Kind::Executable,
        t if t == ET_DYN.0 => Kind::Shared,
        _ => Kind::Other,
    }
}

/// The machine and kind of a file that isn't 64-bit little-endian, from
/// its header alone.
fn header_only<'data, R: ReadRef<'data>>(
    data: R,
    class64: bool,
    little: bool,
) -> Result<Info, ElfError> {
    let (e_type, e_machine) = if class64 {
        let h = FileHeader64::<Endianness>::parse(data).map_err(bad("the header"))?;
        let endian = h.endian().map_err(bad("the header"))?;
        (h.e_type(endian).0, h.e_machine(endian).0)
    } else {
        let h = object::elf::FileHeader32::<Endianness>::parse(data).map_err(bad("the header"))?;
        let endian = h.endian().map_err(bad("the header"))?;
        (h.e_type(endian).0, h.e_machine(endian).0)
    };
    Ok(Info {
        machine: Machine::Other {
            class64,
            little,
            machine: e_machine,
        },
        kind: kind_of(e_type),
        soname: None,
        needed: Vec::new(),
        needs: Vec::new(),
        defines: Vec::new(),
    })
}
