# ordin-pack

Packaging rungs 0 and 1: scanning a tree, inferring requirements, classifying facets and writing a package, and linting it. Layer 2 (engine), licensed GPL-3.0-or-later.

## Walking a tree

`walk(root, &options)` records a directory as an `ordin_tree::Tree`, with `root/usr/bin/x` becoming `/usr/bin/x`, and returns warnings beside it. It needs no privileges, and Linux 5.8 or later.

- **Owners** are never read from the disk, because a packager usually isn't root. Everything is `root:root` unless `options.owners` says otherwise. `PATH=USER:GROUP` covers the path and everything below it, the most specific override wins, and an override that matches nothing is an error.
- **Setuid and setgid files** draw a warning unless `options.setuid` declares them under any of their names. The warning says when the file would run as root only because of the default owner.
- **Hard links** become one file entry, under the first name in sort order, and links to it.
- **Extended attributes:** `user.*` is recorded, and `security.capability` becomes the file's capabilities. `security.selinux`, `security.ima` and `security.evm` describe the packing machine and are left behind. Anything else, POSIX ACLs included, is refused, because dropping it could change what the file allows.
- **Refused, naming the path:** device nodes, sockets, FIFOs, names and symlink targets a tree can't hold, unreadable files, and mount points inside the tree.

The directory isn't trusted. Each name is opened relative to its parent without following symlinks, and files are opened without blocking.

**What the walk notices changing:**
- **A directory** whose details or names change during the walk is an error. Its names are listed again before it is closed, because adding or removing an entry may leave a directory's size and timestamps as they were. On ext4 a directory stays 4096 bytes, and its times come from a coarse clock.
- **A file** that changes while it is read is noticed when its details change. A same-size rewrite within one clock tick can slip past the walk. `pack` still catches it, because the writer reads every file again and refuses one whose digests differ from its tree.

## Normalizing the layout

`normalize(&tree, &options)` maps a walked install root into Ordin's layout. Everything a package ships ends up under `/usr`, and the rest becomes declarations for the manifest. The package's name is needed, because config defaults and seeds are kept under it.

- **`usr/`** stays where it is. `bin/`, `sbin/`, `lib/` and `lib64/` move under `usr/`, as on a merged-`/usr` system, and a top-level link such as `bin -> usr/bin` is dropped.
- **`etc/`** moves to `/usr/share/ordin/defaults/<name>/`. Each file becomes a `three-way` config default, and each empty directory a `drop-in` one. Symlinks and hard links under `etc/` are refused.
- **`var/`:** under `var/lib`, `var/cache`, `var/log`, `var/spool` and `var/tmp`, each directory becomes a state path of that class (data, cache, log, spool, tmp) with its owner, group and mode. An empty file becomes a state file, created if missing. Any other file becomes a seed, kept at `/usr/share/ordin/seeds/<name>/var/…` and copied once if missing.
- **Prefixes:** `--prefix /opt/foo` says the software was installed with that prefix, so `opt/foo/bin/x` moves to `usr/bin/x`.
- **Refused with a hint:**
  - anything else at the top level (`opt/`, `srv/`, `home/`)
  - `run/` and `var/run/`, whose directories are created at boot
  - other directories under `var/`
  - files of Ordin's own under `/usr/share/ordin`
  - paths the manifest can't declare
  - two paths that move to the same place, unless they are identical directories

Missing directories above a moved path are added as `root:root 0755`, and hard links follow their files.

## Classifying facets

`classify(&tree, &overrides)` splits a normalized tree into facets, so an admin chooses what to install and a packager never splits `-dev` or `-doc` packages by hand. Each path goes to the facet of the first rule that matches:

1. under `/usr/lib/debug`: `debug`
2. under `/usr/share/doc`, `/usr/share/man` or `/usr/share/info`: `doc`
3. under a directory `/usr/share/locale/<ll>/`: `locale:<ll>`. A name a facet can't hold stays in `runtime`, with a note.
4. under `/usr/include`, a file or link whose name ends in `.a`, or a `.pc` file in a `pkgconfig` directory: `dev`
5. everything else: `runtime`

- **Overrides** come from the recipe (rung 1). One moves a path and everything below it, the most specific one wins, and one that matches nothing is an error.
- **Each facet's tree** holds the directories above its entries, with their metadata, and the bytes of file content it carries. `runtime` is always there, even when empty.
- **A hard link** whose file lands in another facet becomes a copy of the file. The content is the same object, so it takes no more space, and a note says so.
- **`placements`** lists every path with its facet and the reason, for `ordin show --facets`.

`normalize` also returns `origins`: where each entry of the new tree was in the install root.

## Inferring requirements

`infer(&tree, &mut source)` reads the files of a normalized tree and returns the architecture, requirements and provides they show, with notes. It skips `/usr/lib/debug` and `/usr/share/doc`.

**From ELF files** (executables and shared libraries; object files and core files are skipped):
- **Requires:** each `DT_NEEDED` library becomes one `so:<lib>@<node>` atom per version node needed from it, skipping weak needs. A library needed without any version node becomes the bare `so:<lib>`.
- **Provides:** a library directly in `/usr/lib`, `/usr/lib64` or `/usr/lib/<triplet>` provides `so:<soname>`, plus `so:<soname>@<node>` for each version it defines, without the base definition. A library elsewhere, such as a plugin, provides nothing.
- **What the package ships itself** isn't required: a library with that soname, anywhere in the package, meets the need.
- **Private versions** (nodes containing `PRIVATE`, such as `GLIBC_PRIVATE`) are left out with a note, because only an exact version of the providing package can promise them. If nothing else was needed from that library, the bare atom stays.
- **Names an atom can't hold:** a version node gives the bare atom and a note; a library name gives a note and no atom.
- **Scripts:** `Inferred::scripts` lists each script with the interpreter its `#!` line names, including interpreters the package ships, for `lint`.
- **A file with the ELF magic that can't be read** gives a note and adds nothing.

**The architecture:**
- Programs and libraries must all be 64-bit little-endian x86-64, or all AArch64. Two architectures, or anything else (32-bit, big-endian, another machine), is an error naming the files.
- A package with no programs or libraries is `noarch`.

**From `#!` lines** (executable files only, reading at most 256 bytes, as the kernel does):
- `#!/usr/bin/python3` and `#!/usr/bin/env python3` both become `file:/usr/bin/python3`, and the interpreter's arguments are ignored.
- `/bin`, `/sbin`, `/lib` and `/lib64` are read as their `/usr` counterparts, so `#!/bin/sh` needs `file:/usr/bin/sh`.
- An interpreter the package ships itself isn't required.
- Anything unusual gives a note instead of a guess: options or a variable given to `env`, a relative path, an interpreter outside `/usr`, a path a `file:` atom can't hold, a line longer than 256 bytes.

`elf::inspect` reads one ELF file through `object`, with limits on every count: at most 4,096 needed libraries, 8,192 version definitions and 8,192 version needs. It has a fuzz target, `elf_inspect`.

## Packing

`pack(&options, out)` is rungs 0 and 1 in one call: an install root, with what a recipe declares, becomes a `.ordin` file.

**The steps:**
1. walk the install root
2. normalize the layout
3. infer requirements, provides and the architecture
4. classify facets
5. build the manifest
6. write the file with `ordin-archive`

**What goes into the manifest:**
- **Facets:** every facet is installed by default, except `debug`.
- **Config, state and seeds** come from the layout.
- **Setuid files:** each path in `options.setuid` becomes a `setuid` declaration at the place the layout moved it to. A declared path must be a setuid or setgid file in the package.
- **What a recipe declares** (`options.declared`, from `ordin-recipe`):
  - Requirements and provides are added to the inferred ones, and the manifest records each once.
  - Conflicts, users, groups, units and settings are taken as declared.
  - A declared state path, file or seed wins over an inferred one at the same path, and is added otherwise; the state version and obsolete paths are the recipe's.
  - Each facet move becomes a classification override.
  - Each unit's file must be in the package, under `/usr/lib/systemd/system/` or `/usr/lib/systemd/user/`, or its template's for an instance (`getty@.service` for `getty@tty1.service`). Each seed's source must be a regular file in the package.
  - `options.description`, `options.homepage` and `options.presentation` go into the manifest as given.
- **`Packed::manifest`** is the manifest read back from its signed bytes, so it is exactly what was signed: sets sorted, and without duplicates.

**Licenses:** `options.license` is an SPDX expression, and every ID in it needs a text in `options.license_texts`. `NOASSERTION` and `NONE` need none.

**Reading the files again:** `RootSource` reads each file from where it was in the install root, and trusts nothing about the root since the walk:
- Each name is opened relative to its parent, without following symlinks.
- Only regular files on the root's own mount are read, without blocking.
- The writer checks every file against its tree.

**Writing the output:**
- The file goes to a temporary file beside `out`, which is synced, made mode 0644 and renamed over `out`. Then the directory is synced, so `out` is always either the old file or the complete new one.
- A failed write leaves `out` as it was, and no temporary file behind.
- An output inside the install root is refused, through symlinks too, so an old package can never be packed into the next one.

## Linting

`lint(&mut reader, &allows)` reads a `.ordin` file back and returns the warnings about likely mistakes, each with its `Check` (`ordin-recipe`) and the path it is about, and those the recipe's allows accept, with their reasons.

- **Read through the archive.** The facet trees are put together into one tree, refused if two facets hold the same path other than as a directory. Requirements are inferred again with `infer`, reading each file through `ordin-archive`, which checks it against its digest; a damaged file stops the lint with the archive's error. A file is copied to an unlinked temporary file only once it starts with the ELF magic; of anything else, only the first 256 bytes are kept.
- **The checks:** a `NOASSERTION` license; setuid and setgid files the manifest doesn't declare; files, directories and declared state paths and files with the other-write bit; inference's notes (private versions, names an atom can't hold, unreadable ELF files, unusual `#!` lines); interpreters neither in the package nor in `KNOWN_INTERPRETERS` or `VERSIONED_INTERPRETERS`; `so:` requirements on a library ending in `.so`, and requirements made only of `so:` atoms whose libraries nothing in the package needs; facets with no files; and files in `runtime` that look like `dev`, `doc` or `debug` files. A whole directory that looks wrong, such as `/usr/man` or `/usr/lib/cmake`, is one warning.
- **Order:** warnings come in `Check` order, then by path, so a report is the same every time.
- **Allows** accept a warning of their check, about one of their paths or below it, or anywhere when they name none. An allow, or one of its paths, that accepts nothing is an `unused-allow` warning.

## Versions from git

`git::version(dir)` makes a snapshot's upstream version from the git checkout at `dir`, and returns the full commit for the manifest's provenance. It reads the nearest version tag, the commits since it and HEAD's committer date in UTC, and builds the version with `ordin-version`'s `snapshot`: `1.4.2^20261112.37.g3fa9c1e`, `0^…` without a tag, or the tag's own version at the tagged commit. A checkout whose tracked files differ from HEAD, or a shallow clone, is refused.

It runs the `git` program with read-only commands only (`rev-parse`, `diff --quiet`, `describe`, `rev-list --count`, `cat-file`), with `core.fsmonitor` off, `--no-replace-objects`, no pager, no prompt, no optional locks and the C locale, and parses every output strictly.
