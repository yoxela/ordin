# ordin-pack

Packaging rungs 0 and 1: scanning a tree, inferring requirements, classifying facets and writing a package. Layer 2 (engine), licensed GPL-3.0-or-later.

## Walking a tree

`walk(root, &options)` records a directory as an `ordin_tree::Tree`, with `root/usr/bin/x` becoming `/usr/bin/x`, and returns warnings beside it. It needs no privileges, and Linux 5.8 or later.

- **Owners** are never read from the disk, because a packager usually isn't root. Everything is `root:root` unless `options.owners` says otherwise. `PATH=USER:GROUP` covers the path and everything below it, the most specific override wins, and an override that matches nothing is an error.
- **Setuid and setgid files** draw a warning unless `options.setuid` declares them under any of their names. The warning says when the file would run as root only because of the default owner.
- **Hard links** become one file entry, under the first name in sort order, and links to it.
- **Extended attributes:** `user.*` is recorded, and `security.capability` becomes the file's capabilities. `security.selinux`, `security.ima` and `security.evm` describe the packing machine and are left behind. Anything else, POSIX ACLs included, is refused, because dropping it could change what the file allows.
- **Refused, naming the path:** device nodes, sockets, FIFOs, names and symlink targets a tree can't hold, unreadable files, and mount points inside the tree.

The directory isn't trusted. Each name is opened relative to its parent without following symlinks, files are opened without blocking, and whatever changes during the walk is an error.

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

## Packing

`pack(&options, out)` is rung 0 in one call: an install root becomes a `.ordin` file.

**The steps:**
1. walk the install root
2. normalize the layout
3. classify facets
4. build the manifest
5. write the file with `ordin-archive`

**What goes into the manifest:**
- **Facets:** every facet is installed by default, except `debug`.
- **Config, state and seeds** come from the layout.
- **Setuid files:** each path in `options.setuid` becomes a `setuid` declaration at the place the layout moved it to. A declared path must be a setuid or setgid file in the package.

**Licenses:** `options.license` is an SPDX expression, and every ID in it needs a text in `options.license_texts`. `NOASSERTION` and `NONE` need none.

**Reading the files again:** `RootSource` reads each file from where it was in the install root, and trusts nothing about the root since the walk:
- Each name is opened relative to its parent, without following symlinks.
- Only regular files on the root's own mount are read, without blocking.
- The writer checks every file against its tree.

**Writing the output:**
- The file goes to a temporary file beside `out`, which is synced, made mode 0644 and renamed over `out`. Then the directory is synced, so `out` is always either the old file or the complete new one.
- A failed write leaves `out` as it was, and no temporary file behind.
- An output inside the install root is refused, through symlinks too, so an old package can never be packed into the next one.
