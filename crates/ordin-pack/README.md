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
