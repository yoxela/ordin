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
