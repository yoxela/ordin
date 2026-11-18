<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 The Ordin Authors -->

# The Ordin tree, format 1

A tree is one facet's file list. A package's manifest maps each facet to the digest of its tree, and the tree records every path in the facet with its metadata and the digests of its content. **A tree's identity is the BLAKE3 digest of its canonical bytes**, written `blake3:<64 lowercase hex digits>`.

This document is the reference for every field. `ordin-tree` implements it, and a tree that doesn't follow it is refused.

## Encoding rules

These rules make sure one file list has exactly one encoding, and so exactly one identity.

- **Canonical JSON (RFC 8785).** No whitespace, object keys sorted by UTF-16 code units, strings escaped as ECMAScript's `JSON.stringify` does. A reader requires the bytes to be canonical already.
- **Strict reading.** Duplicate keys, numbers that aren't integers, integers beyond ±(2⁵³−1), unknown fields and fields written with their default value are all refused.
- **Entries sorted by the UTF-8 bytes of their paths,** with no path twice. Entries are an array, not an object keyed by path, because RFC 8785 sorts keys by UTF-16 code units, which differs from byte order.
- **No timestamps.** Nothing about when a file was made or changed is recorded, so it never affects the identity.
- **No facet name.** The manifest names the facet, so two facets with the same files share one tree.
- **No `ignorable` list.** Trees are written by Ordin, never by hand, so a new field needs a new format version.
- **Limits.** A tree is at most 64 MiB and 262,144 entries.

## The tree

```json
{"entries":[...],"ordin-tree":1}
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `ordin-tree` | integer | yes | The format version: `1`. A reader refuses a version it doesn't know, before looking at any other field. |
| `entries` | array of entries | yes | Every path in the facet, sorted. May be empty. |

## Entries

Every entry has a `path` and a `type`. The other fields depend on the type, and a field the type doesn't have is refused.

| Field | file | dir | symlink | hardlink | Default |
| --- | --- | --- | --- | --- | --- |
| `path` (*path*) | required | required | required | required | |
| `type` | `"file"` | `"dir"` | `"symlink"` | `"hardlink"` | |
| `mode` (*mode*) | optional | optional | | | `0644` for a file, `0755` for a directory |
| `owner`, `group` (*account*) | optional | optional | optional | | `root` |
| `size` (integer) | required | | | | |
| `content` (*digest*) | required | | | | |
| `fsverity` (*digest*) | required | | | | |
| `xattrs` (object) | optional | optional | | | none |
| `capabilities` (object) | optional | | | | none |
| `target` | | | required (*target*) | required (*path*) | |

Device nodes, sockets and FIFOs can't be packaged, and any other `type` is refused.

- **`file`:** a regular file.
  - `size` is the length in bytes, at most 2⁵³−1.
  - `content` is the BLAKE3 digest of the file's bytes (`blake3:…`). It is the file object's identity.
  - `fsverity` is the file's fs-verity digest (`sha256:…`): SHA-256, 4 KiB Merkle blocks, no salt, as `fsverity digest` computes it with its defaults. On a host, the file object is stored under this digest, in composefs's `objects/xx/<rest>` layout, so composefs images can point at it.
- **`dir`:** a directory. Its children are the entries whose parent it is.
- **`symlink`:** a symbolic link. `target` is what it points at, exactly as written. Linux gives a symlink no mode of its own and no `user.*` attributes, so neither is recorded.
- **`hardlink`:** another name for a file in the same tree. `target` is that file's path, and it must be a `file` entry, not a directory, symlink or another hard link. The link shares the file's content and metadata, so it records nothing else.

## Value types

| Type | Form |
| --- | --- |
| *path* | Absolute and normalized: starts with `/`, with no empty, `.` or `..` names and no trailing `/`. `/` itself isn't an entry. UTF-8 without control characters (U+0000 to U+001F, U+007F to U+009F); spaces, `~` and other characters are allowed. At most 4,095 bytes, and 255 bytes per name, as Linux allows. |
| *target* | 1 to 4,095 bytes of UTF-8 without control characters, relative or absolute, kept exactly as written |
| *mode* | Four octal digits, at most `7777`: permission bits, setuid, setgid and sticky |
| *account* | A user or group name: `[A-Za-z_][A-Za-z0-9_-]*`, 1 to 32 bytes |
| *digest* | An algorithm, `:`, and 64 lowercase hex digits |

## Parents

Every entry's parent is `/` or a `dir` entry in the same tree. So a tree lists every directory it needs, with its mode and owner, and no path ever passes through a symlink or a file. Compose and unpack can rely on that instead of resolving paths.

## Extended attributes

`xattrs` maps attribute names to values. Each value is base64 (RFC 4648, standard alphabet, padded), and only the one text that encodes the bytes is accepted. An entry has at most 16 attributes, each value at most 4,096 bytes. An empty object is refused; leave the field out instead.

**Only `user.*` attributes can be packaged.** A name is `user.` and 1 to 250 printable ASCII characters other than space.

| Namespace | Why it's refused |
| --- | --- |
| `trusted.*` | composefs and overlayfs use `trusted.overlay.*` to point a file at its object. A package that could set them could point a file at another file. |
| `security.*` | Capabilities have their own field. SELinux labels come from policy and the manifest's declarations, never from the file list. |
| `system.*` | ACLs aren't packaged. |

## Capabilities

`capabilities` gives a file what `setcap` would, by name instead of as the kernel's `security.capability` bytes. Compose writes the bytes.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `permitted` | set of capability names | none | Capabilities the program gets, whoever runs it |
| `inheritable` | set of capability names | none | Capabilities the program gets only if the process running it has them as inheritable |
| `effective` | `true` | `false` | The permitted capabilities are effective from the start, for programs that don't raise them themselves |

- At least one of `permitted` and `inheritable` is present. An empty set is refused; leave the field out instead.
- Sets are sorted by name, without repeats.
- A name is the kernel's lowercase name, from `cap_chown` (0) to `cap_checkpoint_restore` (40), as of Linux 6.12. Unknown names are refused.

## Example

```json
{"entries":[
 {"path":"/usr","type":"dir"},
 {"path":"/usr/bin","type":"dir"},
 {"capabilities":{"effective":true,"permitted":["cap_net_raw"]},"content":"blake3:3d02…84f9","fsverity":"sha256:9a1c…07be","mode":"0755","path":"/usr/bin/ping","size":90312,"type":"file"},
 {"path":"/usr/bin/ping6","target":"/usr/bin/ping","type":"hardlink"},
 {"path":"/usr/bin/ripgrep","target":"rg","type":"symlink"},
 {"path":"/usr/share","type":"dir"},
 {"group":"mail","mode":"2775","owner":"Debian-exim","path":"/usr/share/mail","type":"dir","xattrs":{"user.note":"c3Bvb2w="}}
],"ordin-tree":1}
```

Line breaks are added here for reading, and digests are shortened; the real encoding has neither. `crates/ordin-tree/tests/data/everything.json` is a complete tree that uses every field.
