# ordin-tree

Trees: one facet's file list in a single canonical, hashable form. Layer 0 (pure core), licensed MIT OR Apache-2.0. Later stories add the chunk index and the content-defined chunker here.

[`FORMAT.md`](FORMAT.md) is the reference for every field and rule (CC-BY-4.0).

- `Tree::from_canonical_bytes` reads a tree. The bytes must already be canonical JSON (RFC 8785), byte for byte, and the result includes the tree's identity: the BLAKE3 digest of those bytes.
- `Tree::new` builds a tree from entries in any order, and checks every rule.
- `Tree::to_canonical_bytes` and `Tree::digest` encode a tree and check the result against every rule again.

An entry is a file, a directory, a symlink or a hard link; device nodes, sockets and FIFOs can't be packaged. A file records its mode, owner and group names, size, BLAKE3 and fs-verity digests, `user.*` extended attributes and capabilities, and never a timestamp. Every parent is a directory in the same tree, so no path passes through a symlink, and every hard link points at a file. Every error names the entry and field: `entry 4 ("/usr/bin/rg"), field "mode": written with its default value, which must be left out`.

## File digests

`file_digests` reads any `Read` once and returns what a file entry records about the content: its size, its BLAKE3 digest and its fs-verity digest (SHA-256, 4 KiB blocks, no salt, the value `fsverity digest` prints and the kernel measures). `FileHasher` does the same for bytes given piece by piece. Neither opens a file; the caller supplies the bytes.
