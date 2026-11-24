# ordin-tree

Trees: one facet's file list in a single canonical, hashable form, and the content-defined chunks that carry files between machines. Layer 0 (pure core), licensed MIT OR Apache-2.0.

[`FORMAT.md`](FORMAT.md) is the reference for every field and rule (CC-BY-4.0).

- `Tree::from_canonical_bytes` reads a tree. The bytes must already be canonical JSON (RFC 8785), byte for byte, and the result includes the tree's identity: the BLAKE3 digest of those bytes. It reads one entry at a time, so memory follows the size of the result rather than of the text: a tree at the format's limits takes about 83 MiB beyond its bytes.
- `Tree::new` builds a tree from entries in any order, and checks every rule.
- `Tree::to_canonical_bytes` and `Tree::digest` encode a tree and check the result against every rule again.

An entry is a file, a directory, a symlink or a hard link; device nodes, sockets and FIFOs can't be packaged. A file records its mode, owner and group names, size, BLAKE3 and fs-verity digests, `user.*` extended attributes and capabilities, and never a timestamp. Every parent is a directory in the same tree, so no path passes through a symlink, and every hard link points at a file. Every error names the entry and field: `entry 4 ("/usr/bin/rg"), field "mode": written with its default value, which must be left out`.

## File digests

`file_digests` reads any `Read` once and returns what a file entry records about the content: its size, its BLAKE3 digest and its fs-verity digest (SHA-256, 4 KiB blocks, no salt, the value `fsverity digest` prints and the kernel measures). `FileHasher` does the same for bytes given piece by piece. Neither opens a file; the caller supplies the bytes.

## Chunks and the chunk index

[`CHUNK-INDEX.md`](CHUNK-INDEX.md) is the reference for the index and the chunker (CC-BY-4.0).

- `chunk::chunk_file` reads any `Read` once and cuts it with FastCDC 2020. It returns the file's digests and its chunks, and hands each chunk's bytes to a callback as soon as the chunk is known. Memory stays at one buffer of the maximum chunk length. A file under the whole-file threshold is one chunk.
- `chunk::ChunkParams::DEFAULT` holds the settings ORD-100 measured: chunks of 256 KiB to 4 MiB, 1 MiB on average, normalization level 1, and files under 1 MiB kept whole.
- `chunk::ChunkIndex` records the settings and lists every file at or above the threshold, with its chunks' digests and lengths. It is canonical JSON with a BLAKE3 identity, read as strictly as a tree and one chunk at a time: an index at the format's limits takes about 28 MiB beyond its bytes. `ChunkIndex::chunks_of` tells a reader which chunks make up a file a tree records.
- The cut points match the `fastcdc` crate's, version 3.2.1. The tests check this, and the crate is only a test dependency.
