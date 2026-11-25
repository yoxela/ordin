<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 The Ordin Authors -->

# The `.ordin` file, format 1

A `.ordin` file holds one package. It is an [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md) in a ustar archive, so any OCI registry can store the package unchanged, and a client can fetch any facet, or a single chunk, by range.

This document is the reference for the container. The parts inside it have their own references:
- the manifest: `ordin-manifest`'s `SCHEMA.md`
- signatures: `ordin-sign`'s `FORMAT.md`
- trees: `ordin-tree`'s `FORMAT.md`
- the chunk index: `ordin-tree`'s `CHUNK-INDEX.md`

`ordin-archive` writes files that follow this document, and reads them back with the checks in [How a reader checks a file](#how-a-reader-checks-a-file).

## Identity

**The package's identity is the BLAKE3 digest of its manifest,** whatever the container around it. Nothing in this document is part of that identity:
- the tar
- `index.json`
- the image manifest
- the pack tables
- the compressed chunks

## The archive

The file is a ustar archive of regular files only. It has no directory entries, no pax or GNU extensions, and nothing after the two closing zero blocks.

**Every header is the same apart from the name and size:**
- mode `0644`
- owner and group 0, with empty owner and group names
- modification time 0
- type `0`, a regular file
- magic `ustar`, version `00`
- empty link name, device numbers and prefix
- the name in the name field: at most 100 bytes
- the size in eleven octal digits, so an entry holds at most 8 GiB − 1 bytes

**The entries come in this order:**
1. `oci-layout`: `{"imageLayoutVersion":"1.0.0"}`
2. `index.json`
3. every blob, as `blobs/sha256/<64 lowercase hex digits>`, sorted by path. Each blob appears once, even when several descriptors name it.

## OCI JSON

`index.json` and the image manifest are canonical JSON (RFC 8785), like every other Ordin document.

**`index.json`** lists exactly one manifest. Its descriptor has:
- media type `application/vnd.oci.image.manifest.v1+json`
- artifact type `application/vnd.ordin.package.v1`

**The image manifest** is an OCI 1.1 artifact:
- `schemaVersion` 2
- media type `application/vnd.oci.image.manifest.v1+json`
- `artifactType` `application/vnd.ordin.package.v1`
- `config`: the empty descriptor, media type `application/vnd.oci.empty.v1+json`, whose blob `{}` is stored like any other
- `layers`: the parts, in the order below

**Every descriptor** has:
- `mediaType`
- `digest`: `sha256:<hex>`, which every OCI implementation verifies
- `size`
- the annotation `com.ordinpm.blake3`: the blob's BLAKE3 digest, which Ordin verifies

This includes the config descriptor and the manifest's descriptor in `index.json`.

## Layers

| Order | Part | Media type | Annotations besides `com.ordinpm.blake3` |
| --- | --- | --- | --- |
| 1 | The Ordin manifest | `application/vnd.ordin.manifest.v1+json` | |
| 2 | One signature per key, by key; none if the package is unsigned | `application/vnd.ordin.signature.v1+json` | `com.ordinpm.key`: the key, `ed25519:` and its hex |
| 3 | One license text per license ID, by ID | `application/vnd.ordin.license.v1` | `com.ordinpm.license`: the SPDX ID |
| 4 | One tree per facet, by facet | `application/vnd.ordin.tree.v1+json` | `com.ordinpm.facet` |
| 5 | The chunk index | `application/vnd.ordin.chunk-index.v1+json` | |
| 6 | One pack table per facet, by facet | `application/vnd.ordin.pack-table.v1+json` | `com.ordinpm.facet` |
| 7 | One chunk pack per facet, by facet | `application/vnd.ordin.chunk-pack.v1+zstd` | `com.ordinpm.facet` |

**What the parts must agree on:**
- **Facets and texts.** There is a tree, pack table and chunk pack for every facet the manifest lists, and a text for every license ID it records, each with the digest the manifest records.
- **Signatures.** Each signature is by the key its annotation names, and signs this package's identity. A package carries at most 64.
- **The chunk index** lists every file in any facet at or above its whole-file threshold, once per content.

**Signing changes only the container.** Adding, replacing or removing a signature leaves the manifest, and so the package's identity, as it is. Every other blob is copied byte for byte; only the signature layers, the image manifest and `index.json` change. A package signed as it is written and the same package signed afterwards are the same file.

**What is still to come:** legacy scripts, when a package has any, arrive as a layer with a later story. A reader refuses a layer it doesn't know, so that is a format change when it arrives.

## The chunk index is not signed

The manifest records each facet's tree, and each tree records each file's size and digests. The chunk index sits outside all of that: the manifest doesn't record its digest.

A changed index can't make a host install other content, because every file is checked against its tree when it is reassembled. It can only make a download fail.

Verifying (`ordin verify`, ORD-133) also cuts each file again with the index's recorded settings and compares, so a package can't claim one chunking and carry another.

## Chunk packs

A facet's chunk pack is every chunk its files need, each as an independent zstd frame, back to back.

**Order.** Chunks are stored in the order the facet's files first need them: files in path order, each file's chunks in order. A file's chunks therefore sit next to each other, so it can be fetched with one range request.

**Each chunk once per pack.** A chunk is stored once in a pack, even when several files or several places in one file need it. A chunk two facets share is stored in both packs, so each facet can be fetched alone.

**An empty pack.** A facet with no files has an empty pack (0 bytes) and a pack table with no chunks.

**Frames.**
- Each frame records its uncompressed size in its header.
- A frame has no checksum and no dictionary ID: each chunk is verified by the BLAKE3 digest of its uncompressed bytes.
- A reader decompresses a frame into exactly the chunk's length, which the chunk index or the tree gives, and refuses anything else.

## Pack tables

A pack table says where each chunk's frame is in its facet's pack, in compressed bytes. Its rules:
- It is canonical JSON, with no timestamps and integers only, like every Ordin document.
- The `chunks` array is always present, even when it's empty.

```json
{"chunks":[{"digest":"blake3:…","length":9581,"offset":0}],"ordin-pack-table":1,"zstd-level":19}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `ordin-pack-table` | integer | The format version: `1`. |
| `zstd-level` | integer | The zstd level the frames were made at, 1 to 22. Packages are written at 19. |
| `chunks` | array | The pack's chunks, in pack order. |
| `chunks[].digest` | *digest* | `blake3:` and the digest of the chunk's uncompressed bytes. Each digest appears once. |
| `chunks[].offset` | integer | Where the frame starts, in bytes from the start of the pack. The first is 0, and each next one starts where the one before it ends. |
| `chunks[].length` | integer | The frame's length in bytes. The last frame ends where the pack ends. |

A table names the chunks its facet's files need, and no others.

**How many chunks a table can have.** A table has at most as many chunks as its facet has files under the whole-file threshold, plus the chunks the index lists for the facet's larger files. The tree's and chunk index's limits keep that to 786,432.

## Reproducibility

**What makes the same bytes.** The same package, chunk settings and zstd level always give the same file, on any number of threads. Chunks are compressed independently, so how the work is split doesn't change the frames.

**What can change them.** zstd's compressed output can change between library versions. `Cargo.lock` therefore pins the zstd crate and its bundled libzstd (1.5.7):
- The build always compiles the bundled copy.
- Setting `ZSTD_SYS_USE_PKG_CONFIG` would link the system's libzstd instead. Ordin's release builds never set it.

Compare whole `.ordin` files only within one Ordin version. The reproducibility check (ORD-150) compares manifest digests.

## How a reader checks a file

A `.ordin` file is outside input. A reader accepts only what a writer of this format writes, and never holds more than one part in memory at a time.

**Opening reads only the small parts,** and checks:
- **The archive.** Every header must be exactly the one this document gives for its name and size. The entries must be `oci-layout`, `index.json`, then blobs named `blobs/sha256/<64 lowercase hex digits>` in strictly increasing order. Padding must be zeros, and the file must end with exactly two zero blocks.
- **The OCI files.** `oci-layout` must be the fixed text. `index.json` and the image manifest must be exactly the canonical JSON this document gives for their descriptors. The config must be the empty descriptor with its `{}` blob.
- **The layers.** They must come in the order of the table above, each of a known type, with exactly the annotations it lists. Keys, licenses and facets must be in increasing order, with no repeats.
- **The blobs.** Every blob a descriptor names must be in the archive with its recorded size, and every blob in the archive must be named. Two descriptors that name one blob must record the same digests. Each blob that is read is checked against its SHA-256 and BLAKE3 digests.
- **The manifest** must follow its schema. The layers must have a tree, pack table and chunk pack for every facet it lists and no others, each tree with the digest it records, and a text for every license ID it records and no others, each with the digest it records.
- **Each signature** must follow its format, verify, be by the key its annotation names, and sign this package. A signature that fails any of these is refused, never skipped. Whether a key is trusted is for whoever reads the package to decide.

**Every other part is read when asked for,** and checked then:
- **A tree** must follow its format, and its files' sizes must add up to the size the manifest records for the facet.
- **A pack table** must be exactly the canonical text, with each frame 1 to 16,842,752 bytes long and starting where the one before it ends, and the last ending where the pack ends.
- **A chunk** must be listed in its pack table, inside the pack. Its frame must start with zstd's magic number, have no checksum or dictionary ID, be exactly one frame, and record exactly the chunk's length. It is decompressed with a window of at most 16 MiB, and must have the chunk's BLAKE3 digest.
- **A file** is put together from the chunks the chunk index lists for it. Each chunk is checked as it is read, and the whole must have the size and content digest its tree records. This is what keeps the unsigned chunk index harmless.

**Verifying reads everything** (`Reader::verify`, ORD-133), in this order, so a changed byte is reported against the part that holds it:
- **Every blob** against its SHA-256 and BLAKE3 digests, the chunk packs included: a zstd frame has bytes that can change without changing what it decompresses to.
- **Every part** as above: each license text, tree and pack table, and the chunk index.
- **Every file**, once per content in each facet, put together from its chunks. The whole must also have the fs-verity digest its tree records.
- **The chunking.** Each file, cut again with the chunking the chunk index records, must give exactly the chunks the index lists for it. A file under the whole-file threshold is its one chunk.
- **The pack.** A facet's chunk pack must hold exactly the chunks its files use, in the order they first use them, as the Order rule above says.
- **The index** must list only content that a file at or above the whole-file threshold has.

**The limits:**

| Part | Limit | Why |
| --- | --- | --- |
| Tar entries | 65,536 | The image manifest's limit allows fewer descriptors than that. |
| `index.json` | 4 KiB | It lists one manifest, about 400 bytes. |
| The image manifest | 4 MiB | The size every OCI registry must accept. |
| The manifest | 1 MiB | The manifest's own limit. |
| Signatures | 64, of at most 1 KiB each | One per key: enough for a publisher and rebuilders, and each is checked when the file is opened. |
| A license text | 1 MiB | `ordin pack` reads no more. |
| A tree, the chunk index | 64 MiB each | Their own limits. |
| A pack table | 786,432 chunks, 96,731,186 bytes | One chunk per file a tree can hold, plus every chunk the chunk index can list. |
| A chunk | 16 MiB | The largest chunk any chunking allows. |
| A frame | 16,842,752 bytes | zstd's bound for a 16 MiB chunk. |

A writer refuses a package that would break any of these limits.
