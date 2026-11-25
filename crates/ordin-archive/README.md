# ordin-archive

Reading and writing .ordin files in the OCI image layout. Layer 1 (infrastructure), licensed MIT OR Apache-2.0.

A `.ordin` file is one package: an OCI artifact in a deterministic ustar archive. `FORMAT.md` is the reference. Its layers, in order:
- the manifest
- the license texts
- one tree per facet
- the chunk index
- per facet, a pack table and a chunk pack of independent zstd frames

## Writing

`write(&package, &mut source, &options, spool_dir, &mut out)` writes a package:

- **`Package`** holds the manifest, the trees by facet, the license texts by ID, and the chunk settings.
- **`Source`** opens a file by its tree path. Each content is read once per facet.
- **`Options`** gives the zstd level (`LEVEL`, 19, by default) and the number of compression threads.
- **The spool directory** holds the chunk packs as anonymous temporary files until every blob's digest is known. Nothing is left there afterwards.

**What `write` checks.** It refuses a package whose parts disagree with the manifest:
- a missing or extra tree
- a tree digest or facet size that differs from the manifest
- a missing, extra or different license text

**Every file is checked as it is read.** Each file is cut into chunks with `ordin-tree`'s chunker, in the same pass that computes its digests. A file whose size or digests differ from its tree is refused, so a file that changed after the walk can't slip in. Every blob is hashed again as it is copied into the archive.

**The same input gives the same bytes:** the same package, chunk settings and level, on any number of threads. That holds while the zstd library is the same, and `Cargo.lock` pins it.

The ustar writer and the OCI JSON are Ordin's own, so a dependency update can't change the bytes. The tests read the output back with the `tar` crate and serde_json as second opinions.

## Reading

`Reader::open(input)` opens a `.ordin` file in place, from anything that can be read and seeked.

**Opening reads only the small parts:** the tar headers, `oci-layout`, `index.json`, the image manifest, the config and the Ordin manifest. It refuses anything the writer wouldn't have written: a header other than the writer's, entries out of order, padding that isn't zeros, OCI JSON other than the writer's, layers out of order or of unknown types, blobs that are missing or unused, and layers that disagree with the manifest.

**Everything else is read when asked for**, within its own limit, and checked against its digests:
- `license_text(id)`, `tree(facet)`, `chunk_index()` and `pack_table(facet)`
- `chunk(facet, table, chunk)`: one frame, decompressed into exactly the chunk's length and checked against its digest
- `read_file(facet, table, index, path, file, out)`: a file chunk by chunk, checked as a whole against its tree record at the end

A hostile file can't make the reader hold more than one part at a time. Each error names the `Part` that failed. `FORMAT.md` lists every check and limit.

## Verifying

`reader.verify()` checks every byte that opening didn't, and returns what it checked per facet (`Verified`):
- **Every blob** against both digests its descriptor records, the chunk packs included. A zstd frame can change in places that don't change what it decompresses to, so checking each chunk alone isn't enough.
- **Every part** as its reader reads it: license texts, trees, the chunk index and the pack tables.
- **Every file**, once per content in each facet, put together from its chunks, each checked against its digest. The whole is checked against the size, BLAKE3 and fs-verity digests its tree records.
- **The chunking.** Each file is cut again with the chunking the chunk index records, and must give exactly the chunks the index lists. The package's identity covers only the manifest, so a chunk index and packs with self-consistent digests could otherwise claim one chunking and carry another.
- **What the writer writes.** A chunk pack must hold only the chunks its facet's files use, in the order they first use them, and the chunk index must list only content at or above the whole-file threshold that some file has.

The checks run in that order, so a changed byte is reported against the part that holds it. Whether a signature's key is trusted is the caller's question: `ordin verify --trust` answers it.
