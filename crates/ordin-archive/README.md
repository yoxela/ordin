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

Reading `.ordin` files arrives with ORD-131.
