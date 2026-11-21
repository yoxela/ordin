<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 The Ordin Authors -->

# The Ordin chunk index, format 1

Repositories and `.ordin` files move file content in content-defined chunks, so similar versions of a large file share most of their chunks and an interrupted download resumes where it stopped. A host joins the chunks back into whole files as they arrive and never keeps them.

A package has one chunk index. It records how the package's files were cut and lists every large file with its chunks. **An index's identity is the BLAKE3 digest of its canonical bytes**, written `blake3:<64 lowercase hex digits>`.

This document is the reference for every field and for the chunker. `ordin-tree` implements both, and an index that doesn't follow it is refused.

## Encoding rules

The tree's rules apply (see `FORMAT.md`):
- canonical JSON (RFC 8785), required byte for byte
- strict reading: duplicate keys, unknown fields and numbers that aren't integers are refused
- no timestamps

Also:

- **Files sorted by content digest** (the bytes of the digest, which is also the order of its hex text), with no file twice.
- **Only uncompressed bytes.** A chunk is named by the BLAKE3 digest of its uncompressed bytes, and lengths count uncompressed bytes. zstd's output can change between library versions, so compressed sizes live only in a container's own tables, outside any identity.
- **Limits.** An index is at most 64 MiB, and lists at most 262,144 files and 524,288 chunks in all. The chunker refuses a file it would cut into more chunks than that, since no index could list it.

## The index

```json
{"chunking":{...},"files":[...],"ordin-chunk-index":1}
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `ordin-chunk-index` | integer | yes | The format version: `1`. A reader refuses a version it doesn't know, before looking at any other field. |
| `chunking` | object | yes | How the files were cut: see below. |
| `files` | array of files | yes | Every file at or above the whole-file threshold, sorted. May be empty. |

## Chunking

Every field is required, so two indexes made with different settings never encode identically. Readers only follow the index and never re-chunk. The settings are there so that `ordin verify` and the reproducibility check can cut the files again and compare.

| Field | Type | Meaning |
| --- | --- | --- |
| `algorithm` | string | `"fastcdc-2020"`, the chunker below. Format 1 knows no other. |
| `minimum` | integer | No chunk but a file's last is shorter. A power of two, 64 to 1,048,576. |
| `average` | integer | The length chunks are normalized around. A power of two, 256 to 4,194,304. |
| `maximum` | integer | No chunk is longer. A power of two, 1,024 to 16,777,216. |
| `whole-below` | integer | A file shorter than this is one chunk and isn't listed. Between `minimum` and `maximum`. |
| `normalization` | integer | 0 to 3: how much more likely a cut is after the average than before it. |

The minimum, average and maximum don't decrease. `ordin pack` writes the settings that ORD-100 measured:

```json
{"algorithm":"fastcdc-2020","average":1048576,"maximum":4194304,"minimum":262144,"normalization":1,"whole-below":1048576}
```

## Files

```json
{"chunks":[{"digest":"blake3:…","length":1108502},{"digest":"blake3:…","length":774520}],"content":"blake3:…"}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `content` | *digest* | The BLAKE3 digest of the whole file, the same as its tree entry's `content`. |
| `chunks` | array of chunks | The file's chunks in order. At least one. |
| `chunks[].digest` | *digest* | The BLAKE3 digest of the chunk's bytes. |
| `chunks[].length` | integer | The chunk's length in bytes. |

- **Lengths:**
  - Every chunk is 1 byte to `maximum`.
  - Every chunk but the last is at least `minimum`.
  - The lengths add up to the file's size, which is at least `whole-below`.
- **Offsets aren't recorded.** A chunk's offset is the sum of the lengths before it.
- **One chunk is the whole file.** A file with a single chunk has a chunk digest equal to its `content`.
- **Small files aren't listed.** A file under `whole-below` is one chunk, the file itself, named by its content digest. Listing it would only repeat its tree entry.

### Finding a file's chunks

For each file a tree records, with its `content` and `size`:

1. If `size` is under `whole-below`, fetch one chunk: `content`, `size` bytes long.
2. Otherwise the index must list `content`, with lengths adding up to `size`. Fetch its chunks in order. A file the index doesn't list, or lists with another size, is an error.

Each chunk is checked against its digest as it arrives, and the joined file against `content`.

## The chunker: `fastcdc-2020`

This is FastCDC as published in 2020 (Xia et al., "The Design of Fast Content-Defined Chunking for Data Deduplication Based Storage Systems"), with its gear hash, sub-minimum cut-point skipping and normalized chunking. It gives the same cut points as the `fastcdc` crate's `v2020` module, version 3.2.1. Ordin implements it itself, so a crate update can never change where files are cut.

**Gear table.** For each byte value `b` from 0 to 255, `GEAR[b]` is the first 8 bytes, read big-endian, of the MD5 digest of 64 bytes all equal to `b`. For example, `GEAR[0]` is `0x3b5d3c7d207e37dc`: the start of `head -c 64 /dev/zero | md5sum`.

**Masks.** With `bits` = log₂(`average`) and `n` = `normalization`, the chunker uses `MASK_S = MASKS[bits + n]` before the average and `MASK_L = MASKS[bits − n]` from the average on:

| Bits | Mask | Bits | Mask | Bits | Mask |
| --- | --- | --- | --- | --- | --- |
| 5 | `0x0000000001804110` | 12 | `0x0000d90103530000` | 19 | `0x0000d91707537000` |
| 6 | `0x0000000001803110` | 13 | `0x0000d90303530000` | 20 | `0x0000d91747537000` |
| 7 | `0x0000000018035100` | 14 | `0x0000d90313530000` | 21 | `0x0000d91767537000` |
| 8 | `0x0000001800035300` | 15 | `0x0000d90f03530000` | 22 | `0x0000d93767537000` |
| 9 | `0x0000019000353000` | 16 | `0x0000d90303537000` | 23 | `0x0000d93777537000` |
| 10 | `0x0000590003530000` | 17 | `0x0000d90703537000` | 24 | `0x0000d93777577000` |
| 11 | `0x0000d90003530000` | 18 | `0x0000d90707537000` | 25 | `0x0000db3777577000` |

The values for 6 to 17 bits come from the C reference implementation (destor), and the others from restic's FastCDC.

**Cutting.** A file at or above `whole-below` is cut from its start. Each chunk is found in `data`, the rest of the file, by this procedure:

1. If `data` is at most `minimum` bytes, it's the last chunk.
2. Let `remaining` = min(len(`data`), `maximum`), and `center` = min(`remaining`, `average`).
3. Let `hash` = 0. For each position `p` from `minimum` up to, but not including, `remaining` rounded down to an even number:
   - `hash` = (`hash` × 2 + `GEAR[data[p]]`) mod 2⁶⁴
   - Let `mask` be `MASK_S` if `p` is less than `center` rounded down to an even number, and `MASK_L` otherwise.
   - If `hash` AND `mask` is 0, the chunk is the first `p` bytes. Stop.
4. If no position matched, the chunk is the first `remaining` bytes.

The procedure keeps three quirks of the paper's two-bytes-at-a-time loop:
- the byte at the matching position starts the next chunk
- the search stops at the last even position
- bytes before `minimum` never affect the hash

## Example

With chunks of 64 to 1,024 bytes, 256 on average, and files under 256 bytes kept whole:

```json
{"chunking":{"algorithm":"fastcdc-2020","average":256,"maximum":1024,"minimum":64,"normalization":1,"whole-below":256},
 "files":[{"chunks":[{"digest":"blake3:…","length":100},{"digest":"blake3:…","length":200}],"content":"blake3:…"}],
 "ordin-chunk-index":1}
```

Line breaks are added here for reading, and digests are left out; the real encoding has neither. The test `an_index_encodes_as_documented` in `tests/chunk_index.rs` builds this index with real digests.
