// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Checking every byte of a `.ordin` file.
//!
//! [`Reader::open`] checks the archive, the OCI JSON, the manifest and the
//! signatures. [`Reader::verify`] reads everything else, in an order that
//! makes the part it names the part a changed byte is in: first every
//! blob against both its digests, then each part as its reader reads it,
//! then each file put together from its chunks and cut again with the
//! chunking the chunk index records. Last, it refuses anything else the
//! writer wouldn't have written: a chunk no file uses, chunks out of the
//! order the writer stores them in, and an index entry nothing needs.

use std::collections::BTreeSet;
use std::io::{self, Cursor, Read, Seek, SeekFrom};

use ordin_core::{Digest, Facet};
use ordin_tree::chunk::{ChunkIndex, ChunkParams, ChunkRef, chunk_file};
use ordin_tree::{File, Kind, TreePath};

use super::{Reader, io_error};
use crate::blob::{BlobId, HashingReader};
use crate::error::{Part, ReadError, ReadErrorKind};
use crate::pack::PackTable;

/// What [`Reader::verify`] checked.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Verified {
    /// Each facet, in order.
    pub facets: Vec<VerifiedFacet>,
    /// How many license texts the package carries.
    pub licenses: usize,
    /// How many signatures it carries. Each verifies; whether its key is
    /// trusted is the caller's question.
    pub signatures: usize,
}

/// One facet [`Reader::verify`] checked.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedFacet {
    /// The facet.
    pub facet: Facet,
    /// How many files its tree has, hard links counted each time.
    pub files: usize,
    /// How many chunks its chunk pack holds.
    pub chunks: usize,
    /// How many bytes of file content its tree has, as the manifest
    /// records.
    pub size: u64,
}

/// A file's content, read from its chunks one at a time: each chunk is
/// checked against its digest as it is read. The first error is kept, so
/// it can be given instead of the I/O error the chunker sees.
struct Content<'a, R> {
    reader: &'a mut Reader<R>,
    facet: &'a Facet,
    table: &'a PackTable,
    chunks: std::slice::Iter<'a, ChunkRef>,
    current: Cursor<Vec<u8>>,
    failed: Option<ReadError>,
}

impl<R: Read + Seek> Read for Content<'_, R> {
    /// Gives what is left of the current chunk, reading the next one when
    /// it is used up. Each pass uses up a chunk, so this always ends.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let count = self.current.read(buf)?;
            if count > 0 || buf.is_empty() {
                return Ok(count);
            }
            let Some(chunk) = self.chunks.next() else {
                return Ok(0);
            };
            match self.reader.chunk(self.facet, self.table, chunk) {
                Ok(bytes) => self.current = Cursor::new(bytes),
                Err(e) => {
                    self.failed = Some(e);
                    return Err(io::Error::other("a chunk failed its check"));
                }
            }
        }
    }
}

/// Where two lists of chunks first differ: the first chunk that isn't the
/// same in both, or the end of the shorter one.
fn first_difference(a: &[ChunkRef], b: &[ChunkRef]) -> usize {
    a.iter()
        .zip(b)
        .position(|(a, b)| a != b)
        .unwrap_or(a.len().min(b.len()))
}

/// Refuses a pack that holds a chunk no file uses, or holds its chunks in
/// another order than `used`, the order the facet's files first use them
/// in. `seen` is the set of `used`.
fn check_pack(
    facet: &Facet,
    table: &PackTable,
    used: &[Digest],
    seen: &BTreeSet<Digest>,
) -> Result<(), ReadError> {
    let error = |kind| ReadError::new(Part::ChunkPack(facet.clone()), kind);
    if let Some(chunk) = table.chunks().iter().find(|c| !seen.contains(&c.digest)) {
        return Err(error(ReadErrorKind::UnusedChunk {
            digest: chunk.digest,
        }));
    }
    // Every chunk used was read from the table, and a table repeats no
    // chunk, so the two hold the same chunks: only the order can differ.
    if let Some(at) = table
        .chunks()
        .iter()
        .zip(used)
        .position(|(c, d)| c.digest != *d)
    {
        return Err(error(ReadErrorKind::ChunkOrder { at }));
    }
    Ok(())
}

impl<R: Read + Seek> Reader<R> {
    /// Checks every byte of the package. Opening it checked the archive,
    /// the OCI JSON, the manifest and the signatures; this reads and
    /// checks everything else:
    ///
    /// - every blob against both the digests its descriptor records;
    /// - every license text, tree, pack table and the chunk index, as
    ///   their readers read them;
    /// - every file of every facet, put together from its chunks, each
    ///   checked against its digest, against the size, content digest and
    ///   fs-verity digest its tree records;
    /// - that cutting each file again with the chunking the chunk index
    ///   records gives exactly the chunks the index lists, so an index
    ///   can't claim one chunking and carry another;
    /// - that each chunk pack holds only the chunks its facet's files use,
    ///   in the order they first use them, and that the chunk index lists
    ///   only content a file needs listed, as the writer writes them.
    ///
    /// It holds one part, or one chunk and one chunker buffer, at a time.
    ///
    /// # Errors
    ///
    /// The first part that fails, named by the error: a blob that isn't
    /// what its descriptor records, any error the part's reader gives, a
    /// file whose content isn't what its tree records or that cuts into
    /// other chunks, a chunk nothing uses or out of order, an index entry
    /// nothing uses, or an error reading the input.
    pub fn verify(&mut self) -> Result<Verified, ReadError> {
        for (part, id) in self.parts.clone() {
            self.check_blob(&part, &id)?;
        }
        let licenses: Vec<String> = self.license_ids().map(str::to_owned).collect();
        for id in &licenses {
            self.license_text(id)?;
        }
        let index = self.chunk_index()?;
        let facets: Vec<Facet> = self.facets().cloned().collect();
        let mut listed = BTreeSet::new();
        let mut checked = Vec::with_capacity(facets.len());
        for facet in &facets {
            let tree = self.tree(facet)?;
            let table = self.pack_table(facet)?;
            let (mut files, mut done) = (0, BTreeSet::new());
            let (mut used, mut seen) = (Vec::new(), BTreeSet::new());
            for entry in tree.entries() {
                let Kind::File(file) = &entry.kind else {
                    continue;
                };
                files += 1;
                if !done.insert(file.content) {
                    continue;
                }
                let chunks = self.check_file(facet, &table, &index, &entry.path, file)?;
                if file.size >= u64::from(index.chunking().whole_below()) {
                    listed.insert(file.content);
                }
                for chunk in chunks {
                    if seen.insert(chunk.digest) {
                        used.push(chunk.digest);
                    }
                }
            }
            check_pack(facet, &table, &used, &seen)?;
            checked.push(VerifiedFacet {
                facet: facet.clone(),
                files,
                chunks: table.chunks().len(),
                size: self.manifest.facets.get(facet).map_or(0, |f| f.size),
            });
        }
        if let Some(extra) = index
            .files()
            .iter()
            .find(|f| !listed.contains(&f.content()))
        {
            return Err(ReadError::new(
                Part::ChunkIndex,
                ReadErrorKind::UnusedIndexEntry {
                    content: extra.content(),
                },
            ));
        }
        Ok(Verified {
            facets: checked,
            licenses: licenses.len(),
            signatures: self.signatures.len(),
        })
    }

    /// Reads the blob `id` as it streams past and checks both its digests.
    /// A blob cut short can't match: its size is part of its identity.
    fn check_blob(&mut self, part: &Part, id: &BlobId) -> Result<(), ReadError> {
        let blob = self.blob(Some(id), part)?;
        self.input
            .seek(SeekFrom::Start(blob.offset))
            .map_err(io_error(part.clone()))?;
        let mut hashing = HashingReader::new((&mut self.input).take(id.size));
        io::copy(&mut hashing, &mut io::sink()).map_err(io_error(part.clone()))?;
        let read = hashing.finish();
        if read != *id {
            return Err(ReadError::new(
                part.clone(),
                ReadErrorKind::Corrupt {
                    recorded: id.blake3,
                    read: read.blake3,
                },
            ));
        }
        Ok(())
    }

    /// Puts the file `path` together from its chunks, checks it against
    /// its tree's record, and cuts it again with the index's chunking.
    /// Returns its chunks.
    fn check_file(
        &mut self,
        facet: &Facet,
        table: &PackTable,
        index: &ChunkIndex,
        path: &TreePath,
        file: &File,
    ) -> Result<Vec<ChunkRef>, ReadError> {
        let error = |kind| {
            ReadError::new(
                Part::File {
                    facet: facet.clone(),
                    path: path.clone(),
                },
                kind,
            )
        };
        let chunks = index
            .chunks_of(&file.content, file.size)
            .map_err(|e| error(ReadErrorKind::ChunkIndex(Box::new(e))))?;
        let chunking: ChunkParams = *index.chunking();
        let mut content = Content {
            reader: self,
            facet,
            table,
            chunks: chunks.iter(),
            current: Cursor::new(Vec::new()),
            failed: None,
        };
        let cut = chunk_file(&mut content, &chunking, |_, _| Ok(()));
        if let Some(e) = content.failed {
            return Err(e);
        }
        // The content comes from chunks the index lists, so only cutting
        // it into more chunks than an index can list fails here.
        let cut = cut.map_err(|e| error(ReadErrorKind::Disagrees(e.to_string())))?;
        let read = cut.digests();
        if read.size != file.size || read.content != file.content {
            return Err(error(ReadErrorKind::Content {
                recorded_size: file.size,
                recorded: file.content,
                read_size: read.size,
                read: read.content,
            }));
        }
        if read.fsverity != file.fsverity {
            return Err(error(ReadErrorKind::Fsverity {
                recorded: file.fsverity,
                read: read.fsverity,
            }));
        }
        if cut.chunks() != chunks.as_slice() {
            return Err(error(ReadErrorKind::Rechunked {
                chunking,
                at: first_difference(cut.chunks(), &chunks),
            }));
        }
        Ok(chunks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_of_chunks_first_differ_where_a_chunk_differs_or_one_ends() {
        let c = |n: u8, length| ChunkRef {
            digest: Digest::blake3(&[n]),
            length,
        };
        let a = [c(1, 1), c(2, 1), c(3, 1)];
        assert_eq!(first_difference(&a, &a), 3);
        assert_eq!(first_difference(&a, &[c(1, 1), c(9, 1), c(3, 1)]), 1);
        assert_eq!(first_difference(&a, &[c(1, 2)]), 0);
        assert_eq!(first_difference(&a, &a[..2]), 2);
        assert_eq!(first_difference(&a[..1], &a), 1);
        assert_eq!(first_difference(&[], &a), 0);
    }
}
