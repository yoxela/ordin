// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The chunk index: how each large file of a package is cut, in a single
//! canonical, hashable form.

use std::collections::BTreeMap;

use ordin_core::json::{self, Value};
use ordin_core::{Algorithm, Digest};

use super::error::{IndexError, IndexErrorKind};
use super::file::ChunkRef;
use super::params::ChunkParams;

/// The largest chunk index, in bytes.
pub const MAX_SIZE: usize = 64 << 20;

/// The most files a chunk index lists.
pub const MAX_FILES: usize = 1 << 18;

/// The most chunks a chunk index lists, over all its files.
pub const MAX_CHUNKS: usize = 1 << 19;

/// The format version's key.
const FORMAT: &str = "ordin-chunk-index";

/// The only chunking algorithm format 1 knows.
const ALGORITHM: &str = "fastcdc-2020";

type R<T> = Result<T, IndexError>;

/// One listed file: its content digest and its chunks in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexFile {
    content: Digest,
    chunks: Vec<ChunkRef>,
}

impl IndexFile {
    /// A file's entry. [`ChunkIndex::new`] checks it.
    #[must_use]
    pub fn new(content: Digest, chunks: Vec<ChunkRef>) -> Self {
        Self { content, chunks }
    }

    /// The BLAKE3 digest of the whole file: the file object's identity.
    #[must_use]
    pub fn content(&self) -> Digest {
        self.content
    }

    /// The chunks, in order.
    #[must_use]
    pub fn chunks(&self) -> &[ChunkRef] {
        &self.chunks
    }

    /// The file's size: its chunks' lengths added up.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.chunks
            .iter()
            .fold(0, |sum, c| sum.saturating_add(c.length))
    }

    /// Each chunk with its offset in the file.
    pub fn offsets(&self) -> impl Iterator<Item = (u64, &ChunkRef)> {
        self.chunks.iter().scan(0u64, |offset, chunk| {
            let at = *offset;
            *offset = offset.saturating_add(chunk.length);
            Some((at, chunk))
        })
    }
}

/// A chunk index: the chunker's settings and every file at or above its
/// whole-file threshold, sorted by content digest, every rule checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkIndex {
    chunking: ChunkParams,
    files: Vec<IndexFile>,
}

fn file_error(
    index: usize,
    f: &IndexFile,
    chunk: Option<usize>,
    field: Option<&str>,
    kind: IndexErrorKind,
) -> IndexError {
    IndexError::file(index, Some(&f.content.to_string()), chunk, field, kind)
}

/// The rules within one file.
fn check_file(index: usize, f: &IndexFile, params: &ChunkParams) -> R<()> {
    let err = |chunk, field, kind| file_error(index, f, chunk, field, kind);
    if f.content.algorithm() != Algorithm::Blake3 {
        return Err(err(None, Some("content"), IndexErrorKind::NotBlake3));
    }
    let Some((_, all_but_last)) = f.chunks.split_last() else {
        return Err(err(None, Some("chunks"), IndexErrorKind::NoChunks));
    };
    let maximum = params.maximum();
    for (c, chunk) in f.chunks.iter().enumerate() {
        if chunk.digest.algorithm() != Algorithm::Blake3 {
            return Err(err(Some(c), Some("digest"), IndexErrorKind::NotBlake3));
        }
        if !(1..=u64::from(maximum)).contains(&chunk.length) {
            return Err(err(
                Some(c),
                Some("length"),
                IndexErrorKind::ChunkLength {
                    maximum,
                    length: chunk.length,
                },
            ));
        }
    }
    let minimum = params.minimum();
    if let Some((c, chunk)) = all_but_last
        .iter()
        .enumerate()
        .find(|(_, c)| c.length < u64::from(minimum))
    {
        return Err(err(
            Some(c),
            Some("length"),
            IndexErrorKind::ChunkTooShort {
                minimum,
                length: chunk.length,
            },
        ));
    }
    let whole_below = params.whole_below();
    if f.size() < u64::from(whole_below) {
        return Err(err(
            None,
            None,
            IndexErrorKind::FileTooSmall {
                whole_below,
                size: f.size(),
            },
        ));
    }
    if let [only] = f.chunks.as_slice()
        && only.digest != f.content
    {
        return Err(err(Some(0), Some("digest"), IndexErrorKind::SingleChunk));
    }
    Ok(())
}

/// Checks every rule, for files in the order given.
fn check(params: &ChunkParams, files: &[IndexFile]) -> R<()> {
    if files.len() > MAX_FILES {
        return Err(IndexError::index(
            Some("files"),
            IndexErrorKind::TooManyFiles {
                max: MAX_FILES,
                len: files.len(),
            },
        ));
    }
    let chunks: usize = files.iter().map(|f| f.chunks.len()).sum();
    if chunks > MAX_CHUNKS {
        return Err(IndexError::index(
            Some("files"),
            IndexErrorKind::TooManyChunks { max: MAX_CHUNKS },
        ));
    }
    for (index, (previous, f)) in files.iter().zip(files.iter().skip(1)).enumerate() {
        let kind = match f.content.cmp(&previous.content) {
            std::cmp::Ordering::Greater => continue,
            std::cmp::Ordering::Equal => IndexErrorKind::Duplicate,
            std::cmp::Ordering::Less => IndexErrorKind::NotSorted {
                previous: previous.content.to_string(),
            },
        };
        return Err(file_error(index + 1, f, None, None, kind));
    }
    for (index, f) in files.iter().enumerate() {
        check_file(index, f, params)?;
    }
    Ok(())
}

fn s(text: impl ToString) -> Value {
    Value::Str(text.to_string())
}

/// A length or size as JSON. Every one an index holds is far below 2⁵³.
fn int(n: impl TryInto<i64>) -> Value {
    Value::Int(n.try_into().unwrap_or(i64::MAX))
}

/// The index's JSON value.
fn encode(params: &ChunkParams, files: &[IndexFile]) -> Value {
    let chunking = BTreeMap::from([
        ("algorithm".to_owned(), s(ALGORITHM)),
        ("minimum".to_owned(), int(params.minimum())),
        ("average".to_owned(), int(params.average())),
        ("maximum".to_owned(), int(params.maximum())),
        ("whole-below".to_owned(), int(params.whole_below())),
        ("normalization".to_owned(), int(params.normalization())),
    ]);
    let files = files
        .iter()
        .map(|f| {
            let chunks = f
                .chunks
                .iter()
                .map(|c| {
                    Value::Object(BTreeMap::from([
                        ("digest".to_owned(), s(c.digest)),
                        ("length".to_owned(), int(c.length)),
                    ]))
                })
                .collect();
            Value::Object(BTreeMap::from([
                ("content".to_owned(), s(f.content)),
                ("chunks".to_owned(), Value::Array(chunks)),
            ]))
        })
        .collect();
    Value::Object(BTreeMap::from([
        (FORMAT.to_owned(), Value::Int(1)),
        ("chunking".to_owned(), Value::Object(chunking)),
        ("files".to_owned(), Value::Array(files)),
    ]))
}

/// Where a value being decoded is: the index itself, a file, or one of
/// its chunks.
#[derive(Clone, Copy)]
struct At<'a> {
    file: Option<(usize, Option<&'a str>)>,
    chunk: Option<usize>,
}

impl At<'_> {
    const INDEX: Self = Self {
        file: None,
        chunk: None,
    };

    fn err(&self, field: Option<&str>, kind: IndexErrorKind) -> IndexError {
        match self.file {
            None => IndexError::index(field, kind),
            Some((index, content)) => IndexError::file(index, content, self.chunk, field, kind),
        }
    }

    fn wrong(&self, field: Option<&str>, expected: &'static str, found: &Value) -> IndexError {
        self.err(
            field,
            IndexErrorKind::WrongType {
                expected,
                found: found.type_name(),
            },
        )
    }

    /// `v` as an object with no fields outside `fields`.
    fn object<'v>(&self, v: &'v Value, fields: &[&str]) -> R<&'v BTreeMap<String, Value>> {
        let Value::Object(map) = v else {
            return Err(self.wrong(None, "an object", v));
        };
        if let Some(unknown) = map.keys().find(|k| !fields.contains(&k.as_str())) {
            return Err(self.err(Some(unknown), IndexErrorKind::UnknownField));
        }
        Ok(map)
    }

    fn get<'v>(&self, map: &'v BTreeMap<String, Value>, field: &str) -> R<&'v Value> {
        map.get(field)
            .ok_or_else(|| self.err(Some(field), IndexErrorKind::Missing))
    }

    fn string<'v>(&self, map: &'v BTreeMap<String, Value>, field: &str) -> R<&'v str> {
        match self.get(map, field)? {
            Value::Str(text) => Ok(text),
            other => Err(self.wrong(Some(field), "a string", other)),
        }
    }

    fn integer(&self, map: &BTreeMap<String, Value>, field: &str) -> R<u64> {
        match self.get(map, field)? {
            Value::Int(n) => u64::try_from(*n).map_err(|_| {
                self.err(
                    Some(field),
                    IndexErrorKind::Invalid("can't be negative".into()),
                )
            }),
            other => Err(self.wrong(Some(field), "an integer", other)),
        }
    }

    fn digest(&self, map: &BTreeMap<String, Value>, field: &str) -> R<Digest> {
        let digest: Digest = self
            .string(map, field)?
            .parse()
            .map_err(|e: ordin_core::Error| {
                self.err(Some(field), IndexErrorKind::Invalid(e.to_string()))
            })?;
        if digest.algorithm() != Algorithm::Blake3 {
            return Err(self.err(Some(field), IndexErrorKind::NotBlake3));
        }
        Ok(digest)
    }

    fn array<'v>(&self, map: &'v BTreeMap<String, Value>, field: &str) -> R<&'v [Value]> {
        match self.get(map, field)? {
            Value::Array(items) => Ok(items),
            other => Err(self.wrong(Some(field), "an array", other)),
        }
    }
}

const INDEX_FIELDS: [&str; 3] = [FORMAT, "chunking", "files"];
const CHUNKING_FIELDS: [&str; 6] = [
    "algorithm",
    "minimum",
    "average",
    "maximum",
    "whole-below",
    "normalization",
];
const FILE_FIELDS: [&str; 2] = ["content", "chunks"];
const CHUNK_FIELDS: [&str; 2] = ["digest", "length"];

fn decode_chunking(v: &Value) -> R<ChunkParams> {
    let field = |name: &str| format!("chunking.{name}");
    let at = At::INDEX;
    let Value::Object(map) = v else {
        return Err(at.wrong(Some("chunking"), "an object", v));
    };
    if let Some(unknown) = map.keys().find(|k| !CHUNKING_FIELDS.contains(&k.as_str())) {
        return Err(at.err(Some(&field(unknown)), IndexErrorKind::UnknownField));
    }
    let value = |name: &str| {
        map.get(name)
            .ok_or_else(|| at.err(Some(&field(name)), IndexErrorKind::Missing))
    };
    let number = |name: &str| match value(name)? {
        Value::Int(n) => u64::try_from(*n).map_err(|_| {
            at.err(
                Some(&field(name)),
                IndexErrorKind::Invalid("can't be negative".into()),
            )
        }),
        other => Err(at.wrong(Some(&field(name)), "an integer", other)),
    };
    match value("algorithm")? {
        Value::Str(name) if name == ALGORITHM => {}
        Value::Str(name) => {
            return Err(at.err(
                Some(&field("algorithm")),
                IndexErrorKind::UnknownAlgorithm(name.clone()),
            ));
        }
        other => return Err(at.wrong(Some(&field("algorithm")), "a string", other)),
    }
    ChunkParams::new(
        number("minimum")?,
        number("average")?,
        number("maximum")?,
        number("whole-below")?,
        number("normalization")?,
    )
    .map_err(|e| at.err(Some("chunking"), IndexErrorKind::Params(e)))
}

fn decode_file(index: usize, v: &Value) -> R<IndexFile> {
    let mut at = At {
        file: Some((index, None)),
        chunk: None,
    };
    let map = at.object(v, &FILE_FIELDS)?;
    let content = at.digest(map, "content")?;
    at.file = Some((index, at.string(map, "content").ok()));
    let chunks = at
        .array(map, "chunks")?
        .iter()
        .enumerate()
        .map(|(c, v)| {
            let at = At {
                chunk: Some(c),
                ..at
            };
            let map = at.object(v, &CHUNK_FIELDS)?;
            Ok(ChunkRef {
                digest: at.digest(map, "digest")?,
                length: at.integer(map, "length")?,
            })
        })
        .collect::<R<_>>()?;
    Ok(IndexFile { content, chunks })
}

fn decode(v: &Value) -> R<ChunkIndex> {
    let at = At::INDEX;
    let Value::Object(map) = v else {
        return Err(at.wrong(None, "an object", v));
    };
    match map.get(FORMAT) {
        None => return Err(at.err(Some(FORMAT), IndexErrorKind::Missing)),
        Some(Value::Int(1)) => {}
        Some(other) => {
            return Err(at.err(
                Some(FORMAT),
                IndexErrorKind::UnknownFormat(json::canonical(other)),
            ));
        }
    }
    let map = at.object(v, &INDEX_FIELDS)?;
    let chunking = decode_chunking(at.get(map, "chunking")?)?;
    let files = at
        .array(map, "files")?
        .iter()
        .enumerate()
        .map(|(i, v)| decode_file(i, v))
        .collect::<R<_>>()?;
    Ok(ChunkIndex { chunking, files })
}

/// Requires `written` to be exactly the bytes that were `read`.
fn same_encoding(read: &str, written: &str) -> R<()> {
    if read == written {
        return Ok(());
    }
    Err(IndexError::index(
        None,
        IndexErrorKind::NotCanonical {
            at: crate::first_difference(read.as_bytes(), written.as_bytes()),
        },
    ))
}

impl ChunkIndex {
    /// Builds an index from files in any order.
    ///
    /// # Errors
    ///
    /// Returns the first rule the files break, and where.
    pub fn new(chunking: ChunkParams, mut files: Vec<IndexFile>) -> R<Self> {
        files.sort_by_key(|f| f.content);
        check(&chunking, &files)?;
        Ok(Self { chunking, files })
    }

    /// Reads an index from its canonical bytes and returns it with its
    /// identity.
    ///
    /// # Errors
    ///
    /// Returns the first rule the bytes break, and where.
    pub fn from_canonical_bytes(bytes: &[u8]) -> R<(Self, Digest)> {
        if bytes.len() > MAX_SIZE {
            return Err(IndexError::index(
                None,
                IndexErrorKind::TooLarge {
                    max: MAX_SIZE,
                    len: bytes.len(),
                },
            ));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| IndexError::index(None, IndexErrorKind::NotUtf8))?;
        let value =
            json::parse(text).map_err(|e| IndexError::index(None, IndexErrorKind::Json(e.0)))?;
        same_encoding(text, &json::canonical(&value))?;
        let index = decode(&value)?;
        check(&index.chunking, &index.files)?;
        // Decoding refuses every choice the encoder wouldn't make, so
        // encoding gives back the same bytes. Check it anyway: the
        // identity must be the digest of exactly what was read.
        same_encoding(text, &json::canonical(&index.encode()))?;
        Ok((index, Digest::blake3(bytes)))
    }

    fn encode(&self) -> Value {
        encode(&self.chunking, &self.files)
    }

    /// The index's canonical bytes, checked against every rule.
    ///
    /// # Errors
    ///
    /// Returns the first rule the index breaks, and where.
    pub fn to_canonical_bytes(&self) -> R<Vec<u8>> {
        let bytes = json::canonical(&self.encode()).into_bytes();
        Self::from_canonical_bytes(&bytes)?;
        Ok(bytes)
    }

    /// The index's identity: the BLAKE3 digest of its canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns the first rule the index breaks, and where.
    pub fn digest(&self) -> R<Digest> {
        Ok(Digest::blake3(&self.to_canonical_bytes()?))
    }

    /// The settings the files were cut with.
    #[must_use]
    pub fn chunking(&self) -> &ChunkParams {
        &self.chunking
    }

    /// The listed files, sorted by content digest.
    #[must_use]
    pub fn files(&self) -> &[IndexFile] {
        &self.files
    }

    /// The listed file with this content digest, if there is one.
    #[must_use]
    pub fn get(&self, content: &Digest) -> Option<&IndexFile> {
        self.position(content).and_then(|i| self.files.get(i))
    }

    fn position(&self, content: &Digest) -> Option<usize> {
        self.files.binary_search_by(|f| f.content.cmp(content)).ok()
    }

    /// The chunks to fetch for a file a tree records with this content
    /// digest and size. A file under the whole-file threshold is one chunk,
    /// the file itself. A larger one must be listed, with chunks that add up
    /// to its size.
    ///
    /// # Errors
    ///
    /// A file at or above the threshold that isn't listed, or is listed
    /// with another size.
    pub fn chunks_of(&self, content: &Digest, size: u64) -> R<Vec<ChunkRef>> {
        if size < u64::from(self.chunking.whole_below()) {
            return Ok(vec![ChunkRef {
                digest: *content,
                length: size,
            }]);
        }
        let Some((index, f)) = self
            .position(content)
            .and_then(|i| Some((i, self.files.get(i)?)))
        else {
            return Err(IndexError::index(
                None,
                IndexErrorKind::NotListed {
                    content: content.to_string(),
                    size,
                },
            ));
        };
        if f.size() != size {
            return Err(file_error(
                index,
                f,
                None,
                None,
                IndexErrorKind::WrongSize {
                    listed: f.size(),
                    size,
                },
            ));
        }
        Ok(f.chunks.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_different_encoding_is_refused_where_it_differs() {
        assert!(same_encoding("{}", "{}").is_ok());
        assert_eq!(
            same_encoding("{\"a\":1}", "{\"a\":2}").unwrap_err().kind,
            IndexErrorKind::NotCanonical { at: 5 }
        );
    }

    #[test]
    fn lengths_far_beyond_any_index_are_written_as_the_largest_integer() {
        assert_eq!(int(5u64), Value::Int(5));
        assert_eq!(int(u64::MAX), Value::Int(i64::MAX));
    }
}
