// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The chunk index: how each large file of a package is cut, in a single
//! canonical, hashable form.

use std::collections::BTreeMap;

use ordin_core::json::{self, JsonError, LayoutError, Member, Value};
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

/// The most JSON values the chunking settings, a chunk or a content
/// digest may hold. The settings hold the most: their object and six
/// fields.
const LEAF_VALUES: usize = 16;

/// The most JSON values an unknown format version may hold to be shown.
const VERSION_VALUES: usize = 64;

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

fn encode_chunking(params: &ChunkParams) -> Value {
    Value::Object(BTreeMap::from([
        ("algorithm".to_owned(), s(ALGORITHM)),
        ("minimum".to_owned(), int(params.minimum())),
        ("average".to_owned(), int(params.average())),
        ("maximum".to_owned(), int(params.maximum())),
        ("whole-below".to_owned(), int(params.whole_below())),
        ("normalization".to_owned(), int(params.normalization())),
    ]))
}

fn encode_chunk(c: &ChunkRef) -> Value {
    Value::Object(BTreeMap::from([
        ("digest".to_owned(), s(c.digest)),
        ("length".to_owned(), int(c.length)),
    ]))
}

/// The index's canonical text, written a chunk at a time.
fn text(params: &ChunkParams, files: &[IndexFile]) -> String {
    let mut out = String::from("{\"chunking\":");
    json::write_canonical(&encode_chunking(params), &mut out);
    out.push_str(",\"files\":[");
    for (i, f) in files.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"chunks\":[");
        for (c, chunk) in f.chunks.iter().enumerate() {
            if c > 0 {
                out.push(',');
            }
            json::write_canonical(&encode_chunk(chunk), &mut out);
        }
        out.push_str("],\"content\":");
        json::write_canonical(&s(f.content), &mut out);
        out.push('}');
    }
    out.push_str("],\"");
    out.push_str(FORMAT);
    out.push_str("\":1}");
    out
}

/// The index's JSON value: the encoding before [`text`], kept for the
/// tests to compare with.
#[cfg(test)]
fn encode(params: &ChunkParams, files: &[IndexFile]) -> Value {
    let files = files
        .iter()
        .map(|f| {
            let chunks = f.chunks.iter().map(encode_chunk).collect();
            Value::Object(BTreeMap::from([
                ("content".to_owned(), s(f.content)),
                ("chunks".to_owned(), Value::Array(chunks)),
            ]))
        })
        .collect();
    Value::Object(BTreeMap::from([
        (FORMAT.to_owned(), Value::Int(1)),
        ("chunking".to_owned(), encode_chunking(params)),
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

    /// A layout error, with `field` named if it is a value of the wrong
    /// type. The other errors are the index's.
    fn layout(&self, field: Option<&str>, e: LayoutError) -> IndexError {
        match e {
            LayoutError::Json(e) => json_error(e),
            LayoutError::NotCanonical { at } => {
                IndexError::index(None, IndexErrorKind::NotCanonical { at })
            }
            LayoutError::WrongType { expected, found } => {
                self.err(field, IndexErrorKind::WrongType { expected, found })
            }
        }
    }

    #[cfg(test)]
    fn string<'v>(&self, map: &'v BTreeMap<String, Value>, field: &str) -> R<&'v str> {
        self.string_value(field, self.get(map, field)?)
    }

    fn string_value<'v>(&self, field: &str, v: &'v Value) -> R<&'v str> {
        match v {
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
        self.digest_value(field, self.get(map, field)?)
    }

    fn digest_value(&self, field: &str, v: &Value) -> R<Digest> {
        let digest: Digest =
            self.string_value(field, v)?
                .parse()
                .map_err(|e: ordin_core::Error| {
                    self.err(Some(field), IndexErrorKind::Invalid(e.to_string()))
                })?;
        if digest.algorithm() != Algorithm::Blake3 {
            return Err(self.err(Some(field), IndexErrorKind::NotBlake3));
        }
        Ok(digest)
    }

    #[cfg(test)]
    fn array<'v>(&self, map: &'v BTreeMap<String, Value>, field: &str) -> R<&'v [Value]> {
        match self.get(map, field)? {
            Value::Array(items) => Ok(items),
            other => Err(self.wrong(Some(field), "an array", other)),
        }
    }
}

#[cfg(test)]
const INDEX_FIELDS: [&str; 3] = [FORMAT, "chunking", "files"];
const CHUNKING_FIELDS: [&str; 6] = [
    "algorithm",
    "minimum",
    "average",
    "maximum",
    "whole-below",
    "normalization",
];
#[cfg(test)]
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

/// One chunk, from its object.
fn decode_chunk(at: &At<'_>, v: &Value) -> R<ChunkRef> {
    let map = at.object(v, &CHUNK_FIELDS)?;
    Ok(ChunkRef {
        digest: at.digest(map, "digest")?,
        length: at.integer(map, "length")?,
    })
}

fn json_error(e: JsonError) -> IndexError {
    IndexError::index(None, IndexErrorKind::Json(e.0))
}

/// Requires `written` to be exactly what `read` holds.
fn same(read: Member<'_>, written: &str) -> R<()> {
    if read.text == written {
        return Ok(());
    }
    Err(IndexError::index(
        None,
        IndexErrorKind::NotCanonical {
            at: read.at + json::first_difference(read.text.as_bytes(), written.as_bytes()),
        },
    ))
}

/// A small part of the index as a JSON value, which must be written
/// canonically.
fn leaf(m: Member<'_>) -> R<Value> {
    let value = json::parse_bounded(m.text, m.at, LEAF_VALUES).map_err(json_error)?;
    same(m, &json::canonical(&value))?;
    Ok(value)
}

/// Reads an index from its canonical text a chunk at a time: the text is
/// checked as JSON without building it, then walked as written. Only the
/// result and one chunk's JSON value are in memory at once. The format
/// version is checked before any other field.
fn read(text: &str) -> R<ChunkIndex> {
    json::check_syntax(text).map_err(json_error)?;
    let at = At::INDEX;
    let json::Object {
        members: [chunking, files, version],
        unknown,
    } = json::object(text, 0, ["chunking", "files", FORMAT]).map_err(|e| at.layout(None, e))?;
    match version {
        None => return Err(at.err(Some(FORMAT), IndexErrorKind::Missing)),
        Some(v) if v.text == "1" => {}
        Some(v) => {
            let shown = json::parse_bounded(v.text, v.at, VERSION_VALUES).map_err(json_error)?;
            return Err(at.err(
                Some(FORMAT),
                IndexErrorKind::UnknownFormat(json::canonical(&shown)),
            ));
        }
    }
    if let Some(name) = unknown {
        return Err(at.err(Some(&name), IndexErrorKind::UnknownField));
    }
    let Some(chunking) = chunking else {
        return Err(at.err(Some("chunking"), IndexErrorKind::Missing));
    };
    let params = decode_chunking(&leaf(chunking)?)?;
    // Decoding refuses every choice the encoder wouldn't make, so encoding
    // gives back the same text. Check it anyway, here and for each chunk
    // and digest: the identity must be the digest of exactly what was read.
    same(chunking, &json::canonical(&encode_chunking(&params)))?;
    let Some(files) = files else {
        return Err(at.err(Some("files"), IndexErrorKind::Missing));
    };
    let mut out = Vec::new();
    for (index, item) in json::array(files.text, files.at)
        .map_err(|e| at.layout(Some("files"), e))?
        .enumerate()
    {
        out.push(read_file(index, item.map_err(|e| at.layout(None, e))?)?);
    }
    Ok(ChunkIndex {
        chunking: params,
        files: out,
    })
}

/// One listed file, from its object's text.
fn read_file(index: usize, item: Member<'_>) -> R<IndexFile> {
    let at = At {
        file: Some((index, None)),
        chunk: None,
    };
    let json::Object {
        members: [chunks, content],
        unknown,
    } = json::object(item.text, item.at, ["chunks", "content"]).map_err(|e| at.layout(None, e))?;
    if let Some(name) = unknown {
        return Err(at.err(Some(&name), IndexErrorKind::UnknownField));
    }
    let Some(content) = content else {
        return Err(at.err(Some("content"), IndexErrorKind::Missing));
    };
    let written = leaf(content)?;
    let digest = at.digest_value("content", &written)?;
    same(content, &json::canonical(&s(digest)))?;
    let at = At {
        file: Some((index, at.string_value("content", &written).ok())),
        chunk: None,
    };
    let Some(chunks) = chunks else {
        return Err(at.err(Some("chunks"), IndexErrorKind::Missing));
    };
    let mut out = Vec::new();
    for (c, item) in json::array(chunks.text, chunks.at)
        .map_err(|e| at.layout(Some("chunks"), e))?
        .enumerate()
    {
        let item = item.map_err(|e| at.layout(None, e))?;
        let chunk = decode_chunk(
            &At {
                chunk: Some(c),
                ..at
            },
            &leaf(item)?,
        )?;
        same(item, &json::canonical(&encode_chunk(&chunk)))?;
        out.push(chunk);
    }
    Ok(IndexFile {
        content: digest,
        chunks: out,
    })
}

/// One listed file from its JSON value: the reader before [`read`], kept
/// for the tests to compare with.
#[cfg(test)]
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
            decode_chunk(
                &At {
                    chunk: Some(c),
                    ..at
                },
                v,
            )
        })
        .collect::<R<_>>()?;
    Ok(IndexFile { content, chunks })
}

/// The whole index from its JSON value: the reader before [`read`], kept
/// for the tests to compare with.
#[cfg(test)]
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
#[cfg(test)]
fn same_encoding(read: &str, written: &str) -> R<()> {
    if read == written {
        return Ok(());
    }
    Err(IndexError::index(
        None,
        IndexErrorKind::NotCanonical {
            at: json::first_difference(read.as_bytes(), written.as_bytes()),
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
        let index = read(Self::text(bytes)?)?;
        check(&index.chunking, &index.files)?;
        Ok((index, Digest::blake3(bytes)))
    }

    /// The bytes as text, if they are within the size limit and UTF-8.
    fn text(bytes: &[u8]) -> R<&str> {
        if bytes.len() > MAX_SIZE {
            return Err(IndexError::index(
                None,
                IndexErrorKind::TooLarge {
                    max: MAX_SIZE,
                    len: bytes.len(),
                },
            ));
        }
        std::str::from_utf8(bytes).map_err(|_| IndexError::index(None, IndexErrorKind::NotUtf8))
    }

    /// The index's canonical bytes, checked against every rule.
    ///
    /// # Errors
    ///
    /// Returns the first rule the index breaks, and where.
    pub fn to_canonical_bytes(&self) -> R<Vec<u8>> {
        let bytes = text(&self.chunking, &self.files).into_bytes();
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

/// The reader and writer this crate had before reading a chunk at a
/// time, which built the whole index as one JSON value. The tests hold
/// the new ones to them.
#[cfg(test)]
impl ChunkIndex {
    fn from_canonical_bytes_by_value(bytes: &[u8]) -> R<(Self, Digest)> {
        let text = Self::text(bytes)?;
        let value = json::parse(text).map_err(json_error)?;
        same_encoding(text, &json::canonical(&value))?;
        let index = decode(&value)?;
        check(&index.chunking, &index.files)?;
        same_encoding(
            text,
            &json::canonical(&encode(&index.chunking, &index.files)),
        )?;
        Ok((index, Digest::blake3(bytes)))
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

    fn chunk(seed: u64, length: u64) -> ChunkRef {
        ChunkRef {
            digest: Digest::blake3(&seed.to_le_bytes()),
            length,
        }
    }

    /// A small index: files of one, two and three chunks.
    fn sample() -> Vec<u8> {
        let params = ChunkParams::new(64, 256, 1024, 256, 1).unwrap();
        let files = vec![
            IndexFile::new(Digest::blake3(b"a"), vec![chunk(1, 300), chunk(2, 70)]),
            IndexFile::new(
                Digest::blake3(b"b"),
                vec![chunk(3, 1024), chunk(4, 900), chunk(5, 1)],
            ),
            IndexFile::new(Digest::blake3(b"c"), vec![chunk(6, 256), chunk(7, 99)]),
        ];
        ChunkIndex::new(params, files)
            .unwrap()
            .to_canonical_bytes()
            .unwrap()
    }

    /// Both readers give the same answer: the same index and identity, or
    /// a refusal. The errors may differ.
    fn agree(bytes: &[u8]) -> bool {
        let new = ChunkIndex::from_canonical_bytes(bytes);
        let old = ChunkIndex::from_canonical_bytes_by_value(bytes);
        assert_eq!(
            new.as_ref().ok(),
            old.as_ref().ok(),
            "{}",
            String::from_utf8_lossy(bytes)
        );
        new.is_ok()
    }

    /// The sample with each change applied: a byte changed, inserted or
    /// removed.
    fn changed(changes: &[(usize, u8, u8)]) -> Vec<u8> {
        let mut bytes = sample();
        for &(at, byte, how) in changes {
            let i = at % (bytes.len() + 1);
            match how {
                0 if i < bytes.len() => bytes[i] ^= byte.max(1),
                1 => bytes.insert(i, byte),
                _ if i < bytes.len() => {
                    bytes.remove(i);
                }
                _ => {}
            }
        }
        bytes
    }

    #[test]
    fn both_readers_read_the_sample_and_refuse_it_spaced_out() {
        let bytes = sample();
        assert!(agree(&bytes));
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(!agree(&serde_json::to_vec_pretty(&value).unwrap()));
        let text = String::from_utf8(bytes).unwrap();
        let chunking = &text[text.find(':').unwrap() + 1..text.find(r#","files""#).unwrap()];
        for refused in [
            "[]".to_owned(),
            format!(r#"{{"chunking":{chunking},"files":{{}},"ordin-chunk-index":1}}"#),
        ] {
            assert!(!agree(refused.as_bytes()), "{refused}");
        }
    }

    #[test]
    fn a_part_that_differs_from_its_encoding_is_refused_where_it_differs() {
        let item = Member {
            at: 10,
            text: r#"{"a":1}"#,
        };
        assert!(same(item, r#"{"a":1}"#).is_ok());
        assert_eq!(
            same(item, r#"{"a":2}"#).unwrap_err().kind,
            IndexErrorKind::NotCanonical { at: 15 }
        );
        let text = String::from_utf8(sample()).unwrap();
        let at = text.find(r#","length""#).unwrap() + 1;
        let spaced = text.replacen(r#","length""#, r#", "length""#, 1);
        assert_eq!(
            ChunkIndex::from_canonical_bytes(spaced.as_bytes())
                .unwrap_err()
                .kind,
            IndexErrorKind::NotCanonical { at }
        );
    }

    #[test]
    fn a_repeated_field_is_refused() {
        let text = String::from_utf8(sample()).unwrap();
        let repeated = text.replacen(r#","files":"#, r#","chunking":{},"files":"#, 1);
        let e = ChunkIndex::from_canonical_bytes(repeated.as_bytes()).unwrap_err();
        assert!(
            matches!(&e.kind, IndexErrorKind::Json(m) if m.contains("appears twice")),
            "{e}"
        );
    }

    #[test]
    fn both_writers_agree() {
        let (index, _) = ChunkIndex::from_canonical_bytes(&sample()).unwrap();
        assert_eq!(
            text(&index.chunking, &index.files),
            json::canonical(&encode(&index.chunking, &index.files))
        );
        let empty = ChunkIndex::new(*index.chunking(), vec![]).unwrap();
        assert_eq!(
            text(&empty.chunking, &empty.files),
            json::canonical(&encode(&empty.chunking, &empty.files))
        );
    }

    #[test]
    fn changed_bytes_are_sometimes_accepted() {
        // The comparison below has teeth only if some changes are read:
        // a changed digit of a digest or a length still makes an index.
        let accepted = (0..sample().len())
            .filter(|&at| agree(&changed(&[(at, 1, 0)])))
            .count();
        assert!(accepted > 100, "{accepted}");
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(4096))]

        #[test]
        fn both_readers_agree_on_changed_bytes(
            changes in proptest::collection::vec(
                (0..usize::MAX, proptest::prelude::any::<u8>(), 0u8..3),
                1..4,
            )
        ) {
            agree(&changed(&changes));
        }
    }
}
