// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The chunk index: its encoding, every rule it checks, and how readers
//! find a file's chunks.

#[cfg(test)]
mod chunk_index {
    use ordin_core::{Algorithm, Digest};
    use ordin_tree::chunk::{
        ChunkIndex, ChunkParams, ChunkRef, IndexError, IndexErrorKind, IndexFile, MAX_CHUNKS,
        MAX_FILES, MAX_SIZE, ParamsError,
    };
    use proptest::prelude::*;

    /// Chunks of 64 to 1024 bytes, 256 on average, files under 256 whole.
    fn small() -> ChunkParams {
        ChunkParams::new(64, 256, 1024, 256, 1).unwrap()
    }

    const CHUNKING: &str = r#"{"algorithm":"fastcdc-2020","average":256,"maximum":1024,"minimum":64,"normalization":1,"whole-below":256}"#;

    fn d(name: &str) -> Digest {
        Digest::blake3(name.as_bytes())
    }

    fn chunk(name: &str, length: u64) -> ChunkRef {
        ChunkRef {
            digest: d(name),
            length,
        }
    }

    /// A file of two chunks, 100 and 200 bytes.
    fn two(name: &str) -> IndexFile {
        IndexFile::new(d(name), vec![chunk("x", 100), chunk("y", 200)])
    }

    fn json(chunking: &str, files: &str) -> String {
        format!(r#"{{"chunking":{chunking},"files":{files},"ordin-chunk-index":1}}"#)
    }

    fn file_json(content: &Digest, chunks: &[(Digest, u64)]) -> String {
        let chunks: Vec<String> = chunks
            .iter()
            .map(|(digest, length)| format!(r#"{{"digest":"{digest}","length":{length}}}"#))
            .collect();
        format!(
            r#"{{"chunks":[{}],"content":"{content}"}}"#,
            chunks.join(",")
        )
    }

    fn refused(text: &str) -> IndexError {
        ChunkIndex::from_canonical_bytes(text.as_bytes()).unwrap_err()
    }

    fn refused_new(files: Vec<IndexFile>) -> IndexError {
        ChunkIndex::new(small(), files).unwrap_err()
    }

    #[test]
    fn an_index_encodes_as_documented() {
        let index = ChunkIndex::new(small(), vec![two("a")]).unwrap();
        let bytes = index.to_canonical_bytes().unwrap();
        let expected = json(
            CHUNKING,
            &format!("[{}]", file_json(&d("a"), &[(d("x"), 100), (d("y"), 200)])),
        );
        assert_eq!(String::from_utf8(bytes.clone()).unwrap(), expected);
        assert_eq!(index.digest().unwrap(), Digest::blake3(&bytes));
        let (read, digest) = ChunkIndex::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(read, index);
        assert_eq!(digest, Digest::blake3(&bytes));
    }

    #[test]
    fn an_empty_index_is_allowed() {
        let index = ChunkIndex::new(ChunkParams::DEFAULT, vec![]).unwrap();
        let bytes = index.to_canonical_bytes().unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            r#"{"chunking":{"algorithm":"fastcdc-2020","average":1048576,"maximum":4194304,"minimum":262144,"normalization":1,"whole-below":1048576},"files":[],"ordin-chunk-index":1}"#
        );
        assert!(index.files().is_empty());
        assert_eq!(index.chunking(), &ChunkParams::DEFAULT);
    }

    #[test]
    fn files_are_sorted_by_content_digest() {
        let names = ["a", "b", "c", "d", "e"];
        let index = ChunkIndex::new(small(), names.iter().rev().map(|n| two(n)).collect()).unwrap();
        let contents: Vec<Digest> = index.files().iter().map(IndexFile::content).collect();
        let mut sorted = contents.clone();
        sorted.sort();
        assert_eq!(contents, sorted);
        assert_eq!(contents.len(), 5);
        for name in names {
            assert_eq!(index.get(&d(name)).unwrap().content(), d(name));
        }
        assert_eq!(index.get(&d("f")), None);
    }

    #[test]
    fn an_unsorted_file_is_refused_where_it_is() {
        let mut contents = [d("a"), d("b")];
        contents.sort();
        let [first, second] = contents;
        let files = format!(
            "[{},{}]",
            file_json(&second, &[(d("x"), 300)]),
            file_json(&first, &[(d("x"), 300)])
        );
        // One-chunk files whose chunk isn't the content are refused too,
        // but sorting is checked first.
        let error = refused(&json(CHUNKING, &files));
        assert_eq!(
            error.kind,
            IndexErrorKind::NotSorted {
                previous: second.to_string()
            }
        );
        assert_eq!(error.at.file, Some((1, Some(first.to_string()))));
    }

    #[test]
    fn a_file_listed_twice_is_refused() {
        let error = refused_new(vec![two("a"), two("a")]);
        assert_eq!(error.kind, IndexErrorKind::Duplicate);
        assert_eq!(error.at.file, Some((1, Some(d("a").to_string()))));
    }

    #[test]
    fn digests_are_blake3() {
        let sha = Digest::new(Algorithm::Sha256, [1; 32]);
        let error = refused_new(vec![IndexFile::new(sha, vec![chunk("x", 300)])]);
        assert_eq!(error.kind, IndexErrorKind::NotBlake3);
        assert_eq!(error.at.field.as_deref(), Some("content"));
        let error = refused_new(vec![IndexFile::new(
            d("a"),
            vec![
                chunk("x", 100),
                ChunkRef {
                    digest: sha,
                    length: 200,
                },
            ],
        )]);
        assert_eq!(error.kind, IndexErrorKind::NotBlake3);
        assert_eq!(error.at.chunk, Some(1));
        assert_eq!(error.at.field.as_deref(), Some("digest"));
    }

    #[test]
    fn a_listed_file_has_chunks() {
        let error = refused_new(vec![IndexFile::new(d("a"), vec![])]);
        assert_eq!(error.kind, IndexErrorKind::NoChunks);
        assert_eq!(error.at.field.as_deref(), Some("chunks"));
    }

    #[test]
    fn chunks_are_1_byte_to_the_maximum() {
        for (lengths, at) in [
            (vec![300, 0], 1),
            (vec![1025], 0),
            (vec![100, 1025, 100], 1),
            (vec![u64::MAX], 0),
        ] {
            let chunks = lengths.iter().map(|&l| chunk("x", l)).collect();
            let error = refused_new(vec![IndexFile::new(d("a"), chunks)]);
            assert_eq!(
                error.kind,
                IndexErrorKind::ChunkLength {
                    maximum: 1024,
                    length: lengths[at]
                },
                "{lengths:?}"
            );
            assert_eq!(error.at.chunk, Some(at));
        }
        // Both ends are allowed: a 1-byte last chunk and a maximal one.
        ChunkIndex::new(
            small(),
            vec![IndexFile::new(
                d("a"),
                vec![chunk("x", 1024), chunk("y", 1)],
            )],
        )
        .unwrap();
    }

    #[test]
    fn only_the_last_chunk_is_shorter_than_the_minimum() {
        let error = refused_new(vec![IndexFile::new(
            d("a"),
            vec![chunk("x", 200), chunk("y", 63), chunk("z", 100)],
        )]);
        assert_eq!(
            error.kind,
            IndexErrorKind::ChunkTooShort {
                minimum: 64,
                length: 63
            }
        );
        assert_eq!(error.at.chunk, Some(1));
        assert_eq!(error.at.field.as_deref(), Some("length"));
        // At the minimum is allowed, and so is a short last chunk.
        ChunkIndex::new(
            small(),
            vec![IndexFile::new(
                d("a"),
                vec![chunk("x", 200), chunk("y", 64), chunk("z", 1)],
            )],
        )
        .unwrap();
    }

    #[test]
    fn small_files_are_not_listed() {
        let error = refused_new(vec![IndexFile::new(
            d("a"),
            vec![chunk("x", 100), chunk("y", 155)],
        )]);
        assert_eq!(
            error.kind,
            IndexErrorKind::FileTooSmall {
                whole_below: 256,
                size: 255
            }
        );
        assert_eq!(error.at.chunk, None);
        // A file at the threshold is listed.
        ChunkIndex::new(
            small(),
            vec![IndexFile::new(
                d("a"),
                vec![chunk("x", 100), chunk("y", 156)],
            )],
        )
        .unwrap();
    }

    #[test]
    fn a_files_only_chunk_is_the_file() {
        let error = refused_new(vec![IndexFile::new(d("a"), vec![chunk("x", 300)])]);
        assert_eq!(error.kind, IndexErrorKind::SingleChunk);
        assert_eq!(error.at.chunk, Some(0));
        let whole = IndexFile::new(d("a"), vec![chunk("a", 300)]);
        ChunkIndex::new(small(), vec![whole]).unwrap();
    }

    #[test]
    fn an_index_lists_at_most_262144_files() {
        assert_eq!(MAX_FILES, 262_144);
        let file = |i: u32| IndexFile::new(Digest::blake3(&i.to_le_bytes()), vec![]);
        let files: Vec<IndexFile> = (0..=MAX_FILES as u32).map(file).collect();
        let error = refused_new(files);
        assert_eq!(
            error.kind,
            IndexErrorKind::TooManyFiles {
                max: MAX_FILES,
                len: MAX_FILES + 1
            }
        );
        assert_eq!(error.at.field.as_deref(), Some("files"));
        // Exactly the limit is allowed.
        let whole = |i: u32| {
            let content = Digest::blake3(&i.to_le_bytes());
            IndexFile::new(
                content,
                vec![ChunkRef {
                    digest: content,
                    length: 300,
                }],
            )
        };
        let index = ChunkIndex::new(small(), (0..MAX_FILES as u32).map(whole).collect()).unwrap();
        assert_eq!(index.files().len(), MAX_FILES);
    }

    #[test]
    fn an_index_lists_at_most_524288_chunks() {
        assert_eq!(MAX_CHUNKS, 524_288);
        let chunks = |n: usize| vec![chunk("x", 64); n];
        let error = refused_new(vec![
            IndexFile::new(d("a"), chunks(MAX_CHUNKS - 1)),
            IndexFile::new(d("b"), chunks(2)),
        ]);
        assert_eq!(
            error.kind,
            IndexErrorKind::TooManyChunks { max: MAX_CHUNKS }
        );
        // Exactly the limit is allowed.
        ChunkIndex::new(
            small(),
            vec![
                IndexFile::new(d("a"), chunks(MAX_CHUNKS - 4)),
                IndexFile::new(d("b"), chunks(4)),
            ],
        )
        .unwrap();
    }

    #[test]
    fn offsets_follow_from_lengths() {
        let f = IndexFile::new(
            d("a"),
            vec![chunk("x", 100), chunk("y", 200), chunk("z", 5)],
        );
        let offsets: Vec<u64> = f.offsets().map(|(at, _)| at).collect();
        assert_eq!(offsets, [0, 100, 300]);
        assert_eq!(f.size(), 305);
        assert_eq!(f.chunks()[1], chunk("y", 200));
    }

    #[test]
    fn readers_find_each_files_chunks() {
        let index = ChunkIndex::new(small(), vec![two("a")]).unwrap();
        // Listed: its chunks.
        assert_eq!(
            index.chunks_of(&d("a"), 300).unwrap(),
            [chunk("x", 100), chunk("y", 200)]
        );
        // Under the threshold: the file itself, listed or not.
        for size in [0, 255] {
            assert_eq!(index.chunks_of(&d("b"), size).unwrap(), [chunk("b", size)]);
        }
        // At the threshold and not listed.
        let error = index.chunks_of(&d("b"), 256).unwrap_err();
        assert_eq!(
            error.kind,
            IndexErrorKind::NotListed {
                content: d("b").to_string(),
                size: 256
            }
        );
        // Listed with another size.
        let error = index.chunks_of(&d("a"), 301).unwrap_err();
        assert_eq!(
            error.kind,
            IndexErrorKind::WrongSize {
                listed: 300,
                size: 301
            }
        );
        assert_eq!(error.at.file, Some((0, Some(d("a").to_string()))));
        assert_eq!(
            error.to_string(),
            format!(
                "file 0 ({}): the file is 301 bytes, and its chunks add up to 300",
                d("a")
            )
        );
    }

    #[test]
    fn bytes_that_arent_an_index_are_refused() {
        // Exactly the limit gets past the size check, and is refused as JSON.
        let at_limit = vec![b' '; MAX_SIZE];
        assert!(matches!(
            ChunkIndex::from_canonical_bytes(&at_limit)
                .unwrap_err()
                .kind,
            IndexErrorKind::Json(_)
        ));
        let too_large = vec![b' '; MAX_SIZE + 1];
        assert_eq!(
            ChunkIndex::from_canonical_bytes(&too_large)
                .unwrap_err()
                .kind,
            IndexErrorKind::TooLarge {
                max: MAX_SIZE,
                len: MAX_SIZE + 1
            }
        );
        assert_eq!(
            ChunkIndex::from_canonical_bytes(&[0xff]).unwrap_err().kind,
            IndexErrorKind::NotUtf8
        );
        assert!(matches!(refused("{").kind, IndexErrorKind::Json(_)));
        let spaced = json(CHUNKING, "[]").replacen(':', ": ", 1);
        assert_eq!(
            refused(&spaced).kind,
            IndexErrorKind::NotCanonical { at: 12 }
        );
        assert_eq!(
            refused("[]").kind,
            IndexErrorKind::WrongType {
                expected: "an object",
                found: "an array"
            }
        );
    }

    #[test]
    fn the_format_version_is_checked_first() {
        let error = refused(r#"{"chunking":1,"files":[]}"#);
        assert_eq!(error.kind, IndexErrorKind::Missing);
        assert_eq!(error.at.field.as_deref(), Some("ordin-chunk-index"));
        for version in ["2", "\"1\"", "0"] {
            let text = format!(r#"{{"chunking":1,"files":[],"ordin-chunk-index":{version}}}"#);
            assert_eq!(
                refused(&text).kind,
                IndexErrorKind::UnknownFormat(version.to_owned())
            );
        }
    }

    /// The field an index is refused at, and why.
    fn at(text: &str) -> (Option<String>, IndexErrorKind) {
        let error = refused(text);
        (error.at.field, error.kind)
    }

    fn field(name: &str, kind: IndexErrorKind) -> (Option<String>, IndexErrorKind) {
        (Some(name.to_owned()), kind)
    }

    fn wrong(expected: &'static str, found: &'static str) -> IndexErrorKind {
        IndexErrorKind::WrongType { expected, found }
    }

    #[test]
    fn the_index_has_exactly_its_fields() {
        assert_eq!(
            at(r#"{"chunking":{},"extra":1,"files":[],"ordin-chunk-index":1}"#),
            field("extra", IndexErrorKind::UnknownField)
        );
        assert_eq!(
            at(r#"{"files":[],"ordin-chunk-index":1}"#),
            field("chunking", IndexErrorKind::Missing)
        );
        assert_eq!(
            at(&format!(
                r#"{{"chunking":{CHUNKING},"ordin-chunk-index":1}}"#
            )),
            field("files", IndexErrorKind::Missing)
        );
        assert_eq!(
            at(&json(CHUNKING, "{}")),
            field("files", wrong("an array", "an object"))
        );
    }

    /// The chunking object with one field replaced, or removed if `value`
    /// is empty.
    fn chunking_with(name: &str, value: &str) -> String {
        let mut fields: Vec<(String, String)> = [
            ("algorithm", "\"fastcdc-2020\""),
            ("average", "256"),
            ("maximum", "1024"),
            ("minimum", "64"),
            ("normalization", "1"),
            ("whole-below", "256"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .filter(|(k, _)| k != name)
        .collect();
        if !value.is_empty() {
            fields.push((name.to_owned(), value.to_owned()));
            fields.sort();
        }
        let body: Vec<String> = fields.iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
        format!("{{{}}}", body.join(","))
    }

    #[test]
    fn the_chunking_settings_are_all_recorded() {
        assert_eq!(chunking_with("none", ""), CHUNKING);
        assert_eq!(
            at(&json("[]", "[]")),
            field("chunking", wrong("an object", "an array"))
        );
        for name in [
            "algorithm",
            "average",
            "maximum",
            "minimum",
            "normalization",
            "whole-below",
        ] {
            assert_eq!(
                at(&json(&chunking_with(name, ""), "[]")),
                field(&format!("chunking.{name}"), IndexErrorKind::Missing)
            );
        }
        assert_eq!(
            at(&json(&chunking_with("seed", "0"), "[]")),
            field("chunking.seed", IndexErrorKind::UnknownField)
        );
    }

    #[test]
    fn the_chunking_settings_are_checked() {
        assert_eq!(
            at(&json(&chunking_with("algorithm", "\"fastcdc-2016\""), "[]")),
            field(
                "chunking.algorithm",
                IndexErrorKind::UnknownAlgorithm("fastcdc-2016".into())
            )
        );
        assert_eq!(
            at(&json(&chunking_with("algorithm", "1"), "[]")),
            field("chunking.algorithm", wrong("a string", "an integer"))
        );
        assert_eq!(
            at(&json(&chunking_with("minimum", "-64"), "[]")),
            field(
                "chunking.minimum",
                IndexErrorKind::Invalid("can't be negative".into())
            )
        );
        assert_eq!(
            at(&json(&chunking_with("average", "\"256\""), "[]")),
            field("chunking.average", wrong("an integer", "a string"))
        );
        assert_eq!(
            at(&json(&chunking_with("normalization", "4"), "[]")),
            field(
                "chunking",
                IndexErrorKind::Params(ParamsError::Normalization(4))
            )
        );
        // Every setting reaches the check, in its own place.
        for (name, value) in [
            ("minimum", "128"),
            ("average", "512"),
            ("maximum", "2048"),
            ("whole-below", "300"),
            ("normalization", "2"),
        ] {
            let text = json(&chunking_with(name, value), "[]");
            let (index, _) = ChunkIndex::from_canonical_bytes(text.as_bytes()).unwrap();
            let p = index.chunking();
            let read = match name {
                "minimum" => p.minimum(),
                "average" => p.average(),
                "maximum" => p.maximum(),
                "whole-below" => p.whole_below(),
                _ => u32::from(p.normalization()),
            };
            assert_eq!(read.to_string(), value, "{name}");
        }
    }

    /// The file and chunk an index with this one file is refused at.
    fn file_at(file: &str) -> (Option<usize>, Option<String>, IndexErrorKind) {
        let error = refused(&json(CHUNKING, &format!("[{file}]")));
        let (index, _) = error.at.file.unwrap();
        assert_eq!(index, 0);
        (error.at.chunk, error.at.field, error.kind)
    }

    #[test]
    fn files_have_exactly_their_fields() {
        let content = d("a");
        let good = |chunks: &str| format!(r#"{{"chunks":{chunks},"content":"{content}"}}"#);
        assert_eq!(file_at("1"), (None, None, wrong("an object", "an integer")));
        assert_eq!(
            file_at(&format!(
                r#"{{"chunks":[],"content":"{content}","size":1}}"#
            )),
            (None, Some("size".into()), IndexErrorKind::UnknownField)
        );
        assert_eq!(
            file_at(r#"{"chunks":[]}"#),
            (None, Some("content".into()), IndexErrorKind::Missing)
        );
        assert_eq!(
            file_at(&format!(r#"{{"content":"{content}"}}"#)),
            (None, Some("chunks".into()), IndexErrorKind::Missing)
        );
        assert_eq!(
            file_at(&good("{}")),
            (None, Some("chunks".into()), wrong("an array", "an object"))
        );
        assert_eq!(
            file_at(&good("[]")),
            (None, Some("chunks".into()), IndexErrorKind::NoChunks)
        );
        let (_, field, kind) = file_at(r#"{"chunks":[],"content":"blake3:00"}"#);
        assert_eq!(field.as_deref(), Some("content"));
        assert!(matches!(kind, IndexErrorKind::Invalid(_)));
        let sha = Digest::new(Algorithm::Sha256, [1; 32]);
        assert_eq!(
            file_at(&format!(r#"{{"chunks":[],"content":"{sha}"}}"#)),
            (None, Some("content".into()), IndexErrorKind::NotBlake3)
        );
        assert_eq!(
            file_at(r#"{"chunks":[],"content":7}"#),
            (
                None,
                Some("content".into()),
                wrong("a string", "an integer")
            )
        );
    }

    #[test]
    fn chunks_have_exactly_their_fields() {
        let content = d("a");
        let x = d("x");
        let with = |chunk: &str| {
            format!(
                r#"{{"chunks":[{{"digest":"{x}","length":100}},{chunk}],"content":"{content}"}}"#
            )
        };
        assert_eq!(
            file_at(&with("[]")),
            (Some(1), None, wrong("an object", "an array"))
        );
        assert_eq!(
            file_at(&with(&format!(
                r#"{{"digest":"{x}","length":200,"offset":100}}"#
            ))),
            (Some(1), Some("offset".into()), IndexErrorKind::UnknownField)
        );
        assert_eq!(
            file_at(&with(r#"{"length":200}"#)),
            (Some(1), Some("digest".into()), IndexErrorKind::Missing)
        );
        assert_eq!(
            file_at(&with(&format!(r#"{{"digest":"{x}"}}"#))),
            (Some(1), Some("length".into()), IndexErrorKind::Missing)
        );
        assert_eq!(
            file_at(&with(&format!(r#"{{"digest":"{x}","length":-1}}"#))),
            (
                Some(1),
                Some("length".into()),
                IndexErrorKind::Invalid("can't be negative".into())
            )
        );
        assert_eq!(
            file_at(&with(&format!(r#"{{"digest":"{x}","length":"200"}}"#))),
            (
                Some(1),
                Some("length".into()),
                wrong("an integer", "a string")
            )
        );
        let sha = Digest::new(Algorithm::Sha256, [1; 32]);
        assert_eq!(
            file_at(&with(&format!(r#"{{"digest":"{sha}","length":200}}"#))),
            (Some(1), Some("digest".into()), IndexErrorKind::NotBlake3)
        );
    }

    #[test]
    fn a_files_location_shows_its_content_once_it_is_read() {
        let error = refused(&json(CHUNKING, r#"[{"chunks":1,"content":"x"}]"#));
        assert_eq!(error.at.file, Some((0, None)));
        let content = d("a");
        let error = refused(&json(
            CHUNKING,
            &format!(r#"[{{"chunks":1,"content":"{content}"}}]"#),
        ));
        assert_eq!(error.at.file, Some((0, Some(content.to_string()))));
        assert_eq!(
            error.to_string(),
            format!("file 0 ({content}), field \"chunks\": expected an array, found an integer")
        );
    }

    fn params() -> impl Strategy<Value = ChunkParams> {
        (6u32..=20, 8u32..=22, 10u32..=24, 0u64..=3, any::<u64>()).prop_filter_map(
            "ordered lengths",
            |(min_bits, average_bits, max_bits, level, threshold)| {
                let minimum = 1u64 << min_bits;
                let maximum = 1u64 << max_bits;
                let whole_below = minimum + threshold % (maximum.checked_sub(minimum)? + 1);
                ChunkParams::new(minimum, 1 << average_bits, maximum, whole_below, level).ok()
            },
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn different_settings_never_encode_identically(a in params(), b in params()) {
            let file = |p: &ChunkParams| {
                let length = u64::from(p.maximum());
                IndexFile::new(d("a"), vec![chunk("x", length), chunk("y", length)])
            };
            let first = ChunkIndex::new(a, vec![file(&a)]).unwrap().to_canonical_bytes().unwrap();
            let second = ChunkIndex::new(b, vec![file(&b)]).unwrap().to_canonical_bytes().unwrap();
            prop_assert_eq!(a == b, first == second);
            let (read, _) = ChunkIndex::from_canonical_bytes(&first).unwrap();
            prop_assert_eq!(read.chunking(), &a);
        }

        #[test]
        fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..400)) {
            let _ = ChunkIndex::from_canonical_bytes(&bytes);
        }
    }
}
