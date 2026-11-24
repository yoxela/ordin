// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The OCI image layout around a package: `oci-layout`, `index.json`, the
//! image manifest and its descriptors, all canonical JSON.

use std::collections::BTreeMap;

use ordin_core::json::{self, MAX_INT, Value};
use ordin_core::{Algorithm, Digest};

use crate::blob::BlobId;
use crate::error::ReadErrorKind;

/// Media types.
pub mod media {
    /// The image manifest's `artifactType`: an Ordin package.
    pub const PACKAGE: &str = "application/vnd.ordin.package.v1";
    /// The Ordin manifest, in canonical JSON. Its BLAKE3 digest is the
    /// package's identity.
    pub const MANIFEST: &str = "application/vnd.ordin.manifest.v1+json";
    /// One license text, as the manifest records it.
    pub const LICENSE: &str = "application/vnd.ordin.license.v1";
    /// One facet's tree, in canonical JSON.
    pub const TREE: &str = "application/vnd.ordin.tree.v1+json";
    /// The chunk index, in canonical JSON.
    pub const CHUNK_INDEX: &str = "application/vnd.ordin.chunk-index.v1+json";
    /// One facet's pack table, in canonical JSON.
    pub const PACK_TABLE: &str = "application/vnd.ordin.pack-table.v1+json";
    /// One facet's chunk pack: independent zstd frames, back to back.
    pub const CHUNK_PACK: &str = "application/vnd.ordin.chunk-pack.v1+zstd";
    /// OCI's image index (`index.json`).
    pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
    /// OCI's image manifest.
    pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
    /// OCI's empty descriptor, the config of an artifact.
    pub const OCI_EMPTY: &str = "application/vnd.oci.empty.v1+json";
}

/// Annotation keys.
pub mod annotations {
    /// Every descriptor's BLAKE3 digest of its blob, which Ordin verifies.
    pub const BLAKE3: &str = "com.ordinpm.blake3";
    /// The facet a tree, pack table or chunk pack belongs to.
    pub const FACET: &str = "com.ordinpm.facet";
    /// The SPDX license ID a license text is for.
    pub const LICENSE: &str = "com.ordinpm.license";
}

/// The `oci-layout` file.
pub const OCI_LAYOUT: &[u8] = br#"{"imageLayoutVersion":"1.0.0"}"#;

/// The empty config blob, as OCI 1.1 defines it for artifacts.
pub const EMPTY_CONFIG: &[u8] = b"{}";

/// One layer of the image manifest.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Layer {
    pub(crate) media_type: &'static str,
    pub(crate) id: BlobId,
    pub(crate) annotations: BTreeMap<String, String>,
}

fn string(text: &str) -> Value {
    Value::Str(text.to_owned())
}

fn object<const N: usize>(fields: [(&str, Value); N]) -> Value {
    Value::Object(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

/// A descriptor: the media type, SHA-256 digest and size OCI requires,
/// and the BLAKE3 digest among the annotations.
fn descriptor(
    media_type: &str,
    id: &BlobId,
    annotations: &BTreeMap<String, String>,
) -> BTreeMap<String, Value> {
    let mut notes: BTreeMap<String, Value> = annotations
        .iter()
        .map(|(k, v)| (k.clone(), string(v)))
        .collect();
    notes.insert(
        annotations::BLAKE3.to_owned(),
        Value::Str(id.blake3.to_string()),
    );
    BTreeMap::from([
        ("annotations".to_owned(), Value::Object(notes)),
        ("digest".to_owned(), Value::Str(id.sha256.to_string())),
        ("mediaType".to_owned(), string(media_type)),
        (
            "size".to_owned(),
            Value::Int(i64::try_from(id.size).unwrap_or(MAX_INT)),
        ),
    ])
}

/// The image manifest: an artifact with the empty config and `layers` in
/// order.
pub(crate) fn image_manifest(config: &BlobId, layers: &[Layer]) -> Vec<u8> {
    let layers = layers
        .iter()
        .map(|l| Value::Object(descriptor(l.media_type, &l.id, &l.annotations)))
        .collect();
    let manifest = object([
        ("artifactType", string(media::PACKAGE)),
        (
            "config",
            Value::Object(descriptor(media::OCI_EMPTY, config, &BTreeMap::new())),
        ),
        ("layers", Value::Array(layers)),
        ("mediaType", string(media::OCI_MANIFEST)),
        ("schemaVersion", Value::Int(2)),
    ]);
    json::canonical(&manifest).into_bytes()
}

/// `index.json`: the one image manifest.
pub(crate) fn index(manifest: &BlobId) -> Vec<u8> {
    let mut entry = descriptor(media::OCI_MANIFEST, manifest, &BTreeMap::new());
    entry.insert("artifactType".to_owned(), string(media::PACKAGE));
    let index = object([
        ("manifests", Value::Array(vec![Value::Object(entry)])),
        ("mediaType", string(media::OCI_INDEX)),
        ("schemaVersion", Value::Int(2)),
    ]);
    json::canonical(&index).into_bytes()
}

/// The layer media types, in the order the layers come.
pub(crate) const LAYER_TYPES: [&str; 6] = [
    media::MANIFEST,
    media::LICENSE,
    media::TREE,
    media::CHUNK_INDEX,
    media::PACK_TABLE,
    media::CHUNK_PACK,
];

/// A descriptor as read: the media type, the blob's identity, and the
/// annotations other than `com.ordinpm.blake3`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Descriptor {
    pub(crate) media_type: String,
    pub(crate) id: BlobId,
    pub(crate) annotations: BTreeMap<String, String>,
}

fn field<'a>(object: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a Value, String> {
    object
        .get(key)
        .ok_or_else(|| format!("a descriptor has no {key:?}"))
}

fn digest(text: &Value, key: &str, algorithm: Algorithm) -> Result<Digest, String> {
    let Value::Str(text) = text else {
        return Err(format!("{key} must be a string"));
    };
    text.parse::<Digest>()
        .ok()
        .filter(|d| d.algorithm() == algorithm)
        .ok_or_else(|| format!("{key} must be {algorithm}: and 64 lowercase hex digits"))
}

/// Reads a descriptor's fields. Fields it doesn't read are left for the
/// caller's comparison with what the writer would write.
fn read_descriptor(value: &Value) -> Result<Descriptor, String> {
    let Value::Object(object) = value else {
        return Err("a descriptor must be an object".to_owned());
    };
    let Value::Str(media_type) = field(object, "mediaType")? else {
        return Err("mediaType must be a string".to_owned());
    };
    let sha256 = digest(field(object, "digest")?, "digest", Algorithm::Sha256)?;
    let size = match field(object, "size")? {
        Value::Int(size) => u64::try_from(*size).map_err(|_| "size must not be negative")?,
        _ => return Err("size must be an integer".to_owned()),
    };
    let Value::Object(notes) = field(object, "annotations")? else {
        return Err("annotations must be an object".to_owned());
    };
    let mut others = BTreeMap::new();
    let mut blake3 = None;
    for (key, value) in notes {
        if key == annotations::BLAKE3 {
            blake3 = Some(digest(value, key, Algorithm::Blake3)?);
        } else {
            let Value::Str(text) = value else {
                return Err(format!("the annotation {key} must be a string"));
            };
            others.insert(key.clone(), text.clone());
        }
    }
    let blake3 = blake3.ok_or_else(|| format!("a descriptor has no {}", annotations::BLAKE3))?;
    Ok(Descriptor {
        media_type: media_type.clone(),
        id: BlobId {
            sha256,
            blake3,
            size,
        },
        annotations: others,
    })
}

/// Where two byte strings first differ.
fn first_difference(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b)
        .position(|(x, y)| x != y)
        .unwrap_or(a.len().min(b.len()))
}

fn json(bytes: &[u8]) -> Result<Value, ReadErrorKind> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| ReadErrorKind::Json("it isn't UTF-8".to_owned()))?;
    json::parse(text).map_err(|e| ReadErrorKind::Json(e.0))
}

/// Refuses `bytes` unless they are exactly `written`.
fn as_written(bytes: &[u8], written: &[u8]) -> Result<(), ReadErrorKind> {
    if bytes == written {
        Ok(())
    } else {
        Err(ReadErrorKind::NotAsWritten {
            at: first_difference(bytes, written),
        })
    }
}

/// Reads `index.json` and returns the image manifest's identity. The
/// bytes must be exactly what [`index`] writes for it.
pub(crate) fn read_index(bytes: &[u8]) -> Result<BlobId, ReadErrorKind> {
    let value = json(bytes)?;
    let entry = match &value {
        Value::Object(o) => match o.get("manifests") {
            Some(Value::Array(manifests)) => manifests.first(),
            _ => None,
        },
        _ => None,
    }
    .ok_or_else(|| ReadErrorKind::Malformed("it lists no manifest".to_owned()))?;
    let id = read_descriptor(entry).map_err(ReadErrorKind::Malformed)?.id;
    as_written(bytes, &index(&id))?;
    Ok(id)
}

/// Reads the image manifest and returns its config's identity and its
/// layers. The bytes must be exactly what [`image_manifest`] writes for
/// them, and every layer's media type must be one of [`LAYER_TYPES`].
pub(crate) fn read_image_manifest(bytes: &[u8]) -> Result<(BlobId, Vec<Layer>), ReadErrorKind> {
    let value = json(bytes)?;
    let Value::Object(o) = &value else {
        return Err(ReadErrorKind::Malformed("it isn't an object".to_owned()));
    };
    let config = read_descriptor(
        o.get("config")
            .ok_or_else(|| ReadErrorKind::Malformed("it has no config".to_owned()))?,
    )
    .map_err(ReadErrorKind::Malformed)?
    .id;
    let Some(Value::Array(descriptors)) = o.get("layers") else {
        return Err(ReadErrorKind::Malformed("it has no layers".to_owned()));
    };
    let layers = descriptors
        .iter()
        .map(|d| {
            let d = read_descriptor(d).map_err(ReadErrorKind::Malformed)?;
            let media_type = LAYER_TYPES
                .into_iter()
                .find(|t| *t == d.media_type)
                .ok_or(ReadErrorKind::UnknownLayer(d.media_type))?;
            Ok(Layer {
                media_type,
                id: d.id,
                annotations: d.annotations,
            })
        })
        .collect::<Result<Vec<_>, ReadErrorKind>>()?;
    as_written(bytes, &image_manifest(&config, &layers))?;
    Ok((config, layers))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_empty_config_is_ocis() {
        // The OCI image spec's empty descriptor.
        assert_eq!(
            BlobId::of(EMPTY_CONFIG).sha256.to_string(),
            "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }

    #[test]
    fn descriptors_carry_both_digests() {
        let id = BlobId::of(b"abc");
        let notes = BTreeMap::from([(annotations::FACET.to_owned(), "doc".to_owned())]);
        let text = json::canonical(&Value::Object(descriptor(media::TREE, &id, &notes)));
        assert_eq!(
            text,
            format!(
                r#"{{"annotations":{{"com.ordinpm.blake3":"{}","com.ordinpm.facet":"doc"}},"digest":"{}","mediaType":"application/vnd.ordin.tree.v1+json","size":3}}"#,
                id.blake3, id.sha256
            )
        );
    }

    #[test]
    fn the_index_points_at_the_image_manifest() {
        let id = BlobId::of(b"m");
        let text = String::from_utf8(index(&id)).unwrap();
        assert_eq!(
            text,
            format!(
                r#"{{"manifests":[{{"annotations":{{"com.ordinpm.blake3":"{}"}},"artifactType":"application/vnd.ordin.package.v1","digest":"{}","mediaType":"application/vnd.oci.image.manifest.v1+json","size":1}}],"mediaType":"application/vnd.oci.image.index.v1+json","schemaVersion":2}}"#,
                id.blake3, id.sha256
            )
        );
    }

    fn malformed(e: ReadErrorKind) -> String {
        match e {
            ReadErrorKind::Malformed(m) => m,
            other => panic!("not malformed: {other}"),
        }
    }

    fn layer(media_type: &'static str, notes: &[(&str, &str)], bytes: &[u8]) -> Layer {
        Layer {
            media_type,
            id: BlobId::of(bytes),
            annotations: notes
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn what_the_writer_writes_reads_back() {
        let id = BlobId::of(b"image");
        assert_eq!(read_index(&index(&id)).unwrap(), id);
        let config = BlobId::of(EMPTY_CONFIG);
        let layers = vec![
            layer(media::MANIFEST, &[], b"m"),
            layer(media::LICENSE, &[(annotations::LICENSE, "MIT")], b"t"),
            layer(media::TREE, &[(annotations::FACET, "doc")], b"tree"),
            layer(media::CHUNK_INDEX, &[], b"i"),
            layer(media::PACK_TABLE, &[(annotations::FACET, "doc")], b"p"),
            layer(media::CHUNK_PACK, &[(annotations::FACET, "doc")], b""),
        ];
        let bytes = image_manifest(&config, &layers);
        assert_eq!(read_image_manifest(&bytes).unwrap(), (config, layers));
        let none = image_manifest(&config, &[]);
        assert_eq!(read_image_manifest(&none).unwrap(), (config, Vec::new()));
    }

    #[test]
    fn json_must_be_exactly_what_the_writer_writes() {
        let id = BlobId::of(b"image");
        let written = String::from_utf8(index(&id)).unwrap();
        // Spacing, an extra field, another schema version, a second
        // manifest: each is valid OCI, and each is refused.
        let spaced = written.replacen(":", ": ", 1);
        let extra = written.replacen("{\"manifests\"", "{\"annotations\":{},\"manifests\"", 1);
        let schema = written.replace("\"schemaVersion\":2", "\"schemaVersion\":3");
        let entry = &written[14..written.find("],").unwrap()];
        let two = written.replacen(entry, &format!("{entry},{entry}"), 1);
        for (text, at) in [
            (spaced, written.find(':').unwrap() + 1),
            (extra, 2),
            (schema, written.rfind('2').unwrap()),
        ] {
            assert!(
                matches!(read_index(text.as_bytes()), Err(ReadErrorKind::NotAsWritten { at: a }) if a == at),
                "{text}"
            );
        }
        assert!(matches!(
            read_index(two.as_bytes()),
            Err(ReadErrorKind::NotAsWritten { .. })
        ));
        assert!(matches!(
            read_index(&written.as_bytes()[..written.len() - 1]),
            Err(ReadErrorKind::Json(_))
        ));
        let mut longer = written.clone().into_bytes();
        longer.push(b' ');
        assert!(matches!(
            read_index(&longer),
            Err(ReadErrorKind::NotAsWritten { at }) if at == written.len()
        ));

        let config = BlobId::of(EMPTY_CONFIG);
        let layers = [layer(media::TREE, &[(annotations::FACET, "doc")], b"tree")];
        let bytes = String::from_utf8(image_manifest(&config, &layers)).unwrap();
        let other_type = bytes.replace(media::PACKAGE, "application/vnd.other");
        assert!(matches!(
            read_image_manifest(other_type.as_bytes()),
            Err(ReadErrorKind::NotAsWritten { .. })
        ));
    }

    #[test]
    fn layers_of_unknown_types_are_refused() {
        let config = BlobId::of(EMPTY_CONFIG);
        let bytes = String::from_utf8(image_manifest(
            &config,
            &[layer(media::CHUNK_INDEX, &[], b"i")],
        ))
        .unwrap();
        let unknown = bytes.replace(media::CHUNK_INDEX, "application/vnd.ordin.signature.v1");
        assert!(matches!(
            read_image_manifest(unknown.as_bytes()),
            Err(ReadErrorKind::UnknownLayer(t)) if t == "application/vnd.ordin.signature.v1"
        ));
    }

    #[test]
    fn the_index_and_image_manifest_need_their_fields() {
        for (text, message) in [
            ("[]", "it lists no manifest"),
            ("{}", "it lists no manifest"),
            (r#"{"manifests":{}}"#, "it lists no manifest"),
            (r#"{"manifests":[]}"#, "it lists no manifest"),
        ] {
            assert_eq!(malformed(read_index(text.as_bytes()).unwrap_err()), message);
        }
        assert!(matches!(
            read_index(b"\xff"),
            Err(ReadErrorKind::Json(m)) if m == "it isn't UTF-8"
        ));
        let d = descriptor(media::OCI_EMPTY, &BlobId::of(b"{}"), &BTreeMap::new());
        let d = json::canonical(&Value::Object(d));
        for (text, message) in [
            ("[]".to_owned(), "it isn't an object"),
            ("{}".to_owned(), "it has no config"),
            (format!(r#"{{"config":{d}}}"#), "it has no layers"),
            (
                format!(r#"{{"config":{d},"layers":{{}}}}"#),
                "it has no layers",
            ),
            (
                r#"{"config":[]}"#.to_owned(),
                "a descriptor must be an object",
            ),
            (
                format!(r#"{{"config":{d},"layers":[1]}}"#),
                "a descriptor must be an object",
            ),
        ] {
            assert_eq!(
                malformed(read_image_manifest(text.as_bytes()).unwrap_err()),
                message,
                "{text}"
            );
        }
    }

    #[test]
    fn descriptors_need_every_field_in_its_form() {
        let id = BlobId::of(b"abc");
        let good = Value::Object(descriptor(
            media::TREE,
            &id,
            &BTreeMap::from([(annotations::FACET.to_owned(), "doc".to_owned())]),
        ));
        let read = read_descriptor(&good).unwrap();
        assert_eq!(read.media_type, media::TREE);
        assert_eq!(read.id, id);
        assert_eq!(
            read.annotations,
            BTreeMap::from([(annotations::FACET.to_owned(), "doc".to_owned())])
        );
        let changed = |key: &str, value: Option<Value>| {
            let Value::Object(mut o) = good.clone() else {
                unreachable!()
            };
            match value {
                Some(v) => o.insert(key.to_owned(), v),
                None => o.remove(key),
            };
            read_descriptor(&Value::Object(o)).unwrap_err()
        };
        let note = |key: &str, value: Option<Value>| {
            let Value::Object(mut o) = good.clone() else {
                unreachable!()
            };
            let Some(Value::Object(notes)) = o.get_mut("annotations") else {
                unreachable!()
            };
            match value {
                Some(v) => notes.insert(key.to_owned(), v),
                None => notes.remove(key),
            };
            read_descriptor(&Value::Object(o)).unwrap_err()
        };
        let s = |t: &str| Some(Value::Str(t.to_owned()));
        assert_eq!(
            changed("mediaType", None),
            "a descriptor has no \"mediaType\""
        );
        assert_eq!(
            changed("mediaType", Some(Value::Int(1))),
            "mediaType must be a string"
        );
        assert_eq!(changed("digest", None), "a descriptor has no \"digest\"");
        assert_eq!(
            changed("digest", Some(Value::Int(1))),
            "digest must be a string"
        );
        assert_eq!(
            changed("digest", s(&id.blake3.to_string())),
            "digest must be sha256: and 64 lowercase hex digits"
        );
        assert_eq!(
            changed("digest", s("sha256:00")),
            "digest must be sha256: and 64 lowercase hex digits"
        );
        assert_eq!(changed("size", None), "a descriptor has no \"size\"");
        assert_eq!(
            changed("size", Some(Value::Int(-1))),
            "size must not be negative"
        );
        assert_eq!(changed("size", s("3")), "size must be an integer");
        assert_eq!(
            changed("annotations", None),
            "a descriptor has no \"annotations\""
        );
        assert_eq!(
            changed("annotations", Some(Value::Array(Vec::new()))),
            "annotations must be an object"
        );
        assert_eq!(
            note(annotations::BLAKE3, None),
            "a descriptor has no com.ordinpm.blake3"
        );
        assert_eq!(
            note(annotations::BLAKE3, s(&id.sha256.to_string())),
            "com.ordinpm.blake3 must be blake3: and 64 lowercase hex digits"
        );
        assert_eq!(
            note(annotations::FACET, Some(Value::Int(1))),
            "the annotation com.ordinpm.facet must be a string"
        );
        let Value::Object(mut empty) = good.clone() else {
            unreachable!()
        };
        empty.insert("size".to_owned(), Value::Int(0));
        assert_eq!(read_descriptor(&Value::Object(empty)).unwrap().id.size, 0);
    }

    #[test]
    fn differences_are_found_where_they_start() {
        assert_eq!(first_difference(b"abc", b"abd"), 2);
        assert_eq!(first_difference(b"abc", b"ab"), 2);
        assert_eq!(first_difference(b"", b"a"), 0);
        assert_eq!(first_difference(b"xbc", b"abc"), 0);
    }
}
