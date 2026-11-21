// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The OCI image layout around a package: `oci-layout`, `index.json`, the
//! image manifest and its descriptors, all canonical JSON.

use std::collections::BTreeMap;

use ordin_core::json::{self, MAX_INT, Value};

use crate::blob::BlobId;

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
}
