// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! Reading `.ordin` files (ORD-131), signed (ORD-140). Any bytes are read or refused, never
//! a panic, and a changed package is either refused or gives exactly the
//! content it held before.
//!
//! An input whose first byte is even is read as a whole file. Otherwise
//! the rest is a list of changes to a small package written at start-up:
//! four bytes of offset and one byte to XOR there, so the fuzzer reaches
//! the checks past the archive and the OCI JSON.

#![no_main]

use std::collections::BTreeMap;
use std::io::{self, Cursor};
use std::num::NonZeroUsize;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use ordin_archive::{Options, Package, Reader, Source, write};
use ordin_core::{Account, Digest, Facet};
use ordin_manifest::Manifest;
use ordin_sign::SecretKeyFile;
use ordin_tree::chunk::ChunkParams;
use ordin_tree::{Entry, FILE_MODE, File, Kind, Tree, TreePath, Xattrs, file_digests};

/// Everything a package holds.
#[derive(Debug, PartialEq, Eq)]
struct Everything {
    package: Digest,
    signers: Vec<String>,
    licenses: Vec<Vec<u8>>,
    trees: Vec<Tree>,
    files: Vec<Vec<u8>>,
}

fn read_all(bytes: &[u8]) -> Option<Everything> {
    let mut r = Reader::open(Cursor::new(bytes)).ok()?;
    let ids: Vec<String> = r.license_ids().map(str::to_owned).collect();
    let licenses = ids
        .iter()
        .map(|id| r.license_text(id).ok())
        .collect::<Option<_>>()?;
    let index = r.chunk_index().ok()?;
    let facets: Vec<Facet> = r.facets().cloned().collect();
    let (mut trees, mut files) = (Vec::new(), Vec::new());
    for facet in &facets {
        let tree = r.tree(facet).ok()?;
        let table = r.pack_table(facet).ok()?;
        for entry in tree.entries() {
            if let Kind::File(file) = &entry.kind {
                let mut out = Vec::new();
                r.read_file(facet, &table, &index, &entry.path, file, &mut out)
                    .ok()?;
                files.push(out);
            }
        }
        trees.push(tree);
    }
    Some(Everything {
        package: r.package(),
        signers: r.signatures().iter().map(|s| s.key().to_string()).collect(),
        licenses,
        trees,
        files,
    })
}

struct Files(BTreeMap<String, Vec<u8>>);

impl Source for Files {
    type Reader = Cursor<Vec<u8>>;

    fn open(&mut self, path: &TreePath, _: &File) -> io::Result<Self::Reader> {
        self.0
            .get(path.as_str())
            .cloned()
            .map(Cursor::new)
            .ok_or_else(|| io::Error::other("no such file"))
    }
}

fn file(path: &str, bytes: &[u8]) -> Entry {
    let d = file_digests(bytes).expect("in memory");
    Entry {
        path: path.parse().expect("a path"),
        kind: Kind::File(File {
            mode: FILE_MODE,
            owner: Account::root(),
            group: Account::root(),
            size: d.size,
            content: d.content,
            fsverity: d.fsverity,
            xattrs: Xattrs::new(),
            capabilities: None,
        }),
    }
}

/// A fixed key: RFC 8032's first test key, from a key file in the clear.
const KEY: &str = r#"{"key":"ed25519:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","ordin-secret-key":1,"secret":"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"}"#;

/// A small package: a runtime facet with a file cut into chunks and an
/// empty file, and a doc facet with one small file, signed by one key.
fn base() -> &'static (Vec<u8>, Everything) {
    static BASE: OnceLock<(Vec<u8>, Everything)> = OnceLock::new();
    BASE.get_or_init(|| {
        let big: Vec<u8> = (0..1500u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
        let files = BTreeMap::from([
            ("/big".to_owned(), big.clone()),
            ("/empty".to_owned(), Vec::new()),
            ("/README".to_owned(), b"Says hello.\n".to_vec()),
        ]);
        let runtime = Tree::new(vec![file("/big", &big), file("/empty", b"")]).expect("a tree");
        let doc = Tree::new(vec![file("/README", b"Says hello.\n")]).expect("a tree");
        let text = b"Permission is hereby granted...\n".to_vec();
        let facet = |tree: &Tree, size: usize| {
            format!(r#"{{"tree":"{}","size":{size}}}"#, tree.digest().expect("a digest"))
        };
        let manifest = Manifest::from_json(&format!(
            r#"{{"ordin":1,"name":"hello","version":{{"upstream":"1","release":"1"}},"kind":"base","arch":"noarch","summary":"Says hello","license":{{"spdx":"MIT","texts":{{"MIT":"{}"}}}},"facets":{{"doc":{},"runtime":{}}}}}"#,
            Digest::blake3(&text),
            facet(&doc, 12),
            facet(&runtime, big.len()),
        ))
        .expect("a manifest");
        let trees: BTreeMap<Facet, Tree> = BTreeMap::from([
            ("doc".parse().expect("a facet"), doc),
            ("runtime".parse().expect("a facet"), runtime),
        ]);
        let licenses = BTreeMap::from([("MIT".to_owned(), text)]);
        let key = SecretKeyFile::from_bytes(KEY.as_bytes())
            .expect("a key file")
            .open(None)
            .expect("a key");
        let identity = Digest::blake3(&manifest.to_canonical_bytes().expect("a manifest"));
        let signatures = [key.sign(&identity).expect("a signature")];
        let package = Package {
            manifest: &manifest,
            trees: &trees,
            licenses: &licenses,
            chunking: ChunkParams::new(64, 256, 1024, 256, 1).expect("chunk settings"),
            signatures: &signatures,
        };
        let mut out = Vec::new();
        write(
            &package,
            &mut Files(files),
            &Options {
                level: 3,
                threads: NonZeroUsize::MIN,
            },
            &std::env::temp_dir(),
            &mut out,
        )
        .expect("the package is written");
        let all = read_all(&out).expect("the package reads back");
        (out, all)
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode % 2 == 0 {
        let _ = read_all(rest);
        return;
    }
    let (bytes, all) = base();
    let mut changed = bytes.clone();
    for change in rest.chunks_exact(5) {
        let at = u32::from_le_bytes([change[0], change[1], change[2], change[3]]) as usize;
        let len = changed.len();
        changed[at % len] ^= change[4];
    }
    if let Some(read) = read_all(&changed) {
        assert_eq!(&read, all, "an accepted change must give the same content");
    }
});
