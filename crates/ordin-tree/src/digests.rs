// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! A file's size and digests, from one pass over its bytes.
//!
//! The fs-verity digest is the one the kernel measures and `fsverity
//! digest` prints, with SHA-256, 4 KiB blocks and no salt:
//!
//! 1. The file is cut into 4 KiB blocks, the last padded with zeros.
//! 2. Each block is hashed, and the hashes are packed 128 to a block, the
//!    last padded with zeros. Those blocks are hashed in turn, level by
//!    level, until a level is a single block. Its hash is the root. An
//!    empty file has an all-zero root.
//! 3. The digest is the SHA-256 of a 256-byte descriptor holding the
//!    parameters, the file's size and the root.

use std::io::{self, ErrorKind, Read};

use ordin_core::{Algorithm, Blake3Hasher, Digest};
use sha2::{Digest as _, Sha256};

/// The size of a Merkle tree block.
const BLOCK_SIZE: usize = 4096;

/// The base-2 logarithm of [`BLOCK_SIZE`], as the descriptor records it.
const LOG_BLOCK_SIZE: u8 = 12;

/// How much [`file_digests`] asks for at a time: 128 KiB. Large reads mean
/// fewer system calls, and let BLAKE3 hash many chunks at once.
const READ_SIZE: usize = 131_072;

/// The descriptor's bytes after the first 32 bytes of the root: the rest
/// of its 64-byte root field, the salt and the reserved space. All zero.
const DESCRIPTOR_TAIL: usize = 208;

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// One level of the Merkle tree: the data itself at the bottom, hashes
/// above it. Only the block being filled is kept, so memory depends on
/// the tree's height, at most nine levels for any file size.
#[derive(Debug, Default)]
struct Level {
    /// The current block, at most [`BLOCK_SIZE`] bytes.
    block: Vec<u8>,
    /// The next level up, which exists once this level has passed a block.
    above: Option<Box<Level>>,
}

impl Level {
    /// Adds bytes. A full block stays here until more bytes arrive,
    /// because only then is it known not to be the level's only block.
    fn append(&mut self, bytes: &[u8]) {
        let room = BLOCK_SIZE - self.block.len();
        let (head, tail) = bytes.split_at(room.min(bytes.len()));
        self.block.extend_from_slice(head);
        for chunk in tail.chunks(BLOCK_SIZE) {
            self.above
                .get_or_insert_default()
                .append(&sha256(&self.block));
            self.block.clear();
            self.block.extend_from_slice(chunk);
        }
    }

    /// Pads the last block and hashes upwards. A level with nothing above
    /// has only ever had this block, so its hash is the root.
    fn root(mut self) -> [u8; 32] {
        self.block.resize(BLOCK_SIZE, 0);
        let hash = sha256(&self.block);
        match self.above {
            Some(mut above) => {
                above.append(&hash);
                above.root()
            }
            None => hash,
        }
    }
}

/// The fs-verity digest of a file with this size and Merkle root.
fn fsverity_digest(size: u64, root: &[u8; 32]) -> Digest {
    let mut descriptor = Sha256::new();
    // Version 1, SHA-256 (algorithm 1), the block size, no salt.
    descriptor.update([1, 1, LOG_BLOCK_SIZE, 0]);
    // Reserved.
    descriptor.update([0; 4]);
    descriptor.update(size.to_le_bytes());
    descriptor.update(root);
    descriptor.update([0; DESCRIPTOR_TAIL]);
    Digest::new(Algorithm::Sha256, descriptor.finalize().into())
}

/// What a file entry records about a file's content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileDigests {
    /// The length in bytes.
    pub size: u64,
    /// The BLAKE3 digest of the bytes: the file object's identity.
    pub content: Digest,
    /// The fs-verity digest: SHA-256, 4 KiB blocks, no salt.
    pub fsverity: Digest,
}

/// Computes a file's digests from its bytes, given piece by piece. The
/// pieces can be any size, and the result depends only on their
/// concatenation.
#[derive(Debug, Default)]
pub struct FileHasher {
    content: Blake3Hasher,
    data: Level,
    size: u64,
}

impl FileHasher {
    /// Adds the file's next bytes.
    pub fn update(&mut self, bytes: &[u8]) {
        self.content.update(bytes);
        self.data.append(bytes);
        let added = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.size = self.size.saturating_add(added);
    }

    /// The size and digests of everything added.
    #[must_use]
    pub fn finish(self) -> FileDigests {
        let root = if self.size == 0 {
            [0; 32]
        } else {
            self.data.root()
        };
        FileDigests {
            size: self.size,
            content: self.content.finish(),
            fsverity: fsverity_digest(self.size, &root),
        }
    }
}

/// Reads `reader` to its end, once, and returns the size and digests of
/// what it gave.
///
/// # Errors
///
/// Any error from `reader`, except that an interrupted read is retried.
/// A reader claiming to have read more than it was asked for gives
/// [`ErrorKind::InvalidData`].
pub fn file_digests(mut reader: impl Read) -> io::Result<FileDigests> {
    let mut hasher = FileHasher::default();
    let mut buffer = vec![0; READ_SIZE];
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(0) => return Ok(hasher.finish()),
            Ok(count) => count,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let Some(bytes) = buffer.get(..count) else {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "a reader claimed more bytes than its buffer holds",
            ));
        };
        hasher.update(bytes);
    }
}
