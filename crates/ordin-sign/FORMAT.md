<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 The Ordin Authors -->

# Ordin package signatures and key files, format 1

A package is signed with plain Ed25519 keys, so air-gapped and hobby use works without any service. Keyless signing with sigstore is a separate story (ORD-141).

This document is the reference for the signature, the message a key signs, the public key file and the secret key file. `ordin-sign` implements all four, and anything that doesn't follow it is refused.

## Encoding rules

- **Canonical JSON.** The signature and the secret key file are canonical JSON (RFC 8785): no whitespace, keys sorted. A reader requires the bytes to be exactly what the writer writes, so each has one encoding.
- **Hex.** Keys, signatures, salts, nonces and secrets are lowercase hex, with exactly two digits per byte.
- **The version first.** A reader checks the format version before any other field, so a newer file says so instead of naming a field.
- **Unknown fields are refused.** A new field needs a new format version.

## What is signed

A key signs the **package's identity**, the BLAKE3 digest of its manifest, never the manifest's bytes directly. The signed message is this text, in UTF-8:

```
ordin-signature 1 package blake3:<64 hex digits>
```

The prefix names the format and what is signed, so a signature over a package can't be taken for one over anything else that might be signed later, such as a level. Only BLAKE3 identities are signed. Signing never changes the manifest, so it never changes the package's identity.

Signatures are Ed25519 (RFC 8032), checked with `ed25519-dalek`'s strict verification: a non-canonical signature and a public key of small order are refused. Ed25519 signatures are deterministic, so one key signing one package always gives the same bytes.

## The signature

```json
{"key":"ed25519:<64 hex>","ordin-signature":1,"package":"blake3:<64 hex>","signature":"<128 hex>"}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `ordin-signature` | integer | The format version: `1`. |
| `key` | *public key* | Who signed. |
| `package` | *digest* | The package signed: `blake3:` and its identity. |
| `signature` | hex | The 64-byte Ed25519 signature over the message above. |

A signature is at most 1 KiB; it is about 250 bytes. A reader refuses one that doesn't verify. **A signature that verifies says only that its key signed the package.** Whether that key is trusted is decided by whoever reads it, against keys they chose to trust (`ordin verify --trust`, ORD-133).

In a `.ordin` file, each signature is a layer of its own, right after the manifest, sorted by key, with media type `application/vnd.ordin.signature.v1+json` and the annotation `com.ordinpm.key` naming its key. A package carries at most 64 signatures, one per key. `ordin-archive`'s `FORMAT.md` has the details.

## Public keys

A public key is written `ed25519:` and its 32 bytes in hex. **The key is its own identity:** it is short enough to need no fingerprint. Keys sort by their bytes, which is also the order of their text.

A key of small order, which every message would verify against, is refused, as is 32 bytes that aren't a point on the curve.

## The public key file

One line, ending with a line break:

```
ordin-ed25519 <64 hex> <comment>
```

- **The comment** is optional and says who or what the key is for. It is at most 256 characters, has no control characters, and doesn't start or end with a space. `ordin key generate` writes no comment unless asked, so a key never carries a user or host name by accident.
- **Strict.** A reader requires exactly this layout: one space between the parts, no other line, and no space after the key when there is no comment.
- A public key file is at most 4 KiB.

## The secret key file

The secret is the 32-byte Ed25519 seed. It is written in the clear only when asked (`ordin key generate --no-passphrase`); otherwise it is encrypted with a passphrase.

**Encrypted:**

```json
{"cipher":"xchacha20-poly1305","kdf":{"algorithm":"argon2id","lanes":1,"memory":65536,"passes":3,"salt":"<32 hex>"},"key":"ed25519:<64 hex>","nonce":"<48 hex>","ordin-secret-key":1,"secret":"<96 hex>"}
```

**In the clear:**

```json
{"key":"ed25519:<64 hex>","ordin-secret-key":1,"secret":"<64 hex>"}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `ordin-secret-key` | integer | The format version: `1`. |
| `key` | *public key* | The public key of the secret. Opening the file checks that the secret gives it. |
| `cipher` | string | `xchacha20-poly1305`. Present only when the file is encrypted. |
| `kdf.algorithm` | string | `argon2id` (RFC 9106), version 1.3, giving a 32-byte key from the passphrase. |
| `kdf.memory` | integer | Memory in KiB: from 8 per lane to 1,048,576 (1 GiB). New files use 65,536 (64 MiB). |
| `kdf.passes` | integer | 1 to 64. New files use 3. |
| `kdf.lanes` | integer | 1 to 16. New files use 1. |
| `kdf.salt` | hex | 16 random bytes, new for every file. |
| `nonce` | hex | 24 random bytes, new for every file. |
| `secret` | hex | Encrypted: the seed sealed with XChaCha20-Poly1305 under the derived key, with its 16-byte tag (48 bytes). In the clear: the seed (32 bytes). |

- **Everything is bound to the secret.** The cipher authenticates, besides the seed, the canonical JSON of every other field (the file without `secret`). Changing the key, the costs, the salt or the nonce makes the file fail to open, exactly as a wrong passphrase does.
- **Costs are limited.** A reader refuses costs beyond the limits above before deriving anything, so a hostile key file can't exhaust memory or time.
- **Files.** A secret key file is at most 4 KiB. `ordin` writes it with mode 0600 and never replaces an existing one, and refuses to use one that anyone but its owner can read or write.
- **Memory.** The seed, the derived key and the passphrase are cleared from memory when they are dropped.
