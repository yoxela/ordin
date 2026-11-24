# ordin-sign

Package signatures with plain Ed25519 keys, so air-gapped and hobby use works without any service. Sigstore bundles come later (ORD-141). Layer 1 (infrastructure), licensed MIT OR Apache-2.0.

[`FORMAT.md`](FORMAT.md) is the reference for every format here (CC-BY-4.0).

- `SecretKey::generate` makes a key from the operating system's random bytes, and `SecretKey::sign` signs a package's identity, the BLAKE3 digest of its manifest. Signing never changes the manifest.
- `Signature::from_bytes` reads a signature and checks that it verifies, with Ed25519's strict rules, so every `Signature` value verifies. Whether its key is trusted is the caller's question.
- `PublicKey` is written `ed25519:` and 64 hex digits, and is its own identity. Weak keys are refused.
- `PublicKeyFile` is the one-line public key file. `SecretKeyFile` is the secret key file: canonical JSON, with the secret encrypted by XChaCha20-Poly1305 under a key Argon2id derives from a passphrase, or in the clear when made without one. Reading a key file refuses Argon2 costs beyond fixed limits, so a hostile file can't exhaust memory.

Secrets, derived keys and passphrases are cleared from memory when dropped, and `Debug` never shows them. Nothing here reads or writes files, and no input makes it panic: every parser has a fuzz target.

The cryptography comes from RustCrypto and `ed25519-dalek`, wrapped here so it can be replaced.
