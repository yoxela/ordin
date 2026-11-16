# ordin-manifest

The package manifest: its schema, validation and canonical JSON (RFC 8785). Layer 0 (pure core), licensed MIT OR Apache-2.0.

[`SCHEMA.md`](SCHEMA.md) is the reference for every field and rule (CC-BY-4.0).

- `Manifest::from_signed_bytes` reads a signed manifest. The bytes must already be canonical JSON, byte for byte, and the result includes the package's identity: the BLAKE3 digest of those bytes.
- `Manifest::from_json` reads any spacing and key order, for tools and tests, and checks every other rule. It is never for signed manifests.
- `Manifest::to_canonical_bytes` and `Manifest::digest` encode a manifest and check the result against every rule again.

Reading refuses duplicate keys, non-integer numbers, unknown fields (unless the manifest's own `ignorable` list names them), unknown values, fields set to their default, unsorted sets and text that isn't in its canonical form. Every error names the field: `declares.users[2].name: an account name uses letters, digits, '_' and '-'; '.' at byte 2 isn't allowed`.
