# ordin-recipe

The recipe (ordin.toml) schema, its typed expression language and preset expansion. Layer 0 (pure core), licensed MIT OR Apache-2.0.

So far it reads rung 1 (ORD-121): `parse(text)` reads an `ordin.toml` and returns a `Recipe`. It refuses any key the format doesn't have, reads each value with the manifest's own parsers, and checks the declarations against every manifest rule, naming the line and column of the first problem. It does no I/O, and uses only the `toml` crate's spanned document parser, without serde. `FORMAT.md` is the reference for the file.
