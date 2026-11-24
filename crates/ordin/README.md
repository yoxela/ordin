# ordin

The ordin command-line interface. Layer 3 (program), licensed GPL-3.0-or-later.

## `ordin pack`

```
ordin pack DIR --name NAME --version VERSION [options]
```

Makes a package from an install root (rung 0): what `make install DESTDIR=DIR` filled. Only `--name` and `--version` are needed.

| Option | Default | Meaning |
| --- | --- | --- |
| `--version VERSION` | | The upstream version, with an optional epoch: `2.12`, `1:2.0` |
| `--release N` | `1` | The release number |
| `--license EXPR` | `NOASSERTION`, with a warning | An SPDX license expression |
| `--license-file ID=PATH` | | The text of one license ID in `--license`. Repeat it for each ID. Every ID needs one, except for `NOASSERTION` and `NONE`. A text is at most 1 MiB. |
| `--summary TEXT` | the name, with a warning | One line about the package |
| `--arch ARCH` | found from the package's programs and libraries, and `noarch` if it has none | `x86_64`, `aarch64` or `noarch`. It must match the programs and libraries. |
| `-o`, `--out FILE` | `NAME-VERSION.ARCH.ordin` here | The file to write. An epoch's `:` becomes `_`. An existing file is replaced. |
| `--owner PATH=USER:GROUP` | `root:root` | The owner of a path in `DIR` and everything below it. Repeatable. |
| `--setuid PATH` | | A file in `DIR` that is setuid or setgid on purpose. Repeatable. |
| `--prefix PATH` | | A prefix the software was installed with, such as `opt/foo`. Its contents move to `/usr`. Repeatable. |
| `--json` | | Print the result as JSON |

Paths in `--owner`, `--setuid` and `--prefix` are paths in `DIR`, with or without the leading `/`.

**What it prints.** It prints the file written, the package's identity and the facets with their sizes.
- Warnings go to standard error, for example for a default that was used, or a setuid file nobody declared.
- With `--json`, it prints one canonical JSON object instead. Its fields are `arch`, `facets` (each with `size` and `tree`), `file`, `image`, `license`, `name`, `package`, `provides`, `requires`, `size`, `version` and `warnings`.

**Requirements are inferred.** Shared-library requirements and provides come from the ELF files, with symbol versions, and interpreters from `#!` lines. `ordin-pack`'s README has the rules. What can't be inferred safely is a warning, never a guess.
- With `--json`, an error is printed as `{"error": "..."}`, and nothing goes to standard error.

## `ordin show`

```
ordin show FILE [--facets] [--json]
```

Shows what a package holds, without installing or unpacking it. It needs no root.

- **What it prints.** The name, version, architecture and kind; the summary and description; the license and the texts it carries; the package and image digests; and the signature status, which is "not signed" until signing arrives (ORD-140).
- **Then each section that has anything in it.** The facets with their sizes, the relations to other packages (requires, provides, conflicts, recommends, supplements, obsoletes, replaces, removes), the declarations (users, groups, units, config, alternatives, triggers, setuid files, boot files), state, settings, the programs it runs, tests, security policy, a delegated payload, fixes and notices.
- **`--facets`** also reads each facet's tree and lists its entries as `ls -l` would: type and mode, owner, size and path, with a symlink's target (`->`), a hard link's file (`=>`), and any capabilities or extended attributes.
- **Every string is made safe for a terminal.** Control characters and the bidirectional formatting characters are printed as `\u{…}`, so a package can't send escape sequences or reorder what you read.

**What it reads.** Opening the file checks its archive, its OCI files and its manifest. `--facets` also reads each tree, checked against the digest the manifest records. The chunks are never read; `ordin verify` checks those. A FIFO, a device or a directory is refused before it is opened.

**With `--json`,** it prints one canonical JSON object:

| Field | Meaning |
| --- | --- |
| `file` | The file shown, as given |
| `files` | With `--facets`: each facet's tree entries, exactly as the tree records them (`ordin-tree`'s `FORMAT.md`) |
| `image` | The OCI image manifest's digest |
| `manifest` | The manifest, exactly as signed (`ordin-manifest`'s `SCHEMA.md`) |
| `package` | The package's identity: the BLAKE3 digest of the manifest |
| `signature` | `null`; signing arrives with ORD-140 |

An error is printed as `{"error": "..."}`, and nothing goes to standard error.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The command did what it was asked |
| 1 | It couldn't; the error says why |
| 2 | The command line is wrong |
