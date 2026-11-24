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
| `--sign-key NAME` | | Sign the package with this secret key file (see `ordin key generate`) |
| `--passphrase-file FILE` | asked for on the terminal | The secret key's passphrase, for scripts and CI. Only with `--sign-key`. |
| `--json` | | Print the result as JSON |

Paths in `--owner`, `--setuid` and `--prefix` are paths in `DIR`, with or without the leading `/`.

**What it prints.** It prints the file written, the package's identity and the facets with their sizes.
- Warnings go to standard error, for example for a default that was used, or a setuid file nobody declared.
- With `--json`, it prints one canonical JSON object instead. Its fields are `arch`, `facets` (each with `size` and `tree`), `file`, `image`, `license`, `name`, `package`, `provides`, `requires`, `signatures` (the keys it was signed with), `size`, `version` and `warnings`.

**Requirements are inferred.** Shared-library requirements and provides come from the ELF files, with symbol versions, and interpreters from `#!` lines. `ordin-pack`'s README has the rules. What can't be inferred safely is a warning, never a guess.
- With `--json`, an error is printed as `{"error": "..."}`, and nothing goes to standard error.

## `ordin show`

```
ordin show FILE [--facets] [--json]
```

Shows what a package holds, without installing or unpacking it. It needs no root.

- **What it prints.** The name, version, architecture and kind; the summary and description; the license and the texts it carries; the package and image digests; and who signed it ("signed by" each key), or "not signed". Every signature has been checked to verify and to sign this package; whether its key is trusted is `ordin verify`'s question (ORD-133).
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
| `signatures` | Each signature's `key`, sorted by key; empty if the package isn't signed |

An error is printed as `{"error": "..."}`, and nothing goes to standard error.

## `ordin key generate`

```
ordin key generate NAME [--comment TEXT] [--passphrase-file FILE | --no-passphrase] [--json]
```

Makes a new Ed25519 key pair for signing packages: `NAME`, the secret key, and `NAME.pub`, the public key to give to whoever checks your packages. `ordin-sign`'s `FORMAT.md` describes both files.

- **The secret key is encrypted** with a passphrase, asked for twice on the terminal with echo off, or read from `--passphrase-file` (its content, without one line break at the end). `--no-passphrase` stores it in the clear, with a warning: then only the file's permissions protect it.
- **Files.** The secret key is written with mode 0600 and the public key with 0644. Neither is ever replaced: an existing file is an error.
- **The comment** goes in the public key file, to say who or what the key is for. There is none unless given, so a key never carries a user or host name by accident.
- **No terminal, no prompt.** A passphrase is only asked for when standard input is a terminal; a script must give `--passphrase-file` or `--no-passphrase`.
- **It prints** the files written and the key. With `--json`: `encrypted`, `key`, `public` and `secret`.

## `ordin sign`

```
ordin sign FILE --key NAME [--passphrase-file FILE] [-o OUT] [--json]
```

Signs a package with the secret key `NAME`, adding its signature, or replacing that key's own. Nothing else changes: the manifest, and so the package's identity, stays the same, and every other part is copied byte for byte. Signing a package afterwards gives exactly the file that `ordin pack --sign-key` would have given.

- **Where it writes.** The package is replaced in place, through a temporary file and a rename, unless `-o` names another file.
- **The key** must be readable and writable by its owner only, as `ssh` requires; otherwise it is refused, with the `chmod` to run. Its passphrase is asked for on the terminal, or read from `--passphrase-file`.
- **It prints** the file, the key, the package and how many signatures it now carries. With `--json`: `file`, `image`, `key`, `package`, `replaced` (whether it replaced the key's earlier signature) and `signatures` (every key, sorted).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The command did what it was asked |
| 1 | It couldn't; the error says why |
| 2 | The command line is wrong |
