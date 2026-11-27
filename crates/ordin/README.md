# ordin

The ordin command-line interface. Layer 3 (program), licensed GPL-3.0-or-later.

## `ordin pack`

```
ordin pack DIR [--name NAME] [--version VERSION | --version-from git] [options]
```

Makes a package from an install root: what `make install DESTDIR=DIR` filled. Only a name and a version are needed, from the flags or from a recipe (rung 1, below); without them it exits with 2.

| Option | Default | Meaning |
| --- | --- | --- |
| `--manifest FILE` | `./ordin.toml`, if there is one | The recipe to read |
| `--no-manifest` | | Read no recipe, not even `./ordin.toml` |
| `--name NAME` | the recipe's | The package's name |
| `--version VERSION` | the recipe's | The upstream version, with an optional epoch: `2.12`, `1:2.0` |
| `--version-from git` | | Make the version from the git checkout at the working directory, and record its commit; see below. Instead of `--version`. |
| `--release N` | the recipe's, or `1` | The release number |
| `--license EXPR` | the recipe's, or `NOASSERTION` with a warning | An SPDX license expression |
| `--license-file ID=PATH` | | The text of one license ID in the license. Repeat it for each ID. Every ID needs one, from here or from the recipe, except for `NOASSERTION` and `NONE`. It replaces the recipe's text for that ID. A text is at most 1 MiB. |
| `--summary TEXT` | the recipe's, or the name with a warning | One line about the package |
| `--arch ARCH` | the recipe's, or found from the package's programs and libraries, and `noarch` if it has none | `x86_64`, `aarch64` or `noarch`. It must match the programs and libraries. |
| `-o`, `--out FILE` | `NAME-VERSION.ARCH.ordin` here | The file to write. An epoch's `:` becomes `_`. An existing file is replaced. |
| `--owner PATH=USER:GROUP` | `root:root` | The owner of a path in `DIR` and everything below it. Repeatable. |
| `--setuid PATH` | | A file in `DIR` that is setuid or setgid on purpose. Repeatable. |
| `--prefix PATH` | | A prefix the software was installed with, such as `opt/foo`. Its contents move to `/usr`. Repeatable. |
| `--sign-key NAME` | | Sign the package with this secret key file (see `ordin key generate`) |
| `--passphrase-file FILE` | asked for on the terminal | The secret key's passphrase, for scripts and CI. Only with `--sign-key`. |
| `--json` | | Print the result as JSON |

Paths in `--owner`, `--setuid` and `--prefix` are paths in `DIR`, with or without the leading `/`.

**What it prints.** It prints the file written, the package's identity and the facets with their sizes, then the recipe read, if any, and the commit with `--version-from git`.
- Warnings go to standard error, for example for a default that was used, or a setuid file nobody declared.
- With `--json`, it prints one canonical JSON object instead. Its fields are `arch`, `commit` (the git commit recorded, or `null`), `facets` (each with `size` and `tree`), `file`, `image`, `license`, `name`, `package`, `provides`, `recipe` (the recipe read, or `null`), `requires`, `signatures` (the keys it was signed with), `size`, `version` and `warnings`.

**A recipe** (rung 1, `crates/ordin-recipe/FORMAT.md`) gives what can't be inferred, in about ten lines of TOML: the name, version, summary and license with its texts and presentation, extra requirements, provides and conflicts, users, groups, units, settings, state, and paths moved to another facet.
- It is `./ordin.toml` in the working directory, the project's own file beside its checkout, or the file `--manifest` names. Its license paths are relative to its own directory, and are read without leaving it or going through a symlink.
- A flag wins over the recipe's value for the same field. Requirements and provides are added to the inferred ones, and declared state wins over inferred state at the same path.
- A unit must be shipped by the package (in `/usr/lib/systemd/system/` or `/usr/lib/systemd/user/`, or its template for an instance), and a seed's source must be a file in the package.
- A mistake in it is an error naming the file, line and column: `ordin.toml:3:8: expected a package name: …`.

**Versions from git.** `--version-from git` versions a snapshot build from its checkout, so nightly packages sort correctly:
- After the nearest tag that looks like a version (`v1.4.2` or `1.4.2`): the tag's version, `^`, HEAD's commit date in UTC, the number of commits since the tag and the first 7 hex digits of the commit: `1.4.2^20261112.37.g3fa9c1e`. That sorts after 1.4.2 and before 1.4.3. With no such tag, it starts from `0^`. At the tagged commit itself, it is the tag's version: `1.4.2`.
- The full commit is recorded in the manifest's `provenance.commit`, and printed.
- A checkout whose tracked files differ from HEAD is refused, since the version would describe something else; untracked files, such as the install root, don't count. A shallow clone is refused, since it can't count the commits: fetch the whole history (`fetch-depth: 0` in GitHub Actions).
- The `git` program is run with read-only commands only, without the file-system monitor, replace refs, a pager or a prompt.

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

## `ordin verify`

```
ordin verify FILE [--trust KEY.pub]... [--json]
```

Checks that a package is intact, every byte of it, and that a key you trust signed it.

- **Every byte.** Each blob is checked against both digests its descriptor records, each part against its format, and each file is put together from its chunks and checked against the size, BLAKE3 and fs-verity digests its tree records. Each file is also cut again with the chunking the chunk index records, which must give exactly the chunks the index lists, so a package can't claim one chunking and carry another. Anything else the writer wouldn't write is refused too: a chunk no file uses, chunks out of order, an index entry nothing needs. A single changed byte anywhere fails, and the error names the part it is in.
- **Trust.** `--trust` names the public key file (`ordin key generate`'s `NAME.pub`) of a signer you trust; give it once for each key. Only a signature by one of those keys makes the package trusted. Without `--trust`, no key is: an intact, signed package then exits 5, so 0 always means "signed by a key you chose".
- **It prints** that the file is intact, the package and image digests, each facet's files, chunks and size, and each signature's key, trusted or not. When the package isn't trusted, standard error says why. With `--json`: `facets` (each with `chunks`, `facet`, `files` and `size`), `file`, `image`, `licenses`, `package`, `result` (`trusted`, `unsigned` or `untrusted`) and `signatures` (each with `key` and `trusted`, sorted by key). A corrupt package prints `{"error": "...", "result": "corrupt"}`.
- **Exit codes**, worst first: 3 if the package is corrupt, 4 if it is intact but not signed, 5 if it is signed only by keys not given with `--trust`, and 0 if a trusted key signed it. 1 means it couldn't be checked: the file can't be read, or a `--trust` file isn't a public key file.

## `ordin unpack`

```
ordin unpack FILE --to DIR [--facet NAME]... [--json]
```

Writes a package's files to a new directory, without root, to see exactly what is inside. Every facet is unpacked into one tree, as a host would see it; `--facet` unpacks only the facets named. A directory can be in several facets if it is the same in each; any other path two facets both have is refused.

- **Nothing is replaced, and a failure leaves nothing.** `DIR` and its sidecar must not exist. Everything is written into a new private directory beside `DIR` and renamed into place only when all of it is there.
- **Nothing lands outside.** Each directory is opened a name at a time without following symlinks, and each file is created new, so no symlink or name in the package can make a write leave `DIR`.
- **Every file is checked** as it is written: each chunk against its digest, then the whole file against its tree. Signatures aren't checked; `ordin verify` does that.
- **Only permission bits are applied.** Owners, the setuid, setgid and sticky bits, extended attributes and capabilities need root, or would make the copy grant what the package grants, so they are left out. `DIR` itself is private (0700).
- **The sidecar,** `DIR.ordin-meta.json` beside `DIR`, records them all: each unpacked facet's tree exactly, in `ordin-tree`'s format, as canonical JSON: `{"facets": {NAME: TREE, ...}, "ordin-unpack": 1, "package": "blake3:..."}`. `ordin-unpack` is the sidecar's format version.
- **It prints** what it wrote: the facets, and how many directories, files (with their size), symlinks and hard links. With `--json`: `dirs`, `facets`, `file`, `files`, `hard_links`, `meta` (the sidecar), `package`, `size`, `symlinks` and `to`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The command did what it was asked |
| 1 | It couldn't; the error says why |
| 2 | The command line is wrong |
| 3 | `ordin verify`: the package is corrupt |
| 4 | `ordin verify`: the package is intact but not signed |
| 5 | `ordin verify`: the package is signed, but by no key given with `--trust` |
