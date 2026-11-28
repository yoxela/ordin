<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 The Ordin Authors -->

# The dogfood corpus

Real upstream artifacts, packed by `ordin pack` in CI, so that packing is tested on reality and not only on fixtures (ORD-152).

| Package | What it stands for |
| --- | --- |
| `ripgrep-x86_64` | A static binary (musl), laid out from an upstream release tarball |
| `ripgrep-aarch64` | The same for aarch64, so inference meets an AArch64 ELF file |
| `go` | A toolchain tarball: about 17,000 files, with links in `/usr/bin`, and test files for other machines left out of inference by its recipe |
| `jq` | A dynamically linked program with the two libraries it needs (Debian trixie) |
| `logrotate` | Config under `etc/`, state under `var/lib` and a systemd timer (Debian trixie) |
| `devscripts` | Scripts in sh, bash, Perl and Python (Debian trixie) |

## Running it

```
cargo xtask corpus            # pack everything and compare with the golden files
cargo xtask corpus --update   # write the golden files instead; review them with git diff corpus/
```

It needs `curl` and `dpkg-deb`, and about 400 MB under `target/corpus/`.

1. It builds the release `ordin` (`cargo build --release --locked -p ordin`).
2. It downloads each source to `target/corpus/downloads/<sha256>`, or reuses the copy there, and checks its size and SHA-256 before anything reads it. A wrong copy is removed and downloaded again; a download no source names any more is removed.
3. It lays the sources out as an install root in `target/corpus/stage/<name>/`.
4. It packs the install root with the package's recipe and license texts into `target/corpus/out/<name>.ordin`.
5. It compares `ordin show --json` of that package with `corpus/<name>/show.json`.

Every package is packed before differences are reported, each as JSON pointers with the old and new values. After a successful run the install roots are removed and the packages kept. After a failure both are kept, so you can look at them.

**A golden file changes** whenever anything about a package changes, since it holds the package and image digests: a manifest field, inference, facet rules, chunking or the archive layout. Review the diff like code. CI checks the same golden files on x86\_64 and on aarch64, so a package that packs differently on one architecture fails there.

## How downloads are handled

The sources are pinned, but they are still read as if they weren't trusted.
- `curl` runs without `~/.curlrc`, over https only, redirects included, and with the declared size as its limit.
- A Debian package is only decompressed, by `dpkg-deb --fsys-tarfile`. xtask reads the tar stream itself.
- An archive path must be plain names: an absolute path, `..`, an empty name, a control character or a name that isn't UTF-8 is refused.
- Nothing is written below a path that isn't a directory written in this run, so a symlink in an archive is never followed. Files are created new, and no path is written twice, except a directory with the same mode.
- Only files, directories, symlinks and hard links to files already laid out are taken. Setuid, setgid and sticky bits are refused.
- An install root may hold at most 100,000 entries and 2 GiB.

## `corpus.toml`

```toml
format = 1

[[package]]
name = "go"
about = "a toolchain tarball"
licenses = { "BSD-3-Clause" = "usr/lib/go/LICENSE" }
links = [{ path = "usr/bin/go", target = "../lib/go/bin/go" }]

[[package.source]]
url = "https://dl.google.com/go/go1.27.4.linux-amd64.tar.gz"
size = 70680823
sha256 = "7226736c…"
format = "tar.gz"
place = [{ from = "go", to = "usr/lib/go" }]
exclude = [{ path = "go/test", reason = "…" }]
```

Every key is checked, and any other key is refused.

**`[[package]]`**

| Key | Required | Meaning |
| --- | --- | --- |
| `name` | yes | The package's name in the corpus, and its directory here: lowercase letters, digits, `-` and `_` |
| `about` | yes | One line: what it stands for in the corpus |
| `licenses` | | Each license ID mapped to its text's path in the install root, passed as `--license-file` |
| `links` | | Symlinks added to the install root after its sources: `path` and `target` |
| `source` | yes | Its downloads, laid out in order into one install root |

**`[[package.source]]`**

| Key | Required | Meaning |
| --- | --- | --- |
| `url` | yes | An `https` URL that won't change: a release asset, or a dated `snapshot.debian.org` path |
| `size` | yes | Its size in bytes, at most 512 MiB |
| `sha256` | yes | Its SHA-256, in lowercase hex. Compare it with a second source when you add it: the project's published checksum, or Debian's `Packages` index |
| `format` | yes | `tar.gz`, or `deb` for a Debian binary package |
| `strip` | | For `tar.gz`: how many leading names to remove from every path, such as a `ripgrep-16.0.0-…/` directory. Every entry must share them. |
| `place` | | Where entries go, as `{ from, to }`: everything at or below `from` in the archive (after stripping) goes to `to` in the install root. The most specific `from` wins, and `""` stands for everything. Without `place`, every entry goes where it is, which suits a deb. |
| `exclude` | | Paths in the archive left out, with everything below them, each with a one-line `reason` |

**Every entry must be placed or excluded,** and every `place` and `exclude` must match something. Then a new or renamed file upstream fails the run instead of being dropped or packed by accident. The only exception is a directory: one that isn't placed is skipped, and made where something placed needs it.

## Adding a package

1. Add its `[[package]]` to `corpus.toml`, with the hash checked against a second source.
2. Write its recipe, `corpus/<name>/ordin.toml`.
3. Run `cargo xtask corpus --update`, and fix whatever it refuses.
4. Review the new `show.json`, and commit all three.

The packages here are tests, and nothing here is ever installed. Their licenses come from each upstream's own statement: Debian's `copyright` files for the Debian packages.
