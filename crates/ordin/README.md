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
| `--arch ARCH` | this machine's, with a warning | `x86_64`, `aarch64` or `noarch` |
| `-o`, `--out FILE` | `NAME-VERSION.ARCH.ordin` here | The file to write. An epoch's `:` becomes `_`. An existing file is replaced. |
| `--owner PATH=USER:GROUP` | `root:root` | The owner of a path in `DIR` and everything below it. Repeatable. |
| `--setuid PATH` | | A file in `DIR` that is setuid or setgid on purpose. Repeatable. |
| `--prefix PATH` | | A prefix the software was installed with, such as `opt/foo`. Its contents move to `/usr`. Repeatable. |
| `--json` | | Print the result as JSON |

Paths in `--owner`, `--setuid` and `--prefix` are paths in `DIR`, with or without the leading `/`.

**What it prints.** It prints the file written, the package's identity and the facets with their sizes.
- Warnings go to standard error, for example for a default that was used, or a setuid file nobody declared.
- With `--json`, it prints one canonical JSON object instead. Its fields are `arch`, `facets` (each with `size` and `tree`), `file`, `image`, `license`, `name`, `package`, `size`, `version` and `warnings`.
- With `--json`, an error is printed as `{"error": "..."}`, and nothing goes to standard error.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The command did what it was asked |
| 1 | It couldn't; the error says why |
| 2 | The command line is wrong |
