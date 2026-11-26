<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 The Ordin Authors -->

# The Ordin package manifest, format 1

A package is one manifest plus content trees. The manifest is a JSON object, encoded canonically (RFC 8785), and signed. **A package's identity is the BLAKE3 digest of its canonical bytes**, written `blake3:<64 lowercase hex digits>`.

This document is the reference for every field. `ordin-manifest` implements it, and a manifest that doesn't follow it is refused.

## Encoding rules

These rules make sure one package has exactly one encoding, and so exactly one identity.

1. **Canonical JSON (RFC 8785).** A signed manifest's bytes must already be canonical, byte for byte. Readers check this and refuse anything else, so the bytes that are signed are the bytes that are parsed.
2. **No duplicate keys.** An object with a repeated key is refused. Common JSON parsers (serde_json among them) silently keep the last value, so the reader detects duplicates itself.
3. **Keys are printable ASCII** (`!` to `~`). For ASCII, RFC 8785's sort by UTF-16 code units and a sort by bytes agree. Each kind of key keeps its own grammar on top (license IDs, sonames, facets, setting names, SELinux booleans).
4. **Integers only.** Every number is an integer with absolute value at most 2⁵³−1. Fractions, exponents and `-0` are refused, so RFC 8785's number formatting never matters.
5. **Defaults are left out.** A field whose value equals its default is refused; it must be omitted. The default of each field is listed below. Empty arrays and empty objects are refused for the same reason.
6. **Sets are sorted.** An array marked *set* holds unique elements in ascending byte order of their canonical text.
7. **Text is checked.** Every field with a grammar (names, atoms, versions, expressions, paths, digests) must be in that grammar's canonical form. A dependency expression must be the text `ordin-depexpr` prints for it.
8. **Free text** (summary, description, notices) is UTF-8 without control characters; only `description` and notices may contain line breaks (`\n`).
9. **Size.** A manifest is at most 1 MiB.
10. **Nothing varies between builds.** There is no build timestamp, host name or builder identity. Two builds of the same recipe and inputs must produce the same manifest, so the same identity; when and where a build ran belongs to the SLSA attestation under `provenance`.

## Versions and evolution

`"ordin": 1` is the format's major version. A reader refuses any other value.

Within format 1:

- **An unknown field is refused,** unless the manifest's own `ignorable` list names it. The writer decides, per field, whether an older reader may skip it. A field an older reader can safely skip (more description, a hint) goes in `ignorable`. A field that changes what installing the package means does not, so old readers refuse the package instead of installing it wrongly; that needs no new major version.
- **An unknown value in a known field is refused,** always: a new kind, state class, hook phase, trigger action or any other enumerated value. `ignorable` covers new fields only, never new values.
- **A new major version** is needed only when the meaning of an existing field or value changes.

`ignorable` lists dotted paths that ignore array positions, with `*` for a key that is data rather than a field name (a facet, license ID, soname, phase or name): `declares.users.uid` covers that field in every user, and `facets.*.digest-v2` in every facet. `ignorable` is signed with everything else, so nobody can mark a field skippable after the fact.

## Common types

| Type | Form |
| --- | --- |
| *name* | A package name (`ordin-core`): `[a-z0-9][a-z0-9+.-]*`, 2 to 128 bytes, and not one of the dependency language's keywords `and`, `or`, `not`, `if` |
| *atom* | A package name, or a `cap:`, `so:` or `file:` atom (`ordin-core`). A `so:` atom may name a symbol version node: `so:libc.so.6@GLIBC_2.38` |
| *facet* | `[a-z][a-z0-9-]*`, optionally followed by `:` and a qualifier of `[A-Za-z0-9_@.+-]+`, up to 64 bytes: `runtime`, `locale:pt_BR`, `locale:ca@valencia` (`ordin-core`) |
| *arch* | `x86_64`, `aarch64` or `noarch` |
| *account* | A user or group name: `[A-Za-z_][A-Za-z0-9_-]*`, 1 to 32 bytes, as systemd allows: `_apt`, `systemd-network`, `Debian-exim` |
| *unit* | A systemd unit name: `[A-Za-z0-9:_.\-]+`, an optional `@` template part, and a unit type suffix (`.service`, `.socket`, `.timer`, `.path`, `.mount`, `.automount`, `.swap`, `.target`, `.slice`), up to 255 bytes, with systemd's `\xNN` escapes: `getty@.service`, `dev-disk-by\x2dlabel.mount` |
| *version text* | A version in canonical form, as `ordin-version` shows it |
| *expr* | A dependency expression in canonical text (`ordin-depexpr`) |
| *digest* | `blake3:` and 64 lowercase hex digits. Only `provenance` may also use `sha256:`, for attestations made by outside tools |
| *path* | Absolute and normalized, printable ASCII without spaces, brackets, `,` or `= ! < > ~` (the `file:` path grammar) |
| *mode* | Four octal digits, as a string: `"0750"` |
| *date* | `YYYY-MM-DD`, a real calendar date |
| *id* | `[a-z0-9][a-z0-9.-]*`, 1 to 64 bytes: setting, test and notice names |
| *url* | An `https://` URL, up to 2,048 bytes |

## Top level

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `ordin` | integer | yes | | The format: `1` |
| `name` | *name* | yes | | The package |
| `version` | object | yes | | See Version |
| `kind` | string | yes | | `base`, `update` or `system-base`; see Kinds |
| `arch` | *arch* | yes | | What it runs on |
| `summary` | string | yes | | One line, 1 to 120 characters |
| `description` | string | no | | Longer text, up to 4,000 characters |
| `homepage` | *url* | no | | Where users go for the software |
| `license` | object | yes | | See License |
| `source` | object | no | | See Source and provenance |
| `provenance` | object | no | | See Source and provenance |
| `facets` | object | yes | | See Facets |
| `provides` | set of strings | no | | Atoms provided besides the package's own name, each optionally followed by ` = ` *version text*: `"cap:go = 1.23"`. Versions only on package and `cap:` atoms |
| `requires` | set of *expr* | no | | Each must hold, or the transaction fails |
| `conflicts` | set of *expr* | no | | None may be co-installed |
| `recommends` | set of *expr* | no | | Installed if possible |
| `supplements` | set of *expr* | no | | "Install me when this holds" |
| `requires-at` | object | no | | Phase-scoped requirements: `apply` and `boot`, each a set of *expr*. Build dependencies live in the recipe, and the build environment in the SLSA attestation |
| `obsoletes` | set of *expr* | no | | Packages this one supersedes (renames and splits): the solver may replace them with this package on upgrade. Package atoms only |
| `replaces` | set of strings | no | | Packages whose files this one may take over, each a package atom with an optional version constraint: `"foo < 2.0"` |
| `updates` | object | no | | Only for `update` packages; see Kinds |
| `declares` | object | no | | See Declarations |
| `state` | object | no | | See State |
| `settings` | array | no | | See Settings |
| `hooks` | object | no | | See Hooks |
| `tests` | array | no | | See Installed tests |
| `security` | object | no | | See Security policy |
| `delegated` | object | no | | See Delegated payloads |
| `switch` | object | no | | See Switching |
| `support` | object | no | | See Support |
| `abi` | object | no | | Per shared library, the digest of its exported ABI: `{"libQt5Core.so.5": "blake3:…"}`. Keys are sonames |
| `fixes` | set of strings | no | | Advisory and fix IDs this package contains (`CVE-2026-1234`, `fix-1234`), 1 to 64 printable ASCII characters each |
| `notices` | array | no | | See Notices |
| `ignorable` | set of strings | no | | Fields an older reader may skip; see Versions and evolution. Only fields this format doesn't define may be listed |

Each requirement field is a set of expressions rather than one long one: each entry diffs cleanly between versions, inferred and declared requirements merge without duplicates, and the solver can name the entry that failed.

## Version

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `epoch` | integer | no | 0 | Raised only when upstream's numbering goes backward |
| `upstream` | string | yes | | The software's version |
| `release` | string | yes | | The packaging revision |
| `update` | integer | no | 0 | The update level, `+uN`; see Kinds |

Together the parts must form a valid `ordin-version` version. The release is required: every Ordin package has one, including imports (their original revision) and native builds (a counter).

## Kinds

| Kind | Meaning |
| --- | --- |
| `base` | Installs a product at a version. `version.update` is 0 |
| `update` | Applies on top of an installed base; see below |
| `system-base` | A closure that must boot to a login prompt (kernel, init, libc, Ordin, a bootloader). Otherwise like `base` |

**Update packages.** An update has the same name as its base, and the base's version with `update` at 1 or more: `nginx 1.27.3-2+u3` is update 3 on base `nginx 1.27.3-2`, and applies only on that exact base. Updates are **cumulative**: `+u3` contains everything `+u1` and `+u2` did, so nobody reasons about update chains, and rejecting goes back to the previous generation's lock without the manifest's help.

An update's facet trees carry only the files that changed or were added since the base. Files the update deletes are listed in `updates.removes`, an object from *facet* to a set of *paths*. `updates` is omitted when nothing is removed, and is refused on any other kind.

**Kernel modules** are ordinary `base` packages that require their kernel's ABI (`cap:kernel-abi = 6.12.116-1`). They are `boot-critical` only when they ship an initrd extension; a module loaded after boot needs no full reboot. Whether a module is required on a host is host policy, not package data.

## License

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `spdx` | string | yes | | An SPDX license expression |
| `presentation` | string | no | `informational` | `informational`, `display` or `accept` |
| `texts` | object | yes, except for `NOASSERTION` and `NONE` | | Each license ID in `spdx` (SPDX IDs and `LicenseRef-` IDs) mapped to the *digest* of its text, which the `.ordin` file carries. Texts are metadata, never doc files |

**`NOASSERTION` and `NONE`** are SPDX's two values that aren't licenses:
- `NOASSERTION` means nobody has said what the license is. `ordin pack` writes it when no license is given.
- `NONE` means there is no license.

Each is a whole expression on its own: it is refused when combined with `AND` or `OR`, or written with `+` or `WITH`. Neither has a text, so `texts` must be left out. An empty object is refused, like every empty object.

## Source and provenance

`source`:

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `repo` | *url* | yes | Where the source lives |
| `rev` | string | yes | The revision built: a tag or a commit, 1 to 128 printable ASCII characters |
| `recipe` | *digest* | yes | The recipe that built it |

`provenance`: where the package came from. At least one of:

| Field | Type | Meaning |
| --- | --- | --- |
| `slsa` | *digest* | The SLSA attestation carried beside the manifest: BLAKE3, or SHA-256 for one made by an outside tool |
| `sbom` | *digest* | The SBOM carried beside the manifest, the same way |
| `commit` | string | The git commit built, as its full object name: 40 lowercase hex digits for SHA-1, 64 for SHA-256. `ordin pack --version-from git` records it; a snapshot version carries only a short form, for reading |

## Facets

An object from *facet* to:

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `tree` | *digest* | yes | | The facet's tree |
| `size` | integer | yes | | Bytes of file content |
| `default` | boolean | no | `true` | Whether the facet is installed unless the host selects otherwise. `debug` must have `false` |

At least one facet. A `base` or `system-base` package has `runtime`. All facets have the package's version.

## Declarations

`declares` holds what Ordin applies and undoes for the package. Each part is optional, and none may be empty.

**`users`** (array, sorted by `name`):

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `name` | *account* | yes | | The user |
| `system` | boolean | no | `true` | A system user |
| `home` | *path* | no | | Home directory |
| `shell` | *path* | no | | Login shell |
| `groups` | set of *accounts* | no | | Extra groups |
| `comment` | string | no | | GECOS text, up to 64 characters, without `:` |

UIDs and GIDs are never declared. They are assigned when a generation is activated.

**`groups`** (array, sorted by `name`): `name` (*account*) and `system` (default `true`).

**`units`** (array, sorted by `name`): `name` (*unit*), `preset` (`enable` or `disable`), and `if` (an optional setting condition, see Settings).

**`config`** (array, sorted by `target`): `default` (*path* under `/usr/share/ordin/defaults/<name>/`), `target` (*path* under `/etc`), and `merge`: `drop-in` (the default; `target` is a directory whose `*.d/` drop-ins the admin adds) or `three-way` (`target` is a file, merged from the old default, the new default and the admin's copy). Packages never write `/etc`.

**`alternatives`** (array, sorted by `name`):

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `name` | string | yes | | The link group: `[A-Za-z0-9+._-]+`, up to 255 bytes (`editor`, `c++`) |
| `link` | *path* | yes | | The generic link |
| `target` | *path* | yes | | This package's file |
| `priority` | integer | yes | | Higher wins |
| `followers` | array | no | | Links that follow the group, sorted by `link`: `{link, target}`, such as `editor.1.gz` following `editor` |

**`triggers`** (array): `paths` (set of *path* prefixes) and `action`, a built-in action by name (`ldconfig`, `systemd-daemon-reload`, `udev-reload`, `shells`, …), `[a-z0-9-]+`. A host refuses an action it doesn't know.

**`setuid`** (set of *paths*): files in the tree that are setuid or setgid on purpose. Any other setuid or setgid file draws a warning at build time.

**`boot`** (object; a minimum, ORD-400 may add to it): `kernel` (*path* of a kernel image in the tree), `uki` (boolean, default `false`), and `initrd-extensions` (set of *paths*: repo-built initrd extensions in the tree, as storage packages ship).

## State

`state` declares the package's paths under `/var` and `/run`.

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `version` | integer | no | 0 | The state version on disk that this release expects |
| `migration` | string | no | `none` | What this release does to state: `none`, `reversible` or `irreversible`. `irreversible` makes Ordin snapshot the package's data and spool paths before applying |
| `paths` | array | no | | Declared paths, sorted by `path` |
| `files` | array | no | | Files created if missing, sorted by `path` |
| `seeds` | array | no | | Files copied once if missing, sorted by `path` |
| `obsolete` | set of *paths* | no | | Removed on upgrade |
| `migrations` | array | no | | Sorted by `from` |

A path:

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `path` | *path* | yes | | Under `/var` or `/run` |
| `class` | string | yes | | `data`, `spool`, `log`, `cache`, `tmp` or `runtime` |
| `owner` | *account* | no | `root` | Owning user |
| `group` | *account* | no | `root` | Owning group |
| `mode` | *mode* | no | `0755` | |
| `flush` | string | no | `never` | `never` or `on-upgrade` |
| `recurse` | boolean | no | `false` | Fix ownership recursively; only for `cache` and `log` |
| `on-remove` | string | no | the class's | `keep`, `purge` or `archive` |

A file: `path`, `owner`, `group` and `mode` (default `0644`). A seed: `path` and `from` (a *path* in the package's tree).

A migration: `from` and `to` (integers, `to` = `from` + 1), and either `ops` (an array of `{"rename": path, "to": path}`, `{"move": path, "to": path}`, `{"link": path, "to": text}`, `{"remove": path}` or `{"chown": path, "owner": account, "group": account}`), or `run` (a *path* to a program, sandboxed to the declared paths) with `reversibility` (`reversible`, which needs `reverse`, a *path*, or `irreversible`). A migration made only of `ops` is reversible by construction.

## Settings

An array sorted by `name`:

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `name` | *id* | yes | | |
| `type` | string | yes | | `bool`, `int`, `port`, `string`, `choice`, `multichoice`, `path` or `list` (a list of strings) |
| `default` | typed | no | | A value of the setting's type. A `string` default may use the placeholders `{host.fqdn}`, `{host.hostname}`, `{host.domain}` and `{host.arch}`, and no other type may. A `multichoice` default is a set; a `list` default an array |
| `required` | boolean | no | `false` | No default; the plan fails until it is set. Can't be combined with `default` |
| `description` | string | no | | One line |
| `min`, `max` | integer | no | | For `int` |
| `pattern` | string | no | | For `string`: a regular expression in the syntax of Rust's `regex` crate, implicitly anchored at both ends |
| `choices` | set of strings | for `choice` and `multichoice` | | The allowed values |
| `aliases` | object | no | | Former names, such as `{"debconf": "postfix/mailname"}` |

There is no password or secret type. A condition (`if` on units, and later on other declarations) is `setting.<name>` for a `bool` setting, or `setting.<name> = <value>`.

## Hooks

Declarative actions are the default for every phase, so hooks list only the sandboxed programs that run in addition. `hooks` maps a phase (`check`, `pre-apply`, `post-apply`, `pre-commit`, `post-commit`, `reject`, `unconfig`, `remove`, `health`) to an array of steps:

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `exec` | array of strings | yes | | The program (a *path* in the tree or under `legacy/`) and its arguments |
| `timeout` | integer | no | 300 | Seconds |
| `writes` | set of *paths* | no | | The only paths it may write |
| `network` | boolean | no | `false` | Whether it may use the network |
| `execs` | set of *paths* | no | | Other programs it may run |
| `legacy` | boolean | no | `false` | A script carried over from another packaging format; `ordin audit` lists these |

## Installed tests

An array sorted by `name`: `name` (*id*), `exec` (array of strings) and `timeout` (seconds, default 60). `ordin selftest` runs them, and they run as `health` hooks after a switch.

## Security policy

`security.selinux`:

- `modules`: set of *paths*
- `booleans`: object from boolean name (`[a-z0-9_]+`) to boolean
- `ports`: array of `{type, proto, port}`, with `proto` `tcp` or `udp`
- `fcontexts`: array of `{pattern, type, file-type}`, where `pattern` is an SELinux file-context regular expression, `type` an SELinux type and `file-type` one of `all` (the default), `file`, `directory`, `symlink`, `socket`, `pipe`, `block` or `char`

`security.apparmor`: `profiles` (set of *paths*) and `tunables` (object from name to string).

What a repo may ship is limited by its namespace.

## Delegated payloads

*Proposed; settled in milestone 8.* `authority` (`{kind, exec}`, with `kind` `self`), `paths` (set of relative paths), `initial` (`facet:<facet>`), `identify` (an array of methods, each `{method, …}` with exactly these fields: `signature` with `sigstore-identity` and `issuer` (*url*); `release-index` with `url` and `signed-by`; `elf-note` with `file`, `note` and `field`; `go-buildinfo`, `cargo-auditable` with `file`; `string` with `file` and `pattern`; `exec` with `command` (array of strings) and `match`), `require` (an evidence level: `signed`, `indexed`, `embedded`, `probed` or `asserted`), `on-insufficient` (`warn`, `quarantine` or `block`) and `payload-on-upgrade` (`keep-newer`, the default, or `replace`).

## Switching

`switch`: `live-apply` (boolean, default `false`) for leaf packages that may be applied live, and `boot-critical` (boolean, default `false`) for packages that need a full reboot. Whether a state snapshot is taken comes from `state.migration` alone, so the two can never disagree.

## Support

`support`: `active-until` and `security-until` (*dates*, the second not before the first) and `successor` (*name*).

## Notices

An array sorted by `id`: `id` (*id*) and `text` (up to 2,000 characters). Shown once in `ordin changes` and plans, and recorded.
