<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 The Ordin Authors -->

# The Ordin recipe, `ordin.toml`, format 1

A recipe is what a packager writes for what `ordin pack` can't infer. Rung 1 is the few lines a real package needs on top of its install root: a name, a license, requirements and a unit, for example. This page is the reference for rung 1; rungs 2 and 3 (sources, build steps and hooks) add tables to the same file later.

```toml
format = 1

[package]
name     = "hello"
version  = "2.12"
summary  = "Says hello"
license  = "MIT"
requires = ["cap:greeter >= 1"]

[license]
files = { MIT = "COPYING" }

[[unit]]
name   = "hello.service"
preset = "enable"
```

`ordin pack DIR` reads `./ordin.toml`, in the working directory, if there is one, or the file `--manifest FILE` names; `--no-manifest` reads none. A recipe is never signed. What it says goes into the manifest, and the manifest is signed.

## Rules for the whole file

- A recipe is TOML 1.1, UTF-8, at most 1 MiB.
- `format = 1` is required. A recipe of another format is refused.
- Every table and key is listed below, and any other key is refused, naming the keys that table has. A misspelt key is an error, never ignored.
- Each value is read by the parser the manifest uses for it, and the declarations are then checked against every rule of the manifest (`crates/ordin-manifest/SCHEMA.md`), so a recipe that reads is one the manifest accepts.
- An error names the line and column of the value, key or table that is wrong, and says what was expected: `ordin.toml:7:12: expected a requirement such as "libfoo >= 1.2": …`.
- Paths in the package are absolute: `/usr/lib/foo`. Paths to files beside the recipe are relative to the recipe's own directory: names separated by single `/`, none of them `.` or `..`.

## `[package]`

Each key here can also be given on the command line, and the command line wins.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | `--name` | The package's name |
| `version` | string | `--version` or `--version-from git` | The upstream version, with an optional epoch: `"2.12"`, `"1:2.0"` |
| `release` | string or integer | `1` | The release |
| `arch` | string | found from the files | `x86_64`, `aarch64` or `noarch` |
| `summary` | string | the name, with a warning | One line, 1 to 120 characters |
| `description` | string | | Longer text, up to 4,000 characters |
| `homepage` | string | | An `https` URL |
| `license` | string | `NOASSERTION`, with a warning | An SPDX license expression |
| `requires` | array of strings | | Requirements besides the inferred ones, each a dependency expression: `"libfoo >= 1.2"`, `"so:libssl.so.3 or so:libssl.so.1"` |
| `provides` | array of strings | | Provides besides the inferred ones: an atom, optionally `= version` for package and `cap:` atoms |
| `conflicts` | array of strings | | Dependency expressions that may not be installed with the package |

Requirements and provides are added to the inferred ones; one that is both inferred and declared is recorded once.

## `[license]`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `presentation` | string | `informational` | `informational`, `display` or `accept`: whether the license is shown on install, or must be accepted |
| `files` | table | | Each license ID in the expression, mapped to its text's path, relative to the recipe's directory: `{ MIT = "COPYING" }` |

A license text is read from inside the recipe's directory only. It can't be reached through a symlink, and it must be a regular file of at most 1 MiB. An upstream recipe therefore can't make `ordin pack` copy another file on the packager's machine into the package. `--license-file ID=PATH` replaces the recipe's text for that ID.

## `[[user]]` and `[[group]]`

System users and groups, created when a generation is activated. UIDs and GIDs are never declared.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | required | The user or group |
| `system` | boolean | `true` | A system account |
| `home` | string | | A user's home directory, an absolute path |
| `shell` | string | | A user's login shell, an absolute path |
| `groups` | array of strings | | A user's extra groups |
| `comment` | string | | A user's GECOS text, up to 64 characters, without `:` |

`home`, `shell`, `groups` and `comment` are for `[[user]]` only. Two users, or two groups, with one name are refused.

## `[[unit]]`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | required | The unit: `"nginx.service"`, `"getty@tty1.service"` |
| `preset` | string | required | `enable` or `disable` |
| `if` | string | | A condition on a setting: `"setting.tls"` for a `bool` setting, or `"setting.mpm = event"` |

The package must ship the unit's file in `/usr/lib/systemd/system/` or `/usr/lib/systemd/user/`: its own, or for an instance, its template's (`getty@.service`). A setting named in `if` must be declared.

## `[[setting]]`

Typed values an admin can set without being asked during a transaction.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | required | The setting: `"listen-port"` |
| `type` | string | required | `bool`, `int`, `port`, `string`, `choice`, `multichoice`, `path` or `list` |
| `default` | by type | | A boolean for `bool`, an integer for `int` and `port`, a string for `string`, `choice` and `path`, an array of strings for `multichoice` and `list`. A `string` default may use `{host.fqdn}`, `{host.hostname}`, `{host.domain}` and `{host.arch}`. |
| `required` | boolean | `false` | No default; the plan fails until it is set |
| `description` | string | | One line |
| `min`, `max` | integer | | For `int` |
| `pattern` | string | | For `string`: a regular expression, anchored at both ends |
| `choices` | array of strings | | The values allowed, for `choice` and `multichoice` |
| `aliases` | table | | Former names: `{ debconf = "postfix/mailname" }` |

## `[state]`

Paths under `/var` and `/run` that the package owns. `ordin pack` already declares what the install root's `var/` holds; a path declared here wins over an inferred one at the same path, and is added otherwise.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `version` | integer | `0` | The state version on disk this release expects |
| `obsolete` | array of strings | | Paths removed on upgrade |

**`[[state.path]]`**, a directory:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `path` | string | required | Under `/var` or `/run` |
| `class` | string | required | `data`, `spool`, `log`, `cache`, `tmp` or `runtime` |
| `owner` | string | `"root:root"` | `"USER:GROUP"` |
| `mode` | string | `"0755"` | Four octal digits |
| `flush` | string | `never` | `never` or `on-upgrade` |
| `recurse` | boolean | `false` | Fix ownership recursively; only for `cache` and `log` |
| `on-remove` | string | the class's | `keep`, `purge` or `archive` |

**`[[state.file]]`**, a file created if missing: `path`, `owner` (`"root:root"`) and `mode` (`"0644"`).

**`[[state.seed]]`**, a file copied once if missing, never overwritten: `path`, and `from`, a regular file the package ships.

Migrations between state versions come with rung 2.

## `[facets.NAME]`

| Key | Type | Meaning |
| --- | --- | --- |
| `extra` | array of strings | Paths moved to facet `NAME`, each with everything below it |

A path is as it is in the package, after `bin/` moves to `/usr/bin` and prefixes move to `/usr`. A trailing `/**` means the same as the directory, and any other pattern is refused. A path moved twice, or one that matches nothing in the package, is refused.

```toml
[facets.dev]
extra = ["/usr/lib/foo/sdk", "/usr/share/foo/headers/**"]
```
