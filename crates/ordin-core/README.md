# ordin-core

Shared types: package names, capabilities, digests, architectures and error types. Layer 0 (pure core), licensed MIT OR Apache-2.0.

## Names and atoms

Every type can only hold a valid value. It is built by parsing, keeps the text exactly as given, and shows it unchanged. Serde reads and writes each one as that string.

| Type | Grammar | Limits | Examples |
| --- | --- | --- | --- |
| Package name | `[a-z0-9][a-z0-9+.-]*` | 2 to 128 bytes; not `and`, `or`, `not` or `if` | `nginx`, `libstdc++6`, `python3.13`, `0ad` |
| `cap:` atom | `cap:` and the package name grammar | 2 to 128 bytes; keywords allowed | `cap:http-server`, `cap:mta` |
| `so:` atom | `so:` and `[A-Za-z0-9._+-]+`, optionally `@` and a symbol version node `[A-Za-z0-9._]+` | up to 255 bytes, the node up to 64; not `.` or `..` | `so:libssl.so.3`, `so:libc.so.6@GLIBC_2.38` |
| `file:` atom | `file:` and an absolute, normalized path: printable ASCII without spaces, brackets, `,` or `= ! < > ~`, no `.` or `..` parts, no `//`, no trailing `/` | up to 4096 bytes | `file:/usr/bin/python3` |
| Architecture | `x86_64`, `aarch64` or `noarch` | a closed list | `aarch64` |
| Facet | `[a-z][a-z0-9-]*`, optionally `:` and `[A-Za-z0-9_@.+-]+` | up to 64 bytes | `runtime`, `doc`, `locale:pt_BR` |

A bare name in a dependency is a package; the prefixes tell the other atoms apart.

**Symbol versions.** A library provides one `so:` atom per symbol version node it defines (`so:libc.so.6@GLIBC_2.38`), and a binary requires the nodes it uses, so matching stays plain atom equality and the bare soname never stands in for a versioned one. Atoms carry no architecture, since Yoxela has no multilib; `#` and `/`, invalid today, are reserved in `so:` atoms for a future qualifier.

- **Lowercase ASCII only** for package names and capabilities, so no two names look alike (`Nginx` can't pass for `nginx`).
- **No grammar characters.** None of the dependency language's operators or brackets can appear in an atom, and its keywords can't be package names, so an expression always parses one way.
- **Debian fits.** Every package name in Debian trixie (68,825) follows the grammar except `and`, which the importer renames.

An error names the value, the character or rule, and where: `a package name can't contain 'N' (at byte 0); use lowercase letters, digits, '+', '.' and '-'`.
