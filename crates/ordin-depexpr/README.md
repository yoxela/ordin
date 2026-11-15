# ordin-depexpr

The dependency grammar: parser, syntax tree and evaluation against a set of provides. Layer 0 (pure core), licensed MIT OR Apache-2.0.

## The grammar

```text
expr        := chain [ "if" chain ]
chain       := unary ( ("and" unary)+ | ("or" unary)+ )?
unary       := "not" unary | "(" expr ")" | requirement
requirement := atom [ facets ] [ op version ] [ facets ]    -- facets once
facets      := "[" facet ( "," facet )* "]"
op          := "=" | "!=" | "<" | "<=" | ">" | ">=" | "~"
```

Atoms, facets and versions are those of `ordin-core` and `ordin-version`.

| Rule | Why |
| --- | --- |
| `and` and `or` can't be mixed without parentheses | An expression reads only one way: write `a and (b or c)` |
| `a if b` requires `a` only when `b` holds, binds loosest, at most once per group | rpm's rich-dependency meaning; `a if b if c` is refused |
| Version constraints only on package and `cap:` atoms | A version on a soname or a file means nothing |
| Facets only on package atoms, sorted, no duplicates | `nginx[doc,runtime]` |
| `~` is compatible-with, like semver's caret | `~1.27` is at least 1.27 and below `2~`; `~0.4` below `0.5~` |
| A versioned requirement needs a provide with a version | As in Debian: `cap:go` with no version doesn't meet `cap:go >= 1.21` |

## Canonical text

An expression shows as its canonical text: single spaces around keywords and operators, facets right after the atom and sorted, versions in canonical form, and only the parentheses the tree needs. Parsing the canonical text gives back the same tree. Input may be spaced differently:

| Input | Canonical |
| --- | --- |
| `cap:go>=1.21` | `cap:go >= 1.21` |
| `nginx >= 1.27 [runtime, doc]` | `nginx[doc,runtime] >= 1.27` |
| `((aa))` | `aa` |
| `not(aa or bb)` | `not (aa or bb)` |

## Limits

An expression is at most 4096 bytes, both as written and in canonical form; parentheses and `not` nest at most 32 deep; and it names at most 256 atoms. Every error gives its byte offset: `at byte 10: 'and' and 'or' can't be mixed without parentheses; group one side, as in 'a and (b or c)'`.
