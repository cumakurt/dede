# Dede 1.9 language-semantic support

Dede 1.9 makes project-wide semantic SAST a first-class capability for the main
application languages instead of treating non-Python code as only a collection
of text rules.

Run:

```bash
dede languages
dede languages --json
```

for the runtime support matrix.

## First-class semantic languages

| Language | Frontend | Project graph | Cross-file taint | Call graph | CFG | Framework-aware models |
|---|---|---:|---:|---:|---:|---:|
| Python | Python AST semantic engine | yes | yes | yes | yes | yes |
| JavaScript | Semantic IR v4 | yes | yes | yes | yes | yes |
| TypeScript | Semantic IR v4 | yes | yes | yes | yes | yes |
| Java | Semantic IR v4 | yes | yes | yes | yes | yes |
| Kotlin | Semantic IR v4 | yes | yes | yes | yes | yes |
| C#/.NET | Semantic IR v4 + native .NET rules | yes | yes | yes | yes | yes |
| Go | Semantic IR v4 (+ gosec/go vet when installed) | yes | yes | yes | yes | yes |
| PHP | Semantic IR v4 | yes | yes | yes | yes | yes |
| Ruby | Semantic IR v4 | yes | yes | yes | yes | yes |
| Rust | Semantic IR v4 | yes | yes | yes | yes | yes |
| C / C++ | Semantic IR v4 | yes | yes | yes | yes | yes |
| Swift | Semantic IR v4 | yes | yes | yes | yes | yes |
| Scala | Semantic IR v4 | yes | yes | yes | yes | yes |
| Dart | Semantic IR v4 | yes | yes | yes | yes | yes |

The Python frontend uses Python's AST. The other language frontends use Dede's
offline structural semantic parser. It indexes functions, modules/imports,
parameters, endpoints, calls and control-flow nodes, computes fixed-point return
summaries, and propagates source taint across resolved project calls. It is
precision-first: when dynamic dispatch or an import cannot be resolved
conservatively, Dede leaves the edge unresolved instead of inventing a flow.

This is intentionally different from claiming compiler/type-checker parity.
Compiler-grade overload resolution, macro expansion and reflection can still
require language-native tooling. Dede combines the semantic graph with its
native rules and optional offline external analyzers to increase coverage
without turning ambiguous call targets into false positives.

## Precision rules

The v4 frontend includes the following safeguards:

- generic `execute()`/`query()` methods are not database sinks unless their API
  family is known;
- parameterized SQL keeps the tainted value outside the SQL-string argument and
  therefore does not produce SQL-injection evidence;
- numeric/UUID-style mapped endpoint parameters are treated as sink-specific
  validated values for injection/path classes, not as universally trusted data;
- sanitizer summaries propagate across helper functions and only suppress sink
  classes for which the sanitizer is valid;
- SSRF requires attacker control over the authority when a static absolute
  origin fixes the host and the taint only affects the path/query;
- project-call resolution prefers same-file, explicit import/alias, static/class
  receiver and globally unique symbols; ambiguous names are not guessed;
- the analysis is bounded by `semantic.max_call_depth` and
  `semantic.max_contexts`.

## Supplementary coverage

Shell, PowerShell, Perl, Lua, R, Julia, Elixir, Erlang, Clojure, Haskell, OCaml,
Solidity, Apex, Zig, Groovy, Objective-C, Vue and Svelte retain Dede native and/or
offline Semgrep rule coverage. Their vulnerability models are often domain
specific (for example Solidity reentrancy/authentication or shell dynamic
execution) and are deliberately not mislabeled as the same web-style taint
frontend.
