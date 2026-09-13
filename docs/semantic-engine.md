# Dede Semantic Engine

Dede 1.4 uses a language-neutral **Security IR v2** and a bounded project-wide
Python semantic frontend. The engine is deterministic and fully offline.

## Architecture

```text
Python source
   -> AST frontend
   -> Security IR v2
      - functions / symbols
      - call graph
      - CFG edges
      - import / dependency graph
      - HTTP endpoints
      - normalized security flows
   -> context-bounded taint propagation
   -> deterministic DedeQL classification
   -> source/sink evidence
   -> attack graph
   -> normalized Dede finding
```

`raw/semantic-python-ir.json` contains structural metadata and normalized flow
records, not complete source files. The SQLite scan index also never stores
source code.

## Cross-file taint and call graph

The Python frontend resolves local modules and `import` / `from ... import ...`
aliases, builds qualified function identities, and propagates tainted positional
**and keyword arguments** through project calls. Function return summaries are
solved to a fixed point, so source-returning and passthrough helpers work across
modules.

Analysis is bounded by `semantic.max_call_depth` and `semantic.max_contexts`.
Recursive paths are cycle checked.

## Framework models and endpoint sources

Built-in source modeling covers Flask/Werkzeug, Django/DRF and Starlette/FastAPI
request objects. FastAPI-style endpoint parameters are treated as HTTP-controlled
inputs by default, except common framework/service object parameter names. This
behavior can be disabled with `semantic.endpoint_parameters_as_sources: false`.

The engine recognizes obvious authentication decorators and FastAPI
`Depends(...)` dependencies whose referenced function names contain auth,
current-user, permission, JWT or principal markers. These are static signals,
not proof that authorization is correct.

Built-in semantic sinks include SQL and command execution plus SSRF, path
traversal, unsafe deserialization, code execution and template injection.

## Control flow

The IR contains lightweight CFG edges for sequential statements, branches and
loops. The taint interpreter stops at `return` / `raise`, merges branch states,
and recognizes narrow numeric guards such as `value.isdigit()` as sanitizing the
validated branch. This is intentionally conservative and is not full symbolic
execution.

## DedeQL v0.1

DedeQL classifies already-proven flows; it never invents a vulnerability. Queries
can match source, sink, CWE, endpoint, authentication, internet exposure and a
minimum exploitability score. Matching query IDs are recorded as static evidence.
See `docs/dedeql.md`.

## Attack graph

Every semantic scan writes:

- `raw/semantic-python-attack-graph.json`
- `raw/semantic-python-attack-graph.dot`

The graph combines endpoints, resolved calls and proven sinks and includes ranked
attack paths. DOT output can be rendered with Graphviz when desired; Dede itself
does not require Graphviz.

## Custom framework models

Projects can extend semantic sources, sinks, sanitizers and flow queries in
`.dede.yml`:

```yaml
semantic:
  enabled: true
  max_call_depth: 12
  max_contexts: 10000
  endpoint_parameters_as_sources: true
  sources:
    - call: mycompany.http.request_value
      kind: http.custom
  sinks:
    - call: legacydb.execute
      kind: sql-execution
      cwe: CWE-89
      severity: HIGH
  sanitizers:
    - mycompany.security.clean_sql_identifier
  queries:
    - id: corp.internet-sql
      source: "http.*"
      sink: "*execute"
      cwe: [CWE-89]
      internet_exposed: true
      min_exploitability: 90
```

These models are data only and remain fully offline.

## Stable identity and lifecycle

Semantic findings include an AST-derived fingerprint in addition to Dede's v1
and semantic-v2 identities. The persistent index tracks automatic `NEW`,
`EXISTING`, `RESOLVED` and `REOPENED` states. Lifecycle snapshots are **not
advanced when analyzer coverage is incomplete**, preventing a failed/skipped
analyzer from incorrectly resolving historical findings.

## Dependency-aware incremental execution

The local SQLite index stores file hashes and import dependency edges. On a later
scan Dede computes the changed/removed set and transitive reverse dependents. A
signature-bound semantic cache reuses only findings whose dataflow evidence does
not intersect the affected set, while affected semantic contexts are re-run.
Changing semantic configuration or the analyzer version invalidates the cache.
See `docs/incremental-analysis.md`.

Other analyzers keep their normal correctness-first execution model unless they
implement their own safe incremental strategy.

## Extension path

Security IR is deliberately language-neutral. Java, C#, JavaScript/TypeScript and
Go semantic frontends can emit the same function/call/CFG/dependency/security-flow
objects and reuse DedeQL, lifecycle, attack-graph and reporting layers.
