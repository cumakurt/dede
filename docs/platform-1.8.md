# Dede 1.8 platform capabilities

Dede 1.8 extends the deterministic core without changing the privacy-first design.

## Polyglot Security IR

`dede-semantic-polyglot` emits the common Security IR for JavaScript/TypeScript,
Java, C#, Go and PHP. Findings require a known untrusted source and a known sink
inside a structural function scope; generic method names are not treated as
security sinks. Python continues to use the deeper AST/cross-file frontend.

## Framework/model packs

Model packs are offline JSON files that extend sources, sinks and sanitizers.
Repository-local packs can live in `.dede/model-packs/`. Organization packs can
be integrity-pinned and HMAC-SHA256 signed.

```bash
export DEDE_MODEL_PACK_KEY='organization-secret-from-a-secure-store'
dede packs sign corp-pack.json
dede packs verify corp-pack.json --require-signature
```

Set `model_packs.require_signature: true` to reject unsigned external packs.
Bundled Dede packs are shipped with SHA-256 integrity metadata and are trusted as
part of the signed/released application artifact.

## Offline SCA + reachability

`dede-sca` parses pinned dependencies from `requirements.txt`, `package-lock.json`,
`go.mod` and literal Maven dependency versions. It consumes local Dede or OSV JSON
advisory snapshots and never performs a network lookup during scanning.

A vulnerable dependency is marked reachable only when source import/use evidence
is found. Unreachable dependencies remain visible at reduced priority unless
`sca.report_unreachable` is disabled.

Place advisory snapshots under `.dede/advisories/` or configure
`sca.advisory_paths`.

## Precision laboratory

```bash
dede benchmark precision
dede benchmark precision --corpus my-corpus.json --output precision.json
```

The command reports TP, FP, FN, precision, recall, F1 and runtime. A non-zero exit
is returned when configured minimum precision/recall thresholds are missed.

## Organization feedback

```bash
dede feedback add <semantic-fingerprint> \
  --verdict false-positive \
  --reason 'validated internal wrapper' \
  --rule-id dede.example
```

Feedback annotates findings but does **not** create a suppression by default.
`feedback.auto_suppress_false_positive` must be explicitly enabled before an
exact false-positive verdict can suppress a future identical finding.

## Agent/MCP security

`dede-agent-security` reports only explicit dangerous configuration such as a
disabled sandbox or wildcard tool auto-approval. Natural-language prompts are
not treated as vulnerabilities.

## Experimental authorization analysis

Set `experimental.authorization_analysis: true` to enable narrow IDOR/BOLA
candidate detection. These findings are marked `EXPERIMENTAL` precision and are
kept out of the default path because authorization intent cannot always be
proven statically.

## Attack graph v2

`raw/attack-graph-v2.json` unifies explicit Python/polyglot source-to-sink paths,
SCA reachability and agent/business-logic evidence without inventing missing
edges.

## Developer workflows

- `dede watch <target>` re-scans on file changes and reuses semantic caches.
- `dede serve <report-dir>` serves report HTML plus read-only JSON APIs on
  `127.0.0.1` only.
- `dede mcp <report.json>` exposes read-only findings tools over MCP stdio.
- `dede verify-fix before.json after.json` verifies remediation through a
  deterministic re-scan diff and detects new HIGH/CRITICAL regressions.
