# Adding offline security rules

Use `rules/semgrep/custom/` for project-owned rules. All profiles load this
directory, and the wheel includes it without registry access at scan time.
Prefer a language parser and taint analysis when the local CE engine supports
the required semantics. Use file-scoped textual patterns only when necessary,
and label their limits explicitly.

For lightweight checks that must work without any external parser, add a JSON
bundle under `rules/dede-engine/`. The native loader accepts only the documented
schema, compiles every regular expression up front, and rejects duplicate IDs
across bundles. Prefer literal `pattern` conditions; use `regex` only when the
same condition cannot be expressed narrowly. Combine line-level `when` entries
with file-level `if`/`if_not` gates to reduce false positives. Every native rule
must include severity, category, confidence, CWE/OWASP/ASVS metadata, a concrete
recommendation and primary references.

## Rule contract

1. Choose a stable, unique `dede.<language>.advanced.<name>` ID and the
   smallest relevant set of `languages`. Extend an existing rule where the same
   vulnerability is already covered instead of creating duplicate findings.
2. Define concrete sources and sinks. For taint rules use exact sources and
   `focus-metavariable` on the sensitive sink argument. Do not treat every
   function parameter as attacker-controlled. Sanitizers must be appropriate to
   the destination: URL encoding is not SSRF protection and SQL parameters do not
   sanitize the SQL statement text.
3. Set `metadata.category: security`, an evidence-based `confidence`, `cwe`,
   `owasp` with the correct edition, `recommendation`, and primary `references`.
   Use `metadata.analysis: taint` for taint rules or `regex` for textual checks.
   Generic/regex rules must include `paths.include` to restrict file types.
4. Add `metadata.standards.owasp-asvs-5.0.0` with versioned requirement IDs such as
   `v5.0.0-1.2.4`. Check each against the
   [published ASVS release](https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release).
   These mappings describe related partial evidence, not proof of compliance.
   For Microsoft guidance, use `metadata.standards.microsoft-dotnet`, e.g.
   `CA3001`, and link the relevant Microsoft documentation.
5. Keep YAML free of anchors/aliases; the native validator can reject aliases
   even when scans accept them. New files must be added to `CUSTOM_FILES` in
   `scripts/download_rules.sh` before regenerating the manifest.

For Dede-engine JSON, keep bundle `schema` at `1`, use a unique stable ID, and
add both an unsafe detection and a safe counterexample to
`tests/unit/test_dede_engine_advanced.py`. Never catch or ignore regex/schema
errors: an invalid bundle must make the engine report incomplete coverage.

Native rules support three bounded modes. The default `line` mode evaluates
conditions on one source line. `document` mode is for a narrow multiline or
configuration pattern and should set `max_span_lines`; comments are masked when
`exclude_comments` is true. `taint` mode currently targets conservative local
C# and Razor flow and requires `taint_sink` (`sql`, `command`, `arguments`,
`path`, `ssrf`, `xss`, `redirect`, `xpath`, `regex`, `ldap` or `code`). Use
`standards` for machine-readable mappings such as
`{"microsoft-dotnet": ["CA2326"]}`. These modes are lexical evidence, not
compiler, interprocedural or cross-file analysis; describe the supported scope
in the rule recommendation and tests.

## Regression examples

For advanced rules, add cases to `tests/rule_samples/advanced_cases.json`:

```json
{
  "rule_id": "dede.csharp.advanced.open-redirect",
  "extension": "cs",
  "unsafe": "class Example { void Run() { Redirect(Request.Query[\"next\"].ToString()); } }",
  "safe": "class Example { void Run() { LocalRedirect(Request.Query[\"next\"].ToString()); } }"
}
```

Each case becomes a separate source file. The integration test scans through the
application's real analyzer, checks positive matches and safe boundaries, and
verifies metadata survives into JSON/HTML reports. Examples are parsed, never
compiled or executed. Use multiple cases for import aliases, fluent APIs, local
assignments, reassignment, constant arguments and late sanitization where relevant.
Avoid real credentials and production endpoints. A safe example means safe for
that specific rule, not safe in every respect.

```bash
python -m pytest -q tests/unit/test_advanced_security_catalog.py tests/integration/test_advanced_security_rules.py
python -m pytest -q tests/unit/test_dede_engine.py tests/unit/test_dede_engine_advanced.py
make rules
make test
```

`make rules` reuses valid cached registry packs by default, validates custom
rules when Semgrep is installed, and regenerates `MANIFEST.yml` and `VERSION`.
It may need network access if packs are missing; rule validation may also fetch
Semgrep's validator rules. Update the version tag in the script when publishing
a changed ruleset. Never hand-edit generated hashes or counts.

Review the final diff and packaged wheel. Keep unsupported parser errors visible;
do not silently remove rules or claim complete coverage to obtain a clean result.
