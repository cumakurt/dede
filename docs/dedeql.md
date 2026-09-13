# DedeQL v0.1 — deterministic semantic flow queries

DedeQL classifies **already-proven semantic source-to-sink flows**. It does not ask an LLM to invent findings and it does not change engine severity. Queries are validated from `.dede.yml` and become static evidence on matching findings.

```yaml
semantic:
  builtin_flow_queries: true
  queries:
    - id: corp.internet-sql
      description: Internet-facing SQL flow requiring security review
      source: "http.*"
      sink: "*execute"
      cwe: [CWE-89]
      endpoint: "/api/*"
      internet_exposed: true
      min_exploitability: 90
```

Supported predicates are `source`, `sink`, `cwe`, `endpoint`, `authentication_required`, `internet_exposed`, and `min_exploitability`. String fields use shell-style glob matching. Matching query IDs appear in `finding.query_matches`, SARIF properties, HTML reports, Security IR flows and attack-graph paths.

Built-in queries currently identify internet-exposed high-exploitability flows and unauthenticated injection paths. They remain classification signals only; deterministic source-to-sink evidence is still required first.
