# Dede Engineering Roadmap

This document tracks the remaining high-value engineering work after the 1.7 precision and installer pass. It is intentionally written in English so the source distribution, runtime messages, reports, warnings, and documentation use one language consistently.

## Product principles

Dede is an evidence-first, privacy-first static analysis platform. Deterministic static evidence remains authoritative; local AI is optional and must never be required to produce core findings. The default user experience should optimize for actionable precision, explainability, reproducibility, and offline operation.

## Current architecture

The product combines the native Dede Engine, the project-wide Python semantic engine, optional external analyzers, normalization/correlation, lifecycle tracking, policy gates, DedeQL, incremental indexing, and HTML/PDF/JSON/SARIF reporting. Native scanning works without Docker. Docker remains an optional isolated runtime. Ollama/local AI remains an independent optional layer.

## Precision roadmap

1. Extend context-sensitive sanitizers to additional languages and framework models.
2. Add type-aware receiver inference for SQL/ORM APIs instead of broad method-name heuristics.
3. Expand path-sensitive guard recognition for allowlists, enum validation, schema validation, and safe URL construction.
4. Add negative test corpora for every security rule and publish precision/recall measurements.
5. Correlate low-confidence native matches with semantic and external-engine evidence before surfacing them as actionable alerts.
6. Add framework-specific models for Django ORM, SQLAlchemy, FastAPI/Pydantic, Flask, Spring, ASP.NET, Express/NestJS, Laravel, and Rails.
7. Continue reducing rules that depend on textual coincidence when AST/IR evidence can replace them.

## Semantic engine roadmap

1. Add language frontends for JavaScript/TypeScript, Java, C#, and Go on the common Security IR.
2. Improve call-graph resolution with lightweight type inference and import/package resolution.
3. Expand CFG/path sensitivity, exception edges, loop summaries, and sanitizer dominance checks.
4. Add field-sensitive object summaries across function boundaries.
5. Add dependency reachability and package vulnerability call-path analysis.
6. Build richer application attack graphs that connect infrastructure exposure, routes, authorization, source-to-sink flow, and data stores.

## Developer experience roadmap

1. LSP server and editor integrations with incremental findings.
2. PR annotations that focus on NEW/REOPENED findings only.
3. Rule/model SDK with deterministic tests and performance budgets.
4. Signed offline rule/model bundles for air-gapped environments.
5. Central server mode that can store finding metadata without requiring source-code upload.

## Quality gates

Every release should run unit, integration, installer, offline, release-metadata, semantic precision, report-generation, and clean-artifact smoke tests. Performance and memory regressions should be measured on fixed repositories. Any unavailable external dependency must be reported as optional/incomplete coverage rather than silently treated as successful coverage.
