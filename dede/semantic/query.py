"""Deterministic flow-query engine for semantic findings.

DedeQL v0.1 intentionally starts as a structured query model instead of a free-
form parser: project configuration is validated by Pydantic and matching stays
fully deterministic. Queries never create speculative vulnerabilities; they
classify already proven source-to-sink flows for policy, triage and reporting.
"""

from __future__ import annotations

from fnmatch import fnmatch

from dede.config import AppConfig, SemanticFlowQuery
from dede.models import Evidence, Finding


_BUILTINS = (
    SemanticFlowQuery(
        id="dedeql.internet-high-exploitability",
        description="Internet-exposed semantic flow with exploitability >= 90",
        internet_exposed=True,
        min_exploitability=90.0,
    ),
    SemanticFlowQuery(
        id="dedeql.unauthenticated-injection",
        description="Unauthenticated internet-facing injection flow",
        cwe=["CWE-78", "CWE-89", "CWE-95", "CWE-1336"],
        internet_exposed=True,
        authentication_required=False,
        min_exploitability=90.0,
    ),
)


def _matches(query: SemanticFlowQuery, finding: Finding) -> bool:
    if not fnmatch(finding.source_kind or "", query.source):
        return False
    if not fnmatch(finding.sink_kind or "", query.sink):
        return False
    if not fnmatch(finding.endpoint or "", query.endpoint):
        return False
    if query.cwe and not set(query.cwe).intersection(finding.cwe):
        return False
    if query.authentication_required is True and finding.authentication_required is not True:
        return False
    if query.authentication_required is False and finding.authentication_required is True:
        return False
    if query.internet_exposed is not None and finding.internet_exposed is not query.internet_exposed:
        return False
    if (finding.exploitability_score or 0.0) < query.min_exploitability:
        return False
    return True


def apply_flow_queries(findings: list[Finding], config: AppConfig) -> list[Finding]:
    queries = [*(_BUILTINS if config.semantic.builtin_flow_queries else ()), *config.semantic.queries]
    for finding in findings:
        if not finding.analysis_kind.startswith("semantic-"):
            continue
        matches = [query for query in queries if _matches(query, finding)]
        finding.query_matches = list(dict.fromkeys([*finding.query_matches, *(q.id for q in matches)]))
        for query in matches:
            evidence = Evidence(
                kind="dedeql",
                value=f"{query.id}: {query.description or 'flow query matched'}",
                confidence=1.0,
            )
            if evidence not in finding.evidence:
                finding.evidence.append(evidence)
    return findings
