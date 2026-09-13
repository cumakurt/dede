"""LLM enrichment for existing findings only (fail-open)."""

from __future__ import annotations

import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from dede.config import AppConfig
from dede.llm.cache import AICache
from dede.llm.client import OllamaClient
from dede.llm.context import ReviewContext
from dede.llm.prompts import SYSTEM_PROMPT
from dede.llm.schema import FindingReview, validate_review
from dede.models import Category, Finding, Severity
from dede.utils.hashes import sha256_text
from dede.utils.redact import (
    redact_snippet_for_secret_finding,
    redact_text,
)
from dede.utils.source import read_source_lines

ProgressFn = Callable[[str], None]


def _context_for_finding(
    finding: Finding, root: Path, lines: int, max_bytes: int = 5 * 1024 * 1024
) -> str:
    if finding.category == Category.SECRET:
        return redact_snippet_for_secret_finding(finding.code_snippet or "***REDACTED***")
    content = read_source_lines(root, finding.file, max_bytes)
    if not content:
        return redact_text(finding.code_snippet or "")
    start = max(1, finding.start_line - lines)
    end = min(len(content), finding.end_line + lines)
    chunk = "\n".join(f"{i}: {content[i - 1]}" for i in range(start, end + 1))
    return redact_text(chunk)


def _apply_enrichment(finding: Finding, data: dict) -> Finding:
    """Apply already validated/redacted review fields without rewriting engine evidence."""
    finding.summary = data["summary"]
    finding.technical_explanation = data["technical_explanation"]
    finding.ai_impact = data["impact"]
    finding.exploitability = data["exploitability"]
    finding.false_positive_probability = data["false_positive_probability"]
    finding.recommended_fix = data["recommended_fix"]
    finding.secure_code_example = data["secure_code_example"]
    finding.ai_confidence = data["confidence"]
    finding.ai_generated = True
    finding.ai_verdict = data["verdict"]
    finding.ai_rationale = data["rationale"]
    finding.ai_assumptions = data["assumptions"]
    finding.ai_verification = data["verification"]
    return finding


def enrich_findings(
    findings: list[Finding],
    root: Path,
    config: AppConfig,
    cache_dir: Path | None = None,
    on_progress: ProgressFn | None = None,
) -> tuple[list[Finding], bool, str, str]:
    """Returns (findings, ai_used, model_digest, status_message). Never raises for LLM failures."""

    def progress(msg: str) -> None:
        if on_progress is not None:
            on_progress(msg)

    if not config.ai.enabled:
        for finding in findings:
            finding.ai_status = "disabled"
        return findings, False, "", "disabled (--no-ai or config)"

    ranks = {severity: rank for rank, severity in enumerate(Severity)}
    targets = sorted(
        (f for f in findings if not f.suppressed and f.analysis_kind != "ai-hunt"),
        key=lambda f: (ranks[f.severity], -len(f.detected_by), f.file, f.start_line, f.rule_id),
    )[: config.ai.max_findings]
    target_ids = {id(f) for f in targets}
    for finding in findings:
        if finding.analysis_kind == "ai-hunt":
            continue
        finding.ai_status = (
            "suppressed"
            if finding.suppressed
            else ("pending" if id(finding) in target_ids else "limit")
        )
    if not targets:
        reason = "ai.max_findings=0" if config.ai.max_findings == 0 else "no findings to enrich"
        return findings, False, "", f"skipped: {reason} (model {config.ai.model})"

    client = OllamaClient(config)
    reachable = client.is_reachable()
    if not reachable and "ollama:" in client.host:
        client = OllamaClient(config)
        client.host = "http://127.0.0.1:11434"
        reachable = client.is_reachable()

    progress(f"Connecting to Ollama at {client.host} ...")
    if not reachable:
        for finding in targets:
            finding.ai_status = "unavailable"
        return (
            findings,
            False,
            "",
            f"skipped: Ollama not reachable at {client.host}",
        )
    progress(f"Checking model '{config.ai.model}' ...")
    if not client.model_installed():
        for finding in targets:
            finding.ai_status = "model_missing"
        return (
            findings,
            False,
            "",
            f"skipped: model not installed ({config.ai.model}) — run: dede model pull {config.ai.model}",
        )

    cache = AICache(cache_dir or Path("/var/lib/dede/cache/ai"))
    digest = client.model_digest()
    client.response_schema = FindingReview.model_json_schema()
    schema_key = json.dumps(client.response_schema, sort_keys=True)

    # --- Pre-compute all prompts before entering the thread pool -----------
    # ReviewContext uses lru_cache internally so each source file is read and
    # parsed only once regardless of how many findings point to it. Doing this
    # here (single-threaded) avoids redundant I/O inside the worker threads.
    contexts = ReviewContext(
        root, int(config.scan.max_file_size_mb * 1024 * 1024), config.ai.context_lines
    )

    # Initialise per-finding metadata and compute prompts up-front.
    precomputed: dict[int, str | None] = {}  # id(finding) → user prompt or None
    for finding in targets:
        finding.ai_source_digest = contexts.source_digest(finding.file)
        finding.ai_validation_status = "UNVERIFIED"
        finding.ai_validation_notes = []
        finding.ai_fix_status = "UNVERIFIED"
        finding.ai_fix_notes = []
        user = contexts.prompt(finding, config.ai.max_context, config.ai.max_output_tokens)
        precomputed[id(finding)] = user

    progress(
        f"Enriching {len(targets)} finding(s) with {config.ai.model} "
        f"(concurrency={config.ai.concurrency})"
    )

    def _one(finding: Finding) -> tuple[Finding, str]:
        label = f"{finding.rule_id} @ {finding.file}:{finding.start_line}"
        user = precomputed[id(finding)]
        if user is None:
            finding.ai_status = "context_limit"
            return finding, f"LLM skipped: context budget too small — {label}"
        context_hash = sha256_text(
            "\0".join(
                (
                    config.ai.model,
                    digest,
                    SYSTEM_PROMPT,
                    user,
                    str(config.ai.max_context),
                    str(config.ai.max_output_tokens),
                    schema_key,
                )
            )
        )
        cached = validate_review(cache.get(finding.fingerprint, context_hash))
        if cached:
            finding.ai_status = "cached"
            finding.ai_model = config.ai.model
            finding.ai_model_digest = digest
            return _apply_enrichment(finding, cached), f"cache hit — {label}"
        data = validate_review(client.chat_json(SYSTEM_PROMPT, user))
        if data is None:
            data = validate_review(
                client.chat_json(
                    SYSTEM_PROMPT,
                    user
                    + "\n\nReturn ONLY JSON with every required field and valid enum values, types and confidence in [0,1].",
                )
            )
        if not data:
            finding.ai_status = "failed"
            return finding, f"LLM empty/failed — {label}"
        cache.set(finding.fingerprint, context_hash, data)
        finding.ai_status = "reviewed"
        finding.ai_model = config.ai.model
        finding.ai_model_digest = digest
        return _apply_enrichment(finding, data), f"LLM OK — {label}"

    done = 0
    cache_hits = 0
    llm_ok = 0
    llm_fail = 0
    # session() opens a single httpx.Client whose connection pool is shared by
    # all concurrent worker threads for the duration of the batch — one TCP
    # handshake to Ollama instead of one per finding.
    with (
        client.session(),
        ThreadPoolExecutor(max_workers=min(len(targets), config.ai.concurrency)) as pool,
    ):
        futures = {pool.submit(_one, f): f for f in targets}
        for future in as_completed(futures):
            done += 1
            try:
                result, detail = future.result()
                if detail.startswith("cache"):
                    cache_hits += 1
                elif detail.startswith("LLM OK"):
                    llm_ok += 1
                else:
                    llm_fail += 1
                progress(f"[{done}/{len(targets)}] {detail}")
            except Exception as exc:  # noqa: BLE001
                llm_fail += 1
                src = futures[future]
                src.ai_status = "failed"
                progress(
                    f"[{done}/{len(targets)}] error — {src.rule_id} @ {src.file}:{src.start_line}: {type(exc).__name__}"
                )

    out: list[Finding] = []
    ai_count = 0
    for finding in findings:
        if finding.ai_status in {"reviewed", "cached"}:
            ai_count += 1
        out.append(finding)

    progress(f"Done: enriched={ai_count} cache={cache_hits} llm_ok={llm_ok} llm_fail={llm_fail}")

    if ai_count == 0:
        return (
            out,
            False,
            digest,
            f"skipped: Ollama reachable but enrichment produced no AI fields (model {config.ai.model})",
        )
    return (
        out,
        True,
        digest,
        f"enabled: model={config.ai.model} enriched={ai_count}/{len(targets)} "
        f"(cache={cache_hits}, llm={llm_ok}, fail={llm_fail})",
    )
