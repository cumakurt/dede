"""Project-wide AI vulnerability hunting on real source code.

Complements deterministic analyzers: the model reads actual project sources and
looks for vulnerabilities that single-file pattern rules structurally miss —
cross-file data flows, broken access control between routes, second-order
injection, and business-logic flaws. All output is advisory: candidates are
strictly validated, source-grounded, and marked ``analysis_kind="ai-hunt"``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from dede.config import AppConfig
from dede.llm.cache import AICache
from dede.llm.client import OllamaClient
from dede.llm.hunt_prompts import HUNT_SYSTEM_PROMPT, build_hunt_user_prompt
from dede.llm.hunt_schema import VulnHuntResponse, validate_hunt_response
from dede.models import Category, Confidence, DataflowStep, Finding, Severity
from dede.utils.hashes import sha256_text
from dede.utils.redact import redact_source_lines
from dede.utils.source import read_source_lines

ProgressFn = Callable[[str], None]

SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

# Long but bounded: covers a focused slice of the project per batch. Kept
# modest because reasoning models need output headroom for their answer.
MAX_FILE_BYTES = 16_000
MAX_TOTAL_BYTES = 80_000
CROSS_FILE_TRIGGERS = (
    "sql",
    "execute",
    "query",
    "cursor",
    "command",
    "subprocess",
    "popen",
    "os.system",
    "eval",
    "render_template",
    "redirect",
    "open(",
    "requests.",
    "httpx.",
    "session.run",
    "send",
    "deserialize",
    "yaml.load",
    "pickle.loads",
)


def _code_suffixes(config: AppConfig) -> set[str]:
    return {
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".go",
        ".java",
        ".rb",
        ".php",
        ".cs",
    }


def _select_files(
    discovered: list[str],
    *,
    max_files: int,
) -> list[str]:
    """Prioritize entry points and sinks so cross-file flows fit the budget."""
    config_like = (
        "config",
        "settings",
        "routes",
        "urls",
        "views",
        "controller",
        "api",
        "main",
        "app",
        "server",
    )
    sink_like = (
        "db",
        "database",
        "query",
        "dao",
        "repository",
        "service",
        "util",
        "exec",
        "command",
    )

    def priority(path: str) -> tuple[int, int]:
        name = Path(path).name.lower()
        score = 2
        if any(key in name for key in config_like):
            score = 0
        elif any(key in name for key in sink_like):
            score = 1
        return (score, -len(path))

    unique = list(dict.fromkeys(discovered))
    # Entry/config files first, sink-ish files next, then everything else.
    ranked = sorted(unique, key=priority)
    selected = ranked[:max_files]
    # Keep deterministic order (path) for cache stability.
    return sorted(selected)


def _is_code_file(path: str, suffixes: set[str]) -> bool:
    return Path(path).suffix.lower() in suffixes


def _read_file_bounded(root: Path, rel: str, max_bytes: int) -> str:
    try:
        path = (root / rel).resolve()
        if not path.is_relative_to(root.resolve()) or not path.is_file():
            return ""
        with path.open("rb") as handle:
            raw = handle.read(max_bytes + 1)[:max_bytes]
    except (OSError, RuntimeError, ValueError):
        return ""
    text = raw.decode("utf-8", errors="replace")
    return "\n".join(redact_source_lines(text.splitlines()))


def build_source_bundle(
    root: Path,
    files: list[str],
    *,
    max_file_bytes: int = MAX_FILE_BYTES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
) -> tuple[str, list[str]]:
    """Read selected files in parallel then assemble bundle in order.

    Returns (bundle_text, files_actually_included).
    """
    from concurrent.futures import ThreadPoolExecutor

    def _read(rel: str) -> tuple[str, str]:
        """Return (rel, text) — empty string when unreadable."""
        return rel, _read_file_bounded(root, rel, max_file_bytes)

    # Read all files concurrently; bounded by the number of files (small set).
    with ThreadPoolExecutor(max_workers=min(len(files), 8)) as pool:
        read_results = list(pool.map(_read, files))

    parts: list[str] = []
    included: list[str] = []
    used = 0
    for rel, text in read_results:
        if used >= max_total_bytes:
            break
        if not text.strip():
            continue
        # Honour per-file budget relative to remaining total budget.
        header = f"===== FILE: {rel} ====="
        budget = min(max_file_bytes, max_total_bytes - used - len(header.encode()) - 2)
        if budget <= 0:
            break
        if len(text.encode("utf-8", errors="replace")) > budget:
            text = text.encode("utf-8", errors="replace")[:budget].decode("utf-8", errors="replace")
        block = f"{header}\n{text.rstrip()}\n"
        parts.append(block)
        included.append(rel)
        used += len(block.encode("utf-8", errors="replace"))
    return "\n".join(parts), included


def build_project_summary(
    root: Path,
    files: list[str],
    languages: dict[str, float],
    frameworks: list[str],
) -> str:
    lines = [
        f"Languages: {', '.join(f'{k} {v:.0f}%' for k, v in languages.items()) or 'unknown'}",
        f"Frameworks: {', '.join(frameworks) or 'unknown'}",
        f"Files ({len(files)}):",
    ]
    for rel in files[:120]:
        lines.append(f"  - {rel}")
    if len(files) > 120:
        lines.append(f"  ... and {len(files) - 120} more")
    return "\n".join(lines)


def hunt_finding_to_finding(data: dict, *, model: str, digest: str) -> Finding:
    """Convert a validated hunt dict into a Finding with AI provenance flags."""
    flow_steps = []
    for step in data.get("dataflow") or []:
        flow_steps.append(
            DataflowStep(
                kind="flow",
                file=str(step.get("file", "")),
                start_line=int(step.get("start_line", 1)),
                end_line=int(step.get("end_line", 1)),
                content=str(step.get("content", "")),
            )
        )
    cwe = str(data.get("cwe") or "").strip()
    cwe_list = [cwe] if cwe else []
    return Finding(
        tool="llm",
        rule_id="AI-HUNT",
        category=Category.SECURITY
        if data.get("category", "security") == "security"
        else Category.BUG,
        severity=SEVERITY_MAP.get(str(data.get("severity", "MEDIUM")).upper(), Severity.MEDIUM),
        confidence=Confidence.LOW,
        cwe=cwe_list,
        file=str(data.get("file", "")),
        start_line=int(data.get("start_line", 1)),
        end_line=int(data.get("end_line", 1)),
        message=str(data.get("message", "")),
        explanation=str(data.get("explanation", "")),
        impact=str(data.get("impact", "")),
        attack_scenario=str(data.get("attack_scenario", "")),
        recommendation=str(data.get("recommendation", "")),
        ai_generated=True,
        ai_status="hunt",
        ai_model=model,
        ai_model_digest=digest,
        ai_confidence=float(data.get("confidence", 0.0)),
        ai_rationale="AI project-wide hunt; advisory only, requires human verification.",
        ai_validation_status="UNVERIFIED",
        ai_validation_notes=["AI candidate; source grounding has not been checked."],
        analysis_kind="ai-hunt",
        normalized_type=f"ai-hunt:{cwe or 'uncategorized'}",
        dataflow=flow_steps,
        detected_by=["llm"],
    )


class _HuntError(Exception):
    """Internal: a batch failed; message is safe to show."""


def _hunt_one_batch(
    client: OllamaClient,
    cache: AICache | None,
    cache_key: str,
    system: str,
    user: str,
    schema_key: str,
    model_digest: str,
) -> list[dict]:
    context_hash = sha256_text("\0".join((client.model, model_digest, system, user, schema_key)))
    if cache is not None:
        cached = validate_hunt_response(cache.get(cache_key, context_hash))
        if cached is not None:
            return cached.get("findings") or []
    raw = client.chat_json(system, user)
    data = validate_hunt_response(raw)
    if data is None and raw is not None:
        # One bounded repair attempt.
        data = validate_hunt_response(
            client.chat_json(
                system,
                user + "\n\nYour previous reply was not valid JSON for the schema. "
                'Return ONLY a JSON object: {"findings": [...]}. '
                "Use exactly the field names and enum values from the schema.",
            )
        )
    if data is None:
        raise _HuntError("invalid or empty model response")
    if cache is not None:
        cache.set(cache_key, context_hash, data)
    return data.get("findings") or []


def _ground_hunt_candidate(
    data: dict,
    *,
    root: Path,
    allowed_files: set[str],
    max_bytes: int,
    model: str,
    digest: str,
) -> Finding | None:
    """Accept only model claims whose every cited location exists in its batch."""
    file = str(data.get("file") or "")
    if file not in allowed_files:
        return None
    lines = read_source_lines(root, file, max_bytes)
    start = int(data.get("start_line") or 0)
    end = int(data.get("end_line") or 0)
    if not lines or not (1 <= start <= end <= len(lines)):
        return None
    for step in data.get("dataflow") or []:
        step_file = str(step.get("file") or "")
        if step_file not in allowed_files:
            return None
        step_lines = read_source_lines(root, step_file, max_bytes)
        step_start = int(step.get("start_line") or 0)
        step_end = int(step.get("end_line") or 0)
        if not step_lines or not (1 <= step_start <= step_end <= len(step_lines)):
            return None
    if any(str(path) not in allowed_files for path in data.get("related_files") or []):
        return None
    finding = hunt_finding_to_finding(data, model=model, digest=digest)
    finding.ai_validation_status = "SOURCE_GROUNDED"
    finding.ai_validation_notes = [
        "Every cited file and line exists in the exact source batch reviewed by the model; "
        "this validates location grounding, not exploitability."
    ]
    return finding


def run_vulnerability_hunt(
    root: Path,
    config: AppConfig,
    *,
    discovered_files: list[str],
    languages: dict[str, float],
    frameworks: list[str],
    cache_dir: Path | None = None,
    on_progress: ProgressFn | None = None,
) -> tuple[list[Finding], str]:
    """Hunt for missed vulnerabilities. Never raises; returns (findings, status)."""
    progress = (lambda msg: on_progress(msg)) if on_progress else (lambda msg: None)

    if not config.ai.enabled or not getattr(config.ai, "hunt_enabled", False):
        return [], "disabled"
    if config.ai.max_hunt_findings <= 0:
        return [], "disabled (max_hunt_findings=0)"

    client = OllamaClient(config)
    if not client.is_reachable() and "ollama:" in client.host:
        client = OllamaClient(config)
        client.host = "http://127.0.0.1:11434"
    if not client.is_reachable():
        return [], f"skipped: Ollama not reachable at {client.host}"
    if not client.model_installed():
        return [], f"skipped: model not installed ({config.ai.model})"

    suffixes = _code_suffixes(config)
    candidates = [f for f in discovered_files if _is_code_file(f, suffixes)]
    if not candidates:
        return [], "skipped: no source files to analyze"

    schema = VulnHuntResponse.model_json_schema()
    client.response_schema = schema
    digest = client.model_digest()
    schema_key = json.dumps(
        {
            "schema": schema,
            "max_context": config.ai.max_context,
            "max_output_tokens": config.ai.max_output_tokens,
            "prompt_version": 2,
        },
        sort_keys=True,
    )
    output_reserve = min(config.ai.max_output_tokens, config.ai.max_context // 4)
    prompt_overhead = (
        len((HUNT_SYSTEM_PROMPT + build_hunt_user_prompt("", "")).encode("utf-8")) + 2048
    )
    per_batch_bytes = config.ai.max_context - output_reserve - prompt_overhead
    if per_batch_bytes < 2048:
        return [], "skipped: context budget too small for AI hunt"

    selected = _select_files(candidates, max_files=config.ai.hunt_max_files)
    bundle, included = build_source_bundle(
        root,
        selected,
        max_file_bytes=min(MAX_FILE_BYTES, max(1024, per_batch_bytes // 2)),
        max_total_bytes=min(MAX_TOTAL_BYTES, per_batch_bytes * 2),
    )
    if not included:
        return [], "skipped: source unreadable"
    progress(f"AI hunt: analyzing {len(included)} file(s) project-wide with {config.ai.model}")

    cache: AICache | None = None
    try:
        cache = AICache(cache_dir or Path("/var/lib/dede/cache/ai"))
    except Exception:  # noqa: BLE001
        cache = None

    # Split the bundle into batches so mid-size projects fit the context window.
    batches = _split_bundle_batches(bundle, included, max_batch_bytes=per_batch_bytes)
    findings: list[Finding] = []
    failures = 0
    max_workers = max(1, min(config.ai.concurrency, len(batches)))

    def _run(batch: tuple[str, list[str]]) -> list[dict]:
        batch_text, batch_files = batch
        batch_summary = build_project_summary(root, batch_files, languages, frameworks)
        user = build_hunt_user_prompt(batch_summary, batch_text)
        return _hunt_one_batch(
            client,
            cache,
            cache_key="ai-hunt",
            system=HUNT_SYSTEM_PROMPT,
            user=user,
            schema_key=schema_key,
            model_digest=digest,
        )

    try:
        # Single HTTP connection pool shared by all batch workers — avoids a
        # new TCP handshake to Ollama per batch.
        with client.session(), ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_run, b): b for b in batches}
            for index, future in enumerate(as_completed(futures), start=1):
                try:
                    items = future.result()
                except _HuntError as exc:
                    failures += 1
                    progress(f"AI hunt: batch {index}/{len(batches)} failed — {exc}")
                    continue
                except Exception as exc:  # noqa: BLE001
                    failures += 1
                    progress(f"AI hunt: batch {index}/{len(batches)} error — {type(exc).__name__}")
                    continue
                _batch_text, batch_files = futures[future]
                for item in items[: min(config.ai.max_hunt_findings, 3)]:
                    grounded = _ground_hunt_candidate(
                        item,
                        root=root,
                        allowed_files=set(batch_files),
                        max_bytes=int(config.scan.max_file_size_mb * 1024 * 1024),
                        model=config.ai.model,
                        digest=digest,
                    )
                    if grounded is None:
                        failures += 1
                        progress("AI hunt: rejected a candidate with an invalid source citation")
                        continue
                    findings.append(grounded)
    except Exception as exc:  # noqa: BLE001
        return findings, f"error: {type(exc).__name__}"
    findings = findings[: config.ai.max_hunt_findings]
    status = f"ai-hunt: {len(findings)} candidate(s)"
    if failures:
        status += f", {failures} batch(es) failed"
    progress(status)
    return findings, status


def _split_bundle_batches(
    bundle: str,
    included: list[str],
    *,
    max_batches: int = 3,
    max_batch_bytes: int | None = None,
) -> list[tuple[str, list[str]]]:
    """Split a large bundle into per-file-group batches within budget."""
    if not included:
        return []
    blocks = bundle.split("===== FILE: ")
    blocks = [b for b in blocks if b.strip()]
    if len(blocks) <= 1:
        return [(bundle, included)]
    parsed: list[tuple[str, str]] = []
    for block in blocks:
        header, _, body = block.partition("\n")
        rel = header.replace(" =====", "").strip()
        parsed.append((rel, body))
    # Balance: chunk consecutive files so each batch stays under ~40KB.
    target = max_batch_bytes or max(
        20_000, len(bundle.encode("utf-8", errors="replace")) // max_batches + 1
    )
    batches: list[tuple[str, list[str]]] = []
    current: list[str] = []
    current_files: list[str] = []
    size = 0
    for rel, body in parsed:
        rendered = f"===== FILE: {rel} =====\n{body.rstrip()}\n"
        block_size = len(rendered.encode("utf-8", errors="replace"))
        if current and size + block_size > target:
            batches.append(("\n".join(current), list(current_files)))
            current, current_files, size = [], [], 0
        current.append(rendered)
        current_files.append(rel)
        size += block_size
    if current:
        batches.append(("\n".join(current), list(current_files)))
    return batches
