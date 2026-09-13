"""Deterministic precision/recall benchmark harness for Dede semantic engines."""
from __future__ import annotations

import json
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dede.config import AppConfig
from dede.discovery.files import discover_files
from dede.discovery.languages import detect_file_language, detect_languages
from dede.models import ProjectContext
from dede.semantic.polyglot import PolyglotSemanticAnalyzer
from dede.semantic.python_ast import PythonSemanticAnalyzer
from dede.security_hardening import SecurityHardeningAnalyzer


@dataclass(frozen=True)
class PrecisionMetrics:
    true_positive: int
    false_positive: int
    false_negative: int
    precision: float
    recall: float
    f1: float
    runtime_seconds: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "false_negative": self.false_negative,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "runtime_seconds": round(self.runtime_seconds, 4),
        }


def _context(root: Path, config: AppConfig) -> ProjectContext:
    files = discover_files(root, config)
    stats = detect_languages(files, root)
    suffixes = {Path(x).suffix.lower() for x in files}
    return ProjectContext(
        root=str(root), files=[str(x) for x in files], languages=stats,
        has_python=".py" in suffixes,
        has_javascript=bool(suffixes & {".js", ".jsx", ".mjs", ".cjs"}),
        has_typescript=bool(suffixes & {".ts", ".tsx"}), has_go=".go" in suffixes,
        has_java=".java" in suffixes, has_csharp=".cs" in suffixes, has_php=".php" in suffixes,
    )


def run_precision_corpus(corpus_path: Path, config: AppConfig | None = None) -> tuple[PrecisionMetrics, dict[str, Any]]:
    data = json.loads(corpus_path.read_text(encoding="utf-8"))
    cases = data.get("cases", []) if isinstance(data, dict) else []
    config = config or AppConfig()
    config.ai.enabled = False
    config.performance.persistent_index = False
    tp = fp = fn = 0
    case_results: list[dict[str, Any]] = []
    by_language_counts: dict[str, dict[str, int]] = {}
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="dede-precision-") as tmp:
        base = Path(tmp)
        for idx, case in enumerate(cases):
            case_id = str(case.get("id", f"case-{idx+1}"))
            case_root = base / case_id
            case_root.mkdir(parents=True, exist_ok=True)
            filename = str(case.get("filename", "sample.py"))
            source = str(case.get("source", ""))
            target = case_root / filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8")
            project = _context(case_root, config)
            findings = []
            raw = case_root / ".raw"
            for analyzer in (PythonSemanticAnalyzer(), PolyglotSemanticAnalyzer()):
                if analyzer.supports(project):
                    findings.extend(analyzer.analyze(project, config, raw).findings)
            actual = {(f.rule_id, tuple(f.cwe)) for f in findings}
            expected_raw = case.get("expected", [])
            expected = set()
            for item in expected_raw:
                if isinstance(item, str):
                    expected.add((item, ()))
                elif isinstance(item, dict):
                    expected.add((str(item.get("rule_id", "")), tuple(item.get("cwe", []))))
            def matches(exp: tuple[str, tuple[str,...]], act: tuple[str, tuple[str,...]]) -> bool:
                rule_ok = not exp[0] or exp[0] == act[0]
                cwe_ok = not exp[1] or bool(set(exp[1]) & set(act[1]))
                return rule_ok and cwe_ok
            matched_actual: set[tuple[str, tuple[str,...]]] = set()
            matched_expected = 0
            for exp in expected:
                act = next((a for a in actual if a not in matched_actual and matches(exp, a)), None)
                if act:
                    matched_actual.add(act); matched_expected += 1
            ctp = matched_expected
            cfn = len(expected) - ctp
            cfp = len(actual) - len(matched_actual)
            tp += ctp; fp += cfp; fn += cfn
            language = detect_file_language(target) or "Unknown"
            bucket = by_language_counts.setdefault(language, {"tp": 0, "fp": 0, "fn": 0, "cases": 0})
            bucket["tp"] += ctp; bucket["fp"] += cfp; bucket["fn"] += cfn; bucket["cases"] += 1
            case_results.append({
                "id": case_id, "language": language, "passed": cfp == 0 and cfn == 0,
                "tp": ctp, "fp": cfp, "fn": cfn,
                "expected": [{"rule_id": r, "cwe": list(c)} for r,c in sorted(expected)],
                "actual": [{"rule_id": r, "cwe": list(c)} for r,c in sorted(actual)],
            })
    runtime = time.perf_counter() - started
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    metrics = PrecisionMetrics(tp, fp, fn, precision, recall, f1, runtime)
    by_language: dict[str, dict[str, Any]] = {}
    for language, counts in sorted(by_language_counts.items()):
        ltp, lfp, lfn = counts["tp"], counts["fp"], counts["fn"]
        lp = ltp / (ltp + lfp) if ltp + lfp else 1.0
        lr = ltp / (ltp + lfn) if ltp + lfn else 1.0
        lf1 = 2 * lp * lr / (lp + lr) if lp + lr else 0.0
        by_language[language] = {
            "cases": counts["cases"], "tp": ltp, "fp": lfp, "fn": lfn,
            "precision": round(lp, 4), "recall": round(lr, 4), "f1": round(lf1, 4),
        }
    return metrics, {"metrics": metrics.to_dict(), "by_language": by_language, "cases": case_results}


def run_hardening_corpus(corpus_path: Path, config: AppConfig | None = None) -> tuple[PrecisionMetrics, dict[str, Any]]:
    """Measure the high-precision hardening analyzer against positive/negative fixtures."""
    data = json.loads(corpus_path.read_text(encoding="utf-8"))
    cases = data.get("cases", []) if isinstance(data, dict) else []
    config = config or AppConfig()
    config.ai.enabled = False
    tp = fp = fn = 0
    results: list[dict[str, Any]] = []
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="dede-hardening-bench-") as tmp:
        base = Path(tmp)
        for index, case in enumerate(cases):
            case_id = str(case.get("id", f"case-{index+1}"))
            root = base / case_id
            root.mkdir(parents=True, exist_ok=True)
            target = root / str(case.get("filename", "sample.py"))
            target.write_text(str(case.get("source", "")), encoding="utf-8")
            project = _context(root, config)
            analyzer = SecurityHardeningAnalyzer()
            findings = analyzer.analyze(project, config, root / ".raw").findings if analyzer.supports(project) else []
            actual = {finding.rule_id for finding in findings}
            expected = {str(item.get("rule_id", "")) for item in case.get("expected", []) if isinstance(item, dict)}
            matched = actual & expected
            ctp, cfp, cfn = len(matched), len(actual - expected), len(expected - actual)
            tp += ctp; fp += cfp; fn += cfn
            results.append({"id": case_id, "passed": cfp == 0 and cfn == 0, "tp": ctp, "fp": cfp, "fn": cfn, "expected": sorted(expected), "actual": sorted(actual)})
    runtime = time.perf_counter() - started
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    metrics = PrecisionMetrics(tp, fp, fn, precision, recall, f1, runtime)
    return metrics, {"metrics": metrics.to_dict(), "cases": results}
