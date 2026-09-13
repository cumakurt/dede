from pathlib import Path

from dede.config import AppConfig, PolicyRule, SuppressionRule
from dede.index import ScanIndex
from dede.models import Category, Finding, Severity
from dede.normalization.baseline import apply_baseline
from dede.normalization.findings import compute_semantic_fingerprint
from dede.normalization.suppress import apply_suppressions
from dede.policy import evaluate_policy


def test_semantic_fingerprint_survives_line_shift():
    a = Finding(tool="x", rule_id="sql", file="app.py", start_line=10, end_line=10,
                cwe=["CWE-89"], normalized_type="sql", code_snippet="10: cursor.execute(query)", function="handler")
    b = Finding(tool="y", rule_id="other", file="app.py", start_line=30, end_line=30,
                cwe=["CWE-89"], normalized_type="sql", code_snippet="30: cursor.execute(query)", function="handler")
    assert compute_semantic_fingerprint(a) == compute_semantic_fingerprint(b)


def test_baseline_uses_semantic_identity(tmp_path):
    current = Finding(tool="x", rule_id="r", file="a.py", fingerprint="new-v1", semantic_fingerprint="stable")
    baseline = tmp_path / "baseline.json"
    baseline.write_text('{"findings":[{"fingerprint":"old-v1","semantic_fingerprint":"stable","file":"a.py"}]}')
    findings, resolved = apply_baseline([current], baseline)
    assert findings[0].baseline_status.value == "EXISTING"
    assert resolved == []


def test_scoped_suppression_and_expiry(tmp_path):
    finding = Finding(tool="x", rule_id="r", file="tests/a.py", fingerprint="fp")
    cfg = AppConfig()
    cfg.suppress.entries = [SuppressionRule(rule="r", path="tests/**", reason="fixture", expires="2999-01-01")]
    active, suppressed = apply_suppressions([finding], cfg)
    assert active == [] and suppressed[0].suppress_reason == "fixture"


def test_policy_gate_matches_path_and_severity():
    finding = Finding(tool="x", rule_id="r", file="services/public/a.py", category=Category.SECURITY, severity=Severity.HIGH, id="SRM-1")
    cfg = AppConfig()
    cfg.policy.enabled = True
    cfg.policy.rules = [PolicyRule(name="public-high", path="services/public/**", deny_severity="HIGH")]
    violations = evaluate_policy([finding], cfg)
    assert violations and violations[0]["policy"] == "public-high"


def test_scan_index_detects_changes(tmp_path):
    source = tmp_path / "a.py"
    source.write_text("print(1)\n")
    db = tmp_path / "cache" / "index.db"
    with ScanIndex(db) as index:
        first = index.detect_changes(tmp_path, [str(source)])
        assert first["changed_files"] == ["a.py"]
        index.commit(tmp_path, [str(source)], [])
    with ScanIndex(db) as index:
        second = index.detect_changes(tmp_path, [str(source)])
        assert second["changed_files"] == []
        assert second["cache_hit_ratio"] == 1.0
        source.write_text("print(2)\n")
        third = index.detect_changes(tmp_path, [str(source)])
        assert third["changed_files"] == ["a.py"]


def test_scan_index_dependency_impact_is_transitive(tmp_path):
    a = tmp_path / "routes.py"
    b = tmp_path / "service.py"
    c = tmp_path / "repo.py"
    for path in (a, b, c):
        path.write_text("# source\n")
    db = tmp_path / "cache" / "index.db"
    dependencies = {
        "routes.py": ["service.py"],
        "service.py": ["repo.py"],
        "repo.py": [],
    }
    with ScanIndex(db) as index:
        index.commit(tmp_path, [str(a), str(b), str(c)], [], dependencies=dependencies)
    with ScanIndex(db) as index:
        assert index.affected_files(["repo.py"]) == ["repo.py", "routes.py", "service.py"]
        assert index.affected_files(["routes.py"]) == ["routes.py"]
        assert index.dependency_count() == 2
