"""AI vulnerability hunt: schema validation, conversion and bundle selection."""

from __future__ import annotations

from pathlib import Path

from dede.llm.hunt import (
    _ground_hunt_candidate,
    _select_files,
    _split_bundle_batches,
    build_source_bundle,
    hunt_finding_to_finding,
)
from dede.llm.hunt_schema import validate_hunt_response


VALID_FINDING = {
    "title": "SQL injection via cross-file flow",
    "severity": "HIGH",
    "category": "security",
    "cwe": "CWE-89",
    "file": "db.py",
    "start_line": 2,
    "end_line": 2,
    "message": "User input concatenated into SQL",
    "explanation": "routes.py passes request args into db.q which concatenates SQL",
    "impact": "Database compromise",
    "attack_scenario": "?x=1;DROP--",
    "recommendation": "Use parameterized queries",
    "confidence": 0.7,
    "dataflow": [
        {
            "description": "arg",
            "file": "routes.py",
            "start_line": 3,
            "end_line": 3,
            "content": "request.args.get",
        }
    ],
    "related_files": ["routes.py"],
}


def _make_project(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "from flask import request\n" "def r():\n" "    return q(request.args.get('x'))\n"
    )
    (tmp_path / "db.py").write_text("def q(x):\n" "    return cursor.execute('SELECT ' + x)\n")


def test_select_files_prioritizes_routes_and_sinks() -> None:
    ordered = _select_files(["zutil.py", "db.py", "routes.py", "unknown.py"], max_files=10)
    # Entry/config-like and sink-like files rank before generic ones.
    assert ordered.index("routes.py") < ordered.index("unknown.py")
    assert ordered.index("db.py") < ordered.index("unknown.py")


def test_build_source_bundle_reads_real_sources(tmp_path: Path) -> None:
    _make_project(tmp_path)
    bundle, included = build_source_bundle(tmp_path, ["db.py", "routes.py"])
    assert set(included) == {"db.py", "routes.py"}
    assert "cursor.execute" in bundle
    assert "request.args.get" in bundle
    assert "FILE: db.py" in bundle


def test_batches_cover_every_included_file(tmp_path: Path) -> None:
    _make_project(tmp_path)
    bundle, included = build_source_bundle(tmp_path, ["db.py", "routes.py"])
    batches = _split_bundle_batches(bundle, included)
    flat = [name for _, files in batches for name in files]
    assert sorted(flat) == sorted(included)


def test_valid_hunt_response_converts_to_finding() -> None:
    data = validate_hunt_response({"findings": [dict(VALID_FINDING)]})
    assert data is not None and len(data["findings"]) == 1
    finding = hunt_finding_to_finding(data["findings"][0], model="m", digest="d")
    assert finding.tool == "llm"
    assert finding.rule_id == "AI-HUNT"
    assert finding.analysis_kind == "ai-hunt"
    assert finding.ai_generated is True
    assert finding.severity.value == "HIGH"
    assert finding.cwe == ["CWE-89"]
    assert len(finding.dataflow) == 1
    assert finding.dataflow[0].file == "routes.py"


def test_hunt_response_rejects_hallucinated_fields_and_enums() -> None:
    assert validate_hunt_response({"findings": [dict(VALID_FINDING)]}) is not None
    assert validate_hunt_response({"findings": [dict(VALID_FINDING)], "x": 1}) is None
    bad_enum = dict(VALID_FINDING, severity="WORLD_ENDING")
    assert validate_hunt_response({"findings": [bad_enum]}) is None
    assert validate_hunt_response({"findings": []}) is not None  # honest empty


def test_hunt_candidate_must_cite_a_file_and_lines_from_its_batch(tmp_path: Path) -> None:
    _make_project(tmp_path)
    valid = _ground_hunt_candidate(
        dict(VALID_FINDING),
        root=tmp_path,
        allowed_files={"db.py", "routes.py"},
        max_bytes=100_000,
        model="m",
        digest="d",
    )
    assert valid is not None
    assert valid.ai_validation_status == "SOURCE_GROUNDED"

    assert (
        _ground_hunt_candidate(
            {**VALID_FINDING, "file": "not-in-prompt.py"},
            root=tmp_path,
            allowed_files={"db.py", "routes.py"},
            max_bytes=100_000,
            model="m",
            digest="d",
        )
        is None
    )
    assert (
        _ground_hunt_candidate(
            {**VALID_FINDING, "start_line": 999, "end_line": 999},
            root=tmp_path,
            allowed_files={"db.py", "routes.py"},
            max_bytes=100_000,
            model="m",
            digest="d",
        )
        is None
    )


def test_hunt_bundle_redacts_embedded_credentials(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text('password="DefinitelySecretValue123"\nprint("ok")\n')
    bundle, included = build_source_bundle(tmp_path, ["app.py"])
    assert included == ["app.py"]
    assert "DefinitelySecretValue123" not in bundle
