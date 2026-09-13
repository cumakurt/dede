"""Offline software-composition analysis with source reachability evidence.

Dede consumes local advisory snapshots (simple Dede JSON or OSV JSON) and only
reports dependencies whose concrete versions are known.  It never queries a
network service during scanning.  Reachability is derived from source imports,
not guessed from installation alone.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dede.analyzers.base import Analyzer
from dede.config import AppConfig
from dede.models import AnalyzerResult, Category, Confidence, DataflowStep, Evidence, Finding, Precision, ProjectContext, Severity, ToolStatus
from dede.utils.hashes import sha256_text


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    version: str
    manifest: str
    line: int


@dataclass(frozen=True)
class Advisory:
    id: str
    ecosystem: str
    package: str
    introduced: str = ""
    fixed: str = ""
    affected_versions: tuple[str, ...] = ()
    severity: str = "HIGH"
    cwe: tuple[str, ...] = ()
    summary: str = ""
    references: tuple[str, ...] = ()


def _version_tuple(value: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", value.split("+", 1)[0].split("-", 1)[0])
    return tuple(int(x) for x in nums[:6]) or (0,)


def _affected(version: str, advisory: Advisory) -> bool:
    if advisory.affected_versions:
        return version in advisory.affected_versions
    current = _version_tuple(version)
    if advisory.introduced and current < _version_tuple(advisory.introduced):
        return False
    if advisory.fixed and current >= _version_tuple(advisory.fixed):
        return False
    return bool(advisory.introduced or advisory.fixed)


def _parse_requirements(path: Path, root: Path) -> list[Dependency]:
    out: list[Dependency] = []
    for idx, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        m = re.match(r"([A-Za-z0-9_.-]+)==([^;\s]+)", line)
        if m:
            out.append(Dependency("PyPI", m.group(1).lower().replace("_", "-"), m.group(2), path.relative_to(root).as_posix(), idx))
    return out


def _parse_package_lock(path: Path, root: Path) -> list[Dependency]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out: list[Dependency] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not key.startswith("node_modules/") or not isinstance(meta, dict):
                continue
            name = key[len("node_modules/"):]
            version = str(meta.get("version", ""))
            if version:
                out.append(Dependency("npm", name.lower(), version, path.relative_to(root).as_posix(), 1))
    elif isinstance(data.get("dependencies"), dict):
        for name, meta in data["dependencies"].items():
            if isinstance(meta, dict) and meta.get("version"):
                out.append(Dependency("npm", name.lower(), str(meta["version"]), path.relative_to(root).as_posix(), 1))
    return out


def _parse_go_mod(path: Path, root: Path) -> list[Dependency]:
    out: list[Dependency] = []
    in_block = False
    for idx, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw.strip()
        if line == "require (": in_block = True; continue
        if in_block and line == ")": in_block = False; continue
        if line.startswith("require "):
            line = line[len("require "):].strip()
        elif not in_block:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            out.append(Dependency("Go", parts[0], parts[1].lstrip("v"), path.relative_to(root).as_posix(), idx))
    return out


def _parse_pom(path: Path, root: Path) -> list[Dependency]:
    text = path.read_text(encoding="utf-8", errors="replace")
    out: list[Dependency] = []
    for m in re.finditer(r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<$][^<]*)</version>", text, re.S):
        line = text[:m.start()].count("\n") + 1
        out.append(Dependency("Maven", f"{m.group(1).strip()}:{m.group(2).strip()}", m.group(3).strip(), path.relative_to(root).as_posix(), line))
    return out


def discover_dependencies(root: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    for name in ("requirements.txt", "requirements-prod.txt", "requirements.lock"):
        p = root / name
        if p.is_file(): deps.extend(_parse_requirements(p, root))
    for p in root.rglob("package-lock.json"):
        if ".git" not in p.parts and "node_modules" not in p.parts: deps.extend(_parse_package_lock(p, root))
    for p in root.rglob("go.mod"):
        if ".git" not in p.parts: deps.extend(_parse_go_mod(p, root))
    for p in root.rglob("pom.xml"):
        if ".git" not in p.parts and "target" not in p.parts: deps.extend(_parse_pom(p, root))
    unique = {(d.ecosystem.lower(), d.name.lower(), d.version, d.manifest): d for d in deps}
    return sorted(unique.values(), key=lambda d: (d.ecosystem, d.name, d.manifest))


def _simple_advisories(data: dict[str, Any]) -> list[Advisory]:
    out: list[Advisory] = []
    for item in data.get("advisories", []):
        if not isinstance(item, dict): continue
        out.append(Advisory(
            id=str(item.get("id", "")), ecosystem=str(item.get("ecosystem", "")), package=str(item.get("package", "")),
            introduced=str(item.get("introduced", "")), fixed=str(item.get("fixed", "")),
            affected_versions=tuple(str(x) for x in item.get("affected_versions", [])),
            severity=str(item.get("severity", "HIGH")).upper(), cwe=tuple(str(x) for x in item.get("cwe", [])),
            summary=str(item.get("summary", "")), references=tuple(str(x) for x in item.get("references", [])),
        ))
    return [x for x in out if x.id and x.ecosystem and x.package]


def _osv_advisories(data: Any) -> list[Advisory]:
    items = data if isinstance(data, list) else ([data] if isinstance(data, dict) and "affected" in data else [])
    out: list[Advisory] = []
    for osv in items:
        if not isinstance(osv, dict): continue
        for affected in osv.get("affected", []):
            package = affected.get("package", {}) if isinstance(affected, dict) else {}
            ecosystem, name = str(package.get("ecosystem", "")), str(package.get("name", ""))
            versions = tuple(str(x) for x in affected.get("versions", [])) if isinstance(affected, dict) else ()
            for rng in affected.get("ranges", []) if isinstance(affected, dict) else []:
                introduced = fixed = ""
                for event in rng.get("events", []):
                    introduced = str(event.get("introduced", introduced))
                    fixed = str(event.get("fixed", fixed))
                out.append(Advisory(str(osv.get("id", "OSV")), ecosystem, name, introduced, fixed, versions, "HIGH", (), str(osv.get("summary", "")), tuple(str(r.get("url")) for r in osv.get("references", []) if isinstance(r, dict) and r.get("url"))))
            if versions and not affected.get("ranges"):
                out.append(Advisory(str(osv.get("id", "OSV")), ecosystem, name, affected_versions=versions, summary=str(osv.get("summary", ""))))
    return out


def load_advisories(config: AppConfig, root: Path) -> list[Advisory]:
    paths: list[Path] = []
    if config.sca.builtin_advisories:
        paths.append(Path(__file__).resolve().parent / "advisories" / "builtin.json")
    for raw in config.sca.advisory_paths:
        p = Path(raw).expanduser()
        if not p.is_absolute(): p = root / p
        if p.is_dir(): paths.extend(sorted(p.glob("*.json")))
        elif p.is_file(): paths.append(p)
    local = root / ".dede" / "advisories"
    if local.is_dir(): paths.extend(sorted(local.glob("*.json")))
    advisories: list[Advisory] = []
    for path in dict.fromkeys(paths):
        try: data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError): continue
        if isinstance(data, dict) and "advisories" in data:
            advisories.extend(_simple_advisories(data))
        else:
            advisories.extend(_osv_advisories(data))
    return advisories


def _source_references(root: Path, dep: Dependency, project: ProjectContext) -> list[tuple[str, int, str]]:
    name = dep.name
    candidates: list[re.Pattern[str]] = []
    if dep.ecosystem == "PyPI":
        module = name.replace("-", "_").split(".")[0]
        candidates = [re.compile(rf"^\s*(?:from|import)\s+{re.escape(module)}\b", re.M)]
    elif dep.ecosystem == "npm":
        candidates = [re.compile(rf"(?:from\s+['\"]{re.escape(name)}(?:/[^'\"]*)?['\"]|require\(\s*['\"]{re.escape(name)}(?:/[^'\"]*)?['\"]\s*\))")]
    elif dep.ecosystem == "Go":
        candidates = [re.compile(rf"['\"]{re.escape(name)}(?:/[^'\"]*)?['\"]")]
    elif dep.ecosystem == "Maven":
        artifact = dep.name.split(":", 1)[-1].replace("-", ".")
        candidates = [re.compile(rf"^\s*import\s+.*{re.escape(artifact.split('.')[0])}.*;", re.M)]
    refs: list[tuple[str,int,str]] = []
    for file_value in project.files:
        path = Path(file_value)
        if path.name in {"requirements.txt", "package-lock.json", "go.mod", "pom.xml"}: continue
        if path.suffix.lower() not in {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".cs", ".php"}: continue
        try: text = path.read_text(encoding="utf-8", errors="replace")
        except OSError: continue
        for pat in candidates:
            m = pat.search(text)
            if m:
                line = text[:m.start()].count("\n") + 1
                try: rel = path.resolve().relative_to(root).as_posix()
                except ValueError: rel = path.name
                refs.append((rel, line, text.splitlines()[line-1].strip()[:240]))
                if len(refs) >= 8: return refs
    return refs


class DependencyReachabilityAnalyzer(Analyzer):
    name = "dede-sca"
    def supports(self, project: ProjectContext) -> bool:
        root = Path(project.root)
        return any((root / name).is_file() for name in ("requirements.txt", "package-lock.json", "go.mod", "pom.xml")) or any(Path(f).name in {"package-lock.json", "go.mod", "pom.xml"} for f in project.files)
    def version(self) -> str: return "1.0.0"
    def analyze(self, project: ProjectContext, config: AppConfig, raw_dir: Path) -> AnalyzerResult:
        started = time.perf_counter()
        if not config.sca.enabled:
            return AnalyzerResult(tool=self.name, status=ToolStatus.SKIPPED, version=self.version(), message="SCA disabled")
        root = Path(project.root).resolve()
        deps = discover_dependencies(root)
        advisories = load_advisories(config, root)
        index = {(a.ecosystem.lower(), a.package.lower()): [] for a in advisories}
        for a in advisories: index.setdefault((a.ecosystem.lower(), a.package.lower()), []).append(a)
        findings: list[Finding] = []
        matches: list[dict[str, Any]] = []
        for dep in deps:
            for adv in index.get((dep.ecosystem.lower(), dep.name.lower()), []):
                if not _affected(dep.version, adv): continue
                refs = _source_references(root, dep, project)
                reachable = bool(refs)
                if not reachable and not config.sca.report_unreachable: continue
                base_severity = Severity(adv.severity) if adv.severity in Severity.__members__ else Severity.HIGH
                severity = base_severity if reachable else Severity.LOW
                fingerprint = sha256_text(f"sca|{adv.id}|{dep.ecosystem}|{dep.name}|{dep.version}|{dep.manifest}")
                evidence = [Evidence(kind="dependency", value=f"{dep.ecosystem}:{dep.name}@{dep.version}", confidence=1.0), Evidence(kind="advisory", value=adv.id, confidence=1.0)]
                dataflow: list[DataflowStep] = []
                for file, line, content in refs:
                    evidence.append(Evidence(kind="source-reference", value=f"{file}:{line}", confidence=0.95))
                    dataflow.append(DataflowStep(kind="dependency-use", file=file, start_line=line, end_line=line, content=content, symbol=dep.name))
                finding = Finding(
                    tool=self.name, rule_id=f"dede.sca.{adv.id}", category=Category.SECURITY,
                    severity=severity, confidence=Confidence.HIGH, confidence_score=0.99,
                    precision=Precision.VERY_HIGH, cwe=list(adv.cwe), file=dep.manifest,
                    start_line=dep.line, end_line=dep.line,
                    message=f"{adv.id} affects {dep.name} {dep.version}; source reachability: {'confirmed' if reachable else 'not observed'}.",
                    explanation=adv.summary, recommendation=(f"Upgrade {dep.name} to {adv.fixed} or later." if adv.fixed else f"Update {dep.name} to a non-affected version."),
                    references=list(adv.references), normalized_type="dependency-vulnerability",
                    analysis_kind="sca-reachability", semantic_fingerprint=fingerprint,
                    source_kind=f"dependency:{dep.ecosystem.lower()}", sink_kind="vulnerable-dependency",
                    reachable=reachable, exploitability_score=82.0 if reachable else 25.0,
                    dataflow=dataflow, evidence=evidence,
                    attack_path=([f"dependency {dep.name}@{dep.version}"] + [f"{f}:{l}" for f,l,_ in refs[:4]]),
                )
                findings.append(finding)
                matches.append({"advisory": adv.id, "dependency": f"{dep.name}@{dep.version}", "reachable": reachable, "references": [f"{f}:{l}" for f,l,_ in refs]})
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_path = raw_dir / "sca-reachability.json"
        raw_path.write_text(json.dumps({"dependencies": [d.__dict__ for d in deps], "advisory_count": len(advisories), "matches": matches}, indent=2), encoding="utf-8")
        return AnalyzerResult(tool=self.name, status=ToolStatus.SUCCESS, version=self.version(), findings=findings, raw_path=str(raw_path), duration_seconds=time.perf_counter()-started, coverage={"dependencies": len(deps), "advisories": len(advisories), "matched": len(findings), "reachable": sum(1 for f in findings if f.reachable)})
