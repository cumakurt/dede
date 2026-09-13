"""Persistent local scan index for change detection and finding history.

The index contains hashes, dependency edges and normalized finding metadata
only. Source code is never stored. Dependency edges enable deterministic
reverse-impact calculation for incremental planning in offline environments.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections import deque
from pathlib import Path

from dede.models import Finding

SCHEMA_VERSION = 3


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ScanIndex:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS files (
                path TEXT PRIMARY KEY,
                sha256 TEXT NOT NULL,
                size INTEGER NOT NULL,
                mtime_ns INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                semantic_fingerprint TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                file TEXT NOT NULL,
                severity TEXT NOT NULL,
                first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS dependencies (
                file TEXT NOT NULL,
                depends_on TEXT NOT NULL,
                PRIMARY KEY(file, depends_on)
            );
            CREATE INDEX IF NOT EXISTS idx_dependencies_target ON dependencies(depends_on);
            """
        )
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(findings)")}
        if "active" not in columns:
            self.db.execute("ALTER TABLE findings ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
        self.db.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        self.db.commit()

    def detect_changes(self, root: Path, files: list[str]) -> dict[str, object]:
        previous = {row[0]: row[1] for row in self.db.execute("SELECT path, sha256 FROM files")}
        current: dict[str, str] = {}
        changed: list[str] = []
        for value in files:
            path = Path(value)
            rel = path.resolve().relative_to(root.resolve()).as_posix()
            digest = _sha256_file(path)
            current[rel] = digest
            if previous.get(rel) != digest:
                changed.append(rel)
        removed = sorted(set(previous) - set(current))
        return {
            "changed_files": sorted(changed),
            "removed_files": removed,
            "unchanged_files": len(current) - len(changed),
            "total_files": len(current),
            "cache_hit_ratio": round((len(current) - len(changed)) / len(current), 4)
            if current
            else 1.0,
            "hashes": current,
        }

    def affected_files(self, changed_files: list[str], removed_files: list[str] | None = None) -> list[str]:
        """Return changed files plus all transitive reverse dependents.

        If ``service.py`` imports ``repository.py``, a repository change affects
        both files. Cycles are safe and produce each path once.
        """
        seeds = set(changed_files) | set(removed_files or [])
        if not seeds:
            return []
        reverse: dict[str, set[str]] = {}
        for file, depends_on in self.db.execute("SELECT file, depends_on FROM dependencies"):
            reverse.setdefault(depends_on, set()).add(file)
        result = set(seeds)
        queue: deque[str] = deque(sorted(seeds))
        while queue:
            target = queue.popleft()
            for dependent in sorted(reverse.get(target, set())):
                if dependent not in result:
                    result.add(dependent)
                    queue.append(dependent)
        return sorted(result)

    def dependency_count(self) -> int:
        row = self.db.execute("SELECT COUNT(*) FROM dependencies").fetchone()
        return int(row[0]) if row else 0

    def lifecycle_diff(self, findings: list[Finding]) -> dict[str, object]:
        """Compare current findings with the previous active snapshot.

        Returns NEW / EXISTING / REOPENED current findings plus RESOLVED prior
        identities. Historical rows are retained, enabling reopen detection.
        """
        previous = {
            row[0]: {
                "active": bool(row[1]),
                "rule_id": row[2],
                "file": row[3],
                "severity": row[4],
            }
            for row in self.db.execute(
                "SELECT semantic_fingerprint, active, rule_id, file, severity FROM findings"
            )
        }
        current: dict[str, Finding] = {}
        counts = {"NEW": 0, "EXISTING": 0, "REOPENED": 0, "RESOLVED": 0}
        self.db.execute("UPDATE findings SET active=0")
        for finding in findings:
            identity = finding.semantic_fingerprint or finding.fingerprint
            if not identity:
                continue
            current[identity] = finding
            prior = previous.get(identity)
            if prior is None:
                status = "NEW"
            elif prior["active"]:
                status = "EXISTING"
            else:
                status = "REOPENED"
            finding.lifecycle_status = status
            counts[status] += 1

        resolved = [
            {"semantic_fingerprint": identity, **meta}
            for identity, meta in previous.items()
            if meta["active"] and identity not in current
        ]
        counts["RESOLVED"] = len(resolved)
        return {
            "counts": counts,
            "resolved": resolved,
            "current_total": len(current),
        }

    def commit(
        self,
        root: Path,
        files: list[str],
        findings: list[Finding],
        *,
        dependencies: dict[str, list[str]] | None = None,
        update_findings: bool = True,
    ) -> None:
        self.db.execute("DELETE FROM files")
        for value in files:
            path = Path(value)
            stat = path.stat()
            rel = path.resolve().relative_to(root.resolve()).as_posix()
            self.db.execute(
                "INSERT INTO files(path, sha256, size, mtime_ns) VALUES(?, ?, ?, ?)",
                (rel, _sha256_file(path), stat.st_size, stat.st_mtime_ns),
            )
        if update_findings:
            self.db.execute("UPDATE findings SET active=0")
            for finding in findings:
                identity = finding.semantic_fingerprint or finding.fingerprint
                if not identity:
                    continue
                self.db.execute(
                    """
                    INSERT INTO findings(semantic_fingerprint, fingerprint, rule_id, file, severity, active)
                    VALUES(?, ?, ?, ?, ?, 1)
                    ON CONFLICT(semantic_fingerprint) DO UPDATE SET
                        fingerprint=excluded.fingerprint,
                        rule_id=excluded.rule_id,
                        file=excluded.file,
                        severity=excluded.severity,
                        last_seen=CURRENT_TIMESTAMP,
                        active=1
                    """,
                    (identity, finding.fingerprint, finding.rule_id, finding.file, finding.severity.value),
                )
        if dependencies is not None:
            self.db.execute("DELETE FROM dependencies")
            for file, targets in sorted(dependencies.items()):
                for target in sorted(set(targets)):
                    if target == file:
                        continue
                    self.db.execute(
                        "INSERT OR IGNORE INTO dependencies(file, depends_on) VALUES(?, ?)",
                        (file, target),
                    )
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "ScanIndex":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
