"""Resolve which offline Semgrep configs to load for a project."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from dede.config import AppConfig, SemgrepConfig
from dede.discovery.languages import detect_file_language
from dede.models import ProjectContext

# Always-on cross-language security packs
ALWAYS_PACKS = ("security-audit", "owasp-top-ten")

# Discovery language name → pack file stem(s)
LANGUAGE_PACKS: dict[str, tuple[str, ...]] = {
    "Python": ("python",),
    "JavaScript": ("javascript",),
    "TypeScript": ("typescript",),
    "Go": ("golang",),
    "Java": ("java",),
    "Kotlin": ("kotlin",),
    "Scala": ("scala",),
    "C#": ("csharp",),
    "PHP": ("php",),
    "Ruby": ("ruby",),
    "Rust": ("rust",),
    "C": ("c",),
    "C++": ("c",),  # CE has p/c; custom cpp rules cover C++ extras
    "Swift": ("swift",),
    "Dockerfile": ("dockerfile",),
    "Terraform": ("terraform",),
    "YAML": ("kubernetes",),  # refined by project types below
    "Nginx": ("nginx",),
}

# Framework / project-type hints → pack stems
FRAMEWORK_PACKS: dict[str, tuple[str, ...]] = {
    "django": ("django",),
    "flask": ("flask",),
    "fastapi": ("fastapi",),
    "react": ("react",),
    "next": ("react",),
    "Java/Maven": ("java",),
    "Java/Gradle": ("java",),
    "Docker": ("dockerfile", "kubernetes"),
    ".NET": ("csharp",),
    "Ruby": ("ruby",),
    "PHP": ("php",),
    "Go": ("golang",),
    "Rust": ("rust",),
    "Node.js": ("javascript", "typescript"),
    "Python": ("python",),
}

# Packs that should not be auto-selected solely because YAML files exist
YAML_OPTIONAL_PACKS = frozenset({"kubernetes", "nginx"})


def default_rules_dir() -> Path:
    candidates = [
        Path("/rules/semgrep"),
        Path(__file__).resolve().parents[2] / "rules" / "semgrep",
        Path(__file__).resolve().parents[3] / "rules" / "semgrep",
        Path(__file__).resolve().parents[1] / "bundled_rules",
    ]
    for path in candidates:
        try:
            if path.is_dir() and any(path.rglob("*.y*ml")):
                return path
        except OSError:
            continue
    return candidates[0]


def _pack_path(rules_dir: Path, name: str) -> Path | None:
    path = rules_dir / "packs" / f"{name}.yml"
    return path if path.is_file() else None


def _custom_configs(rules_dir: Path) -> list[Path]:
    custom = rules_dir / "custom"
    if custom.is_dir():
        files = sorted(custom.glob("*.yml")) + sorted(custom.glob("*.yaml"))
        if files:
            return files
    # Legacy flat layout fallback
    return sorted(
        p for p in rules_dir.glob("*.yml") if p.name not in {"MANIFEST.yml"} and p.is_file()
    ) + sorted(rules_dir.glob("*.yaml"))


def _all_pack_configs(rules_dir: Path) -> list[Path]:
    packs = rules_dir / "packs"
    if not packs.is_dir():
        return []
    return sorted(packs.glob("*.yml")) + sorted(packs.glob("*.yaml"))


def _full_offline_configs(rules_dir: Path) -> list[Path]:
    """Prefer the complete r/all dump; fall back to every vendored pack file."""
    all_dump = rules_dir / "packs" / "all.yml"
    if all_dump.is_file():
        return [all_dump]
    return _all_pack_configs(rules_dir)


def _detected_pack_names(project: ProjectContext) -> set[str]:
    names: set[str] = set()
    languages = set(project.languages.languages.keys())
    frameworks = {f.lower() for f in project.languages.frameworks}
    project_types = set(project.languages.project_types)

    for lang in languages:
        for pack in LANGUAGE_PACKS.get(lang, ()):
            if lang == "YAML" and pack in YAML_OPTIONAL_PACKS:
                # Only pull k8s/nginx when Docker/IaC context exists
                if "Docker" in project_types or "Dockerfile" in languages:
                    names.add(pack)
                continue
            names.add(pack)

    for fw in frameworks:
        for pack in FRAMEWORK_PACKS.get(fw, ()):
            names.add(pack)

    for ptype in project_types:
        for pack in FRAMEWORK_PACKS.get(ptype, ()):
            names.add(pack)
        key = ptype.lower()
        for pack in FRAMEWORK_PACKS.get(key, ()):
            names.add(pack)

    # Terraform files may be detected as HCL later; also check filenames
    for file_entry in project.files:
        path = Path(file_entry)
        suffix = path.suffix.lower()
        name = path.name.lower()
        if suffix in {".tf", ".tfvars"}:
            names.add("terraform")
        if name == "nginx.conf" or name.endswith(".nginx"):
            names.add("nginx")
        if name in {"dockerfile"} or name.startswith("dockerfile."):
            names.add("dockerfile")

    return names


def resolve_semgrep_configs(
    project: ProjectContext,
    config: AppConfig,
    *,
    rules_dir: Path | None = None,
) -> list[Path]:
    """Return ordered Semgrep --config paths for offline scanning."""
    root = rules_dir or default_rules_dir()
    semgrep: SemgrepConfig = config.semgrep
    profile = (semgrep.profile or "smart").lower()

    disable = {n.strip().lower() for n in semgrep.disable_packs if n.strip()}
    extra = {n.strip().lower() for n in semgrep.extra_packs if n.strip()}

    selected: list[Path] = []
    seen: set[Path] = set()

    def add(path: Path | None) -> None:
        if path is None:
            return
        resolved = path.resolve()
        if resolved in seen:
            return
        if not path.is_file() and not path.is_dir():
            return
        seen.add(resolved)
        selected.append(path)

    # Custom rules always (except when packs-only — not a profile we expose)
    for path in _custom_configs(root):
        add(path)

    if profile == "custom-only":
        for name in extra:
            if name not in disable:
                add(_pack_path(root, name))
        return selected

    if profile == "full":
        for path in _full_offline_configs(root):
            stem = path.stem.lower()
            if stem not in disable:
                add(path)
        for name in extra:
            if name not in disable and name != "all":
                add(_pack_path(root, name))
        return selected

    # smart (default)
    pack_names = set(ALWAYS_PACKS) | _detected_pack_names(project) | extra
    packs_added = 0
    for name in sorted(pack_names):
        if name in disable:
            continue
        pack_path = _pack_path(root, name)
        before = len(selected)
        add(pack_path)
        if len(selected) > before:
            packs_added += 1

    # If vendored packs are missing entirely, fall back to directory scan
    if packs_added == 0:
        packs = _all_pack_configs(root)
        if packs:
            for path in packs:
                if path.stem.lower() not in disable:
                    add(path)
        elif root.is_dir() and not selected:
            add(root)

    return selected


def append_config_args(args: list[str], configs: list[Path]) -> None:
    for path in configs:
        args.extend(["--config", str(path)])


def prepare_project_configs(
    configs: list[Path], project: ProjectContext, output: Path
) -> list[Path]:
    """Keep every applicable rule, excluding parsers for languages absent from the target."""
    aliases = {
        "JavaScript": {"javascript", "js"},
        "TypeScript": {"typescript", "ts", "javascript", "js"},
        "C++": {"cpp", "c"},
        "C#": {"csharp", "c#"},
        "Shell": {"bash", "sh"},
        "Terraform": {"hcl", "terraform"},
        "Kotlin": {"kotlin", "kt"},
    }
    languages = {"generic", "regex"}
    for file in project.files:
        language = detect_file_language(Path(file))
        if language:
            languages.update(aliases.get(language, {language.lower()}))
    prepared: list[Path] = []
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    for index, config in enumerate(configs):
        # Legacy directory configs still use Semgrep's own recursive loader.
        if config.is_dir():
            prepared.append(config)
            continue
        payload = yaml.load(config.read_text(encoding="utf-8"), Loader=loader)
        if not isinstance(payload, dict) or not isinstance(payload.get("rules"), list):
            raise ValueError(f"Invalid Semgrep rule configuration: {config}")
        selected = []
        for rule in payload["rules"]:
            if not isinstance(rule, dict) or not isinstance(rule.get("languages"), list):
                raise ValueError(f"Invalid Semgrep rule in {config}")
            if languages & {str(language).lower() for language in rule["languages"]}:
                selected.append(rule)
        if not selected:
            continue
        if len(selected) == len(payload["rules"]):
            prepared.append(config)
            continue
        path = output / f"rules-{index}.yml"
        path.write_text(json.dumps({**payload, "rules": selected}), encoding="utf-8")
        prepared.append(path)
    return prepared
