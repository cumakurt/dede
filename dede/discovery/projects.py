"""Project / framework detection from manifests and directory layout."""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

from dede.utils.source import read_source_lines

MANIFEST_HINTS: dict[str, list[str]] = {
    "Node.js": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
    "Python": ["pyproject.toml", "requirements.txt", "Pipfile", "poetry.lock", "setup.py"],
    "Go": ["go.mod", "go.sum"],
    "Rust": ["Cargo.toml", "Cargo.lock"],
    "Java/Maven": ["pom.xml"],
    "Java/Gradle": ["build.gradle", "build.gradle.kts"],
    "PHP": ["composer.json"],
    "Ruby": ["Gemfile"],
    ".NET": [],  # handled via glob
    "Docker": ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
    "CMake": ["CMakeLists.txt"],
    "Make": ["Makefile"],
}


def detect_projects(root: Path, files: list[Path] | None = None) -> tuple[list[str], list[str]]:
    root = root.resolve()
    if files is None:
        from dede.config import AppConfig
        from dede.discovery.files import discover_files

        files = discover_files(root, AppConfig())
    safe_files: list[Path] = []
    for path in files:
        try:
            resolved = path.resolve()
            if resolved != root and root not in resolved.parents:
                continue
            if resolved.is_file():
                safe_files.append(resolved)
        except (OSError, RuntimeError):
            continue
    files = safe_files
    names = {path.name for path in files}
    project_types = [
        project
        for project, manifests in MANIFEST_HINTS.items()
        if any(name in names for name in manifests)
    ]
    frameworks: set[str] = set()
    dotnet_extensions = {".csproj", ".vbproj", ".fsproj", ".sln", ".slnx"}
    if any(path.suffix.lower() in dotnet_extensions for path in files):
        project_types.append(".NET")
    for path in sorted(files):
        if path.name not in {
            "package.json",
            "pyproject.toml",
            "requirements.txt",
        } and path.suffix.lower() not in dotnet_extensions - {".sln"}:
            continue
        text = "\n".join(read_source_lines(root, str(path), 1024 * 1024))
        if not text:
            continue
        try:
            if path.name == "package.json":
                package = json.loads(text)
                if not isinstance(package, dict):
                    continue
                dependencies = {
                    name
                    for key in ("dependencies", "devDependencies", "peerDependencies")
                    if isinstance(package.get(key), dict)
                    for name in package[key]
                }
                for framework, dependency in {
                    "react": "react",
                    "vue": "vue",
                    "angular": "@angular/core",
                    "next": "next",
                    "nuxt": "nuxt",
                    "express": "express",
                    "nestjs": "@nestjs/core",
                    "svelte": "svelte",
                }.items():
                    if dependency in dependencies:
                        frameworks.add(framework)
            elif path.name == "pyproject.toml":
                package = tomllib.loads(text)
                dependencies = package.get("project", {}).get("dependencies", [])
                if isinstance(dependencies, list):
                    frameworks.update(_python_frameworks(dependencies))
                tool = package.get("tool", {})
                if isinstance(tool, dict) and isinstance(tool.get("poetry"), dict):
                    frameworks.add("poetry")
                    frameworks.update(_python_frameworks(tool["poetry"].get("dependencies", {})))
                if isinstance(tool, dict) and "pytest" in tool:
                    frameworks.add("pytest")
            elif path.name == "requirements.txt":
                frameworks.update(_python_frameworks(text.splitlines()))
            else:
                frameworks.update(_dotnet_frameworks(text))
        except (ValueError, TypeError, AttributeError, ET.ParseError):
            # Discovery is advisory. An invalid manifest remains in the scan
            # target list; it must not crash otherwise valid source analysis.
            continue
    return project_types, sorted(frameworks)


def _python_frameworks(dependencies) -> set[str]:
    names = {
        re.split(r"[\s\[<>=!~;]", value.strip().lower(), maxsplit=1)[0]
        for value in dependencies
        if isinstance(value, str)
    }
    return names & {"django", "flask", "fastapi", "pytest"}


def _dotnet_frameworks(text: str) -> set[str]:
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        return set()
    project = ET.fromstring(text)
    frameworks: set[str] = set()
    sdk = project.attrib.get("Sdk", "")
    if "Microsoft.NET.Sdk.Web" in sdk:
        frameworks.add("ASP.NET Core")
    if "Microsoft.NET.Sdk.Razor" in sdk:
        frameworks.add("Razor")
    if "Microsoft.NET.Sdk.BlazorWebAssembly" in sdk:
        frameworks.add("Blazor")
    for element in project.iter():
        name = element.tag.rsplit("}", 1)[-1]
        dependency = element.attrib.get("Include", "")
        if name in {"PackageReference", "FrameworkReference", "Reference"}:
            for prefix, label in {
                "Microsoft.AspNetCore": "ASP.NET Core",
                "Microsoft.EntityFrameworkCore": "EF Core",
                "EntityFramework": "Entity Framework",
                "System.Web": "ASP.NET",
                "Microsoft.Maui": ".NET MAUI",
                "Avalonia": "Avalonia",
            }.items():
                if dependency == prefix or dependency.startswith(prefix + "."):
                    frameworks.add(label)
        if name == "UseWPF" and (element.text or "").strip().lower() == "true":
            frameworks.add("WPF")
        if name == "UseWindowsForms" and (element.text or "").strip().lower() == "true":
            frameworks.add("Windows Forms")
    return frameworks
