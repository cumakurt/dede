"""Analyzer plugin base classes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from dede.config import AppConfig
from dede.models import AnalyzerResult, ProjectContext


class Analyzer(ABC):
    name: str = "analyzer"

    @abstractmethod
    def supports(self, project: ProjectContext) -> bool: ...

    @abstractmethod
    def analyze(
        self,
        project: ProjectContext,
        config: AppConfig,
        raw_dir: Path,
    ) -> AnalyzerResult: ...

    @abstractmethod
    def version(self) -> str: ...
