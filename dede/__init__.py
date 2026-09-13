"""Dede — offline static code analysis with local LLM enrichment."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("dede")
except PackageNotFoundError:
    __version__ = "1.10.0"
