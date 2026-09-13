"""Discovery package."""

from dede.discovery.files import discover_files
from dede.discovery.languages import detect_languages
from dede.discovery.projects import detect_projects

__all__ = ["detect_languages", "detect_projects", "discover_files"]
