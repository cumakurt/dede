"""Analyzers package.

Registry import is lazy to keep analyzer modules independently importable and
avoid extension/plugin import cycles.
"""

from __future__ import annotations


def get_analyzers():
    from dede.analyzers.registry import get_analyzers as _get_analyzers

    return _get_analyzers()


__all__ = ["get_analyzers"]
