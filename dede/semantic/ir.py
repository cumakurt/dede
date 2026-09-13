"""Language-neutral security intermediate representation.

The IR stores structural graph information plus normalized security flows. It
never stores complete source files, so it can be persisted or exported in
privacy-sensitive/offline environments. Language frontends emit the same
shape and downstream query/attack-graph layers stay parser-independent.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class IRLocation:
    file: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class IRFunction:
    id: str
    language: str
    module: str
    file: str
    name: str
    qualified_name: str
    parameters: tuple[str, ...] = ()
    class_name: str = ""
    start_line: int = 1
    end_line: int = 1
    return_source_kinds: tuple[str, ...] = ()
    passthrough_params: tuple[int, ...] = ()
    endpoint: str = ""
    http_methods: tuple[str, ...] = ()
    authentication_required: bool | None = None


@dataclass(frozen=True)
class IRCallEdge:
    caller: str
    callee: str
    file: str
    line: int
    resolved: bool = True


@dataclass(frozen=True)
class IRCFGEdge:
    function: str
    source: str
    target: str
    kind: str = "next"


@dataclass(frozen=True)
class IREndpoint:
    function: str
    file: str
    line: int
    path: str
    methods: tuple[str, ...] = ()
    authentication_required: bool | None = None


@dataclass(frozen=True)
class IRSecurityFlow:
    """Normalized source-to-sink flow emitted by any semantic frontend."""

    id: str
    rule_id: str
    cwe: tuple[str, ...]
    severity: str
    source_kind: str
    sink_kind: str
    sink_file: str
    sink_line: int
    function: str = ""
    endpoint: str = ""
    http_method: str = ""
    authentication_required: bool | None = None
    internet_exposed: bool | None = None
    exploitability_score: float | None = None
    call_path: tuple[str, ...] = ()
    files: tuple[str, ...] = ()
    query_matches: tuple[str, ...] = ()


@dataclass
class SecurityIR:
    """Serializable language-neutral graph produced by semantic frontends."""

    version: str = "2"
    language: str = ""
    functions: list[IRFunction] = field(default_factory=list)
    calls: list[IRCallEdge] = field(default_factory=list)
    cfg_edges: list[IRCFGEdge] = field(default_factory=list)
    endpoints: list[IREndpoint] = field(default_factory=list)
    security_flows: list[IRSecurityFlow] = field(default_factory=list)
    dependencies: dict[str, list[str]] = field(default_factory=dict)
    stats: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
