"""Bounded, source-grounded context for advisory AI review."""

import ast
from functools import lru_cache
from pathlib import Path

from dede.llm.prompts import SYSTEM_PROMPT, build_user_prompt
from dede.models import Category, Finding
from dede.utils.hashes import sha256_text
from dede.utils.redact import redact_source_lines, redact_text
from dede.utils.source import read_source_lines


class ReviewContext:
    def __init__(self, root: Path, max_bytes: int, context_lines: int):
        self.context_lines = context_lines

        @lru_cache(maxsize=8)
        def read(file: str):
            lines = read_source_lines(root, file, max_bytes)
            tree = None
            if file.endswith((".py", ".pyi")) and sum(map(len, lines)) <= 512_000:
                try:
                    tree = ast.parse("\n".join(lines))
                except (SyntaxError, ValueError, RecursionError):
                    pass  # Incomplete source still supplies line-level evidence.
            return redact_source_lines(lines), tree, sha256_text("\n".join(lines)) if lines else ""

        self.read = read

    def source_digest(self, file: str) -> str:
        return self.read(file)[2]

    def source(self, finding: Finding, budget: int) -> str:
        # Secret findings never need their literal value or surrounding source.
        if finding.category == Category.SECRET:
            return "Secret value and surrounding source withheld. Assess the rule metadata only."
        lines, tree, _ = self.read(finding.file)
        if not lines:
            return redact_text(finding.code_snippet)[:budget]
        anchor = min(max(1, finding.start_line), len(lines))
        priority = list(
            range(anchor, min(len(lines), max(anchor, finding.end_line), anchor + 9) + 1)
        )
        for step in finding.dataflow[:32]:
            if step.file == finding.file:
                priority.append(step.start_line)
        radius = self.context_lines
        if tree is not None:
            functions = [
                node
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.lineno <= anchor <= (node.end_lineno or node.lineno)
            ]
            if functions:
                function = min(
                    functions, key=lambda node: (node.end_lineno or node.lineno) - node.lineno
                )
                priority.extend(node.lineno for node in function.decorator_list)
                priority.append(function.lineno)
                if (function.end_lineno or anchor) - function.lineno <= 120:
                    radius = max(
                        radius, anchor - function.lineno, (function.end_lineno or anchor) - anchor
                    )
            priority.extend(
                node.lineno for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))
            )
        priority.extend(
            sorted(
                range(max(1, anchor - radius), min(len(lines), anchor + radius) + 1),
                key=lambda number: abs(number - anchor),
            )
        )
        selected: dict[int, str] = {}
        remaining = max(0, budget - 100)
        for number in dict.fromkeys(priority):
            if not 1 <= number <= len(lines):
                continue
            rendered = f"{number}: {lines[number - 1]}"
            if len(rendered.encode()) > remaining:
                if number == anchor and remaining > 80:
                    rendered = (
                        rendered.encode()[: remaining - 30].decode(errors="ignore")
                        + " [line truncated]"
                    )
                else:
                    continue
            selected[number] = rendered
            remaining -= len(rendered.encode()) + 1
        return "Source excerpts; omitted lines are not evidence of safety.\n" + "\n".join(
            selected[n] for n in sorted(selected)
        )

    def prompt(self, finding: Finding, max_context: int, output_tokens: int) -> str | None:
        payload = {
            "rule_id": redact_text(finding.rule_id)[:500],
            "tool": finding.tool,
            "severity": finding.severity.value,
            "category": finding.category.value,
            "cwe": finding.cwe[:10],
            "message": "Potential secret detected; literal value withheld."
            if finding.category == Category.SECRET
            else redact_text(finding.message)[:2000],
            "file": finding.file,
            "start_line": finding.start_line,
            "end_line": finding.end_line,
            "analysis_kind": finding.analysis_kind,
            "detected_by": finding.detected_by[:10],
            "engine_recommendation": redact_text(finding.recommendation)[:2000],
            "dataflow": []
            if finding.category == Category.SECRET
            else [
                {**step.model_dump(), "content": redact_text(step.content)[:500]}
                for step in finding.dataflow[:32]
            ],
        }
        # No tokenizer dependency: conservatively budget one UTF-8 byte per token,
        # reserving space for output, schema, chat framing and a repair instruction.
        budget = max_context - min(output_tokens, max_context // 4) - 2048
        base_size = len((SYSTEM_PROMPT + build_user_prompt(payload, "")).encode())
        if base_size + 128 > budget:
            return None
        source_budget = min(16_000, budget - base_size)
        context = self.source(finding, source_budget)
        prompt = build_user_prompt(payload, context)
        while len((SYSTEM_PROMPT + prompt).encode()) > budget:
            # Re-select around the finding; chopping the end could remove the sink.
            source_budget = source_budget * 3 // 4
            context = self.source(finding, source_budget)
            prompt = build_user_prompt(payload, context)
        return prompt
