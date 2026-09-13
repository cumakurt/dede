"""Lexical and multiline matching regressions with real original locations."""

import pytest

from dede.engine.matcher import SourceFile, match_rule, evaluate_when
from dede.engine.rules import parse_rule_document, WhenCondition
from dede.engine.source import mask_comments


@pytest.mark.parametrize(
    "language,comment",
    [
        ("c#", "/* unsafe();\nunsafe(); */"),
        ("java", "// unsafe();"),
        ("python", "# unsafe()"),
        ("visual basic", "' unsafe()"),
        ("f#", "(* outer (* unsafe() *) unsafe() *)"),
        ("powershell", "<# unsafe() #>"),
        ("sql", "-- unsafe()"),
        ("xml", "<!-- unsafe() -->"),
        ("razor", "@* unsafe() *@"),
        ("lua", "--[[ unsafe() ]]"),
        ("rust", "/* outer /* unsafe() */ unsafe() */"),
    ],
)
def test_comment_mask_preserves_offsets_and_live_code(language, comment):
    text = comment + '\nunsafe("https://example.test/#value");'
    masked = mask_comments(text, language)
    assert len(masked) == len(text)
    assert masked.count("\n") == text.count("\n")
    assert "unsafe" not in masked[: len(comment)]
    assert masked[len(comment) :] == text[len(comment) :]


@pytest.mark.parametrize(
    "literal",
    [
        '"https://example.test/a/*value*/"',
        '@"// value ""quoted"""',
        '"""\n// text\n/* text */\n"""',
        '$"https://example.test/{id}"',
        '$@"https://example.test/{id}"',
    ],
)
def test_csharp_strings_are_not_comments(literal):
    assert mask_comments(f"var value = {literal};", "c#") == f"var value = {literal};"


def document_rule(**overrides):
    return parse_rule_document(
        {
            "id": "dede.test.document",
            "message": "Test",
            "languages": ["c#"],
            "mode": "document",
            "exclude_comments": True,
            "when": [{"regex": r"\bValidateIssuer\s*=\s*false\b"}],
            **overrides,
        },
        "test",
    )[0]


def test_document_match_ignores_comments_and_preserves_multiline_range():
    text = "/* ValidateIssuer = false; */\nsettings.ValidateIssuer\n  =\n  false;\n"
    matches = match_rule(document_rule(), SourceFile.from_text("Auth.cs", text), "c#")
    assert [(m.start_line, m.end_line) for m in matches] == [(2, 4)]
    assert matches[0].snippet == "settings.ValidateIssuer\n  =\n  false;"


def test_document_safe_value_is_not_a_match():
    source = SourceFile.from_text("Auth.cs", "ValidateIssuer = true;")
    assert not match_rule(document_rule(), source, "c#")


def test_document_span_limit_is_enforced():
    source = SourceFile.from_text("Auth.cs", "ValidateIssuer\n=\nfalse;")
    assert not match_rule(document_rule(max_span_lines=2), source, "c#")


def test_legacy_secret_matching_keeps_comments():
    rule = parse_rule_document(
        {
            "id": "dede.test.secret",
            "message": "Test",
            "languages": ["*"],
            "when": [{"pattern": "example-token"}],
        },
        "test",
    )[0]
    source = SourceFile.from_text("app.py", "# example-token")
    assert len(match_rule(rule, source, "python")) == 1


def test_mixed_same_line_constraints_keep_all_reachable_candidates():
    source = SourceFile.from_text("a.txt", "declare\nuse safe\nuse unsafe")
    assert evaluate_when(
        source,
        (
            WhenCondition(pattern="declare"),
            WhenCondition(pattern="use"),
            WhenCondition(pattern="unsafe", same_line=True),
        ),
    ) == [2]


def test_ordered_match_reports_every_reachable_use():
    source = SourceFile.from_text("a.txt", "use\ndeclare\nuse\nuse")
    assert evaluate_when(
        source, (WhenCondition(pattern="declare"), WhenCondition(pattern="use"))
    ) == [2, 3]


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16", "utf-16-be"])
def test_bom_decoding(tmp_path, encoding):
    path = tmp_path / "Source.cs"
    data = "ValidateIssuer = false;\n".encode(encoding)
    if encoding == "utf-16-be":
        data = b"\xfe\xff" + data
    path.write_bytes(data)
    source = SourceFile.load(path, "Source.cs")
    assert source.lines[0] == "ValidateIssuer = false;"
