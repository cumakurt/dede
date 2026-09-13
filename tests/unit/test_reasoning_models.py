"""Reasoning-model robustness in OllamaClient.chat_json (gpt-oss, deepseek-r1)."""

from __future__ import annotations

import httpx
import pytest

from dede.llm.client import (
    OllamaClient,
    _last_complete_json_object,
    _model_family_dislikes_grammar,
    _model_family_is_reasoning,
)


def test_gptoss_family_detected_for_grammar_skip():
    details = {"family": "gptoss", "families": ["gptoss"]}
    assert _model_family_dislikes_grammar(details)
    assert _model_family_is_reasoning(details)


def test_normal_family_keeps_grammar_and_no_directive():
    details = {"family": "llama", "families": ["llama"]}
    assert not _model_family_dislikes_grammar(details)
    assert not _model_family_is_reasoning(details)


def test_deepseek_r1_profile_disables_thinking():
    client = OllamaClient(host="http://x", model="deepseek-r1:7b")
    client.max_context = 8192
    captured = {}

    def fake_post(self, url, json=None, **kwargs):
        captured["payload"] = json

        class Resp:
            def raise_for_status(self):
                return None

            def json(self):
                return {"message": {"content": '{"ok": true}'}}

        return Resp()

    monkey = pytest.MonkeyPatch()
    monkey.setattr(httpx.Client, "post", fake_post)
    monkey.setattr(
        client,
        "_probe_family",
        lambda: {"family": "deepseek-r1", "families": ["deepseek-r1"]},
    )
    out = client.chat_json("sys", "user")
    monkey.undo()

    assert out == {"ok": True}
    payload = captured["payload"]
    assert "format" not in payload
    assert payload["think"] is False
    assert payload["options"]["num_predict"] == 2048
    assert payload["options"]["num_predict"] <= client.max_context // 4
    # "Reasoning: low" is a gpt-oss-only directive; r1 must not receive it.
    assert not payload["messages"][0]["content"].startswith("Reasoning: low\n")


def test_thinking_field_salvaged_when_content_empty():
    client = OllamaClient(host="http://x", model="m")

    class Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "done_reason": "length",
                "message": {
                    "content": "",
                    "thinking": 'analyzing... {"findings": []} done',
                },
            }

    monkey = pytest.MonkeyPatch()
    monkey.setattr(httpx.Client, "post", lambda self, url, **k: Resp())
    out = client.chat_json("sys", "user")
    monkey.undo()
    assert out == {"findings": []}


def test_last_complete_json_object_prefers_last_balanced():
    text = 'draft {"a": 1} revised {"findings": [{"b": 2}]} trailing'
    assert _last_complete_json_object(text) == {"findings": [{"b": 2}]}
    assert _last_complete_json_object("no json here") is None
    assert _last_complete_json_object('{"unclosed": true') is None
