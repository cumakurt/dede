"""Ollama HTTP client (local only)."""

from __future__ import annotations

import json
from contextlib import contextmanager
from typing import Any

import httpx

from dede.config import AppConfig

# Models known to be incompatible with Ollama's `format: json` GBNF constraint:
# they return an instant empty response (done_reason=stop, ~11 eval tokens).
# For these we omit the grammar and rely on prompts + strict schema validation.
_NO_GRAMMAR_FAMILIES = ("gptoss", "gpt-oss", "deepseek-r1", "reasoner")

# Reasoning models emit hidden chain-of-thought before the answer. Their
# thinking can silently consume the whole output budget, so we raise the
# output cap for them and let gpt-oss explicitly lower its reasoning effort.
_REASONING_FAMILIES = ("gptoss", "gpt-oss", "deepseek-r1", "reasoner", "qwen3")
# "Reasoning: low" is a gpt-oss (harmony format) system directive; other
# families would just see it as prompt noise.
_DIRECTIVE_FAMILIES = ("gptoss", "gpt-oss")
_REASONING_DIRECTIVE = "Reasoning: low\n"


def _family_text(details: object) -> str:
    if isinstance(details, dict):
        family = str(details.get("family") or "")
        families = details.get("families") or []
        return " ".join([family, *(str(f) for f in families)]).lower()
    try:
        family = str(getattr(details, "family", "") or "")
        families = getattr(details, "families", None) or []
        return " ".join([family, *(str(f) for f in families)]).lower()
    except Exception:  # noqa: BLE001
        return ""


def _model_family_dislikes_grammar(details: object) -> bool:
    text = _family_text(details)
    return any(marker in text for marker in _NO_GRAMMAR_FAMILIES)


def _model_family_is_reasoning(details: object) -> bool:
    text = _family_text(details)
    return any(marker in text for marker in _REASONING_FAMILIES)


class OllamaClient:
    def __init__(
        self,
        config: AppConfig | None = None,
        *,
        host: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
    ) -> None:
        if config is not None:
            self.host = config.ai.ollama_host.rstrip("/")
            self.model = config.ai.model
        else:
            self.host = (host or "http://127.0.0.1:11434").rstrip("/")
            self.model = model or "qwen3-coder:30b"
        self.timeout = (
            timeout
            if timeout is not None
            else (config.ai.request_timeout_seconds if config else 120.0)
        )
        self.max_context = config.ai.max_context if config else 32768
        self.max_output_tokens = config.ai.max_output_tokens if config else 2048
        self.response_schema: dict | None = None
        self._session: httpx.Client | None = None
        self._family_cache: object | None | str = ""  # "" = not probed yet

    def _probe_family(self) -> object | None:
        """Look up model family from /api/tags; cached for the client lifetime."""
        if self._family_cache != "":
            return self._family_cache  # type: ignore[return-value]
        try:
            # Reuse the shared session when one is open (single HTTP pool).
            if self._session is not None:
                response = self._session.get(f"{self.host}/api/tags", timeout=5.0)
                return self._family_from_response(response)
            with httpx.Client(timeout=5.0) as client:
                response = client.get(f"{self.host}/api/tags")
                return self._family_from_response(response)
        except Exception:  # noqa: BLE001
            self._family_cache = None
            return None

    def _family_from_response(self, response: httpx.Response) -> object | None:
        try:
            if response.status_code != 200:
                self._family_cache = None
                return None
            for model in response.json().get("models", []):
                if not isinstance(model, dict):
                    continue
                name = str(model.get("name") or "")
                if _canonical_model_name(name) == _canonical_model_name(self.model):
                    details = model.get("details")
                    self._family_cache = details
                    return details
            self._family_cache = None
            return None
        except Exception:  # noqa: BLE001
            self._family_cache = None
            return None

    @contextmanager
    def session(self):
        """Share a thread-safe HTTP pool for one bounded enrichment run."""
        with httpx.Client(timeout=self.timeout) as client:
            self._session = client
            try:
                yield self
            finally:
                self._session = None

    def is_reachable(self) -> bool:
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(f"{self.host}/api/tags")
                return response.status_code == 200
        except Exception:  # noqa: BLE001
            return False

    def list_installed(self) -> list[dict[str, Any]]:
        try:
            with httpx.Client(timeout=15.0) as client:
                response = client.get(f"{self.host}/api/tags")
                response.raise_for_status()
                models = response.json().get("models", [])
                return (
                    [m for m in models if isinstance(m, dict)] if isinstance(models, list) else []
                )
        except Exception:  # noqa: BLE001
            return []

    def model_installed(self, name: str | None = None) -> bool:
        target = _canonical_model_name(name or self.model)
        names = {str(m.get("name") or "") for m in self.list_installed()}
        return any(_canonical_model_name(n) == target for n in names)

    def model_digest(self, name: str | None = None) -> str:
        target = _canonical_model_name(name or self.model)
        for model in self.list_installed():
            n = str(model.get("name") or "")
            if _canonical_model_name(n) == target:
                return str(model.get("digest") or "")
        return ""

    def pull_model(
        self,
        name: str,
        *,
        timeout: float = 3600.0,
        on_progress: Any | None = None,
    ) -> tuple[bool, str]:
        """Pull a model via Ollama API. Returns (ok, message).

        on_progress(status, completed, total) may be called repeatedly.
        completed/total are byte counts when known, else 0.
        """
        try:
            with (
                httpx.Client(timeout=timeout) as client,
                client.stream(
                    "POST",
                    f"{self.host}/api/pull",
                    json={"name": name, "stream": True},
                ) as response,
            ):
                if response.status_code >= 400:
                    body = ""
                    try:
                        body = response.read().decode("utf-8", errors="replace")[:200]
                    except Exception:  # noqa: BLE001
                        pass
                    return False, f"HTTP {response.status_code} {body}".strip()
                last_status = ""
                error = ""
                for line in response.iter_lines():
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(payload, dict):
                        return False, "Invalid model pull response: expected an object"
                    if payload.get("error"):
                        error = str(payload["error"])
                        break
                    status = str(payload.get("status") or "")
                    if status:
                        last_status = status
                    completed = int(payload.get("completed") or 0)
                    total = int(payload.get("total") or 0)
                    if on_progress is not None:
                        try:
                            on_progress(status or last_status, completed, total)
                        except Exception:  # noqa: BLE001
                            pass
                if error:
                    return False, error
                if last_status != "success":
                    return (
                        False,
                        f"Model pull ended before success ({last_status or 'empty stream'})",
                    )
                return True, last_status
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)

    def chat_json(
        self, system: str, user: str, max_tokens: int | None = None
    ) -> dict[str, Any] | None:
        # Never let output consume more than one quarter of the configured
        # context. This keeps the request within the same budget used while
        # selecting source evidence.
        context_output_cap = max(128, self.max_context // 4)
        predict = min(max_tokens or self.max_output_tokens, context_output_cap)
        payload: dict[str, Any] = {
            "model": self.model,
            "stream": False,
            "options": {
                "num_predict": predict,
                "num_ctx": self.max_context,
                "temperature": 0,
            },
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        # Strict JSON schema constraint by default; skipped for known-incompatible
        # model families (gpt-oss returns empty output under the grammar).
        if self.response_schema is not None:
            payload["format"] = self.response_schema
        else:
            payload["format"] = "json"

        try:
            probe = self._probe_family()
            if probe and _model_family_dislikes_grammar(probe):
                payload.pop("format", None)
            if probe and _model_family_is_reasoning(probe):
                # Reasoning headroom: thinking tokens count against num_predict.
                payload["options"]["num_predict"] = min(max(predict, 4096), context_output_cap)
                # gpt-oss understands the "Reasoning: low" system directive;
                # other families would just see it as prompt noise.
                if any(marker in _family_text(probe) for marker in _DIRECTIVE_FAMILIES):
                    payload["messages"][0]["content"] = _REASONING_DIRECTIVE + str(
                        payload["messages"][0]["content"]
                    )
                # deepseek-r1 supports disabling thinking at the API level.
                if "r1" in _family_text(probe):
                    payload["think"] = False
        except Exception:  # noqa: BLE001
            pass
        try:
            if self._session is not None:
                response = self._session.post(f"{self.host}/api/chat", json=payload)
            else:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.post(f"{self.host}/api/chat", json=payload)
            response.raise_for_status()
            body = response.json()
            if body.get("error"):
                return None
            message = body.get("message", {})
            content = message.get("content", "")
            parsed = _parse_json_content(content)
            if parsed is not None:
                return parsed
            # Reasoning models can exhaust their budget inside hidden
            # chain-of-thought with the answer incomplete or embedded in the
            # thinking field. Salvage a complete JSON object from it if present.
            thinking = message.get("thinking") or ""
            if thinking:
                salvaged = _parse_json_content(thinking)
                if salvaged is not None:
                    return salvaged
                return _last_complete_json_object(thinking)
            return None
        except Exception:  # noqa: BLE001
            return None


def _canonical_model_name(name: str) -> str:
    return name if ":" in name.rsplit("/", 1)[-1] else f"{name}:latest"


def _parse_json_content(content: str) -> dict[str, Any] | None:
    if not isinstance(content, str) or len(content) > 128_000:
        return None
    content = (content or "").strip()
    if not content:
        return None
    try:
        data = json.loads(content)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        start = content.find("{")
        end = content.rfind("}")
        if start >= 0 and end > start:
            try:
                data = json.loads(content[start : end + 1])
                return data if isinstance(data, dict) else None
            except json.JSONDecodeError:
                return None
        return None


def _last_complete_json_object(content: str) -> dict[str, Any] | None:
    """Find the last balanced top-level JSON object in prose/thinking text."""
    if not isinstance(content, str):
        return None
    decoder = json.JSONDecoder()
    best: dict[str, Any] | None = None
    best_end = -1
    index = content.find("{")
    while index != -1:
        if index < best_end:
            index = content.find("{", best_end)
            continue
        try:
            value, end = decoder.raw_decode(content, index)
            if isinstance(value, dict):
                best, best_end = value, index + end
        except json.JSONDecodeError:
            pass
        index = content.find("{", index + 1)
    return best
