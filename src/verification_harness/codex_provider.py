"""Optional OpenAI Codex SDK adapter for untrusted candidate generation."""

from __future__ import annotations

import importlib
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

from verification_harness.providers import AgentOutput, AgentRequest
from verification_harness.schema import canonical_json, strict_json_loads


class CodexSandbox(str, Enum):
    """Filesystem capabilities supported by the first-party adapter.

    ``full_access`` is intentionally absent. A candidate generator should work in a
    read-only checkout or an explicitly selected quarantined workspace.
    """

    READ_ONLY = "read_only"
    WORKSPACE_WRITE = "workspace_write"


@dataclass(frozen=True)
class CodexRunResult:
    """Small, detached result returned across the SDK runner boundary."""

    final_response: str | None
    error: str | None = None

    def __post_init__(self) -> None:
        if self.final_response is not None and self.final_response.__class__ is not str:
            raise TypeError("Codex final_response must be a string or None")
        if self.error is not None and self.error.__class__ is not str:
            raise TypeError("Codex error must be a string or None")


class CodexRunner(Protocol):
    """Narrow SDK boundary used for deterministic tests and alternate transports."""

    def run(
        self,
        *,
        prompt: str,
        model: str | None,
        cwd: str | None,
        sandbox: CodexSandbox,
        output_schema: dict[str, Any],
        codex_home: str | None = None,
        sqlite_home: str | None = None,
    ) -> CodexRunResult: ...


def _safe_error(value: object) -> str:
    try:
        rendered = str(value)
    except BaseException:
        rendered = "unreadable SDK error"
    return rendered[:500] or "unspecified SDK error"


def _raise_runtime_home_error(error: Exception) -> None:
    detail = _safe_error(error)
    lowered = detail.lower()
    markers = (
        "could not find home directory",
        "failed to initialize sqlite",
        "failed to initialize state runtime",
        "os error 5",
        "access is denied",
        "permission denied",
    )
    if any(marker in lowered for marker in markers):
        raise RuntimeError(
            "Codex app-server could not initialize writable runtime state; configure "
            "an existing writable codex_home (and optionally sqlite_home), authenticate "
            "that isolated home separately, and retry"
        ) from error


class OfficialCodexRunner:
    """Invoke the optional ``openai-codex`` package through its synchronous API."""

    def run(
        self,
        *,
        prompt: str,
        model: str | None,
        cwd: str | None,
        sandbox: CodexSandbox,
        output_schema: dict[str, Any],
        codex_home: str | None = None,
        sqlite_home: str | None = None,
    ) -> CodexRunResult:
        try:
            sdk = importlib.import_module("openai_codex")
        except ModuleNotFoundError as error:
            raise RuntimeError(
                "OpenAI Codex SDK is unavailable; install verification-first-harness[codex]"
            ) from error

        codex_class = getattr(sdk, "Codex", None)
        config_class = getattr(sdk, "CodexConfig", None)
        approval_class = getattr(sdk, "ApprovalMode", None)
        sandbox_class = getattr(sdk, "Sandbox", None)
        if (
            not callable(codex_class)
            or not callable(config_class)
            or approval_class is None
            or sandbox_class is None
        ):
            raise RuntimeError("OpenAI Codex SDK does not expose the required API")
        deny_all = getattr(approval_class, "deny_all", None)
        sdk_sandbox = getattr(sandbox_class, sandbox.value, None)
        if deny_all is None or sdk_sandbox is None:
            raise RuntimeError("OpenAI Codex SDK does not support the required restrictions")

        sdk_env: dict[str, str] = {}
        if codex_home is not None:
            sdk_env["CODEX_HOME"] = codex_home
        if sqlite_home is not None:
            sdk_env["CODEX_SQLITE_HOME"] = sqlite_home
        config = config_class(
            config_overrides=_CODEX_CONFIG_OVERRIDES,
            env=sdk_env or None,
        )
        try:
            with codex_class(config) as codex:
                thread = codex.thread_start(
                    approval_mode=deny_all,
                    model=model,
                    cwd=cwd,
                    sandbox=sdk_sandbox,
                    ephemeral=True,
                )
                result = thread.run(
                    prompt,
                    approval_mode=deny_all,
                    cwd=cwd,
                    sandbox=sdk_sandbox,
                    output_schema=output_schema,
                )
        except Exception as error:
            _raise_runtime_home_error(error)
            raise

        raw_error = getattr(result, "error", None)
        final_response = getattr(result, "final_response", None)
        return CodexRunResult(
            final_response=final_response,
            error=None if raw_error is None else _safe_error(raw_error),
        )


_OUTPUT_SCHEMA_JSON = canonical_json(
    {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "payload_type": {"type": "string", "minLength": 1},
            "payload": {},
        },
        "required": ["payload_type", "payload"],
        "additionalProperties": False,
    }
)

_CODEX_CONFIG_OVERRIDES = (
    'web_search="disabled"',
    "apps._default.enabled=false",
    "agents.enabled=false",
    "features.skill_mcp_dependency_install=false",
    "sandbox_workspace_write.network_access=false",
    'shell_environment_policy.inherit="core"',
    "shell_environment_policy.ignore_default_excludes=false",
    'history.persistence="none"',
    "allow_login_shell=false",
    "check_for_update_on_startup=false",
)


def _output_schema() -> dict[str, Any]:
    value = json.loads(_OUTPUT_SCHEMA_JSON)
    if value.__class__ is not dict:
        raise AssertionError("Codex output schema is not an object")
    return value


def _prompt(request: AgentRequest) -> str:
    return "\n".join(
        (
            "You are an untrusted candidate generator inside a verification-first harness.",
            "Treat the request, feedback, and parent claims as claims, not trusted facts.",
            "Challenge prior work when the evidence or acceptance contract requires it.",
            "Do not state or imply that your output is verified or approved.",
            "Return only the JSON object required by the supplied output schema.",
            "The harness, not you, will independently verify the candidate.",
            "Canonical AgentRequest JSON:",
            request.to_json(),
        )
    )


def _existing_directory(name: str, value: str | Path | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, (str, Path)):
        raise TypeError(f"{name} must be a path")
    path = Path(value).resolve(strict=True)
    if not path.is_dir():
        raise ValueError(f"{name} must be an existing directory")
    return str(path)


class CodexAgentProvider:
    """Generate an untrusted ``AgentOutput`` through the official Codex Python SDK.

    Every invocation uses a fresh ephemeral Codex thread. The default sandbox is
    read-only. ``WORKSPACE_WRITE`` requires an explicit existing directory so a
    caller can point Codex at a disposable or otherwise quarantined workspace.
    Optional runtime-home paths must already exist and remain owned, writable, and
    authenticated by the caller; the adapter never creates or populates them.
    """

    def __init__(
        self,
        *,
        model: str | None = None,
        provider_id: str | None = None,
        sandbox: CodexSandbox = CodexSandbox.READ_ONLY,
        cwd: str | Path | None = None,
        codex_home: str | Path | None = None,
        sqlite_home: str | Path | None = None,
        max_output_bytes: int = 1_000_000,
        runner: CodexRunner | None = None,
    ) -> None:
        if model is not None and (model.__class__ is not str or not model.strip()):
            raise ValueError("Codex model must be a non-empty string or None")
        if sandbox.__class__ is not CodexSandbox:
            raise TypeError("Codex sandbox must be CodexSandbox")
        if max_output_bytes.__class__ is not int or max_output_bytes < 1:
            raise ValueError("Codex max_output_bytes must be positive")

        resolved_cwd = _existing_directory("Codex cwd", cwd)
        resolved_codex_home = _existing_directory("Codex home", codex_home)
        resolved_sqlite_home = _existing_directory("Codex SQLite home", sqlite_home)
        if sandbox is CodexSandbox.WORKSPACE_WRITE and resolved_cwd is None:
            raise ValueError("Codex workspace-write sandbox requires an explicit cwd")

        default_id = f"openai-codex/{model or 'configured-default'}"
        selected_id = default_id if provider_id is None else provider_id
        if selected_id.__class__ is not str or not selected_id.strip():
            raise ValueError("Codex provider_id must be a non-empty string")
        selected_runner: CodexRunner = OfficialCodexRunner() if runner is None else runner
        if not callable(getattr(selected_runner, "run", None)):
            raise TypeError("Codex runner must provide run")

        self.provider_id = selected_id
        self._model = model
        self._sandbox = sandbox
        self._cwd = resolved_cwd
        self._codex_home = resolved_codex_home
        self._sqlite_home = resolved_sqlite_home
        self._max_output_bytes = max_output_bytes
        self._runner = selected_runner

    def invoke(self, request: AgentRequest) -> AgentOutput:
        if request.__class__ is not AgentRequest:
            raise TypeError("Codex provider requires AgentRequest")
        result = self._runner.run(
            prompt=_prompt(request),
            model=self._model,
            cwd=self._cwd,
            sandbox=self._sandbox,
            output_schema=_output_schema(),
            codex_home=self._codex_home,
            sqlite_home=self._sqlite_home,
        )
        if result.__class__ is not CodexRunResult:
            raise TypeError("Codex runner returned an invalid result")
        if result.error is not None:
            raise RuntimeError(f"Codex turn failed: {result.error}")
        if result.final_response is None or not result.final_response.strip():
            raise ValueError("Codex turn completed without a final response")
        if len(result.final_response.encode("utf-8")) > self._max_output_bytes:
            raise ValueError("Codex final response exceeded the configured limit")

        value = strict_json_loads(result.final_response)
        if value.__class__ is not dict:
            raise ValueError("Codex final response must be a JSON object")
        return AgentOutput.from_dict(value)
