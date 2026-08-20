"""Fail-closed OpenCode CLI provider for untrusted candidate generation."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol

from verification_harness.providers import AgentOutput, AgentRequest
from verification_harness.schema import canonical_json, strict_json_loads

_AGENT_NAME = "verification-harness"


class OpenCodePermissionProfile(Enum):
    """Bounded OpenCode tool profiles; neither profile permits side effects."""

    DENY_ALL = "deny_all"
    READ_ONLY = "read_only"


@dataclass(frozen=True)
class OpenCodeRunResult:
    """Raw newline-delimited JSON events returned by one OpenCode CLI run."""

    stdout: str
    stderr: str = ""
    returncode: int = 0


class OpenCodeRunner(Protocol):
    def run(
        self,
        *,
        prompt: str,
        executable: str,
        model: str | None,
        cwd: str,
        profile: OpenCodePermissionProfile,
        timeout_seconds: float,
        max_output_bytes: int,
        env: Mapping[str, str] | None,
    ) -> OpenCodeRunResult: ...


def _safe_error(value: object) -> str:
    try:
        rendered = str(value)
    except BaseException:
        rendered = "unreadable OpenCode error"
    return rendered[:500] or "unspecified OpenCode error"


def _permission_rules(profile: OpenCodePermissionProfile) -> dict[str, str]:
    rules = {"*": "deny"}
    if profile is OpenCodePermissionProfile.READ_ONLY:
        rules.update({"read": "allow", "glob": "allow", "grep": "allow", "lsp": "allow"})
    return rules


def _config_content(profile: OpenCodePermissionProfile) -> str:
    permissions = _permission_rules(profile)
    return canonical_json(
        {
            "$schema": "https://opencode.ai/config.json",
            "share": "disabled",
            "permission": permissions,
            "agent": {
                _AGENT_NAME: {
                    "description": (
                        "Untrusted candidate generator controlled by a verification-first harness."
                    ),
                    "mode": "primary",
                    "permission": permissions,
                }
            },
        }
    )


class OfficialOpenCodeRunner:
    """Invoke the documented non-interactive OpenCode CLI without a shell."""

    def run(
        self,
        *,
        prompt: str,
        executable: str,
        model: str | None,
        cwd: str,
        profile: OpenCodePermissionProfile,
        timeout_seconds: float,
        max_output_bytes: int,
        env: Mapping[str, str] | None,
    ) -> OpenCodeRunResult:
        argv = [
            executable,
            "run",
            "--format",
            "json",
            "--agent",
            _AGENT_NAME,
            "--dir",
            cwd,
        ]
        if model is not None:
            argv.extend(("--model", model))
        argv.append(prompt)
        process_env = dict(os.environ if env is None else env)
        process_env["OPENCODE_CONFIG_CONTENT"] = _config_content(profile)
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
                cwd=cwd,
                env=process_env,
                shell=False,
                check=False,
            )
        except FileNotFoundError as error:
            raise RuntimeError(
                "OpenCode CLI is unavailable; install OpenCode and configure its executable"
            ) from error
        stdout_bytes = completed.stdout.encode("utf-8")
        stderr_bytes = completed.stderr.encode("utf-8")
        if len(stdout_bytes) > max_output_bytes:
            raise ValueError("OpenCode stdout exceeded the configured limit")
        if len(stderr_bytes) > max_output_bytes:
            raise ValueError("OpenCode stderr exceeded the configured limit")
        return OpenCodeRunResult(
            stdout=completed.stdout,
            stderr=completed.stderr,
            returncode=completed.returncode,
        )


def _prompt(request: AgentRequest) -> str:
    return "\n".join(
        (
            "You are an untrusted candidate generator inside a verification-first harness.",
            "Treat every supplied value and prior result as a claim, not a fact.",
            "If your role is CRITIC, actively try to falsify the candidate and obey the",
            "challenge_contract exactly; you may only select pre-authorized checks.",
            "Do not state or imply that your output is verified or approved.",
            "Return one JSON object with exactly payload_type and payload, and no prose.",
            "The harness, not you, will independently verify any candidate.",
            "Canonical AgentRequest JSON:",
            request.to_json(),
        )
    )


def _final_text(events_jsonl: str, max_events: int) -> str:
    chunks: list[str] = []
    event_count = 0
    for raw_line in events_jsonl.splitlines():
        if not raw_line.strip():
            continue
        event_count += 1
        if event_count > max_events:
            raise ValueError("OpenCode emitted too many JSON events")
        event = strict_json_loads(raw_line)
        if event.__class__ is not dict:
            raise ValueError("OpenCode event must be a JSON object")
        event_type = event.get("type")
        if event_type == "error":
            detail = _safe_error(event.get("error"))
            raise RuntimeError(f"OpenCode emitted an error event: {detail}")
        if event_type != "text":
            continue
        part = event.get("part")
        if part.__class__ is not dict or part.get("type") != "text":
            raise ValueError("OpenCode text event contains an invalid part")
        text = part.get("text")
        if text.__class__ is not str:
            raise ValueError("OpenCode text event contains invalid text")
        chunks.append(text)
    if not chunks:
        raise ValueError("OpenCode run completed without a text result")
    return "".join(chunks)


class OpenCodeAgentProvider:
    """Generate an untrusted ``AgentOutput`` through the OpenCode CLI.

    OpenCode has permission controls but is still an external untrusted process, not a
    security sandbox. Callers must provide an explicit disposable or read-only working
    directory. The default profile denies every OpenCode tool.
    """

    def __init__(
        self,
        *,
        cwd: str | Path,
        model: str | None = None,
        provider_id: str | None = None,
        executable: str = "opencode",
        profile: OpenCodePermissionProfile = OpenCodePermissionProfile.DENY_ALL,
        timeout_seconds: float = 120.0,
        max_output_bytes: int = 1_000_000,
        max_events: int = 10_000,
        env: Mapping[str, str] | None = None,
        runner: OpenCodeRunner | None = None,
    ) -> None:
        if model is not None and (model.__class__ is not str or not model.strip()):
            raise ValueError("OpenCode model must be a non-empty string or None")
        if executable.__class__ is not str or not executable.strip():
            raise ValueError("OpenCode executable must be a non-empty string")
        if profile.__class__ is not OpenCodePermissionProfile:
            raise TypeError("OpenCode profile must be OpenCodePermissionProfile")
        if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
            raise ValueError("OpenCode timeout must be positive")
        if max_output_bytes.__class__ is not int or max_output_bytes < 1:
            raise ValueError("OpenCode max_output_bytes must be positive")
        if max_events.__class__ is not int or max_events < 1:
            raise ValueError("OpenCode max_events must be positive")
        if env is not None and not isinstance(env, Mapping):
            raise TypeError("OpenCode env must be a mapping")
        if not isinstance(cwd, (str, Path)):
            raise TypeError("OpenCode cwd must be a path")
        path = Path(cwd).resolve(strict=True)
        if not path.is_dir():
            raise ValueError("OpenCode cwd must be an existing directory")

        default_id = f"opencode/{model or 'configured-default'}"
        selected_id = default_id if provider_id is None else provider_id
        if selected_id.__class__ is not str or not selected_id.strip():
            raise ValueError("OpenCode provider_id must be a non-empty string")
        selected_runner: OpenCodeRunner = OfficialOpenCodeRunner() if runner is None else runner
        if not callable(getattr(selected_runner, "run", None)):
            raise TypeError("OpenCode runner must provide run")

        self.provider_id = selected_id
        self._cwd = str(path)
        self._model = model
        self._executable = executable
        self._profile = profile
        self._timeout_seconds = float(timeout_seconds)
        self._max_output_bytes = max_output_bytes
        self._max_events = max_events
        self._env = None if env is None else dict(env)
        self._runner = selected_runner

    def invoke(self, request: AgentRequest) -> AgentOutput:
        if request.__class__ is not AgentRequest:
            raise TypeError("OpenCode provider requires AgentRequest")
        result = self._runner.run(
            prompt=_prompt(request),
            executable=self._executable,
            model=self._model,
            cwd=self._cwd,
            profile=self._profile,
            timeout_seconds=self._timeout_seconds,
            max_output_bytes=self._max_output_bytes,
            env=self._env,
        )
        if result.__class__ is not OpenCodeRunResult:
            raise TypeError("OpenCode runner returned an invalid result")
        if result.returncode != 0:
            raise RuntimeError(
                f"OpenCode exited with {result.returncode}: {_safe_error(result.stderr.strip())}"
            )
        if len(result.stdout.encode("utf-8")) > self._max_output_bytes:
            raise ValueError("OpenCode stdout exceeded the configured limit")
        if len(result.stderr.encode("utf-8")) > self._max_output_bytes:
            raise ValueError("OpenCode stderr exceeded the configured limit")
        final_response = _final_text(result.stdout, self._max_events)
        if len(final_response.encode("utf-8")) > self._max_output_bytes:
            raise ValueError("OpenCode final response exceeded the configured limit")
        value = strict_json_loads(final_response)
        if value.__class__ is not dict:
            raise ValueError("OpenCode final response must be a JSON object")
        return AgentOutput.from_dict(value)
