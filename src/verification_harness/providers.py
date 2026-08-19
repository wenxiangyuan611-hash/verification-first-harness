"""Provider-neutral agent invocation values and local command adapter."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from verification_harness.protocol import AgentRole, RunContext
from verification_harness.schema import canonical_json, strict_json_loads


def _require_text(name: str, value: object) -> None:
    if value.__class__ is not str or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


@dataclass(frozen=True, init=False)
class AgentRequest:
    """Detached task input sent to one untrusted agent provider."""

    run_id: str
    task_id: str
    context_digest: str
    authorized_spec_digest: str
    role: AgentRole
    attempt: int
    parent_claim_ids: tuple[str, ...]
    _input_json: str = field(repr=False)
    _feedback_json: str = field(repr=False)

    def __init__(
        self,
        *,
        context: RunContext,
        authorized_spec_digest: str,
        role: AgentRole,
        attempt: int,
        input_payload: Any,
        feedback: Any | None = None,
        parent_claim_ids: tuple[str, ...] = (),
    ) -> None:
        if context.__class__ is not RunContext:
            raise TypeError("agent request requires RunContext")
        _require_text("authorized_spec_digest", authorized_spec_digest)
        if role.__class__ is not AgentRole:
            raise TypeError("agent request role must be AgentRole")
        if attempt.__class__ is not int or attempt < 1:
            raise ValueError("agent request attempt must be a positive integer")
        if parent_claim_ids.__class__ is not tuple:
            raise TypeError("parent_claim_ids must be a tuple")
        if any(value.__class__ is not str or not value.strip() for value in parent_claim_ids):
            raise ValueError("parent claim IDs must be non-empty strings")
        object.__setattr__(self, "run_id", context.run_id)
        object.__setattr__(self, "task_id", context.task_id)
        object.__setattr__(self, "context_digest", context.digest)
        object.__setattr__(self, "authorized_spec_digest", authorized_spec_digest)
        object.__setattr__(self, "role", role)
        object.__setattr__(self, "attempt", attempt)
        object.__setattr__(self, "parent_claim_ids", parent_claim_ids)
        object.__setattr__(self, "_input_json", canonical_json(input_payload))
        detached_feedback = {} if feedback is None else feedback
        object.__setattr__(self, "_feedback_json", canonical_json(detached_feedback))

    @property
    def input_payload(self) -> Any:
        return json.loads(self._input_json)

    @property
    def feedback(self) -> Any:
        return json.loads(self._feedback_json)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "task_id": self.task_id,
            "context_digest": self.context_digest,
            "authorized_spec_digest": self.authorized_spec_digest,
            "role": self.role.value,
            "attempt": self.attempt,
            "parent_claim_ids": list(self.parent_claim_ids),
            "input": self.input_payload,
            "feedback": self.feedback,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


@dataclass(frozen=True, init=False)
class AgentOutput:
    """A detached provider result that still has no propagation authority."""

    payload_type: str
    _payload_json: str = field(repr=False)

    def __init__(self, *, payload_type: str, payload: Any) -> None:
        _require_text("payload_type", payload_type)
        object.__setattr__(self, "payload_type", payload_type)
        object.__setattr__(self, "_payload_json", canonical_json(payload))

    @property
    def payload(self) -> Any:
        return json.loads(self._payload_json)

    def to_dict(self) -> dict[str, Any]:
        return {"payload_type": self.payload_type, "payload": self.payload}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> AgentOutput:
        if set(value) != {"payload_type", "payload"}:
            raise ValueError("agent output must contain exactly payload_type and payload")
        return cls(payload_type=value["payload_type"], payload=value["payload"])


class AgentProvider(Protocol):
    """Generate an untrusted candidate; providers never issue verification authority."""

    provider_id: str

    def invoke(self, request: AgentRequest) -> AgentOutput: ...


class CallableAgentProvider:
    """Adapter for SDK clients or application callbacks."""

    def __init__(
        self,
        provider_id: str,
        callback: Callable[[AgentRequest], AgentOutput],
    ) -> None:
        _require_text("provider_id", provider_id)
        if not callable(callback):
            raise TypeError("agent provider callback must be callable")
        self.provider_id = provider_id
        self._callback = callback

    def invoke(self, request: AgentRequest) -> AgentOutput:
        return self._callback(request)


class CommandAgentProvider:
    """Invoke a local provider command without a shell and parse strict JSON output.

    The canonical ``AgentRequest`` JSON is sent on stdin. The command must write one
    JSON object with exactly ``payload_type`` and ``payload`` to stdout.
    """

    def __init__(
        self,
        provider_id: str,
        argv: tuple[str, ...],
        *,
        timeout_seconds: float = 120.0,
        max_output_bytes: int = 1_000_000,
        cwd: str | Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        _require_text("provider_id", provider_id)
        if argv.__class__ is not tuple or not argv:
            raise ValueError("agent provider argv must be a non-empty tuple")
        if any(value.__class__ is not str or not value for value in argv):
            raise ValueError("agent provider argv values must be non-empty strings")
        if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
            raise ValueError("agent provider timeout must be positive")
        if max_output_bytes.__class__ is not int or max_output_bytes < 1:
            raise ValueError("agent provider max_output_bytes must be positive")
        if cwd is not None and not isinstance(cwd, (str, Path)):
            raise TypeError("agent provider cwd must be a path")
        if env is not None and not isinstance(env, Mapping):
            raise TypeError("agent provider env must be a mapping")
        self.provider_id = provider_id
        self._argv = argv
        self._timeout_seconds = float(timeout_seconds)
        self._max_output_bytes = max_output_bytes
        self._cwd = None if cwd is None else str(cwd)
        self._env = None if env is None else dict(env)

    def invoke(self, request: AgentRequest) -> AgentOutput:
        if request.__class__ is not AgentRequest:
            raise TypeError("agent provider requires AgentRequest")
        completed = subprocess.run(
            self._argv,
            input=request.to_json(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self._timeout_seconds,
            cwd=self._cwd,
            env=self._env,
            shell=False,
            check=False,
        )
        stdout_bytes = completed.stdout.encode("utf-8")
        stderr_bytes = completed.stderr.encode("utf-8")
        if len(stdout_bytes) > self._max_output_bytes:
            raise ValueError("agent provider stdout exceeded the configured limit")
        if len(stderr_bytes) > self._max_output_bytes:
            raise ValueError("agent provider stderr exceeded the configured limit")
        if completed.returncode != 0:
            stderr = completed.stderr.strip()
            raise RuntimeError(
                f"agent provider exited with {completed.returncode}: {stderr}"
            )
        value = strict_json_loads(completed.stdout)
        if value.__class__ is not dict:
            raise ValueError("agent provider output must be a JSON object")
        return AgentOutput.from_dict(value)
