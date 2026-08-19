"""Independent verifier plugin registry for the v0.3 runtime."""

from __future__ import annotations

import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol

from verification_harness.actions import ActionGate, ActionRequest
from verification_harness.decision import Observation, VerificationObligation
from verification_harness.protocol import (
    AuthorizedSpec,
    ClaimEnvelope,
    EvidenceStatus,
    RunContext,
)
from verification_harness.schema import canonical_json


def _require_text(name: str, value: object) -> None:
    if value.__class__ is not str or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _error_text(error: BaseException, limit: int = 500) -> str:
    try:
        message = str(error)
    except BaseException:
        message = "unreadable error"
    value = f"{type(error).__name__}: {message}"
    return value[:limit]


class VerifierPlugin(Protocol):
    """Collect one observation for an obligation without deciding propagation."""

    plugin_id: str
    kinds: frozenset[str]

    def observe(
        self,
        context: RunContext,
        spec: AuthorizedSpec,
        claim: ClaimEnvelope,
        obligation: VerificationObligation,
    ) -> Observation: ...


class VerifierRegistry:
    """Route obligations to exactly one plugin and contain plugin failures."""

    def __init__(
        self,
        verifier_id: str,
        plugins: tuple[VerifierPlugin, ...],
        action_gate: ActionGate,
    ) -> None:
        _require_text("verifier_id", verifier_id)
        if plugins.__class__ is not tuple or not plugins:
            raise ValueError("verifier registry requires a non-empty plugin tuple")
        routes: dict[str, VerifierPlugin] = {}
        for plugin in plugins:
            _require_text("verifier plugin_id", plugin.plugin_id)
            if plugin.kinds.__class__ is not frozenset or not plugin.kinds:
                raise ValueError("verifier plugin kinds must be a non-empty frozenset")
            if not callable(plugin.observe):
                raise TypeError("verifier plugin must provide observe")
            for kind in plugin.kinds:
                _require_text("verifier obligation kind", kind)
                if kind in routes:
                    raise ValueError(f"multiple verifier plugins handle obligation kind: {kind}")
                routes[kind] = plugin
        if action_gate.__class__ is not ActionGate:
            raise TypeError("verifier registry requires ActionGate")
        self.verifier_id = verifier_id
        self._routes = routes
        self._action_gate = action_gate

    def collect(
        self,
        context: RunContext,
        spec: AuthorizedSpec,
        claim: ClaimEnvelope,
        obligations: tuple[VerificationObligation, ...],
    ) -> tuple[Observation, ...]:
        if context.__class__ is not RunContext:
            raise TypeError("verifier registry requires RunContext")
        if spec.__class__ is not AuthorizedSpec:
            raise TypeError("verifier registry requires AuthorizedSpec")
        if claim.__class__ is not ClaimEnvelope:
            raise TypeError("verifier registry requires ClaimEnvelope")
        if obligations.__class__ is not tuple or not obligations:
            raise ValueError("verifier registry requires non-empty obligations")
        return tuple(
            self._collect_one(context, spec, claim, obligation)
            for obligation in obligations
        )

    def _collect_one(
        self,
        context: RunContext,
        spec: AuthorizedSpec,
        claim: ClaimEnvelope,
        obligation: VerificationObligation,
    ) -> Observation:
        if obligation.__class__ is not VerificationObligation:
            raise TypeError("verifier registry received an invalid obligation")
        plugin = self._routes.get(obligation.kind)
        if plugin is None:
            return Observation(
                obligation.id,
                EvidenceStatus.ERROR,
                "no verifier plugin executed",
                obligation.description,
                f"unsupported obligation kind: {obligation.kind}",
            )
        request = ActionRequest.create(
            run_id=context.run_id,
            actor_id=self.verifier_id,
            kind="verifier.invoke",
            target=plugin.plugin_id,
            payload={
                "claim_digest": claim.digest,
                "authorized_spec_digest": spec.digest,
                "obligation": obligation.to_dict(),
            },
        )
        try:
            observation = self._action_gate.execute(
                request,
                lambda: plugin.observe(context, spec, claim, obligation),
            )
            if observation.__class__ is not Observation:
                raise TypeError("verifier plugin returned an invalid observation")
            if observation.obligation_id != obligation.id:
                raise ValueError("verifier observation obligation identity mismatch")
            return observation
        except (KeyboardInterrupt, GeneratorExit):
            raise
        except BaseException as error:
            return Observation(
                obligation.id,
                EvidenceStatus.ERROR,
                "verifier plugin did not produce usable evidence",
                obligation.description,
                _error_text(error),
            )


class CommandVerifierPlugin:
    """Verify a claim by running an authorized argv check without a shell.

    Obligation payloads must contain ``argv`` and ``expected_exit_code``. The
    canonical claim envelope is provided to the command on stdin.
    """

    kinds = frozenset({"command.exit_code"})

    def __init__(
        self,
        plugin_id: str = "command-exit-code-verifier",
        *,
        timeout_seconds: float = 30.0,
        max_output_bytes: int = 250_000,
        cwd: str | Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        _require_text("plugin_id", plugin_id)
        if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
            raise ValueError("command verifier timeout must be positive")
        if max_output_bytes.__class__ is not int or max_output_bytes < 1:
            raise ValueError("command verifier max_output_bytes must be positive")
        if cwd is not None and not isinstance(cwd, (str, Path)):
            raise TypeError("command verifier cwd must be a path")
        if env is not None and not isinstance(env, Mapping):
            raise TypeError("command verifier env must be a mapping")
        self.plugin_id = plugin_id
        self._timeout_seconds = float(timeout_seconds)
        self._max_output_bytes = max_output_bytes
        self._cwd = None if cwd is None else str(cwd)
        self._env = None if env is None else dict(env)

    def observe(
        self,
        context: RunContext,
        spec: AuthorizedSpec,
        claim: ClaimEnvelope,
        obligation: VerificationObligation,
    ) -> Observation:
        del context, spec
        payload = obligation.payload
        if payload.__class__ is not dict:
            raise ValueError("command obligation payload must be an object")
        if set(payload) != {"argv", "expected_exit_code"}:
            raise ValueError(
                "command obligation requires exactly argv and expected_exit_code"
            )
        argv_value = payload["argv"]
        expected_exit_code = payload["expected_exit_code"]
        if argv_value.__class__ is not list or not argv_value:
            raise ValueError("command verifier argv must be a non-empty list")
        if any(value.__class__ is not str or not value for value in argv_value):
            raise ValueError("command verifier argv values must be non-empty strings")
        if expected_exit_code.__class__ is not int:
            raise ValueError("expected_exit_code must be an integer")
        try:
            completed = subprocess.run(
                tuple(argv_value),
                input=canonical_json(claim.to_dict()),
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
        except subprocess.TimeoutExpired as error:
            return Observation(
                obligation.id,
                EvidenceStatus.ERROR,
                "command verifier timed out",
                f"exit code {expected_exit_code}",
                _error_text(error),
            )
        stdout = completed.stdout.encode("utf-8")
        stderr = completed.stderr.encode("utf-8")
        if len(stdout) > self._max_output_bytes or len(stderr) > self._max_output_bytes:
            return Observation(
                obligation.id,
                EvidenceStatus.ERROR,
                "command verifier output exceeded the configured limit",
                f"exit code {expected_exit_code}",
                "verifier output limit exceeded",
            )
        status = (
            EvidenceStatus.PASSED
            if completed.returncode == expected_exit_code
            else EvidenceStatus.FAILED
        )
        details = completed.stdout.strip() or completed.stderr.strip()
        observed = f"exit code {completed.returncode}"
        if details:
            observed = f"{observed}: {details[:500]}"
        return Observation(
            obligation.id,
            status,
            observed,
            f"exit code {expected_exit_code}",
        )
