"""Fail-closed authorization boundary for consequential runtime actions."""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, TypeVar

from verification_harness.schema import canonical_json, digest_value

T = TypeVar("T")


def _require_text(name: str, value: object) -> None:
    if value.__class__ is not str or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _safe_error(error: BaseException) -> str:
    try:
        message = str(error)
    except BaseException:
        message = "unreadable error"
    return f"{type(error).__name__}: {message}"[:500]


class ActionVerdict(Enum):
    """Policy outcomes for a proposed side effect."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


@dataclass(frozen=True, init=False)
class ActionRequest:
    """An immutable proposal to invoke an agent, verifier, tool, or other effect."""

    action_id: str
    run_id: str
    actor_id: str
    kind: str
    target: str
    _payload_json: str = field(repr=False)

    def __init__(
        self,
        *,
        action_id: str,
        run_id: str,
        actor_id: str,
        kind: str,
        target: str,
        payload: Any,
    ) -> None:
        for name, value in (
            ("action_id", action_id),
            ("run_id", run_id),
            ("actor_id", actor_id),
            ("kind", kind),
            ("target", target),
        ):
            _require_text(name, value)
        object.__setattr__(self, "action_id", action_id)
        object.__setattr__(self, "run_id", run_id)
        object.__setattr__(self, "actor_id", actor_id)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "_payload_json", canonical_json(payload))

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        actor_id: str,
        kind: str,
        target: str,
        payload: Any,
    ) -> ActionRequest:
        return cls(
            action_id=uuid.uuid4().hex,
            run_id=run_id,
            actor_id=actor_id,
            kind=kind,
            target=target,
            payload=payload,
        )

    @property
    def payload(self) -> Any:
        return json.loads(self._payload_json)

    @property
    def digest(self) -> str:
        return digest_value(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "run_id": self.run_id,
            "actor_id": self.actor_id,
            "kind": self.kind,
            "target": self.target,
            "payload": self.payload,
        }


@dataclass(frozen=True)
class ActionDecision:
    """A deterministic policy result; it is not proof that an action occurred."""

    verdict: ActionVerdict
    policy_id: str
    reason: str

    def __post_init__(self) -> None:
        if self.verdict.__class__ is not ActionVerdict:
            raise TypeError("action verdict must be ActionVerdict")
        _require_text("policy_id", self.policy_id)
        _require_text("reason", self.reason)


class ActionPolicy(Protocol):
    policy_id: str

    def decide(self, request: ActionRequest) -> ActionDecision: ...


class ApprovalResolver(Protocol):
    def approve(self, request: ActionRequest, decision: ActionDecision) -> bool: ...


class AllowListActionPolicy:
    """Small reference policy that denies every action kind not explicitly allowed."""

    def __init__(
        self,
        allowed_kinds: frozenset[str],
        *,
        approval_kinds: frozenset[str] = frozenset(),
        policy_id: str = "allow-list-action-policy",
    ) -> None:
        _require_text("policy_id", policy_id)
        if allowed_kinds.__class__ is not frozenset:
            raise TypeError("allowed_kinds must be a frozenset")
        if approval_kinds.__class__ is not frozenset:
            raise TypeError("approval_kinds must be a frozenset")
        if any(value.__class__ is not str or not value.strip() for value in allowed_kinds):
            raise ValueError("allowed action kinds must be non-empty strings")
        if any(value.__class__ is not str or not value.strip() for value in approval_kinds):
            raise ValueError("approval action kinds must be non-empty strings")
        if allowed_kinds & approval_kinds:
            raise ValueError("an action kind cannot be both allowed and approval-required")
        self.policy_id = policy_id
        self._allowed_kinds = allowed_kinds
        self._approval_kinds = approval_kinds

    def decide(self, request: ActionRequest) -> ActionDecision:
        if request.__class__ is not ActionRequest:
            raise TypeError("action policy requires ActionRequest")
        if request.kind in self._allowed_kinds:
            return ActionDecision(ActionVerdict.ALLOW, self.policy_id, "action kind allowed")
        if request.kind in self._approval_kinds:
            return ActionDecision(
                ActionVerdict.REQUIRE_APPROVAL,
                self.policy_id,
                "action kind requires independent approval",
            )
        return ActionDecision(ActionVerdict.DENY, self.policy_id, "action kind not allowed")


class ActionDenied(PermissionError):
    """Raised before an operation when policy did not grant execution authority."""


class ActionGate:
    """Evaluate policy before invoking an operation; invalid decisions fail closed."""

    def __init__(
        self,
        policy: ActionPolicy,
        approval_resolver: ApprovalResolver | None = None,
    ) -> None:
        _require_text("action policy_id", policy.policy_id)
        if not callable(policy.decide):
            raise TypeError("action policy must provide decide")
        if approval_resolver is not None and not callable(approval_resolver.approve):
            raise TypeError("approval resolver must provide approve")
        self._policy = policy
        self._approval_resolver = approval_resolver

    def execute(self, request: ActionRequest, operation: Callable[[], T]) -> T:
        if request.__class__ is not ActionRequest:
            raise TypeError("action gate requires ActionRequest")
        if not callable(operation):
            raise TypeError("action operation must be callable")
        try:
            decision = self._policy.decide(request)
        except (KeyboardInterrupt, GeneratorExit):
            raise
        except BaseException as error:
            raise ActionDenied(f"action policy failed closed: {_safe_error(error)}") from error
        if decision.__class__ is not ActionDecision:
            raise ActionDenied("action policy returned an invalid decision")
        if decision.policy_id != self._policy.policy_id:
            raise ActionDenied("action decision policy identity mismatch")
        if decision.verdict is ActionVerdict.DENY:
            raise ActionDenied(decision.reason)
        if decision.verdict is ActionVerdict.REQUIRE_APPROVAL:
            if self._approval_resolver is None:
                raise ActionDenied("action requires approval but no resolver is configured")
            try:
                approved = self._approval_resolver.approve(request, decision)
            except (KeyboardInterrupt, GeneratorExit):
                raise
            except BaseException as error:
                raise ActionDenied(
                    f"approval resolver failed closed: {_safe_error(error)}"
                ) from error
            if approved.__class__ is not bool:
                raise ActionDenied("approval resolver returned an invalid decision")
            if not approved:
                raise ActionDenied("independent approval was denied")
        return operation()
