"""Trusted, deterministic decision policy over independently collected evidence."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from verification_harness.protocol import (
    AuthorizedSpec,
    EvidenceStatus,
    Verdict,
)
from verification_harness.schema import canonical_json, digest_value


def _require_text(name: str, value: object) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a non-empty string")
    if value.__class__ is not str or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


@dataclass(frozen=True, init=False)
class VerificationObligation:
    """An authorized check mapped to one or more acceptance criteria."""

    id: str
    kind: str
    description: str
    criterion_ids: tuple[str, ...]
    _payload_json: str = field(repr=False)

    def __init__(
        self,
        id: str,
        kind: str,
        description: str,
        criterion_ids: tuple[str, ...],
        payload: Any | None = None,
    ) -> None:
        _require_text("obligation id", id)
        _require_text("obligation kind", kind)
        _require_text("obligation description", description)
        if criterion_ids.__class__ is not tuple or not criterion_ids:
            raise ValueError("criterion_ids must be a non-empty tuple")
        if any(item.__class__ is not str or not item.strip() for item in criterion_ids):
            raise ValueError("criterion IDs must be non-empty strings")
        if len(criterion_ids) != len(set(criterion_ids)):
            raise ValueError("obligation criterion IDs must be unique")
        object.__setattr__(self, "id", id)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "description", description)
        object.__setattr__(self, "criterion_ids", criterion_ids)
        detached_payload = {} if payload is None else payload
        object.__setattr__(self, "_payload_json", canonical_json(detached_payload))

    @property
    def payload(self) -> Any:
        return json.loads(self._payload_json)

    @property
    def digest(self) -> str:
        return digest_value(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "description": self.description,
            "criterion_ids": list(self.criterion_ids),
            "payload": self.payload,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> VerificationObligation:
        return cls(
            id=value["id"],
            kind=value["kind"],
            description=value["description"],
            criterion_ids=tuple(value["criterion_ids"]),
            payload=value["payload"],
        )


@dataclass(frozen=True)
class Observation:
    """An untrusted observation returned by a verification backend."""

    obligation_id: str
    status: EvidenceStatus
    observed: str
    expected: str
    error: str = ""

    def __post_init__(self) -> None:
        _require_text("observation obligation_id", self.obligation_id)
        if self.status.__class__ is not EvidenceStatus:
            raise TypeError("observation status must be EvidenceStatus")
        if self.observed.__class__ is not str:
            raise TypeError("observation observed value must be a string")
        if self.expected.__class__ is not str:
            raise TypeError("observation expected value must be a string")
        if self.error.__class__ is not str:
            raise TypeError("observation error must be a string")

    @property
    def digest(self) -> str:
        return digest_value(self.to_dict())

    def to_dict(self) -> dict[str, str]:
        return {
            "obligation_id": self.obligation_id,
            "status": self.status.value,
            "observed": self.observed,
            "expected": self.expected,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Observation:
        return cls(
            obligation_id=value["obligation_id"],
            status=EvidenceStatus(value["status"]),
            observed=value["observed"],
            expected=value["expected"],
            error=value.get("error", ""),
        )


@dataclass(frozen=True)
class CriterionTrace:
    """Trace one authorized criterion to checks and their evidence."""

    criterion_id: str
    obligation_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_text("trace criterion_id", self.criterion_id)
        if self.obligation_ids.__class__ is not tuple or not self.obligation_ids:
            raise ValueError("trace obligation_ids must be a non-empty tuple")
        if len(self.obligation_ids) != len(set(self.obligation_ids)):
            raise ValueError("trace obligation IDs must be unique")

    def to_dict(self) -> dict[str, Any]:
        return {
            "criterion_id": self.criterion_id,
            "obligation_ids": list(self.obligation_ids),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> CriterionTrace:
        return cls(
            criterion_id=value["criterion_id"],
            obligation_ids=tuple(value["obligation_ids"]),
        )


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    traces: tuple[CriterionTrace, ...]

    def __post_init__(self) -> None:
        if self.verdict.__class__ is not Verdict:
            raise TypeError("decision verdict must be Verdict")
        if self.traces.__class__ is not tuple or not self.traces:
            raise ValueError("decision traces must be a non-empty tuple")


class DecisionPolicy:
    """Fail closed unless evidence is complete and every criterion is traced."""

    def decide(
        self,
        spec: AuthorizedSpec,
        obligations: tuple[VerificationObligation, ...],
        observations: tuple[Observation, ...],
    ) -> Decision:
        if spec.__class__ is not AuthorizedSpec:
            raise TypeError("spec must be AuthorizedSpec")
        if obligations.__class__ is not tuple or not obligations:
            raise ValueError("decision requires a non-empty obligation tuple")
        if observations.__class__ is not tuple:
            raise TypeError("observations must be a tuple")
        if any(item.__class__ is not VerificationObligation for item in obligations):
            raise TypeError("obligations must contain VerificationObligation values")
        if any(item.__class__ is not Observation for item in observations):
            raise TypeError("observations must contain Observation values")

        obligation_ids = [item.id for item in obligations]
        if len(obligation_ids) != len(set(obligation_ids)):
            raise ValueError("obligation IDs must be unique")
        observation_ids = [item.obligation_id for item in observations]
        if observation_ids != obligation_ids:
            raise ValueError("observations must exactly match the ordered obligations")

        criterion_ids = tuple(item.id for item in spec.proposal.criteria)
        allowed_criteria = set(criterion_ids)
        mapped: dict[str, list[str]] = {criterion_id: [] for criterion_id in criterion_ids}
        for obligation in obligations:
            unknown = set(obligation.criterion_ids) - allowed_criteria
            if unknown:
                joined = ", ".join(sorted(unknown))
                raise ValueError(f"obligation references unknown criteria: {joined}")
            for criterion_id in obligation.criterion_ids:
                mapped[criterion_id].append(obligation.id)

        uncovered = [criterion_id for criterion_id, ids in mapped.items() if not ids]
        if uncovered:
            raise ValueError(
                "acceptance criteria lack verification obligations: " + ", ".join(uncovered)
            )

        traces = tuple(
            CriterionTrace(criterion_id, tuple(mapped[criterion_id]))
            for criterion_id in criterion_ids
        )
        statuses = {item.status for item in observations}
        if EvidenceStatus.ERROR in statuses:
            verdict = Verdict.ERROR
        elif EvidenceStatus.INCONCLUSIVE in statuses:
            verdict = Verdict.INCONCLUSIVE
        elif EvidenceStatus.FAILED in statuses:
            verdict = Verdict.REJECTED
        elif statuses == {EvidenceStatus.PASSED}:
            verdict = Verdict.VERIFIED
        else:
            verdict = Verdict.ERROR
        return Decision(verdict=verdict, traces=traces)
