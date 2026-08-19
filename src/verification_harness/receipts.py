"""Stable, signed decision receipts for the generic trust kernel."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from verification_harness.decision import (
    CriterionTrace,
    Observation,
    VerificationObligation,
)
from verification_harness.protocol import PROTOCOL_VERSION, Verdict
from verification_harness.schema import canonical_json, digest_value, strict_json_loads


def _require_text(name: str, value: object) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a non-empty string")
    if value.__class__ is not str or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


@dataclass(frozen=True)
class DecisionReceipt:
    """An authenticated verdict bound to one exact run, spec, claim, and evidence set."""

    receipt_id: str
    run_id: str
    context_digest: str
    authorized_spec_digest: str
    claim_digest: str
    evidence_bundle_digest: str
    verifier_id: str
    attempt: int
    verdict: Verdict
    obligations: tuple[VerificationObligation, ...]
    observations: tuple[Observation, ...]
    traces: tuple[CriterionTrace, ...]
    authority_id: str
    protocol_version: str = PROTOCOL_VERSION
    signature: str = ""

    def __post_init__(self) -> None:
        text_values = (
            ("receipt_id", self.receipt_id),
            ("run_id", self.run_id),
            ("context_digest", self.context_digest),
            ("authorized_spec_digest", self.authorized_spec_digest),
            ("claim_digest", self.claim_digest),
            ("evidence_bundle_digest", self.evidence_bundle_digest),
            ("verifier_id", self.verifier_id),
            ("authority_id", self.authority_id),
        )
        for name, value in text_values:
            _require_text(name, value)
        if self.attempt.__class__ is not int or self.attempt < 1:
            raise ValueError("receipt attempt must be a positive integer")
        if self.verdict.__class__ is not Verdict:
            raise TypeError("receipt verdict must be Verdict")
        if self.protocol_version != PROTOCOL_VERSION:
            raise ValueError(f"unsupported protocol version: {self.protocol_version}")
        if self.signature.__class__ is not str:
            raise TypeError("receipt signature must be a string")
        if self.obligations.__class__ is not tuple or not self.obligations:
            raise ValueError("receipt obligations must be a non-empty tuple")
        if any(item.__class__ is not VerificationObligation for item in self.obligations):
            raise TypeError("receipt obligations contain an invalid value")
        if self.observations.__class__ is not tuple:
            raise TypeError("receipt observations must be a tuple")
        if any(item.__class__ is not Observation for item in self.observations):
            raise TypeError("receipt observations contain an invalid value")
        if self.traces.__class__ is not tuple or not self.traces:
            raise ValueError("receipt traces must be a non-empty tuple")
        if any(item.__class__ is not CriterionTrace for item in self.traces):
            raise TypeError("receipt traces contain an invalid value")
        obligation_ids = [item.id for item in self.obligations]
        if len(obligation_ids) != len(set(obligation_ids)):
            raise ValueError("receipt obligation IDs must be unique")
        if [item.obligation_id for item in self.observations] != obligation_ids:
            raise ValueError("receipt observations must exactly match ordered obligations")
        trace_ids = [item.criterion_id for item in self.traces]
        if len(trace_ids) != len(set(trace_ids)):
            raise ValueError("receipt criterion traces must be unique")
        known_obligations = set(obligation_ids)
        if any(
            not set(trace.obligation_ids).issubset(known_obligations) for trace in self.traces
        ):
            raise ValueError("receipt trace references an unknown obligation")

    @property
    def signing_payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "run_id": self.run_id,
            "context_digest": self.context_digest,
            "authorized_spec_digest": self.authorized_spec_digest,
            "claim_digest": self.claim_digest,
            "evidence_bundle_digest": self.evidence_bundle_digest,
            "verifier_id": self.verifier_id,
            "attempt": self.attempt,
            "verdict": self.verdict.value,
            "obligations": [item.to_dict() for item in self.obligations],
            "observations": [item.to_dict() for item in self.observations],
            "traces": [item.to_dict() for item in self.traces],
            "authority_id": self.authority_id,
            "protocol_version": self.protocol_version,
        }

    @property
    def digest(self) -> str:
        return digest_value(self.to_dict())

    @property
    def is_signed(self) -> bool:
        return bool(self.signature)

    def to_dict(self) -> dict[str, Any]:
        return {**self.signing_payload, "signature": self.signature}

    def to_json(self) -> str:
        """Export one deterministic, portable JSON representation."""
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> DecisionReceipt:
        return cls(
            receipt_id=value["receipt_id"],
            run_id=value["run_id"],
            context_digest=value["context_digest"],
            authorized_spec_digest=value["authorized_spec_digest"],
            claim_digest=value["claim_digest"],
            evidence_bundle_digest=value["evidence_bundle_digest"],
            verifier_id=value["verifier_id"],
            attempt=value["attempt"],
            verdict=Verdict(value["verdict"]),
            obligations=tuple(
                VerificationObligation.from_dict(item) for item in value["obligations"]
            ),
            observations=tuple(Observation.from_dict(item) for item in value["observations"]),
            traces=tuple(CriterionTrace.from_dict(item) for item in value["traces"]),
            authority_id=value["authority_id"],
            protocol_version=value["protocol_version"],
            signature=value["signature"],
        )

    @classmethod
    def from_json(cls, raw: str) -> DecisionReceipt:
        if raw.__class__ is not str:
            raise TypeError("receipt JSON must be a string")
        value = strict_json_loads(raw)
        if value.__class__ is not dict:
            raise ValueError("receipt JSON must contain an object")
        receipt = cls.from_dict(value)
        if receipt.to_json() != canonical_json(value):
            raise ValueError("receipt JSON is not in the canonical protocol shape")
        return receipt
