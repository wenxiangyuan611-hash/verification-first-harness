"""Authenticated evidence bundles emitted by independent verification boundaries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from verification_harness.decision import Observation, VerificationObligation
from verification_harness.protocol import PROTOCOL_VERSION
from verification_harness.schema import canonical_json, digest_value, strict_json_loads


def _require_text(name: str, value: object) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a non-empty string")
    if value.__class__ is not str or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


@dataclass(frozen=True)
class EvidenceBundle:
    """Observations authenticated by an independent evidence authority."""

    bundle_id: str
    run_id: str
    context_digest: str
    authorized_spec_digest: str
    claim_digest: str
    attempt: int
    obligations: tuple[VerificationObligation, ...]
    observations: tuple[Observation, ...]
    verifier_id: str
    protocol_version: str = PROTOCOL_VERSION
    signature: str = ""

    def __post_init__(self) -> None:
        for name, value in (
            ("bundle_id", self.bundle_id),
            ("run_id", self.run_id),
            ("context_digest", self.context_digest),
            ("authorized_spec_digest", self.authorized_spec_digest),
            ("claim_digest", self.claim_digest),
            ("verifier_id", self.verifier_id),
        ):
            _require_text(name, value)
        if self.attempt.__class__ is not int or self.attempt < 1:
            raise ValueError("evidence attempt must be a positive integer")
        if self.protocol_version != PROTOCOL_VERSION:
            raise ValueError(f"unsupported protocol version: {self.protocol_version}")
        if self.signature.__class__ is not str:
            raise TypeError("evidence signature must be a string")
        if self.obligations.__class__ is not tuple or not self.obligations:
            raise ValueError("evidence obligations must be a non-empty tuple")
        if any(item.__class__ is not VerificationObligation for item in self.obligations):
            raise TypeError("evidence obligations contain an invalid value")
        if self.observations.__class__ is not tuple:
            raise TypeError("evidence observations must be a tuple")
        if any(item.__class__ is not Observation for item in self.observations):
            raise TypeError("evidence observations contain an invalid value")
        obligation_ids = [item.id for item in self.obligations]
        if len(obligation_ids) != len(set(obligation_ids)):
            raise ValueError("evidence obligation IDs must be unique")
        if [item.obligation_id for item in self.observations] != obligation_ids:
            raise ValueError("evidence observations must exactly match ordered obligations")

    @property
    def signing_payload(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "run_id": self.run_id,
            "context_digest": self.context_digest,
            "authorized_spec_digest": self.authorized_spec_digest,
            "claim_digest": self.claim_digest,
            "attempt": self.attempt,
            "obligations": [item.to_dict() for item in self.obligations],
            "observations": [item.to_dict() for item in self.observations],
            "verifier_id": self.verifier_id,
            "protocol_version": self.protocol_version,
        }

    @property
    def digest(self) -> str:
        return digest_value(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self.signing_payload, "signature": self.signature}

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> EvidenceBundle:
        return cls(
            bundle_id=value["bundle_id"],
            run_id=value["run_id"],
            context_digest=value["context_digest"],
            authorized_spec_digest=value["authorized_spec_digest"],
            claim_digest=value["claim_digest"],
            attempt=value["attempt"],
            obligations=tuple(
                VerificationObligation.from_dict(item) for item in value["obligations"]
            ),
            observations=tuple(Observation.from_dict(item) for item in value["observations"]),
            verifier_id=value["verifier_id"],
            protocol_version=value["protocol_version"],
            signature=value["signature"],
        )

    @classmethod
    def from_json(cls, raw: str) -> EvidenceBundle:
        if raw.__class__ is not str:
            raise TypeError("evidence JSON must be a string")
        value = strict_json_loads(raw)
        if value.__class__ is not dict:
            raise ValueError("evidence JSON must contain an object")
        bundle = cls.from_dict(value)
        if bundle.to_json() != canonical_json(value):
            raise ValueError("evidence JSON is not in the canonical protocol shape")
        return bundle
