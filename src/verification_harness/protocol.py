"""Language-neutral protocol values for the verification trust kernel."""

from __future__ import annotations

import json
import secrets
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from verification_harness.schema import canonical_json, digest_value

PROTOCOL_VERSION = "3.0"


def _require_text(name: str, value: object) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a non-empty string")
    if value.__class__ is not str or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _require_positive_int(name: str, value: object) -> None:
    if not isinstance(value, int):
        raise ValueError(f"{name} must be a positive integer")
    if value.__class__ is not int or value < 1:
        raise ValueError(f"{name} must be a positive integer")


def _payload_json(value: Any) -> str:
    """Return a canonical detached representation of an untrusted JSON value."""
    return canonical_json(value)


def _decode_payload(payload_json: str) -> Any:
    return json.loads(payload_json)


class AgentRole(Enum):
    PLANNER = "PLANNER"
    WORKER = "WORKER"
    CRITIC = "CRITIC"
    REVIEWER = "REVIEWER"
    VERIFIER = "VERIFIER"
    MASTER = "MASTER"
    SUB_AGENT = "SUB_AGENT"


class Verdict(Enum):
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"


class EvidenceStatus(Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"


@dataclass(frozen=True)
class RunContext:
    """A fresh run identity that prevents cross-run receipt reuse."""

    run_id: str
    task_id: str
    nonce: str
    protocol_version: str = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        _require_text("run_id", self.run_id)
        _require_text("task_id", self.task_id)
        _require_text("nonce", self.nonce)
        if self.protocol_version != PROTOCOL_VERSION:
            raise ValueError(f"unsupported protocol version: {self.protocol_version}")

    @classmethod
    def create(cls, task_id: str) -> RunContext:
        return cls(
            run_id=uuid.uuid4().hex,
            task_id=task_id,
            nonce=secrets.token_hex(16),
        )

    @property
    def digest(self) -> str:
        return digest_value(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "task_id": self.task_id,
            "nonce": self.nonce,
            "protocol_version": self.protocol_version,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> RunContext:
        return cls(
            run_id=value["run_id"],
            task_id=value["task_id"],
            nonce=value["nonce"],
            protocol_version=value["protocol_version"],
        )


@dataclass(frozen=True)
class AcceptanceCriterion:
    id: str
    description: str

    def __post_init__(self) -> None:
        _require_text("criterion id", self.id)
        _require_text("criterion description", self.description)

    def to_dict(self) -> dict[str, str]:
        return {"id": self.id, "description": self.description}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> AcceptanceCriterion:
        return cls(id=value["id"], description=value["description"])


@dataclass(frozen=True, init=False)
class SpecProposal:
    """An untrusted proposal that has no authority until separately signed."""

    proposal_id: str
    task_id: str
    proposer_id: str
    domain: str
    criteria: tuple[AcceptanceCriterion, ...]
    _payload_json: str = field(repr=False)

    def __init__(
        self,
        proposal_id: str,
        task_id: str,
        proposer_id: str,
        domain: str,
        criteria: tuple[AcceptanceCriterion, ...],
        payload: Any,
    ) -> None:
        _require_text("proposal_id", proposal_id)
        _require_text("task_id", task_id)
        _require_text("proposer_id", proposer_id)
        _require_text("domain", domain)
        if criteria.__class__ is not tuple or not criteria:
            raise ValueError("criteria must be a non-empty tuple")
        if any(item.__class__ is not AcceptanceCriterion for item in criteria):
            raise TypeError("criteria must contain AcceptanceCriterion values")
        criterion_ids = [item.id for item in criteria]
        if len(criterion_ids) != len(set(criterion_ids)):
            raise ValueError("acceptance criterion IDs must be unique")
        object.__setattr__(self, "proposal_id", proposal_id)
        object.__setattr__(self, "task_id", task_id)
        object.__setattr__(self, "proposer_id", proposer_id)
        object.__setattr__(self, "domain", domain)
        object.__setattr__(self, "criteria", criteria)
        object.__setattr__(self, "_payload_json", _payload_json(payload))

    @property
    def payload(self) -> Any:
        return _decode_payload(self._payload_json)

    @property
    def digest(self) -> str:
        return digest_value(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "task_id": self.task_id,
            "proposer_id": self.proposer_id,
            "domain": self.domain,
            "criteria": [item.to_dict() for item in self.criteria],
            "payload": self.payload,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> SpecProposal:
        criteria = tuple(AcceptanceCriterion.from_dict(item) for item in value["criteria"])
        return cls(
            proposal_id=value["proposal_id"],
            task_id=value["task_id"],
            proposer_id=value["proposer_id"],
            domain=value["domain"],
            criteria=criteria,
            payload=value["payload"],
        )


@dataclass(frozen=True)
class SpecAuthorization:
    authority_id: str
    proposal_digest: str
    protocol_version: str
    signature: str

    def __post_init__(self) -> None:
        _require_text("authority_id", self.authority_id)
        _require_text("proposal_digest", self.proposal_digest)
        _require_text("signature", self.signature)
        if self.protocol_version != PROTOCOL_VERSION:
            raise ValueError(f"unsupported protocol version: {self.protocol_version}")

    @property
    def signing_payload(self) -> dict[str, str]:
        return {
            "authority_id": self.authority_id,
            "proposal_digest": self.proposal_digest,
            "protocol_version": self.protocol_version,
        }

    def to_dict(self) -> dict[str, str]:
        return {**self.signing_payload, "signature": self.signature}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> SpecAuthorization:
        return cls(
            authority_id=value["authority_id"],
            proposal_digest=value["proposal_digest"],
            protocol_version=value["protocol_version"],
            signature=value["signature"],
        )


@dataclass(frozen=True)
class AuthorizedSpec:
    """A proposal plus proof from the non-agent acceptance-criteria authority."""

    proposal: SpecProposal
    authorization: SpecAuthorization

    def __post_init__(self) -> None:
        if self.proposal.__class__ is not SpecProposal:
            raise TypeError("proposal must be SpecProposal")
        if self.authorization.__class__ is not SpecAuthorization:
            raise TypeError("authorization must be SpecAuthorization")
        if self.authorization.proposal_digest != self.proposal.digest:
            raise ValueError("authorization is not bound to this proposal")

    @property
    def digest(self) -> str:
        return digest_value(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal": self.proposal.to_dict(),
            "authorization": self.authorization.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> AuthorizedSpec:
        return cls(
            proposal=SpecProposal.from_dict(value["proposal"]),
            authorization=SpecAuthorization.from_dict(value["authorization"]),
        )


@dataclass(frozen=True, init=False)
class ClaimEnvelope:
    """A role-neutral, immutable envelope for any untrusted agent output."""

    claim_id: str
    run_id: str
    role: AgentRole
    producer_id: str
    payload_type: str
    parent_claim_ids: tuple[str, ...]
    attempt: int
    _payload_json: str = field(repr=False)

    def __init__(
        self,
        claim_id: str,
        run_id: str,
        role: AgentRole,
        producer_id: str,
        payload_type: str,
        payload: Any,
        parent_claim_ids: tuple[str, ...] = (),
        attempt: int = 1,
    ) -> None:
        _require_text("claim_id", claim_id)
        _require_text("run_id", run_id)
        _require_text("producer_id", producer_id)
        _require_text("payload_type", payload_type)
        if role.__class__ is not AgentRole:
            raise TypeError("role must be AgentRole")
        _require_positive_int("attempt", attempt)
        if parent_claim_ids.__class__ is not tuple:
            raise TypeError("parent_claim_ids must be a tuple")
        if any(value.__class__ is not str or not value.strip() for value in parent_claim_ids):
            raise ValueError("parent claim IDs must be non-empty strings")
        if len(parent_claim_ids) != len(set(parent_claim_ids)):
            raise ValueError("parent claim IDs must be unique")
        if claim_id in parent_claim_ids:
            raise ValueError("a claim cannot be its own parent")
        object.__setattr__(self, "claim_id", claim_id)
        object.__setattr__(self, "run_id", run_id)
        object.__setattr__(self, "role", role)
        object.__setattr__(self, "producer_id", producer_id)
        object.__setattr__(self, "payload_type", payload_type)
        object.__setattr__(self, "parent_claim_ids", parent_claim_ids)
        object.__setattr__(self, "attempt", attempt)
        object.__setattr__(self, "_payload_json", _payload_json(payload))

    @classmethod
    def create(
        cls,
        context: RunContext,
        role: AgentRole,
        producer_id: str,
        payload_type: str,
        payload: Any,
        parent_claim_ids: tuple[str, ...] = (),
        attempt: int = 1,
    ) -> ClaimEnvelope:
        return cls(
            claim_id=uuid.uuid4().hex,
            run_id=context.run_id,
            role=role,
            producer_id=producer_id,
            payload_type=payload_type,
            payload=payload,
            parent_claim_ids=parent_claim_ids,
            attempt=attempt,
        )

    @property
    def payload(self) -> Any:
        return _decode_payload(self._payload_json)

    @property
    def digest(self) -> str:
        return digest_value(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "run_id": self.run_id,
            "role": self.role.value,
            "producer_id": self.producer_id,
            "payload_type": self.payload_type,
            "payload": self.payload,
            "parent_claim_ids": list(self.parent_claim_ids),
            "attempt": self.attempt,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ClaimEnvelope:
        return cls(
            claim_id=value["claim_id"],
            run_id=value["run_id"],
            role=AgentRole(value["role"]),
            producer_id=value["producer_id"],
            payload_type=value["payload_type"],
            payload=value["payload"],
            parent_claim_ids=tuple(value["parent_claim_ids"]),
            attempt=value["attempt"],
        )
