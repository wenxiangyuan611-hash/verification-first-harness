"""Immutable, canonical data structures used by the verification protocol."""

from __future__ import annotations

import hashlib
import json
import keyword
from dataclasses import asdict, dataclass, field, is_dataclass
from enum import Enum
from typing import Any


def _json_default(value: Any) -> Any:
    """Convert protocol values to a deterministic JSON representation."""
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    raise TypeError(f"Protocol value is not JSON serializable: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """Serialize protocol data deterministically or fail closed."""
    return json.dumps(
        value,
        default=_json_default,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def digest_value(value: Any) -> str:
    """Return the SHA-256 digest of a canonical protocol value."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class TaskState(Enum):
    PLANNING = "PLANNING"
    WORKING = "WORKING"
    CHALLENGING = "CHALLENGING"
    VERIFYING = "VERIFYING"
    REPAIRING = "REPAIRING"
    PASSED = "PASSED"
    REJECTED = "REJECTED"


class VerificationStatus(Enum):
    PENDING = "PENDING"
    PASSED = "PASSED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class ComponentFailure:
    """A bounded, structured description of an untrusted component failure."""

    component: str
    operation: str
    error_type: str
    message: str

    def __post_init__(self) -> None:
        values = (self.component, self.operation, self.error_type, self.message)
        if any(not value.strip() for value in values):
            raise ValueError("component failure fields must be non-empty")


@dataclass(frozen=True)
class TestCase:
    id: str
    input: Any
    expected: Any

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("test case ID must be non-empty")
        canonical_json({"input": self.input, "expected": self.expected})


@dataclass(frozen=True)
class Spec:
    """A complete task contract accepted by the harness."""

    task_id: str
    description: str
    requirements: tuple[str, ...]
    test_cases: tuple[TestCase, ...]
    entrypoint: str

    def __post_init__(self) -> None:
        if not self.task_id.strip():
            raise ValueError("task_id must be non-empty")
        if not self.description.strip():
            raise ValueError("description must be non-empty")
        if not self.requirements or any(not item.strip() for item in self.requirements):
            raise ValueError("requirements must contain non-empty acceptance criteria")
        if not self.test_cases:
            raise ValueError("at least one test case is required")
        if not self.entrypoint.isidentifier() or keyword.iskeyword(self.entrypoint):
            raise ValueError("entrypoint must be a valid Python identifier")
        case_ids = [case.id for case in self.test_cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("test case IDs must be unique")

    @property
    def digest(self) -> str:
        return digest_value(
            {
                "task_id": self.task_id,
                "description": self.description,
                "requirements": self.requirements,
                "test_cases": self.test_cases,
                "entrypoint": self.entrypoint,
            }
        )


@dataclass(frozen=True)
class Claim:
    """An untrusted candidate supplied by a worker."""

    worker_id: str
    attempt: int
    code: str
    description: str

    def __post_init__(self) -> None:
        if not self.worker_id.strip():
            raise ValueError("worker_id must be non-empty")
        if self.attempt < 1:
            raise ValueError("attempt must be positive")
        if not self.code.strip():
            raise ValueError("claim code must be non-empty")

    @property
    def digest(self) -> str:
        return digest_value(
            {
                "worker_id": self.worker_id,
                "attempt": self.attempt,
                "code": self.code,
                "description": self.description,
            }
        )


@dataclass(frozen=True)
class Obligation:
    """A specific requirement that the verifier can evaluate."""

    id: str
    kind: str
    description: str
    payload: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id.strip() or not self.kind.strip():
            raise ValueError("obligation id and kind must be non-empty")
        canonical_json(self.payload)


@dataclass(frozen=True)
class Evidence:
    """The verifier's observation for exactly one obligation."""

    obligation_id: str
    status: VerificationStatus
    observed: str
    expected_repr: str
    error: str = ""

    def __post_init__(self) -> None:
        if not self.obligation_id.strip():
            raise ValueError("evidence obligation_id must be non-empty")
        if self.status.__class__ is not VerificationStatus:
            raise TypeError("evidence status must be VerificationStatus")

    @property
    def is_passed(self) -> bool:
        return self.status is VerificationStatus.PASSED


@dataclass(frozen=True)
class VerificationReceipt:
    """A signed result bound to one claim, spec, and obligation set."""

    run_id: str
    claim_digest: str
    spec_digest: str
    attempt: int
    protocol_version: str
    obligations: tuple[Obligation, ...]
    evidence: tuple[Evidence, ...]
    signature: str

    def __post_init__(self) -> None:
        if not self.run_id.strip():
            raise ValueError("receipt run_id must be non-empty")
        if self.attempt < 1:
            raise ValueError("receipt attempt must be positive")
        if not self.protocol_version.strip():
            raise ValueError("receipt protocol_version must be non-empty")
        if self.obligations.__class__ is not tuple or any(
            obligation.__class__ is not Obligation for obligation in self.obligations
        ):
            raise TypeError("receipt obligations must be a tuple of Obligation values")
        if self.evidence.__class__ is not tuple or any(
            item.__class__ is not Evidence for item in self.evidence
        ):
            raise TypeError("receipt evidence must be a tuple of Evidence values")
        obligation_ids = [obligation.id for obligation in self.obligations]
        if len(obligation_ids) != len(set(obligation_ids)):
            raise ValueError("receipt obligation IDs must be unique")

    @property
    def signing_payload(self) -> dict[str, Any]:
        """Return all receipt fields protected by the verifier signature."""
        return {
            "run_id": self.run_id,
            "claim_digest": self.claim_digest,
            "spec_digest": self.spec_digest,
            "attempt": self.attempt,
            "protocol_version": self.protocol_version,
            "obligations": self.obligations,
            "evidence": self.evidence,
        }

    @property
    def is_passed(self) -> bool:
        return self.is_complete and self.is_final and all(
            evidence.is_passed for evidence in self.evidence
        )

    @property
    def is_complete(self) -> bool:
        """Whether every obligation has exactly one ordered evidence item."""
        if not self.obligations or len(self.evidence) != len(self.obligations):
            return False
        expected_ids = [obligation.id for obligation in self.obligations]
        evidence_ids = [evidence.obligation_id for evidence in self.evidence]
        return evidence_ids == expected_ids

    @property
    def is_final(self) -> bool:
        """Whether the verifier resolved every evidence item to pass or fail."""
        final_statuses = {VerificationStatus.PASSED, VerificationStatus.FAILED}
        return bool(self.evidence) and all(
            evidence.status in final_statuses for evidence in self.evidence
        )
