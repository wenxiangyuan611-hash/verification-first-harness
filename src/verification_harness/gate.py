"""Capability-oriented propagation gate for verified artifacts."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from typing import Any, Protocol

from verification_harness.audit import AuditKind, AuditSink
from verification_harness.authority import EvidenceVerifier, ReceiptAuthority, SpecAuthority
from verification_harness.boundary import AgentCallBoundary
from verification_harness.decision import DecisionPolicy
from verification_harness.evidence import EvidenceBundle
from verification_harness.protocol import (
    AuthorizedSpec,
    ClaimEnvelope,
    RunContext,
    Verdict,
)
from verification_harness.receipts import DecisionReceipt
from verification_harness.schema import canonical_json, digest_value

_ARTIFACT_ISSUER = object()


class ReplayError(ValueError):
    """Raised when a receipt is consumed more than once."""


class ReceiptUseStore(Protocol):
    def consume(self, receipt: DecisionReceipt) -> None: ...


class InMemoryReceiptUseStore:
    """Reference atomic-use registry for one controller process."""

    def __init__(self) -> None:
        self._consumed: dict[str, str] = {}
        self._lock = threading.Lock()

    @property
    def consumed_receipt_ids(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._consumed)

    def consume(self, receipt: DecisionReceipt) -> None:
        with self._lock:
            existing = self._consumed.get(receipt.receipt_id)
            if existing is not None:
                if existing != receipt.digest:
                    raise ReplayError("receipt ID was reused with different contents")
                raise ReplayError("receipt has already been consumed")
            self._consumed[receipt.receipt_id] = receipt.digest


@dataclass(frozen=True, init=False)
class VerifiedArtifact:
    """The only public value authorized to carry a claim payload downstream."""

    run_id: str
    claim_id: str
    claim_digest: str
    authorized_spec_digest: str
    receipt_id: str
    receipt_digest: str
    payload_type: str
    _payload_json: str = field(repr=False)

    def __init__(
        self,
        *,
        issuer: object,
        run_id: str,
        claim_id: str,
        claim_digest: str,
        authorized_spec_digest: str,
        receipt_id: str,
        receipt_digest: str,
        payload_type: str,
        payload: Any,
    ) -> None:
        if issuer is not _ARTIFACT_ISSUER:
            raise PermissionError("VerifiedArtifact can only be issued by TrustGate")
        object.__setattr__(self, "run_id", run_id)
        object.__setattr__(self, "claim_id", claim_id)
        object.__setattr__(self, "claim_digest", claim_digest)
        object.__setattr__(self, "authorized_spec_digest", authorized_spec_digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        object.__setattr__(self, "receipt_digest", receipt_digest)
        object.__setattr__(self, "payload_type", payload_type)
        object.__setattr__(self, "_payload_json", canonical_json(payload))

    @property
    def payload(self) -> Any:
        return json.loads(self._payload_json)

    @property
    def digest(self) -> str:
        return digest_value(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "claim_id": self.claim_id,
            "claim_digest": self.claim_digest,
            "authorized_spec_digest": self.authorized_spec_digest,
            "receipt_id": self.receipt_id,
            "receipt_digest": self.receipt_digest,
            "payload_type": self.payload_type,
            "payload": self.payload,
        }


class TrustGate:
    """Validate all authorities and bindings before issuing propagation capability."""

    def __init__(
        self,
        spec_authority: SpecAuthority,
        evidence_verifier: EvidenceVerifier,
        receipt_authority: ReceiptAuthority,
        decision_policy: DecisionPolicy,
        receipt_use_store: ReceiptUseStore,
        audit_sink: AuditSink,
    ) -> None:
        self.spec_authority = spec_authority
        self.evidence_verifier = evidence_verifier
        self.receipt_authority = receipt_authority
        self.decision_policy = decision_policy
        self.receipt_use_store = receipt_use_store
        self.audit_sink = audit_sink

    def propagate(
        self,
        context: RunContext,
        spec: AuthorizedSpec,
        claim: ClaimEnvelope,
        evidence: EvidenceBundle,
        receipt: DecisionReceipt,
    ) -> VerifiedArtifact:
        """Consume one VERIFIED receipt and issue a payload-carrying capability."""
        try:
            self.validate_decision_receipt(context, spec, claim, evidence, receipt)
            if receipt.verdict is not Verdict.VERIFIED:
                raise ValueError(f"receipt verdict {receipt.verdict.value} cannot propagate")
            self.receipt_use_store.consume(receipt)
        except (KeyboardInterrupt, GeneratorExit):
            raise
        except BaseException as error:  # noqa: B036 - audit fail-closed gate errors.
            failure = AgentCallBoundary.failure("trust_gate", "propagate", error)
            context_id = (
                context.run_id
                if context.__class__ is RunContext
                else "invalid-run-context"
            )
            subject_digest = (
                receipt.digest
                if receipt.__class__ is DecisionReceipt
                else digest_value(
                    {
                        "invalid_receipt_type": type(receipt).__name__,
                        "operation": "propagate",
                    }
                )
            )
            self.audit_sink.append(
                context_id,
                AuditKind.PROPAGATION_BLOCKED,
                subject_digest,
                {"error_type": failure.error_type, "message": failure.message},
            )
            raise

        artifact = VerifiedArtifact(
            issuer=_ARTIFACT_ISSUER,
            run_id=context.run_id,
            claim_id=claim.claim_id,
            claim_digest=claim.digest,
            authorized_spec_digest=spec.digest,
            receipt_id=receipt.receipt_id,
            receipt_digest=receipt.digest,
            payload_type=claim.payload_type,
            payload=claim.payload,
        )
        self.audit_sink.append(
            context.run_id,
            AuditKind.ARTIFACT_PROPAGATED,
            receipt.digest,
            {"claim_id": claim.claim_id, "receipt_id": receipt.receipt_id},
        )
        return artifact

    @staticmethod
    def _require_valid_authority_decision(name: str, value: object) -> None:
        if value.__class__ is not bool:
            raise TypeError(f"{name} authority verifier must return bool")
        if not value:
            raise ValueError(f"{name} signature is invalid")

    def validate_decision_receipt(
        self,
        context: RunContext,
        spec: AuthorizedSpec,
        claim: ClaimEnvelope,
        evidence: EvidenceBundle,
        receipt: DecisionReceipt,
    ) -> None:
        if context.__class__ is not RunContext:
            raise TypeError("context must be RunContext")
        if spec.__class__ is not AuthorizedSpec:
            raise TypeError("spec must be AuthorizedSpec")
        if claim.__class__ is not ClaimEnvelope:
            raise TypeError("claim must be ClaimEnvelope")
        if evidence.__class__ is not EvidenceBundle:
            raise TypeError("evidence must be EvidenceBundle")
        if receipt.__class__ is not DecisionReceipt:
            raise TypeError("receipt must be DecisionReceipt")
        self._require_valid_authority_decision(
            "authorized specification",
            self.spec_authority.verify(spec),
        )
        if spec.proposal.task_id != context.task_id:
            raise ValueError("authorized specification belongs to a different task")
        if claim.run_id != context.run_id:
            raise ValueError("claim belongs to a different run")
        if receipt.run_id != context.run_id:
            raise ValueError("receipt belongs to a different run")
        if receipt.context_digest != context.digest:
            raise ValueError("receipt context digest mismatch")
        if receipt.authorized_spec_digest != spec.digest:
            raise ValueError("receipt authorized specification digest mismatch")
        if receipt.claim_digest != claim.digest:
            raise ValueError("receipt claim digest mismatch")
        self._require_valid_authority_decision(
            "evidence bundle",
            self.evidence_verifier.verify(evidence),
        )
        if evidence.verifier_id != self.evidence_verifier.verifier_id:
            raise ValueError("evidence bundle verifier identity mismatch")
        if evidence.run_id != context.run_id or evidence.context_digest != context.digest:
            raise ValueError("evidence bundle belongs to a different run")
        if evidence.authorized_spec_digest != spec.digest:
            raise ValueError("evidence bundle authorized specification digest mismatch")
        if evidence.claim_digest != claim.digest or evidence.attempt != claim.attempt:
            raise ValueError("evidence bundle claim binding mismatch")
        if receipt.evidence_bundle_digest != evidence.digest:
            raise ValueError("receipt evidence bundle digest mismatch")
        if receipt.verifier_id != evidence.verifier_id:
            raise ValueError("receipt verifier identity mismatch")
        if receipt.obligations != evidence.obligations:
            raise ValueError("receipt obligations differ from authenticated evidence")
        if receipt.observations != evidence.observations:
            raise ValueError("receipt observations differ from authenticated evidence")
        if receipt.attempt != claim.attempt:
            raise ValueError("receipt claim attempt mismatch")
        self._require_valid_authority_decision(
            "receipt",
            self.receipt_authority.verify(receipt),
        )
        decision = self.decision_policy.decide(
            spec,
            receipt.obligations,
            receipt.observations,
        )
        if decision.verdict is not receipt.verdict or decision.traces != receipt.traces:
            raise ValueError("receipt decision does not match deterministic policy")
