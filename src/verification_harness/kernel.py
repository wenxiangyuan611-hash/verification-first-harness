"""Generic trust-kernel composition over untrusted verification observations."""

from __future__ import annotations

from dataclasses import dataclass

from verification_harness.audit import AuditKind, AuditSink, InMemoryAuditSink
from verification_harness.authority import (
    EvidenceVerifier,
    EvidenceVerifierView,
    ReceiptAuthority,
    SpecAuthority,
)
from verification_harness.decision import DecisionPolicy
from verification_harness.evidence import EvidenceBundle
from verification_harness.gate import (
    InMemoryReceiptUseStore,
    ReceiptUseStore,
    TrustGate,
    VerifiedArtifact,
)
from verification_harness.protocol import (
    AuthorizedSpec,
    ClaimEnvelope,
    RunContext,
    SpecProposal,
    Verdict,
)
from verification_harness.receipts import DecisionReceipt


@dataclass(frozen=True)
class KernelDecision:
    """A quarantined decision; only ``artifact`` carries propagation authority."""

    verdict: str
    receipt: DecisionReceipt
    artifact: VerifiedArtifact | None


class VerificationKernel:
    """Authorize specs, decide evidence, sign receipts, and gate propagation."""

    def __init__(
        self,
        spec_authority: SpecAuthority,
        evidence_verifier: EvidenceVerifier,
        receipt_authority: ReceiptAuthority,
        decision_policy: DecisionPolicy | None = None,
        receipt_use_store: ReceiptUseStore | None = None,
        audit_sink: AuditSink | None = None,
    ) -> None:
        self.spec_authority = spec_authority
        self.evidence_verifier = EvidenceVerifierView(evidence_verifier)
        self.receipt_authority = receipt_authority
        self.decision_policy = (
            DecisionPolicy() if decision_policy is None else decision_policy
        )
        self.receipt_use_store = (
            InMemoryReceiptUseStore() if receipt_use_store is None else receipt_use_store
        )
        self.audit_sink = InMemoryAuditSink() if audit_sink is None else audit_sink
        self.trust_gate = TrustGate(
            spec_authority=self.spec_authority,
            evidence_verifier=self.evidence_verifier,
            receipt_authority=self.receipt_authority,
            decision_policy=self.decision_policy,
            receipt_use_store=self.receipt_use_store,
            audit_sink=self.audit_sink,
        )

    def open_run(self, task_id: str) -> RunContext:
        context = RunContext.create(task_id)
        self.audit_sink.append(
            context.run_id,
            AuditKind.RUN_OPENED,
            context.digest,
            {"task_id": task_id},
        )
        return context

    def authorize(self, proposal: SpecProposal) -> AuthorizedSpec:
        if proposal.__class__ is not SpecProposal:
            raise TypeError("proposal must be SpecProposal")
        spec = self.spec_authority.authorize(proposal)
        if spec.__class__ is not AuthorizedSpec:
            raise TypeError("specification authority must return AuthorizedSpec")
        if spec.proposal != proposal:
            raise ValueError("specification authority changed the proposed contract")
        verified = self.spec_authority.verify(spec)
        if verified.__class__ is not bool:
            raise TypeError("specification authority verifier must return bool")
        if not verified:
            raise ValueError("authorized specification signature is invalid")
        return spec

    def evaluate(
        self,
        context: RunContext,
        spec: AuthorizedSpec,
        claim: ClaimEnvelope,
        evidence: EvidenceBundle,
        *,
        propagate: bool = True,
    ) -> KernelDecision:
        if context.__class__ is not RunContext:
            raise TypeError("context must be RunContext")
        if spec.__class__ is not AuthorizedSpec:
            raise TypeError("spec must be AuthorizedSpec")
        if claim.__class__ is not ClaimEnvelope:
            raise TypeError("claim must be ClaimEnvelope")
        if evidence.__class__ is not EvidenceBundle:
            raise TypeError("evidence must be EvidenceBundle")
        if claim.run_id != context.run_id:
            raise ValueError("claim belongs to a different run")
        if spec.proposal.task_id != context.task_id:
            raise ValueError("authorized specification belongs to a different task")
        spec_verified = self.spec_authority.verify(spec)
        if spec_verified.__class__ is not bool:
            raise TypeError("specification authority verifier must return bool")
        if not spec_verified:
            raise ValueError("authorized specification signature is invalid")
        evidence_verified = self.evidence_verifier.verify(evidence)
        if evidence_verified.__class__ is not bool:
            raise TypeError("evidence authority verifier must return bool")
        if not evidence_verified:
            raise ValueError("evidence bundle signature is invalid")
        if evidence.verifier_id != self.evidence_verifier.verifier_id:
            raise ValueError("evidence bundle verifier identity mismatch")
        if evidence.run_id != context.run_id or evidence.context_digest != context.digest:
            raise ValueError("evidence bundle belongs to a different run")
        if evidence.authorized_spec_digest != spec.digest:
            raise ValueError("evidence bundle authorized specification digest mismatch")
        if evidence.claim_digest != claim.digest or evidence.attempt != claim.attempt:
            raise ValueError("evidence bundle claim binding mismatch")

        self.audit_sink.append(
            context.run_id,
            AuditKind.CLAIM_QUARANTINED,
            claim.digest,
            {
                "claim_id": claim.claim_id,
                "role": claim.role.value,
                "producer_id": claim.producer_id,
                "attempt": claim.attempt,
                "parent_claim_ids": list(claim.parent_claim_ids),
            },
        )
        decision = self.decision_policy.decide(
            spec,
            evidence.obligations,
            evidence.observations,
        )
        receipt = self.receipt_authority.issue(
            context=context,
            spec=spec,
            claim=claim,
            evidence=evidence,
            decision=decision,
        )
        if receipt.__class__ is not DecisionReceipt:
            raise TypeError("receipt authority must return DecisionReceipt")
        self.trust_gate.validate_decision_receipt(
            context,
            spec,
            claim,
            evidence,
            receipt,
        )
        self.audit_sink.append(
            context.run_id,
            AuditKind.DECISION_ISSUED,
            receipt.digest,
            {
                "receipt_id": receipt.receipt_id,
                "verdict": receipt.verdict.value,
            },
        )
        artifact = None
        if propagate and receipt.verdict is Verdict.VERIFIED:
            artifact = self.trust_gate.propagate(context, spec, claim, evidence, receipt)
        elif propagate:
            self.audit_sink.append(
                context.run_id,
                AuditKind.PROPAGATION_BLOCKED,
                receipt.digest,
                {
                    "receipt_id": receipt.receipt_id,
                    "verdict": receipt.verdict.value,
                    "reason": "verdict did not authorize propagation",
                },
            )
        return KernelDecision(
            verdict=receipt.verdict.value,
            receipt=receipt,
            artifact=artifact,
        )
