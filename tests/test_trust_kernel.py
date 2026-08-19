import json
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

from verification_harness.audit import InMemoryAuditSink
from verification_harness.authority import (
    HMACEvidenceAuthority,
    HMACReceiptAuthority,
    HMACSpecAuthority,
)
from verification_harness.decision import (
    DecisionPolicy,
    Observation,
    VerificationObligation,
)
from verification_harness.evidence import EvidenceBundle
from verification_harness.gate import ReplayError, VerifiedArtifact
from verification_harness.kernel import VerificationKernel
from verification_harness.protocol import (
    AcceptanceCriterion,
    AgentRole,
    ClaimEnvelope,
    EvidenceStatus,
    RunContext,
    SpecProposal,
    Verdict,
)
from verification_harness.receipts import DecisionReceipt


class TrustKernelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = InMemoryAuditSink()
        self.spec_authority = HMACSpecAuthority(
            "spec-authority",
            b"s" * 32,
            lambda proposal: proposal.task_id == "task-1",
        )
        self.evidence_authority = HMACEvidenceAuthority("verifier-1", b"e" * 32)
        self.receipt_authority = HMACReceiptAuthority("receipt-authority", b"r" * 32)
        self.kernel = VerificationKernel(
            spec_authority=self.spec_authority,
            evidence_verifier=self.evidence_authority,
            receipt_authority=self.receipt_authority,
            audit_sink=self.audit,
        )
        self.context = RunContext(
            run_id="run-1",
            task_id="task-1",
            nonce="nonce-1",
        )
        proposal = SpecProposal(
            proposal_id="proposal-1",
            task_id="task-1",
            proposer_id="planner-1",
            domain="generic",
            criteria=(
                AcceptanceCriterion("correct", "Result must be correct."),
                AcceptanceCriterion("safe", "Result must satisfy the safety policy."),
            ),
            payload={"goal": "produce a bounded result"},
        )
        self.spec = self.kernel.authorize(proposal)
        self.claim = ClaimEnvelope(
            claim_id="claim-1",
            run_id=self.context.run_id,
            role=AgentRole.WORKER,
            producer_id="worker-1",
            payload_type="application/json",
            payload={"answer": 42},
        )
        self.obligations = (
            VerificationObligation(
                id="correct-check",
                kind="deterministic",
                description="Check correctness.",
                criterion_ids=("correct",),
            ),
            VerificationObligation(
                id="safe-check",
                kind="policy",
                description="Check safety.",
                criterion_ids=("safe",),
            ),
        )

    def observations(
        self,
        first: EvidenceStatus = EvidenceStatus.PASSED,
        second: EvidenceStatus = EvidenceStatus.PASSED,
    ) -> tuple[Observation, ...]:
        return (
            Observation("correct-check", first, "correct", "correct"),
            Observation("safe-check", second, "safe", "safe"),
        )

    def evidence(
        self,
        observations: tuple[Observation, ...] | None = None,
        obligations: tuple[VerificationObligation, ...] | None = None,
    ) -> EvidenceBundle:
        return self.evidence_authority.issue(
            self.context,
            self.spec,
            self.claim,
            obligations or self.obligations,
            observations or self.observations(),
        )

    def test_only_verified_decision_issues_an_artifact(self) -> None:
        self.assertFalse(hasattr(self.kernel.evidence_verifier, "issue"))
        result = self.kernel.evaluate(
            self.context,
            self.spec,
            self.claim,
            self.evidence(),
        )
        self.assertEqual(Verdict.VERIFIED.value, result.verdict)
        self.assertIsInstance(result.artifact, VerifiedArtifact)
        self.assertEqual({"answer": 42}, result.artifact.payload)
        self.assertTrue(self.receipt_authority.verify(result.receipt))
        self.assertTrue(self.audit.verify_chain())

    def test_non_verified_verdicts_never_carry_claim_payload(self) -> None:
        cases = (
            (EvidenceStatus.FAILED, Verdict.REJECTED),
            (EvidenceStatus.INCONCLUSIVE, Verdict.INCONCLUSIVE),
            (EvidenceStatus.ERROR, Verdict.ERROR),
        )
        for status, verdict in cases:
            with self.subTest(status=status):
                result = self.kernel.evaluate(
                    self.context,
                    self.spec,
                    self.claim,
                    self.evidence(self.observations(first=status)),
                )
                self.assertEqual(verdict.value, result.verdict)
                self.assertIsNone(result.artifact)
                self.assertFalse(hasattr(result, "claim"))

    def test_artifact_cannot_be_constructed_outside_trust_gate(self) -> None:
        with self.assertRaisesRegex(PermissionError, "TrustGate"):
            VerifiedArtifact(
                issuer=object(),
                run_id="run-1",
                claim_id="claim-1",
                claim_digest="digest",
                authorized_spec_digest="spec",
                receipt_id="receipt",
                receipt_digest="receipt-digest",
                payload_type="text/plain",
                payload="forged",
            )

    def test_receipt_is_single_use_and_cross_run_reuse_is_blocked(self) -> None:
        evidence = self.evidence()
        result = self.kernel.evaluate(
            self.context,
            self.spec,
            self.claim,
            evidence,
        )
        with self.assertRaisesRegex(ReplayError, "already been consumed"):
            self.kernel.trust_gate.propagate(
                self.context,
                self.spec,
                self.claim,
                evidence,
                result.receipt,
            )
        other_context = RunContext(run_id="run-2", task_id="task-1", nonce="nonce-2")
        with self.assertRaisesRegex(ValueError, "different run"):
            self.kernel.trust_gate.propagate(
                other_context,
                self.spec,
                self.claim,
                evidence,
                result.receipt,
            )

    def test_concurrent_receipt_consumption_issues_exactly_one_artifact(self) -> None:
        evidence = self.evidence()
        result = self.kernel.evaluate(
            self.context,
            self.spec,
            self.claim,
            evidence,
            propagate=False,
        )

        def propagate() -> str:
            try:
                self.kernel.trust_gate.propagate(
                    self.context,
                    self.spec,
                    self.claim,
                    evidence,
                    result.receipt,
                )
            except ReplayError:
                return "REPLAY"
            return "ARTIFACT"

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = tuple(executor.map(lambda _: propagate(), range(2)))
        self.assertEqual(1, outcomes.count("ARTIFACT"))
        self.assertEqual(1, outcomes.count("REPLAY"))
        self.assertTrue(self.audit.verify_chain())

    def test_non_boolean_authority_verification_fails_closed(self) -> None:
        original_verify = self.kernel.evidence_verifier._verify
        self.kernel.evidence_verifier._verify = lambda bundle: 1  # type: ignore[assignment]
        try:
            with self.assertRaisesRegex(TypeError, "must return bool"):
                self.kernel.evaluate(
                    self.context,
                    self.spec,
                    self.claim,
                    self.evidence(),
                )
        finally:
            self.kernel.evidence_verifier._verify = original_verify

    def test_tampered_receipt_and_forged_verdict_fail_closed(self) -> None:
        evidence = self.evidence(self.observations(first=EvidenceStatus.FAILED))
        result = self.kernel.evaluate(
            self.context,
            self.spec,
            self.claim,
            evidence,
            propagate=False,
        )
        forged = replace(result.receipt, verdict=Verdict.VERIFIED)
        with self.assertRaisesRegex(ValueError, "signature"):
            self.kernel.trust_gate.propagate(
                self.context,
                self.spec,
                self.claim,
                evidence,
                forged,
            )

    def test_malformed_receipt_is_blocked_without_breaking_audit(self) -> None:
        evidence = self.evidence()
        with self.assertRaisesRegex(TypeError, "receipt must be DecisionReceipt"):
            self.kernel.trust_gate.propagate(
                self.context,
                self.spec,
                self.claim,
                evidence,
                object(),  # type: ignore[arg-type]
            )
        self.assertEqual("PROPAGATION_BLOCKED", self.audit.events[-1].kind.value)
        self.assertTrue(self.audit.verify_chain())

    def test_forged_or_cross_claim_evidence_is_rejected_before_decision(self) -> None:
        evidence = self.evidence()
        forged = replace(evidence, signature="f" * 64)
        with self.assertRaisesRegex(ValueError, "evidence bundle signature"):
            self.kernel.evaluate(self.context, self.spec, self.claim, forged)

        other_claim = ClaimEnvelope(
            claim_id="claim-2",
            run_id=self.context.run_id,
            role=AgentRole.WORKER,
            producer_id="worker-2",
            payload_type="application/json",
            payload={"answer": "different"},
        )
        with self.assertRaisesRegex(ValueError, "claim binding"):
            self.kernel.evaluate(self.context, self.spec, other_claim, evidence)

    def test_receipt_json_round_trip_is_stable_and_tamper_evident(self) -> None:
        result = self.kernel.evaluate(
            self.context,
            self.spec,
            self.claim,
            self.evidence(),
            propagate=False,
        )
        raw = result.receipt.to_json()
        restored = DecisionReceipt.from_json(raw)
        self.assertEqual(result.receipt, restored)
        self.assertTrue(self.receipt_authority.verify(restored))
        changed = json.loads(raw)
        changed["observations"][0]["observed"] = "forged"
        tampered = DecisionReceipt.from_json(json.dumps(changed))
        self.assertFalse(self.receipt_authority.verify(tampered))
        duplicate = '{"receipt_id":"duplicate",' + raw[1:]
        with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
            DecisionReceipt.from_json(duplicate)

    def test_evidence_json_round_trip_is_stable_and_tamper_evident(self) -> None:
        evidence = self.evidence()
        restored = EvidenceBundle.from_json(evidence.to_json())
        self.assertEqual(evidence, restored)
        self.assertTrue(self.evidence_authority.verify(restored))
        changed = json.loads(evidence.to_json())
        changed["observations"][0]["observed"] = "forged"
        tampered = EvidenceBundle.from_json(json.dumps(changed))
        self.assertFalse(self.evidence_authority.verify(tampered))
        duplicate = '{"bundle_id":"duplicate",' + evidence.to_json()[1:]
        with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
            EvidenceBundle.from_json(duplicate)

    def test_signed_rejection_is_validated_and_audited_without_propagation(self) -> None:
        result = self.kernel.evaluate(
            self.context,
            self.spec,
            self.claim,
            self.evidence(self.observations(first=EvidenceStatus.FAILED)),
        )
        self.assertEqual(Verdict.REJECTED.value, result.verdict)
        self.assertIsNone(result.artifact)
        self.assertTrue(self.receipt_authority.verify(result.receipt))
        self.assertTrue(self.audit.verify_chain())
        self.assertEqual(
            "PROPAGATION_BLOCKED",
            self.audit.events[-1].kind.value,
        )

    def test_artifact_payload_is_detached_and_self_describing(self) -> None:
        result = self.kernel.evaluate(
            self.context,
            self.spec,
            self.claim,
            self.evidence(),
        )
        if result.artifact is None:
            self.fail("VERIFIED decision did not issue an artifact")
        exposed = result.artifact.payload
        exposed["answer"] = "mutated"
        self.assertEqual({"answer": 42}, result.artifact.payload)
        self.assertEqual(result.artifact.claim_digest, result.artifact.to_dict()["claim_digest"])

    def test_incomplete_criterion_trace_is_rejected_before_signing(self) -> None:
        incomplete = (self.obligations[0],)
        observations = (self.observations()[0],)
        with self.assertRaisesRegex(ValueError, "lack verification obligations"):
            self.kernel.evaluate(
                self.context,
                self.spec,
                self.claim,
                self.evidence(observations, incomplete),
            )

    def test_observation_order_and_unknown_criteria_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "ordered obligations"):
            DecisionPolicy().decide(
                self.spec,
                self.obligations,
                tuple(reversed(self.observations())),
            )
        bad_obligation = VerificationObligation(
            id="bad",
            kind="deterministic",
            description="Unknown mapping.",
            criterion_ids=("missing",),
        )
        with self.assertRaisesRegex(ValueError, "unknown criteria"):
            DecisionPolicy().decide(
                self.spec,
                (bad_obligation,),
                (Observation("bad", EvidenceStatus.PASSED, "ok", "ok"),),
            )

    def test_falsy_obligation_payload_is_not_rewritten(self) -> None:
        for payload in (False, 0, ""):
            with self.subTest(payload=payload):
                obligation = VerificationObligation(
                    id="falsy",
                    kind="deterministic",
                    description="Preserve a JSON value exactly.",
                    criterion_ids=("correct",),
                    payload=payload,
                )
                self.assertEqual(payload, obligation.payload)


if __name__ == "__main__":
    unittest.main()
