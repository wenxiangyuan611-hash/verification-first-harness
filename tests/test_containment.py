import unittest
from dataclasses import replace

from verification_harness.agents import CriticAgent, PlannerAgent, VerifierAgent, WorkerAgent
from verification_harness.engine import TrustGateEngine
from verification_harness.policy import ChallengePolicy
from verification_harness.schema import Claim, Obligation, Spec, TestCase, VerificationReceipt


class ExplodingCritic:
    def challenge(self, claim: Claim, spec: Spec) -> tuple[Obligation, ...]:
        raise SystemExit("critic attempted to terminate the controller")


class UnreadableError(Exception):
    def __str__(self) -> str:
        raise RuntimeError("message formatting failed")


class UnreadableErrorCritic:
    def challenge(self, claim: Claim, spec: Spec) -> tuple[Obligation, ...]:
        raise UnreadableError


class WrongShapeCritic:
    def challenge(self, claim: Claim, spec: Spec) -> tuple[Obligation, ...]:
        return []  # type: ignore[return-value]


class WrongItemCritic:
    def challenge(self, claim: Claim, spec: Spec) -> tuple[Obligation, ...]:
        return (object(),)  # type: ignore[return-value]


class ReservedIdCritic:
    def challenge(self, claim: Claim, spec: Spec) -> tuple[Obligation, ...]:
        return (
            Obligation(
                "HARNESS_TEST_PASS",
                "FORBIDDEN_TEXT",
                "Attempt to replace the baseline.",
                {"text": "pass"},
            ),
        )


class WrongAttemptWorker(WorkerAgent):
    def propose(self, attempt: int, spec: Spec) -> Claim:
        return Claim(self.agent_id, attempt + 1, "def add_one(value): return value + 1", "bad")


class MutatingWorker(WorkerAgent):
    def propose(self, attempt: int, spec: Spec) -> Claim:
        object.__setattr__(spec, "entrypoint", "evil")
        return Claim(self.agent_id, attempt, "def evil(value): return value + 1", "mutated")


class MutatingCritic:
    def challenge(self, claim: Claim, spec: Spec) -> tuple[Obligation, ...]:
        object.__setattr__(spec, "entrypoint", "evil")
        return ()


class ExplodingRepairWorker(WorkerAgent):
    def repair(self, attempt: int, spec: Spec, receipt: VerificationReceipt) -> Claim:
        raise TimeoutError("provider timed out during repair")


class MutatingRepairWorker(WorkerAgent):
    def repair(self, attempt: int, spec: Spec, receipt: VerificationReceipt) -> Claim:
        object.__setattr__(spec, "entrypoint", "evil")
        receipt.obligations[0].payload["tampered"] = True
        return Claim(self.agent_id, attempt, "def add_one(value): return value + 1", "repaired")


class ForgedReceiptVerifier:
    PROTOCOL_VERSION = VerifierAgent.PROTOCOL_VERSION

    def __init__(self, delegate: VerifierAgent) -> None:
        self.delegate = delegate

    def verify(
        self,
        claim: Claim,
        spec: Spec,
        obligations: tuple[Obligation, ...],
    ) -> VerificationReceipt:
        receipt = self.delegate.verify(claim, spec, obligations)
        return replace(receipt, signature="forged")

    def verify_receipt_signature(self, receipt: VerificationReceipt) -> bool:
        return self.delegate.verify_receipt_signature(receipt)


class InvalidSignatureDecisionVerifier(ForgedReceiptVerifier):
    def verify(
        self,
        claim: Claim,
        spec: Spec,
        obligations: tuple[Obligation, ...],
    ) -> VerificationReceipt:
        return self.delegate.verify(claim, spec, obligations)

    def verify_receipt_signature(self, receipt: VerificationReceipt) -> bool:
        return "yes"  # type: ignore[return-value]


class WrongShapeVerifier(ForgedReceiptVerifier):
    def verify(
        self,
        claim: Claim,
        spec: Spec,
        obligations: tuple[Obligation, ...],
    ) -> VerificationReceipt:
        return object()  # type: ignore[return-value]


class FlakySignatureVerifier(ForgedReceiptVerifier):
    def __init__(self, delegate: VerifierAgent) -> None:
        super().__init__(delegate)
        self.signature_checks = 0

    def verify(
        self,
        claim: Claim,
        spec: Spec,
        obligations: tuple[Obligation, ...],
    ) -> VerificationReceipt:
        return self.delegate.verify(claim, spec, obligations)

    def verify_receipt_signature(self, receipt: VerificationReceipt) -> bool:
        self.signature_checks += 1
        return self.signature_checks == 1


class ExplodingChallengePolicy(ChallengePolicy):
    def authorize(
        self,
        baseline: tuple[Obligation, ...],
        proposals: tuple[Obligation, ...],
    ) -> tuple[Obligation, ...]:
        raise SystemExit("policy terminated")


class ContainmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.planner = PlannerAgent()
        self.planner.register_task(
            "add_one",
            "Increment an integer.",
            ("Return input plus one.",),
            (TestCase("one", 1, 2),),
            "add_one",
        )
        self.verifier = VerifierAgent(signing_key=b"x" * 32, execution_timeout_seconds=0.5)

    def engine(
        self,
        *,
        worker: WorkerAgent | None = None,
        critic: object | None = None,
        verifier: object | None = None,
        max_repairs: int = 0,
        challenge_policy: ChallengePolicy | None = None,
    ) -> TrustGateEngine:
        return TrustGateEngine(
            self.planner,
            worker or WorkerAgent(
                faulty_implementations={"add_one": "def add_one(value): return value"}
            ),
            critic or CriticAgent(),  # type: ignore[arg-type]
            verifier or self.verifier,  # type: ignore[arg-type]
            max_repairs=max_repairs,
            challenge_policy=challenge_policy,
        )

    def test_system_exit_from_critic_is_contained(self) -> None:
        result = self.engine(critic=ExplodingCritic()).run("add_one")
        self.assertEqual("REJECTED", result["status"])
        self.assertEqual("critic", result["failure"].component)
        self.assertEqual("SystemExit", result["failure"].error_type)

    def test_exception_with_unreadable_message_is_contained(self) -> None:
        result = self.engine(critic=UnreadableErrorCritic()).run("add_one")
        self.assertEqual("REJECTED", result["status"])
        self.assertEqual("UnreadableError", result["failure"].error_type)
        self.assertIn("unreadable message", result["failure"].message)

    def test_wrong_critic_shape_is_rejected_before_verification(self) -> None:
        result = self.engine(critic=WrongShapeCritic()).run("add_one")
        self.assertEqual("REJECTED", result["status"])
        self.assertEqual("TypeError", result["failure"].error_type)
        self.assertIn("expected tuple", result["failure"].message)

    def test_wrong_critic_item_is_rejected_by_policy(self) -> None:
        result = self.engine(critic=WrongItemCritic()).run("add_one")
        self.assertEqual("REJECTED", result["status"])
        self.assertEqual("challenge_policy", result["failure"].operation)
        self.assertIn("must be Obligation", result["failure"].message)

    def test_unexpected_policy_termination_is_contained(self) -> None:
        result = self.engine(challenge_policy=ExplodingChallengePolicy()).run("add_one")
        self.assertEqual("REJECTED", result["status"])
        self.assertEqual("SystemExit", result["failure"].error_type)

    def test_critic_cannot_replace_a_baseline_obligation(self) -> None:
        result = self.engine(critic=ReservedIdCritic()).run("add_one")
        self.assertEqual("REJECTED", result["status"])
        self.assertEqual("challenge_policy", result["failure"].operation)
        self.assertIn("duplicate", result["failure"].message)

    def test_worker_claim_attempt_mismatch_is_contained(self) -> None:
        result = self.engine(worker=WrongAttemptWorker()).run("add_one")
        self.assertEqual("REJECTED", result["status"])
        self.assertEqual("worker", result["failure"].component)
        self.assertIn("expected 1", result["failure"].message)

    def test_worker_cannot_mutate_the_engine_owned_spec(self) -> None:
        result = self.engine(worker=MutatingWorker()).run("add_one")
        self.assertEqual("REJECTED", result["status"])
        self.assertEqual(self.planner.create_spec("add_one").digest, result["receipt"].spec_digest)

    def test_critic_receives_a_detached_spec_snapshot(self) -> None:
        worker = WorkerAgent(
            faulty_implementations={"add_one": "def add_one(value): return value + 1"}
        )
        result = self.engine(worker=worker, critic=MutatingCritic()).run("add_one")
        self.assertEqual("APPROVED", result["status"])

    def test_worker_repair_timeout_is_contained(self) -> None:
        worker = ExplodingRepairWorker(
            faulty_implementations={"add_one": "def add_one(value): return value"}
        )
        result = self.engine(worker=worker, max_repairs=1).run("add_one")
        self.assertEqual("REJECTED", result["status"])
        self.assertEqual("repair", result["failure"].operation)
        self.assertEqual("TimeoutError", result["failure"].error_type)

    def test_repair_receives_detached_spec_and_receipt_snapshots(self) -> None:
        worker = MutatingRepairWorker(
            faulty_implementations={"add_one": "def add_one(value): return value"}
        )
        result = self.engine(worker=worker, max_repairs=1).run("add_one")
        self.assertEqual("APPROVED", result["status"])
        self.assertNotIn("tampered", result["receipt"].obligations[0].payload)

    def test_forged_failed_receipt_never_reaches_repair(self) -> None:
        result = self.engine(
            verifier=ForgedReceiptVerifier(self.verifier),
            max_repairs=1,
        ).run("add_one")
        self.assertEqual("REJECTED", result["status"])
        self.assertEqual(1, result["attempts"])
        self.assertEqual("receipt_validation", result["failure"].operation)
        self.assertIn("invalid verifier signature", result["failure"].message)

    def test_non_boolean_signature_decision_fails_closed(self) -> None:
        result = self.engine(
            verifier=InvalidSignatureDecisionVerifier(self.verifier),
        ).run("add_one")
        self.assertEqual("REJECTED", result["status"])
        self.assertEqual("TypeError", result["failure"].error_type)
        self.assertIn("must return bool", result["failure"].message)

    def test_wrong_verifier_shape_is_contained(self) -> None:
        result = self.engine(verifier=WrongShapeVerifier(self.verifier)).run("add_one")
        self.assertEqual("REJECTED", result["status"])
        self.assertEqual("verifier", result["failure"].component)
        self.assertIn("expected VerificationReceipt", result["failure"].message)

    def test_propagation_revalidates_the_receipt(self) -> None:
        worker = WorkerAgent(
            faulty_implementations={"add_one": "def add_one(value): return value + 1"}
        )
        verifier = FlakySignatureVerifier(self.verifier)
        result = self.engine(worker=worker, verifier=verifier).run("add_one")
        self.assertEqual("REJECTED", result["status"])
        self.assertEqual("trust_gate", result["failure"].component)
        self.assertEqual(2, verifier.signature_checks)


if __name__ == "__main__":
    unittest.main()
