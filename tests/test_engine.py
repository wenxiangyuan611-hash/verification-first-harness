import unittest

from verification_harness.agents import CriticAgent, PlannerAgent, VerifierAgent, WorkerAgent
from verification_harness.audit import AuditKind
from verification_harness.engine import TrustGateEngine
from verification_harness.gate import VerifiedArtifact
from verification_harness.protocol import Verdict
from verification_harness.receipts import DecisionReceipt
from verification_harness.schema import Spec, TestCase


class ChangedContractPlanner(PlannerAgent):
    """Return a valid but unauthorized contract instead of the registered one."""

    def create_spec(self, task_id: str) -> Spec:
        registered = super().create_spec(task_id)
        return Spec(
            task_id=registered.task_id,
            description="Planner silently changed the authorized contract.",
            requirements=("Return input minus one.",),
            test_cases=(TestCase("changed", 1, 0),),
            entrypoint=registered.entrypoint,
        )


class EngineTests(unittest.TestCase):
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

    def test_failure_repair_and_reverification_is_normal_control_flow(self) -> None:
        worker = WorkerAgent(
            faulty_implementations={"add_one": "def add_one(value): return value"},
            repaired_implementations={"add_one": "def add_one(value): return value + 1"},
        )
        engine = TrustGateEngine(
            self.planner,
            worker,
            CriticAgent(),
            self.verifier,
            max_repairs=1,
        )
        result = engine.run("add_one")
        self.assertEqual("APPROVED", result["status"])
        self.assertEqual(2, result["attempts"])
        self.assertEqual("PASSED", result["final_state"])
        self.assertEqual(Verdict.VERIFIED.value, result["verdict"])
        self.assertIsInstance(result["artifact"], VerifiedArtifact)
        self.assertEqual(
            "def add_one(value): return value + 1",
            result["artifact"].payload["code"],
        )
        self.assertIsInstance(result["decision_receipt"], DecisionReceipt)
        events = engine.kernel.audit_sink.snapshot(result["context"].run_id)
        claims = [event for event in events if event.kind is AuditKind.CLAIM_QUARANTINED]
        self.assertEqual(2, len(claims))
        self.assertEqual([], claims[0].details["parent_claim_ids"])
        self.assertEqual(
            [claims[0].details["claim_id"]],
            claims[1].details["parent_claim_ids"],
        )

    def test_persistent_failure_is_rejected(self) -> None:
        worker = WorkerAgent(
            faulty_implementations={"add_one": "def add_one(value): return value"},
            repaired_implementations={"add_one": "def add_one(value): return value"},
        )
        result = TrustGateEngine(
            self.planner,
            worker,
            CriticAgent(),
            self.verifier,
            max_repairs=1,
        ).run("add_one")
        self.assertEqual("REJECTED", result["status"])
        self.assertEqual(2, result["attempts"])
        self.assertEqual(Verdict.REJECTED.value, result["verdict"])
        self.assertIsNone(result["artifact"])
        self.assertIsInstance(result["decision_receipt"], DecisionReceipt)

    def test_negative_repair_limit_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "zero or greater"):
            TrustGateEngine(
                self.planner,
                WorkerAgent(),
                CriticAgent(),
                self.verifier,
                max_repairs=-1,
            )

    def test_unknown_task_is_rejected_before_work_starts(self) -> None:
        engine = TrustGateEngine(
            self.planner,
            WorkerAgent(),
            CriticAgent(),
            self.verifier,
        )
        result = engine.run("missing")
        self.assertEqual("REJECTED", result["status"])
        self.assertEqual(0, result["attempts"])
        self.assertEqual("planner", result["failure"].component)
        self.assertIn("no knowledge", result["failure"].message)

    def test_default_worker_stub_is_challenged_and_rejected(self) -> None:
        result = TrustGateEngine(
            self.planner,
            WorkerAgent(),
            CriticAgent(),
            self.verifier,
            max_repairs=0,
        ).run("add_one")
        self.assertEqual("REJECTED", result["status"])
        obligation_ids = {item.obligation_id for item in result["receipt"].evidence}
        self.assertIn("CRITIC_NO_STUB", obligation_ids)
        self.assertIsNone(result["artifact"])

    def test_planner_cannot_replace_the_registered_contract(self) -> None:
        planner = ChangedContractPlanner()
        planner.register_task(
            "add_one",
            "Increment an integer.",
            ("Return input plus one.",),
            (TestCase("one", 1, 2),),
            "add_one",
        )
        result = TrustGateEngine(
            planner,
            WorkerAgent(),
            CriticAgent(),
            self.verifier,
        ).run("add_one")
        self.assertEqual("REJECTED", result["status"])
        self.assertEqual(0, result["attempts"])
        self.assertEqual("spec_authority", result["failure"].component)
        self.assertIsNone(result["artifact"])


if __name__ == "__main__":
    unittest.main()
