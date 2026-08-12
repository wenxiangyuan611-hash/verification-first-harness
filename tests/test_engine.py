import unittest

from verification_harness.agents import CriticAgent, PlannerAgent, VerifierAgent, WorkerAgent
from verification_harness.engine import TrustGateEngine
from verification_harness.schema import TestCase


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
        result = TrustGateEngine(
            self.planner,
            worker,
            CriticAgent(),
            self.verifier,
            max_repairs=1,
        ).run("add_one")
        self.assertEqual("APPROVED", result["status"])
        self.assertEqual(2, result["attempts"])
        self.assertEqual("PASSED", result["final_state"])

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
        with self.assertRaisesRegex(ValueError, "no knowledge"):
            engine.run("missing")

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


if __name__ == "__main__":
    unittest.main()
