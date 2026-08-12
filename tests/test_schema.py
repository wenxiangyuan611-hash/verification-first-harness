import math
import unittest
from dataclasses import replace

from verification_harness.schema import (
    Claim,
    ComponentFailure,
    Evidence,
    Obligation,
    Spec,
    TestCase,
    VerificationReceipt,
    VerificationStatus,
    canonical_json,
)


class SchemaTests(unittest.TestCase):
    @staticmethod
    def spec() -> Spec:
        return Spec(
            task_id="identity",
            description="Return the input.",
            requirements=("Preserve the JSON value.",),
            test_cases=(TestCase("one", {"value": 1}, {"value": 1}),),
            entrypoint="identity",
        )

    def test_spec_digest_covers_all_contract_fields(self) -> None:
        spec = self.spec()
        self.assertNotEqual(spec.digest, replace(spec, description="Changed contract.").digest)
        self.assertNotEqual(spec.digest, replace(spec, requirements=("Changed.",)).digest)
        self.assertNotEqual(spec.digest, replace(spec, entrypoint="other").digest)

    def test_claim_digest_covers_identity_attempt_code_and_description(self) -> None:
        claim = Claim("worker-a", 1, "def identity(x): return x", "initial")
        self.assertNotEqual(claim.digest, replace(claim, worker_id="worker-b").digest)
        self.assertNotEqual(claim.digest, replace(claim, attempt=2).digest)
        self.assertNotEqual(claim.digest, replace(claim, description="repair").digest)

    def test_invalid_specs_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "task_id"):
            replace(self.spec(), task_id=" ")
        with self.assertRaisesRegex(ValueError, "description"):
            replace(self.spec(), description=" ")
        with self.assertRaisesRegex(ValueError, "requirements"):
            replace(self.spec(), requirements=())
        with self.assertRaisesRegex(ValueError, "at least one test"):
            Spec("task", "Description", ("Requirement",), (), "run")
        with self.assertRaisesRegex(ValueError, "unique"):
            Spec(
                "task",
                "Description",
                ("Requirement",),
                (TestCase("same", 1, 1), TestCase("same", 2, 2)),
                "run",
            )
        with self.assertRaisesRegex(ValueError, "identifier"):
            replace(self.spec(), entrypoint="not-valid!")
        with self.assertRaisesRegex(ValueError, "identifier"):
            replace(self.spec(), entrypoint="class")

    def test_invalid_test_case_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-empty"):
            TestCase(" ", 1, 1)
        with self.assertRaises(TypeError):
            TestCase("bad-json", object(), None)

    def test_invalid_claims_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "positive"):
            Claim("worker", 0, "pass", "invalid")
        with self.assertRaisesRegex(ValueError, "non-empty"):
            Claim("worker", 1, "  ", "invalid")

    def test_canonical_json_rejects_non_finite_numbers(self) -> None:
        with self.assertRaises(ValueError):
            canonical_json({"value": math.nan})
        with self.assertRaises(TypeError):
            canonical_json(object())
        with self.assertRaises(TypeError):
            canonical_json(Spec)

    def test_component_failure_and_evidence_validate_their_shape(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-empty"):
            ComponentFailure("critic", "challenge", "ValueError", " ")
        with self.assertRaisesRegex(ValueError, "obligation_id"):
            Evidence(" ", VerificationStatus.FAILED, "", "")
        with self.assertRaisesRegex(TypeError, "VerificationStatus"):
            Evidence("TEST", "FAILED", "", "")  # type: ignore[arg-type]

    def test_receipt_completeness_and_finality_are_explicit(self) -> None:
        obligation = Obligation("TEST", "TEST_EXECUTION", "Run tests.")
        incomplete = VerificationReceipt(
            "run",
            "claim",
            "spec",
            1,
            "2.0",
            (obligation,),
            (),
            "signature",
        )
        self.assertFalse(incomplete.is_complete)
        self.assertFalse(incomplete.is_final)
        self.assertFalse(incomplete.is_passed)

        pending = VerificationReceipt(
            "run",
            "claim",
            "spec",
            1,
            "2.0",
            (obligation,),
            (Evidence("TEST", VerificationStatus.PENDING, "pending", "pass"),),
            "signature",
        )
        self.assertTrue(pending.is_complete)
        self.assertFalse(pending.is_final)
        self.assertFalse(pending.is_passed)

        with self.assertRaisesRegex(TypeError, "tuple of Obligation"):
            VerificationReceipt(
                "run",
                "claim",
                "spec",
                1,
                "2.0",
                [obligation],  # type: ignore[arg-type]
                (),
                "signature",
            )


if __name__ == "__main__":
    unittest.main()
