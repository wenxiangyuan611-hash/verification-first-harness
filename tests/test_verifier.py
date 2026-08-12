import unittest
from dataclasses import replace

from verification_harness.agents.verifier import VerifierAgent
from verification_harness.engine import TrustGate
from verification_harness.schema import (
    Claim,
    Evidence,
    Obligation,
    Spec,
    TestCase,
    VerificationStatus,
)


class VerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = VerifierAgent(
            signing_key=b"x" * 32,
            execution_timeout_seconds=0.4,
        )
        self.spec = Spec(
            "add_one",
            "Increment an integer.",
            ("Return input plus one.",),
            (TestCase("one", 1, 2), TestCase("negative", -2, -1)),
            "add_one",
        )
        self.obligations = (Obligation("TEST", "TEST_EXECUTION", "Run test cases."),)

    def test_valid_candidate_produces_authentic_pass_receipt(self) -> None:
        claim = Claim("worker", 1, "def add_one(value):\n    return value + 1\n", "candidate")
        receipt = self.verifier.verify(claim, self.spec, self.obligations)
        self.assertTrue(receipt.is_passed)
        self.assertTrue(self.verifier.verify_receipt_signature(receipt))
        propagated = TrustGate.propagate(
            claim,
            self.spec,
            receipt,
            self.verifier,
            self.obligations,
            lambda *_: "approved",
        )
        self.assertEqual("approved", propagated)

    def test_tampered_evidence_is_rejected(self) -> None:
        claim = Claim("worker", 1, "def add_one(value):\n    return value + 1\n", "candidate")
        receipt = self.verifier.verify(claim, self.spec, self.obligations)
        tampered = replace(
            receipt,
            evidence=(Evidence("TEST", VerificationStatus.PASSED, "forged", "forged"),),
        )
        with self.assertRaisesRegex(ValueError, "invalid verifier signature"):
            TrustGate.propagate(
                claim,
                self.spec,
                tampered,
                self.verifier,
                self.obligations,
                lambda *_: None,
            )

    def test_changed_claim_is_rejected(self) -> None:
        claim = Claim("worker", 1, "def add_one(value):\n    return value + 1\n", "candidate")
        receipt = self.verifier.verify(claim, self.spec, self.obligations)
        with self.assertRaisesRegex(ValueError, "claim digest mismatch"):
            TrustGate.propagate(
                replace(claim, description="changed"),
                self.spec,
                receipt,
                self.verifier,
                self.obligations,
                lambda *_: None,
            )

    def test_obligation_mismatch_is_rejected(self) -> None:
        claim = Claim("worker", 1, "def add_one(value):\n    return value + 1\n", "candidate")
        receipt = self.verifier.verify(claim, self.spec, self.obligations)
        different = (Obligation("OTHER", "TEST_EXECUTION", "Different."),)
        with self.assertRaisesRegex(ValueError, "obligation set mismatch"):
            TrustGate.propagate(
                claim,
                self.spec,
                receipt,
                self.verifier,
                different,
                lambda *_: None,
            )

    def test_failed_receipt_never_propagates(self) -> None:
        claim = Claim("worker", 1, "def add_one(value): return value", "wrong")
        receipt = self.verifier.verify(claim, self.spec, self.obligations)
        with self.assertRaisesRegex(ValueError, "verification failed"):
            TrustGate.propagate(
                claim,
                self.spec,
                receipt,
                self.verifier,
                self.obligations,
                lambda *_: None,
            )

    def test_spec_attempt_and_protocol_mismatches_are_rejected(self) -> None:
        claim = Claim("worker", 1, "def add_one(value): return value + 1", "candidate")
        receipt = self.verifier.verify(claim, self.spec, self.obligations)
        changed_spec = replace(self.spec, description="Changed contract.")
        with self.assertRaisesRegex(ValueError, "spec digest mismatch"):
            TrustGate.propagate(
                claim,
                changed_spec,
                receipt,
                self.verifier,
                self.obligations,
                lambda *_: None,
            )

        changed_attempt = replace(receipt, attempt=2, signature="")
        changed_attempt = replace(
            changed_attempt,
            signature=self.verifier.sign_receipt(changed_attempt),
        )
        with self.assertRaisesRegex(ValueError, "attempt mismatch"):
            TrustGate.propagate(
                claim,
                self.spec,
                changed_attempt,
                self.verifier,
                self.obligations,
                lambda *_: None,
            )

        changed_protocol = replace(receipt, protocol_version="999", signature="")
        changed_protocol = replace(
            changed_protocol,
            signature=self.verifier.sign_receipt(changed_protocol),
        )
        with self.assertRaisesRegex(ValueError, "protocol version"):
            TrustGate.propagate(
                claim,
                self.spec,
                changed_protocol,
                self.verifier,
                self.obligations,
                lambda *_: None,
            )

    def test_infinite_loop_times_out(self) -> None:
        claim = Claim("worker", 1, "def add_one(value):\n    while True:\n        pass\n", "loop")
        receipt = self.verifier.verify(claim, self.spec, self.obligations)
        self.assertFalse(receipt.is_passed)
        self.assertIn("Timed out", receipt.evidence[0].error)

    def test_process_exit_is_rejected(self) -> None:
        claim = Claim("worker", 1, "import sys\nsys.exit(0)\n", "exit")
        receipt = self.verifier.verify(claim, self.spec, self.obligations)
        self.assertFalse(receipt.is_passed)
        self.assertIn("SystemExit", receipt.evidence[0].error)

    def test_unknown_obligation_fails_closed(self) -> None:
        claim = Claim("worker", 1, "def add_one(value): return value + 1", "candidate")
        receipt = self.verifier.verify(
            claim,
            self.spec,
            (Obligation("UNKNOWN", "NOT_SUPPORTED", "Unknown."),),
        )
        self.assertFalse(receipt.is_passed)
        self.assertIn("Unknown obligation kind", receipt.evidence[0].error)

    def test_static_obligations_are_independently_evaluated(self) -> None:
        claim = Claim("worker", 1, "def add_one(value): return value + 1", "candidate")
        static_obligations = (
            Obligation(
                "ENTRY",
                "REQUIRED_ENTRYPOINT",
                "Entrypoint exists.",
                {"name": "add_one"},
            ),
            Obligation(
                "STUB",
                "FORBIDDEN_TEXT",
                "No stub.",
                {"text": "raise NotImplementedError"},
            ),
        )
        receipt = self.verifier.verify(claim, self.spec, static_obligations)
        self.assertTrue(receipt.is_passed)

        invalid = Claim("worker", 1, "def other():\n    raise NotImplementedError\n", "stub")
        receipt = self.verifier.verify(invalid, self.spec, static_obligations)
        self.assertFalse(receipt.is_passed)
        self.assertEqual(2, sum(not evidence.is_passed for evidence in receipt.evidence))

    def test_non_json_output_and_malformed_protocol_output_are_rejected(self) -> None:
        non_json = Claim("worker", 1, "def add_one(value): return {value}", "set")
        receipt = self.verifier.verify(non_json, self.spec, self.obligations)
        self.assertFalse(receipt.is_passed)
        self.assertIn("TypeError", receipt.evidence[0].error)

        malformed = Claim(
            "worker",
            1,
            "import os\nos.write(1, b'junk')\ndef add_one(value): return value + 1\n",
            "malformed",
        )
        receipt = self.verifier.verify(malformed, self.spec, self.obligations)
        self.assertFalse(receipt.is_passed)
        self.assertIn("Invalid runner response", receipt.evidence[0].error)

    def test_response_limit_is_enforced(self) -> None:
        verifier = VerifierAgent(
            signing_key=b"x" * 32,
            execution_timeout_seconds=0.5,
            max_response_bytes=1,
        )
        claim = Claim("worker", 1, "def add_one(value): return value + 1", "candidate")
        receipt = verifier.verify(claim, self.spec, self.obligations)
        self.assertFalse(receipt.is_passed)
        self.assertIn("size limit", receipt.evidence[0].error)

    def test_duplicate_obligations_are_rejected(self) -> None:
        claim = Claim("worker", 1, "def add_one(value): return value + 1", "candidate")
        duplicate = Obligation("SAME", "TEST_EXECUTION", "Duplicate.")
        with self.assertRaisesRegex(ValueError, "unique"):
            self.verifier.verify(claim, self.spec, (duplicate, duplicate))

    def test_short_signing_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least 32"):
            VerifierAgent(signing_key="too-short")
        with self.assertRaisesRegex(ValueError, "timeout"):
            VerifierAgent(signing_key=b"x" * 32, execution_timeout_seconds=0)
        with self.assertRaisesRegex(ValueError, "response"):
            VerifierAgent(signing_key=b"x" * 32, max_response_bytes=0)


if __name__ == "__main__":
    unittest.main()
