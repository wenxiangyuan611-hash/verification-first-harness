import unittest

from verification_harness.policy import ChallengePolicy, ChallengePolicyError
from verification_harness.schema import Obligation


class ChallengePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.baseline = (
            Obligation("HARNESS_TEST_PASS", "TEST_EXECUTION", "Run baseline tests."),
        )

    def test_authorized_proposals_are_appended_after_immutable_baseline(self) -> None:
        proposal = Obligation(
            "CRITIC_ENTRYPOINT",
            "REQUIRED_ENTRYPOINT",
            "Require the entrypoint.",
            {"name": "add_one"},
        )
        obligations = ChallengePolicy().authorize(self.baseline, (proposal,))
        self.assertEqual(self.baseline + (proposal,), obligations)
        proposal.payload["name"] = "mutated"
        self.assertEqual("add_one", obligations[1].payload["name"])

    def test_reserved_duplicate_and_unsupported_obligations_fail_closed(self) -> None:
        reserved = Obligation(
            "HARNESS_OVERRIDE",
            "FORBIDDEN_TEXT",
            "Attempt to use a reserved ID.",
            {"text": "pass"},
        )
        with self.assertRaisesRegex(ChallengePolicyError, "reserved"):
            ChallengePolicy().authorize(self.baseline, (reserved,))

        duplicate = Obligation(
            "HARNESS_TEST_PASS",
            "FORBIDDEN_TEXT",
            "Attempt to replace baseline.",
            {"text": "pass"},
        )
        with self.assertRaisesRegex(ChallengePolicyError, "duplicate"):
            ChallengePolicy().authorize(self.baseline, (duplicate,))

        unsupported = Obligation("CRITIC_SHELL", "SHELL", "Run arbitrary shell.")
        with self.assertRaisesRegex(ChallengePolicyError, "not authorized"):
            ChallengePolicy().authorize(self.baseline, (unsupported,))

    def test_obligation_count_and_payload_size_are_bounded(self) -> None:
        proposals = tuple(
            Obligation(f"CRITIC_{index}", "FORBIDDEN_TEXT", "Check.", {"text": str(index)})
            for index in range(2)
        )
        with self.assertRaisesRegex(ChallengePolicyError, "limit"):
            ChallengePolicy(max_obligations=1).authorize(self.baseline, proposals)

        large = Obligation(
            "CRITIC_LARGE",
            "FORBIDDEN_TEXT",
            "Oversized payload.",
            {"text": "x" * 100},
        )
        with self.assertRaisesRegex(ChallengePolicyError, "payload"):
            ChallengePolicy(max_payload_bytes=16).authorize(self.baseline, (large,))

        malformed = Obligation(
            "CRITIC_MALFORMED",
            "REQUIRED_ENTRYPOINT",
            "Missing required payload field.",
        )
        with self.assertRaisesRegex(ChallengePolicyError, "non-empty string"):
            ChallengePolicy().authorize(self.baseline, (malformed,))

    def test_invalid_policy_configuration_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "zero or greater"):
            ChallengePolicy(max_obligations=-1)
        with self.assertRaisesRegex(ValueError, "allowed_kinds"):
            ChallengePolicy(allowed_kinds=frozenset())
        with self.assertRaisesRegex(ValueError, "identifier"):
            ChallengePolicy(max_identifier_chars=0)
        with self.assertRaisesRegex(ValueError, "description"):
            ChallengePolicy(max_description_chars=0)
        with self.assertRaisesRegex(ValueError, "payload"):
            ChallengePolicy(max_payload_bytes=0)

    def test_identifier_and_description_limits_are_enforced(self) -> None:
        long_id = Obligation("CRITIC_LONG", "FORBIDDEN_TEXT", "Check.", {"text": "x"})
        with self.assertRaisesRegex(ChallengePolicyError, "ID is too long"):
            ChallengePolicy(max_identifier_chars=3).authorize(self.baseline, (long_id,))

        empty_description = Obligation(
            "CRITIC_EMPTY",
            "FORBIDDEN_TEXT",
            " ",
            {"text": "x"},
        )
        with self.assertRaisesRegex(ChallengePolicyError, "description must be non-empty"):
            ChallengePolicy().authorize(self.baseline, (empty_description,))

        long_description = Obligation(
            "CRITIC_DESCRIPTION",
            "FORBIDDEN_TEXT",
            "too long",
            {"text": "x"},
        )
        with self.assertRaisesRegex(ChallengePolicyError, "description exceeds"):
            ChallengePolicy(max_description_chars=3).authorize(
                self.baseline,
                (long_description,),
            )

    def test_explicitly_allowed_custom_kind_uses_generic_payload_boundary(self) -> None:
        custom = Obligation("CUSTOM", "CUSTOM_KIND", "Custom check.")
        policy = ChallengePolicy(allowed_kinds=frozenset({"CUSTOM_KIND"}))
        self.assertEqual(self.baseline + (custom,), policy.authorize(self.baseline, (custom,)))


if __name__ == "__main__":
    unittest.main()
