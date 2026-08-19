import sys
import unittest

from verification_harness.actions import ActionGate, AllowListActionPolicy
from verification_harness.authority import HMACSpecAuthority
from verification_harness.decision import Observation, VerificationObligation
from verification_harness.protocol import (
    AcceptanceCriterion,
    AgentRole,
    ClaimEnvelope,
    EvidenceStatus,
    RunContext,
    SpecProposal,
)
from verification_harness.verifiers import CommandVerifierPlugin, VerifierRegistry


class BrokenPlugin:
    plugin_id = "broken"
    kinds = frozenset({"broken.kind"})

    def __init__(self) -> None:
        self.calls = 0

    def observe(self, context, spec, claim, obligation):  # type: ignore[no-untyped-def]
        del context, spec, claim, obligation
        self.calls += 1
        raise RuntimeError("verifier failed")


class WrongIdentityPlugin:
    plugin_id = "wrong-identity"
    kinds = frozenset({"wrong.kind"})

    def observe(self, context, spec, claim, obligation):  # type: ignore[no-untyped-def]
        del context, spec, claim, obligation
        return Observation("different", EvidenceStatus.PASSED, "ok", "ok")


class VerifierRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = RunContext("run-1", "task-1", "nonce-1")
        proposal = SpecProposal(
            proposal_id="proposal-1",
            task_id="task-1",
            proposer_id="planner-1",
            domain="example",
            criteria=(AcceptanceCriterion("correct", "Answer must equal 42."),),
            payload={"question": "six times seven"},
        )
        self.spec = HMACSpecAuthority(
            "spec-authority",
            b"s" * 32,
            lambda value: value.task_id == "task-1",
        ).authorize(proposal)
        self.claim = ClaimEnvelope(
            claim_id="claim-1",
            run_id="run-1",
            role=AgentRole.WORKER,
            producer_id="worker-1",
            payload_type="application/json",
            payload={"answer": 42},
        )

    def obligation(self, code: str) -> VerificationObligation:
        return VerificationObligation(
            id="answer-check",
            kind="command.exit_code",
            description="Check the claimed answer.",
            criterion_ids=("correct",),
            payload={
                "argv": [sys.executable, "-c", code],
                "expected_exit_code": 0,
            },
        )

    def test_command_verifier_checks_canonical_claim_on_stdin(self) -> None:
        code = (
            "import json,sys; c=json.load(sys.stdin); "
            "sys.exit(0 if c['payload']['answer']==42 else 1)"
        )
        plugin = CommandVerifierPlugin()
        passed = plugin.observe(self.context, self.spec, self.claim, self.obligation(code))
        self.assertEqual(EvidenceStatus.PASSED, passed.status)

        wrong_claim = ClaimEnvelope(
            claim_id="claim-2",
            run_id="run-1",
            role=AgentRole.WORKER,
            producer_id="worker-1",
            payload_type="application/json",
            payload={"answer": 41},
        )
        failed = plugin.observe(self.context, self.spec, wrong_claim, self.obligation(code))
        self.assertEqual(EvidenceStatus.FAILED, failed.status)

    def test_timeout_and_malformed_command_become_error_evidence(self) -> None:
        timeout_plugin = CommandVerifierPlugin(timeout_seconds=0.05)
        timeout = timeout_plugin.observe(
            self.context,
            self.spec,
            self.claim,
            self.obligation("import time;time.sleep(0.2)"),
        )
        self.assertEqual(EvidenceStatus.ERROR, timeout.status)

        malformed = VerificationObligation(
            id="bad",
            kind="command.exit_code",
            description="Malformed check.",
            criterion_ids=("correct",),
            payload={"argv": [sys.executable]},
        )
        registry = VerifierRegistry(
            "verifier-1",
            (CommandVerifierPlugin(),),
            ActionGate(AllowListActionPolicy(frozenset({"verifier.invoke"}))),
        )
        result = registry.collect(self.context, self.spec, self.claim, (malformed,))
        self.assertEqual(EvidenceStatus.ERROR, result[0].status)
        self.assertIn("requires exactly", result[0].error)

    def test_registry_contains_plugins_unsupported_kinds_and_action_denials(self) -> None:
        broken = BrokenPlugin()
        gate = ActionGate(AllowListActionPolicy(frozenset({"verifier.invoke"})))
        registry = VerifierRegistry("verifier-1", (broken,), gate)
        obligation = VerificationObligation(
            "broken-check",
            "broken.kind",
            "Broken verifier.",
            ("correct",),
        )
        result = registry.collect(self.context, self.spec, self.claim, (obligation,))
        self.assertEqual(EvidenceStatus.ERROR, result[0].status)
        self.assertIn("RuntimeError", result[0].error)
        self.assertEqual(1, broken.calls)

        unsupported = VerificationObligation(
            "unknown",
            "unknown.kind",
            "No plugin.",
            ("correct",),
        )
        result = registry.collect(self.context, self.spec, self.claim, (unsupported,))
        self.assertEqual(EvidenceStatus.ERROR, result[0].status)

        denied = VerifierRegistry(
            "verifier-1",
            (broken,),
            ActionGate(AllowListActionPolicy(frozenset())),
        )
        result = denied.collect(self.context, self.spec, self.claim, (obligation,))
        self.assertEqual(EvidenceStatus.ERROR, result[0].status)
        self.assertEqual(1, broken.calls)

    def test_registry_rejects_mismatched_observation_identity(self) -> None:
        registry = VerifierRegistry(
            "verifier-1",
            (WrongIdentityPlugin(),),
            ActionGate(AllowListActionPolicy(frozenset({"verifier.invoke"}))),
        )
        obligation = VerificationObligation(
            "expected",
            "wrong.kind",
            "Identity must match.",
            ("correct",),
        )
        result = registry.collect(self.context, self.spec, self.claim, (obligation,))
        self.assertEqual(EvidenceStatus.ERROR, result[0].status)
        self.assertIn("identity mismatch", result[0].error)


if __name__ == "__main__":
    unittest.main()
