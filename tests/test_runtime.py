import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from verification_harness.actions import ActionGate, AllowListActionPolicy
from verification_harness.authority import (
    HMACEvidenceAuthority,
    HMACReceiptAuthority,
    HMACSpecAuthority,
)
from verification_harness.decision import VerificationObligation
from verification_harness.gate import ReplayError
from verification_harness.kernel import VerificationKernel
from verification_harness.persistence import (
    RunRecordKind,
    SQLiteReceiptUseStore,
    SQLiteRunStore,
    TrustLabel,
)
from verification_harness.protocol import AcceptanceCriterion, SpecProposal, Verdict
from verification_harness.providers import AgentOutput, AgentRequest, CommandAgentProvider
from verification_harness.runtime import AgentInvocationError, VerificationRuntime
from verification_harness.verifiers import CommandVerifierPlugin, VerifierRegistry


class CountingProvider:
    provider_id = "counting-provider"

    def __init__(self) -> None:
        self.calls = 0

    def invoke(self, request: AgentRequest) -> AgentOutput:
        self.calls += 1
        return AgentOutput(payload_type="application/json", payload={"answer": 42})


class UnreadableProvider:
    provider_id = "unreadable-provider"

    def invoke(self, request: AgentRequest) -> AgentOutput:
        del request

        class UnreadableError(Exception):
            def __str__(self) -> str:
                raise RuntimeError("cannot render")

        raise UnreadableError()


class VerificationRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "runtime.sqlite3"
        self.proposal = SpecProposal(
            proposal_id="proposal-1",
            task_id="answer-task",
            proposer_id="planner-model",
            domain="example.answer",
            criteria=(AcceptanceCriterion("correct", "Answer must equal 42."),),
            payload={"question": "What is six times seven?"},
        )
        verifier_code = (
            "import json,sys; c=json.load(sys.stdin); "
            "sys.exit(0 if c['payload']['answer']==42 else 1)"
        )
        self.obligations = (
            VerificationObligation(
                id="answer-check",
                kind="command.exit_code",
                description="Check the answer with an independent process.",
                criterion_ids=("correct",),
                payload={
                    "argv": [sys.executable, "-c", verifier_code],
                    "expected_exit_code": 0,
                },
            ),
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def runtime(
        self,
        allowed_kinds: frozenset[str] = frozenset(
            {"agent.invoke", "verifier.invoke"}
        ),
    ) -> tuple[VerificationRuntime, SQLiteRunStore]:
        store = SQLiteRunStore(self.database)
        gate = ActionGate(AllowListActionPolicy(allowed_kinds))
        evidence_authority = HMACEvidenceAuthority("runtime-verifier", b"e" * 32)
        kernel = VerificationKernel(
            spec_authority=HMACSpecAuthority(
                "spec-authority",
                b"s" * 32,
                lambda proposal: proposal == self.proposal,
            ),
            evidence_verifier=evidence_authority,
            receipt_authority=HMACReceiptAuthority("receipt-authority", b"r" * 32),
            receipt_use_store=SQLiteReceiptUseStore(store),
        )
        registry = VerifierRegistry(
            "runtime-verifier",
            (CommandVerifierPlugin(),),
            gate,
        )
        return (
            VerificationRuntime(
                kernel=kernel,
                evidence_authority=evidence_authority,
                verifier_registry=registry,
                action_gate=gate,
                run_store=store,
            ),
            store,
        )

    def test_real_subprocess_failure_repair_reverification_and_persistence(self) -> None:
        provider_code = (
            "import json,sys; r=json.load(sys.stdin); a=r['attempt']; "
            "ok=(a==1 or ('failed_claim' in r['feedback'] and "
            "r['parent_claim_ids'])); "
            "sys.exit(9) if not ok else None; "
            "json.dump({'payload_type':'application/json',"
            "'payload':{'answer':41 if a==1 else 42}},sys.stdout)"
        )
        provider = CommandAgentProvider(
            "local-command-agent",
            (sys.executable, "-c", provider_code),
        )
        runtime, store = self.runtime()
        result = runtime.run(
            proposal=self.proposal,
            provider=provider,
            input_payload={"instruction": "answer the question"},
            obligations=self.obligations,
            max_repairs=1,
        )
        self.assertEqual(Verdict.VERIFIED.value, result.verdict)
        self.assertIsNotNone(result.artifact)
        if result.artifact is None:
            self.fail("verified runtime result did not contain an artifact")
        self.assertEqual({"answer": 42}, result.artifact.payload)
        self.assertEqual(
            [Verdict.REJECTED.value, Verdict.VERIFIED.value],
            [attempt.verdict for attempt in result.attempts],
        )
        self.assertFalse(hasattr(result.attempts[0], "claim"))
        self.assertEqual(
            [result.attempts[0].claim_id],
            tuple(
                record.payload["parent_claim_ids"]
                for record in store.records(result.context.run_id)
                if record.kind is RunRecordKind.CLAIM
            )[1],
        )

        records = store.records(result.context.run_id)
        labels = [record.trust_label for record in records]
        self.assertEqual(2, labels.count(TrustLabel.QUARANTINED))
        self.assertEqual(2, labels.count(TrustLabel.AUTHENTICATED_EVIDENCE))
        self.assertEqual(2, labels.count(TrustLabel.DECISION_ONLY))
        self.assertEqual(1, labels.count(TrustLabel.VERIFIED))
        self.assertEqual(result.context, store.load_context(result.context.run_id))

        with self.assertRaisesRegex(ReplayError, "already been consumed"):
            SQLiteReceiptUseStore(SQLiteRunStore(self.database)).consume(
                result.attempts[-1].receipt
            )

    def test_denied_agent_action_never_invokes_provider_or_creates_claim(self) -> None:
        provider = CountingProvider()
        runtime, store = self.runtime(frozenset())
        with self.assertRaisesRegex(AgentInvocationError, "not allowed"):
            runtime.run(
                proposal=self.proposal,
                provider=provider,
                input_payload={},
                obligations=self.obligations,
            )
        self.assertEqual(0, provider.calls)
        with closing(sqlite3.connect(store.path)) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM run_records WHERE kind = ?",
                (RunRecordKind.CLAIM.value,),
            ).fetchone()[0]
        self.assertEqual(0, count)

    def test_denied_verifier_action_produces_error_and_no_artifact(self) -> None:
        provider = CountingProvider()
        runtime, store = self.runtime(frozenset({"agent.invoke"}))
        result = runtime.run(
            proposal=self.proposal,
            provider=provider,
            input_payload={},
            obligations=self.obligations,
        )
        self.assertEqual(Verdict.ERROR.value, result.verdict)
        self.assertIsNone(result.artifact)
        self.assertEqual(1, provider.calls)
        records = store.records(result.context.run_id)
        self.assertNotIn(TrustLabel.VERIFIED, [record.trust_label for record in records])

    def test_unreadable_provider_failure_is_contained_before_claim_creation(self) -> None:
        runtime, store = self.runtime()
        with self.assertRaisesRegex(AgentInvocationError, "unreadable error"):
            runtime.run(
                proposal=self.proposal,
                provider=UnreadableProvider(),
                input_payload={},
                obligations=self.obligations,
            )
        with closing(sqlite3.connect(store.path)) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM run_records WHERE kind = ?",
                (RunRecordKind.CLAIM.value,),
            ).fetchone()[0]
        self.assertEqual(0, count)

    def test_persistence_detects_context_and_record_tampering(self) -> None:
        provider = CountingProvider()
        runtime, store = self.runtime()
        result = runtime.run(
            proposal=self.proposal,
            provider=provider,
            input_payload={},
            obligations=self.obligations,
        )
        with closing(sqlite3.connect(store.path)) as connection, connection:
            connection.execute(
                "UPDATE run_records SET payload_json = ? WHERE kind = ?",
                (json.dumps({"forged": True}), RunRecordKind.CLAIM.value),
            )
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            store.records(result.context.run_id)


if __name__ == "__main__":
    unittest.main()
