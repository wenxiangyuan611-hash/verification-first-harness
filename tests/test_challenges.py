import tempfile
import unittest
from pathlib import Path

from verification_harness.actions import ActionGate, AllowListActionPolicy
from verification_harness.challenges import (
    CHALLENGE_PAYLOAD_TYPE,
    ChallengeInvocationError,
    ChallengeScheduler,
    ChallengeSelection,
    RuntimeChallengePolicy,
    RuntimeChallengePolicyError,
)
from verification_harness.decision import VerificationObligation
from verification_harness.persistence import RunRecordKind, SQLiteRunStore, TrustLabel
from verification_harness.protocol import (
    AcceptanceCriterion,
    AgentRole,
    AuthorizedSpec,
    ClaimEnvelope,
    RunContext,
    SpecAuthorization,
    SpecProposal,
)
from verification_harness.providers import AgentOutput, AgentRequest


def obligation(identifier: str) -> VerificationObligation:
    return VerificationObligation(
        id=identifier,
        kind="test.check",
        description=f"Run {identifier}.",
        criterion_ids=("correct",),
        payload={"id": identifier},
    )


class StaticCritic:
    provider_id = "critic-provider"

    def __init__(self, selected: list[str]) -> None:
        self.selected = selected
        self.requests: list[AgentRequest] = []

    def invoke(self, request: AgentRequest) -> AgentOutput:
        self.requests.append(request)
        return AgentOutput(
            payload_type=CHALLENGE_PAYLOAD_TYPE,
            payload={
                "selected_obligation_ids": self.selected,
                "rationale": {"reason": "try the edge case"},
            },
        )


class ChallengeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = RunContext("run-1", "task-1", "nonce-1")
        proposal = SpecProposal(
            proposal_id="proposal-1",
            task_id="task-1",
            proposer_id="planner",
            domain="example",
            criteria=(AcceptanceCriterion("correct", "The result must be correct."),),
            payload={},
        )
        self.spec = AuthorizedSpec(
            proposal=proposal,
            authorization=SpecAuthorization(
                authority_id="spec-authority",
                proposal_digest=proposal.digest,
                protocol_version=self.context.protocol_version,
                signature="signature",
            ),
        )
        self.worker_claim = ClaimEnvelope.create(
            context=self.context,
            role=AgentRole.WORKER,
            producer_id="worker-provider",
            payload_type="application/json",
            payload={"answer": 41},
        )
        self.baseline = (obligation("baseline"),)
        self.catalog = (obligation("edge"), obligation("stress"))

    def test_policy_preserves_baseline_and_catalog_order(self) -> None:
        selection = ChallengeSelection(
            selected_obligation_ids=("stress", "edge"),
            rationale={"claim": "both may fail"},
        )
        authorized = RuntimeChallengePolicy().authorize(
            worker_provider_id="worker-provider",
            critic_provider_id="critic-provider",
            baseline=self.baseline,
            catalog=self.catalog,
            selection=selection,
        )
        self.assertEqual(["baseline", "edge", "stress"], [item.id for item in authorized])

    def test_policy_rejects_self_review_unknown_checks_and_baseline_replacement(self) -> None:
        selection = ChallengeSelection(
            selected_obligation_ids=("edge",),
            rationale="challenge",
        )
        policy = RuntimeChallengePolicy()
        with self.assertRaisesRegex(RuntimeChallengePolicyError, "distinct"):
            policy.authorize(
                worker_provider_id="same",
                critic_provider_id="same",
                baseline=self.baseline,
                catalog=self.catalog,
                selection=selection,
            )
        unknown = ChallengeSelection(
            selected_obligation_ids=("shell-from-agent",),
            rationale="run arbitrary code",
        )
        with self.assertRaisesRegex(RuntimeChallengePolicyError, "unauthorized"):
            policy.authorize(
                worker_provider_id="worker",
                critic_provider_id="critic",
                baseline=self.baseline,
                catalog=self.catalog,
                selection=unknown,
            )
        with self.assertRaisesRegex(RuntimeChallengePolicyError, "replace baseline"):
            policy.authorize(
                worker_provider_id="worker",
                critic_provider_id="critic",
                baseline=self.baseline,
                catalog=(self.baseline[0],),
                selection=ChallengeSelection(
                    selected_obligation_ids=(),
                    rationale="none",
                ),
            )

    def test_selection_parser_is_strict_and_detached(self) -> None:
        payload = {"selected_obligation_ids": ["edge"], "rationale": {"why": "x"}}
        selection = ChallengeSelection.from_output(
            AgentOutput(payload_type=CHALLENGE_PAYLOAD_TYPE, payload=payload)
        )
        payload["selected_obligation_ids"].append("stress")
        self.assertEqual(("edge",), selection.selected_obligation_ids)
        with self.assertRaisesRegex(ValueError, "unsupported"):
            ChallengeSelection.from_output(
                AgentOutput(payload_type="application/json", payload=payload)
            )
        with self.assertRaisesRegex(ValueError, "exactly"):
            ChallengeSelection.from_output(
                AgentOutput(
                    payload_type=CHALLENGE_PAYLOAD_TYPE,
                    payload={"selected_obligation_ids": [], "rationale": "x", "pass": True},
                )
            )

    def test_scheduler_quarantines_critic_claim_and_returns_only_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRunStore(Path(directory) / "runs.sqlite3")
            store.save_context(self.context)
            store.save_authorized_spec(self.context.run_id, self.spec)
            store.quarantine_claim(self.worker_claim)
            scheduler = ChallengeScheduler(
                action_gate=ActionGate(
                    AllowListActionPolicy(frozenset({"agent.challenge"}))
                ),
                run_store=store,
            )
            critic = StaticCritic(["edge"])
            schedule = scheduler.schedule(
                context=self.context,
                spec=self.spec,
                worker_claim=self.worker_claim,
                worker_provider_id="worker-provider",
                critic_provider=critic,
                attempt=1,
                baseline=self.baseline,
                catalog=self.catalog,
            )

            self.assertEqual(("edge",), schedule.selected_obligation_ids)
            self.assertEqual(["baseline", "edge"], [item.id for item in schedule.obligations])
            self.assertFalse(hasattr(schedule, "rationale"))
            self.assertIs(AgentRole.CRITIC, critic.requests[0].role)
            self.assertEqual(
                (self.worker_claim.claim_id,), critic.requests[0].parent_claim_ids
            )
            critic_record = store.records(self.context.run_id)[-1]
            self.assertIs(RunRecordKind.CLAIM, critic_record.kind)
            self.assertIs(TrustLabel.QUARANTINED, critic_record.trust_label)
            self.assertEqual("CRITIC", critic_record.payload["role"])

    def test_scheduler_fails_closed_before_critic_when_action_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRunStore(Path(directory) / "runs.sqlite3")
            store.save_context(self.context)
            store.save_authorized_spec(self.context.run_id, self.spec)
            store.quarantine_claim(self.worker_claim)
            scheduler = ChallengeScheduler(
                action_gate=ActionGate(AllowListActionPolicy(frozenset())),
                run_store=store,
            )
            critic = StaticCritic(["edge"])
            with self.assertRaisesRegex(ChallengeInvocationError, "not allowed"):
                scheduler.schedule(
                    context=self.context,
                    spec=self.spec,
                    worker_claim=self.worker_claim,
                    worker_provider_id="worker-provider",
                    critic_provider=critic,
                    attempt=1,
                    baseline=self.baseline,
                    catalog=self.catalog,
                )
            self.assertEqual([], critic.requests)


if __name__ == "__main__":
    unittest.main()
