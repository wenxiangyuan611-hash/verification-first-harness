import unittest

from verification_harness.authority import HMACSpecAuthority
from verification_harness.protocol import (
    PROTOCOL_VERSION,
    AcceptanceCriterion,
    AgentRole,
    AuthorizedSpec,
    ClaimEnvelope,
    RunContext,
    SpecProposal,
)


class ProtocolV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = RunContext(
            run_id="run-1",
            task_id="task-1",
            nonce="nonce-1",
        )
        self.proposal = SpecProposal(
            proposal_id="proposal-1",
            task_id="task-1",
            proposer_id="planner-1",
            domain="python",
            criteria=(AcceptanceCriterion("returns", "Return input plus one."),),
            payload={"entrypoint": "add_one", "tests": [{"input": 1, "expected": 2}]},
        )
        self.authority = HMACSpecAuthority(
            "spec-authority",
            b"s" * 32,
            lambda proposal: proposal.task_id == "task-1",
        )

    def test_run_context_is_versioned_and_digest_bound(self) -> None:
        restored = RunContext.from_dict(self.context.to_dict())
        self.assertEqual(self.context, restored)
        self.assertEqual(self.context.digest, restored.digest)
        self.assertEqual(PROTOCOL_VERSION, restored.protocol_version)

    def test_spec_proposal_requires_independent_authorization(self) -> None:
        authorized = self.authority.authorize(self.proposal)
        self.assertIsInstance(authorized, AuthorizedSpec)
        self.assertTrue(self.authority.verify(authorized))
        self.assertNotEqual(self.proposal.digest, authorized.digest)

    def test_authorization_cannot_be_reused_for_a_changed_proposal(self) -> None:
        authorized = self.authority.authorize(self.proposal)
        changed = SpecProposal(
            proposal_id=self.proposal.proposal_id,
            task_id=self.proposal.task_id,
            proposer_id=self.proposal.proposer_id,
            domain=self.proposal.domain,
            criteria=self.proposal.criteria,
            payload={"entrypoint": "subtract_one"},
        )
        with self.assertRaisesRegex(ValueError, "not bound"):
            AuthorizedSpec(changed, authorized.authorization)

    def test_spec_authority_denies_or_rejects_ambiguous_policy_decisions(self) -> None:
        denied = HMACSpecAuthority("denied", b"d" * 32, lambda proposal: False)
        with self.assertRaisesRegex(PermissionError, "not authorized"):
            denied.authorize(self.proposal)

        def ambiguous_policy(proposal: SpecProposal) -> bool:
            return 1  # type: ignore[return-value]

        ambiguous = HMACSpecAuthority("ambiguous", b"a" * 32, ambiguous_policy)
        with self.assertRaisesRegex(TypeError, "must return bool"):
            ambiguous.authorize(self.proposal)

    def test_claim_envelope_is_role_neutral_and_detaches_payload(self) -> None:
        source = {"code": "def add_one(x): return x + 1", "metadata": {"model": "demo"}}
        claim = ClaimEnvelope(
            claim_id="claim-1",
            run_id=self.context.run_id,
            role=AgentRole.WORKER,
            producer_id="worker-1",
            payload_type="python.source",
            payload=source,
            parent_claim_ids=("plan-1",),
        )
        source["metadata"]["model"] = "mutated"
        exposed = claim.payload
        exposed["metadata"]["model"] = "also-mutated"
        self.assertEqual("demo", claim.payload["metadata"]["model"])
        self.assertEqual(claim, ClaimEnvelope.from_dict(claim.to_dict()))

    def test_all_agent_roles_use_the_same_claim_envelope(self) -> None:
        claims = tuple(
            ClaimEnvelope(
                claim_id=f"claim-{role.value.lower()}",
                run_id=self.context.run_id,
                role=role,
                producer_id=f"{role.value.lower()}-1",
                payload_type="application/json",
                payload={"claim": role.value},
            )
            for role in AgentRole
        )
        self.assertEqual(set(AgentRole), {claim.role for claim in claims})

    def test_invalid_lineage_and_non_json_payload_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "own parent"):
            ClaimEnvelope(
                claim_id="claim-1",
                run_id=self.context.run_id,
                role=AgentRole.CRITIC,
                producer_id="critic-1",
                payload_type="challenge",
                payload={},
                parent_claim_ids=("claim-1",),
            )
        with self.assertRaises(TypeError):
            SpecProposal(
                proposal_id="bad",
                task_id="task-1",
                proposer_id="planner-1",
                domain="generic",
                criteria=(AcceptanceCriterion("one", "One criterion"),),
                payload={"not-json": object()},
            )


if __name__ == "__main__":
    unittest.main()
