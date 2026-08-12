"""Minimal domain-neutral trust-kernel flow with an independent evidence signer."""

from verification_harness import (
    AcceptanceCriterion,
    AgentRole,
    ClaimEnvelope,
    EvidenceStatus,
    HMACEvidenceAuthority,
    HMACReceiptAuthority,
    HMACSpecAuthority,
    Observation,
    SpecProposal,
    VerificationKernel,
    VerificationObligation,
)


def main() -> None:
    expected_criteria = (
        AcceptanceCriterion("bounded", "The answer must be between 0 and 100."),
    )

    def authorized_contract(proposal: SpecProposal) -> bool:
        return (
            proposal.task_id == "answer-task"
            and proposal.domain == "example.answer"
            and proposal.criteria == expected_criteria
            and proposal.payload == {"question": "What is six times seven?"}
        )

    spec_authority = HMACSpecAuthority(
        "example-spec-authority",
        b"spec-authority-demo-key-32-bytes!",
        authorized_contract,
    )
    evidence_authority = HMACEvidenceAuthority(
        "example-independent-verifier",
        b"evidence-authority-demo-key-32b!",
    )
    kernel = VerificationKernel(
        spec_authority=spec_authority,
        # The kernel retains a verify-only facade. The issuing object stays here,
        # representing a separately isolated evidence-collection boundary.
        evidence_verifier=evidence_authority,
        receipt_authority=HMACReceiptAuthority(
            "example-receipt-authority",
            b"receipt-authority-demo-key-32b!!",
        ),
    )

    context = kernel.open_run("answer-task")
    proposal = SpecProposal(
        proposal_id=f"{context.run_id}:spec",
        task_id=context.task_id,
        proposer_id="planner-model",
        domain="example.answer",
        criteria=expected_criteria,
        payload={"question": "What is six times seven?"},
    )
    spec = kernel.authorize(proposal)
    claim = ClaimEnvelope.create(
        context=context,
        role=AgentRole.WORKER,
        producer_id="worker-model",
        payload_type="application/json",
        payload={"answer": 42},
    )
    obligations = (
        VerificationObligation(
            id="range-check",
            kind="deterministic.range",
            description="Check that the answer is inside the authorized range.",
            criterion_ids=("bounded",),
            payload={"minimum": 0, "maximum": 100},
        ),
    )

    # A real adapter computes these observations with a deterministic tool before
    # the independent evidence authority authenticates the complete bundle.
    observations = (
        Observation(
            obligation_id="range-check",
            status=EvidenceStatus.PASSED,
            observed="42 is inside [0, 100]",
            expected="answer inside [0, 100]",
        ),
    )
    evidence = evidence_authority.issue(
        context,
        spec,
        claim,
        obligations,
        observations,
    )
    result = kernel.evaluate(context, spec, claim, evidence)

    assert result.verdict == "VERIFIED"
    assert result.artifact is not None
    print(result.verdict, result.artifact.payload)


if __name__ == "__main__":
    main()
