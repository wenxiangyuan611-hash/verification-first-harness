"""Run one real Codex candidate through independent verification.

This example uses the caller's existing Codex authentication and may consume model
usage. Codex runs read-only; the independent verifier is a separate Python process.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from verification_harness import (
    AcceptanceCriterion,
    ActionGate,
    AllowListActionPolicy,
    CodexAgentProvider,
    CodexSandbox,
    HMACEvidenceAuthority,
    HMACReceiptAuthority,
    HMACSpecAuthority,
    SpecProposal,
    SQLiteReceiptUseStore,
    SQLiteRunStore,
    Verdict,
    VerificationKernel,
    VerificationObligation,
    VerificationRuntime,
    VerifierRegistry,
)
from verification_harness.verifiers import CommandVerifierPlugin


def build_runtime(
    proposal: SpecProposal,
    database: Path,
) -> VerificationRuntime:
    store = SQLiteRunStore(database)
    action_gate = ActionGate(
        AllowListActionPolicy(frozenset({"agent.invoke", "verifier.invoke"}))
    )
    evidence_authority = HMACEvidenceAuthority("demo-verifier", b"e" * 32)
    kernel = VerificationKernel(
        spec_authority=HMACSpecAuthority(
            "demo-spec-authority",
            b"s" * 32,
            lambda candidate: candidate == proposal,
        ),
        evidence_verifier=evidence_authority,
        receipt_authority=HMACReceiptAuthority(
            "demo-receipt-authority",
            b"r" * 32,
        ),
        receipt_use_store=SQLiteReceiptUseStore(store),
    )
    registry = VerifierRegistry(
        "demo-verifier",
        (CommandVerifierPlugin(),),
        action_gate,
    )
    return VerificationRuntime(
        kernel=kernel,
        evidence_authority=evidence_authority,
        verifier_registry=registry,
        action_gate=action_gate,
        run_store=store,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a real read-only Codex claim through the verification gate."
    )
    parser.add_argument("--model", help="Optional Codex model; omit for configured default.")
    parser.add_argument("--cwd", default=".", help="Read-only repository/context directory.")
    parser.add_argument(
        "--database",
        default="work/codex-smoke.sqlite3",
        help="SQLite audit database path.",
    )
    args = parser.parse_args()

    cwd = Path(args.cwd).resolve(strict=True)
    if not cwd.is_dir():
        parser.error("--cwd must be an existing directory")
    database = Path(args.database).resolve()
    database.parent.mkdir(parents=True, exist_ok=True)

    proposal = SpecProposal(
        proposal_id="codex-smoke-spec",
        task_id="codex-answer-task",
        proposer_id="demo-controller",
        domain="example.arithmetic",
        criteria=(
            AcceptanceCriterion(
                "answer-is-42",
                "The candidate payload must be an object whose answer is integer 42.",
            ),
        ),
        payload={"question": "What is six multiplied by seven?"},
    )
    verifier_code = (
        "import json,sys; claim=json.load(sys.stdin); "
        "payload=claim.get('payload'); "
        "sys.exit(0 if payload == {'answer': 42} else 1)"
    )
    obligations = (
        VerificationObligation(
            id="independent-arithmetic-check",
            kind="command.exit_code",
            description="Check the exact answer in an independent Python process.",
            criterion_ids=("answer-is-42",),
            payload={
                "argv": [sys.executable, "-c", verifier_code],
                "expected_exit_code": 0,
            },
        ),
    )
    provider = CodexAgentProvider(
        model=args.model,
        provider_id="codex/worker",
        cwd=cwd,
        sandbox=CodexSandbox.READ_ONLY,
    )
    result = build_runtime(proposal, database).run(
        proposal=proposal,
        provider=provider,
        input_payload={
            "instruction": (
                "Solve the authorized question. Return application/json with payload "
                "exactly equal to an object containing only the integer field answer."
            )
        },
        obligations=obligations,
        max_repairs=1,
    )

    summary = {
        "run_id": result.context.run_id,
        "verdict": result.verdict,
        "attempts": [attempt.verdict for attempt in result.attempts],
        "artifact": None if result.artifact is None else result.artifact.payload,
        "database": str(database),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if result.verdict == Verdict.VERIFIED.value else 1


if __name__ == "__main__":
    raise SystemExit(main())
