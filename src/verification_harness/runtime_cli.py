"""Small CLI for the v0.3 alpha runtime demo and durable-record inspection."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from verification_harness.actions import ActionGate, AllowListActionPolicy
from verification_harness.authority import (
    HMACEvidenceAuthority,
    HMACReceiptAuthority,
    HMACSpecAuthority,
)
from verification_harness.decision import VerificationObligation
from verification_harness.kernel import VerificationKernel
from verification_harness.persistence import SQLiteReceiptUseStore, SQLiteRunStore
from verification_harness.protocol import AcceptanceCriterion, SpecProposal
from verification_harness.providers import CommandAgentProvider
from verification_harness.runtime import VerificationRuntime
from verification_harness.verifiers import CommandVerifierPlugin, VerifierRegistry


def _demo(database: Path) -> dict[str, Any]:
    proposal = SpecProposal(
        proposal_id="runtime-demo-spec",
        task_id="runtime-demo-answer",
        proposer_id="demo-planner",
        domain="example.answer",
        criteria=(AcceptanceCriterion("correct", "Answer must equal 42."),),
        payload={"question": "What is six times seven?"},
    )
    provider_code = (
        "import json,sys; r=json.load(sys.stdin); a=r['attempt']; "
        "json.dump({'payload_type':'application/json',"
        "'payload':{'answer':41 if a==1 else 42}},sys.stdout)"
    )
    verifier_code = (
        "import json,sys; c=json.load(sys.stdin); "
        "sys.exit(0 if c['payload']['answer']==42 else 1)"
    )
    obligations = (
        VerificationObligation(
            id="answer-check",
            kind="command.exit_code",
            description="Check the answer in an independent process.",
            criterion_ids=("correct",),
            payload={
                "argv": [sys.executable, "-c", verifier_code],
                "expected_exit_code": 0,
            },
        ),
    )
    store = SQLiteRunStore(database)
    action_gate = ActionGate(
        AllowListActionPolicy(frozenset({"agent.invoke", "verifier.invoke"}))
    )
    evidence_authority = HMACEvidenceAuthority("demo-verifier", b"e" * 32)
    kernel = VerificationKernel(
        spec_authority=HMACSpecAuthority(
            "demo-spec-authority",
            b"s" * 32,
            lambda value: value == proposal,
        ),
        evidence_verifier=evidence_authority,
        receipt_authority=HMACReceiptAuthority("demo-receipt-authority", b"r" * 32),
        receipt_use_store=SQLiteReceiptUseStore(store),
    )
    runtime = VerificationRuntime(
        kernel=kernel,
        evidence_authority=evidence_authority,
        verifier_registry=VerifierRegistry(
            "demo-verifier",
            (CommandVerifierPlugin(),),
            action_gate,
        ),
        action_gate=action_gate,
        run_store=store,
    )
    result = runtime.run(
        proposal=proposal,
        provider=CommandAgentProvider(
            "demo-command-agent",
            (sys.executable, "-c", provider_code),
        ),
        input_payload={"instruction": "answer the authorized question"},
        obligations=obligations,
        max_repairs=1,
    )
    return {
        "run_id": result.context.run_id,
        "verdict": result.verdict,
        "attempts": [
            {
                "attempt": attempt.attempt,
                "claim_id": attempt.claim_id,
                "verdict": attempt.verdict,
            }
            for attempt in result.attempts
        ],
        "artifact": None if result.artifact is None else result.artifact.to_dict(),
        "database": str(database.resolve()),
    }


def _inspect(database: Path, run_id: str) -> dict[str, Any]:
    store = SQLiteRunStore(database)
    context = store.load_context(run_id)
    return {
        "context": context.to_dict(),
        "records": [
            {
                "sequence": record.sequence,
                "kind": record.kind.value,
                "subject_id": record.subject_id,
                "trust_label": record.trust_label.value,
                "payload_digest": record.payload_digest,
            }
            for record in store.records(run_id)
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(prog="verification-harness-runtime")
    parser.add_argument(
        "--database",
        type=Path,
        default=Path(".verification-harness/runtime.sqlite3"),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("demo", help="run one rejection, repair, and verification flow")
    inspect_parser = subparsers.add_parser("inspect", help="inspect durable trust labels")
    inspect_parser.add_argument("run_id")
    arguments = parser.parse_args()
    if arguments.command == "demo":
        output = _demo(arguments.database)
    else:
        output = _inspect(arguments.database, arguments.run_id)
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
