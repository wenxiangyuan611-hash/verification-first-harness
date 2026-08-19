"""Run Codex as worker, OpenCode as critic, and Python as final verifier.

This live example uses existing Codex and OpenCode authentication and may consume
model usage. Both agents are untrusted. OpenCode may only select a check from the
controller-owned catalog; it cannot issue evidence or decide the final verdict.
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
    OpenCodeAgentProvider,
    OpenCodePermissionProfile,
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


def build_runtime(proposal: SpecProposal, database: Path) -> VerificationRuntime:
    store = SQLiteRunStore(database)
    action_gate = ActionGate(
        AllowListActionPolicy(
            frozenset({"agent.invoke", "agent.challenge", "verifier.invoke"})
        )
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
        description="Run a Codex worker through an OpenCode challenge and verifier gate."
    )
    parser.add_argument("--codex-model", help="Optional Codex model.")
    parser.add_argument(
        "--opencode-model",
        help="Optional OpenCode provider/model identifier.",
    )
    parser.add_argument(
        "--opencode-executable",
        default="opencode",
        help="OpenCode CLI executable or absolute path.",
    )
    parser.add_argument(
        "--cwd",
        default=".",
        help="Explicit read-only or disposable context directory.",
    )
    parser.add_argument(
        "--codex-home",
        help="Optional existing writable Codex home for the worker process.",
    )
    parser.add_argument(
        "--codex-sqlite-home",
        help="Optional existing directory for Codex SQLite runtime state.",
    )
    parser.add_argument(
        "--database",
        default="work/codex-opencode-smoke.sqlite3",
        help="SQLite audit database path.",
    )
    args = parser.parse_args()

    cwd = Path(args.cwd).resolve(strict=True)
    if not cwd.is_dir():
        parser.error("--cwd must be an existing directory")
    database = Path(args.database).resolve()
    database.parent.mkdir(parents=True, exist_ok=True)

    proposal = SpecProposal(
        proposal_id="codex-opencode-smoke-spec",
        task_id="codex-opencode-answer-task",
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
    exact_answer_code = (
        "import json,sys; c=json.load(sys.stdin); p=c.get('payload'); "
        "sys.exit(0 if p == {'answer': 42} and type(p['answer']) is int else 1)"
    )
    baseline = (
        VerificationObligation(
            id="mandatory-exact-answer",
            kind="command.exit_code",
            description="Check the exact answer in an independent Python process.",
            criterion_ids=("answer-is-42",),
            payload={
                "argv": [sys.executable, "-c", exact_answer_code],
                "expected_exit_code": 0,
            },
        ),
    )
    no_extra_fields_code = (
        "import json,sys; c=json.load(sys.stdin); p=c.get('payload'); "
        "sys.exit(0 if isinstance(p,dict) and set(p)=={'answer'} else 1)"
    )
    challenge_catalog = (
        VerificationObligation(
            id="optional-no-extra-fields",
            kind="command.exit_code",
            description="Try the stricter exact-field-set check.",
            criterion_ids=("answer-is-42",),
            payload={
                "argv": [sys.executable, "-c", no_extra_fields_code],
                "expected_exit_code": 0,
            },
        ),
    )
    worker = CodexAgentProvider(
        model=args.codex_model,
        provider_id="codex/worker",
        cwd=cwd,
        sandbox=CodexSandbox.READ_ONLY,
        codex_home=args.codex_home,
        sqlite_home=args.codex_sqlite_home,
    )
    critic = OpenCodeAgentProvider(
        model=args.opencode_model,
        provider_id="opencode/critic",
        executable=args.opencode_executable,
        cwd=cwd,
        profile=OpenCodePermissionProfile.DENY_ALL,
    )
    result = build_runtime(proposal, database).run(
        proposal=proposal,
        provider=worker,
        critic_provider=critic,
        input_payload={
            "instruction": (
                "Solve the authorized question. Return application/json with payload "
                "exactly equal to an object containing only the integer field answer."
            )
        },
        obligations=baseline,
        challenge_obligations=challenge_catalog,
        max_repairs=1,
    )

    summary = {
        "run_id": result.context.run_id,
        "verdict": result.verdict,
        "attempts": [
            {
                "verdict": attempt.verdict,
                "challenge": (
                    None
                    if attempt.challenge is None
                    else list(attempt.challenge.selected_obligation_ids)
                ),
            }
            for attempt in result.attempts
        ],
        "artifact": None if result.artifact is None else result.artifact.payload,
        "database": str(database),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if result.verdict == Verdict.VERIFIED.value else 1


if __name__ == "__main__":
    raise SystemExit(main())
