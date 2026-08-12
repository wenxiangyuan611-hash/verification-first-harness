"""Verification-first orchestration and trust-gate enforcement."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from verification_harness.interfaces import Critic, Planner, Verifier, Worker
from verification_harness.schema import Claim, Obligation, Spec, TaskState, VerificationReceipt


class TrustGate:
    """Validate a complete signed receipt before allowing propagation."""

    @staticmethod
    def propagate(
        claim: Claim,
        spec: Spec,
        receipt: VerificationReceipt,
        verifier: Verifier,
        expected_obligations: tuple[Obligation, ...],
        downstream_callback: Callable[[Claim, VerificationReceipt], Any],
    ) -> Any:
        if not receipt.is_passed:
            raise ValueError("TrustGate blocked propagation: receipt indicates verification failed")
        if receipt.claim_digest != claim.digest:
            raise ValueError("TrustGate blocked propagation: claim digest mismatch")
        if receipt.spec_digest != spec.digest:
            raise ValueError("TrustGate blocked propagation: spec digest mismatch")
        if receipt.attempt != claim.attempt:
            raise ValueError("TrustGate blocked propagation: claim attempt mismatch")
        if receipt.protocol_version != verifier.PROTOCOL_VERSION:
            raise ValueError("TrustGate blocked propagation: unsupported protocol version")
        if receipt.obligations != tuple(expected_obligations):
            raise ValueError("TrustGate blocked propagation: obligation set mismatch")
        if not verifier.verify_receipt_signature(receipt):
            raise ValueError("TrustGate blocked propagation: invalid verifier signature")
        return downstream_callback(claim, receipt)


class TrustGateEngine:
    """Orchestrate propose, challenge, verify, repair, and re-verify."""

    def __init__(
        self,
        planner: Planner,
        worker: Worker,
        critic: Critic,
        verifier: Verifier,
        max_repairs: int = 2,
    ) -> None:
        if max_repairs < 0:
            raise ValueError("max_repairs must be zero or greater")
        self.planner = planner
        self.worker = worker
        self.critic = critic
        self.verifier = verifier
        self.max_repairs = max_repairs
        self.state = TaskState.PLANNING
        self.audit_trail: list[dict[str, str]] = []

    def log_state(self, message: str) -> None:
        border = "=" * 60
        print(f"\n{border}\n[STATE: {self.state.value}] {message}\n{border}")
        self.audit_trail.append({"state": self.state.value, "message": message})

    def run(self, task_id: str) -> dict[str, Any]:
        self.state = TaskState.PLANNING
        self.audit_trail = []
        self.log_state("Initializing task specification and test requirements...")
        spec = self.planner.create_spec(task_id)

        attempt = 1
        self.state = TaskState.WORKING
        self.log_state(f"Worker generating initial claim (Attempt #{attempt})...")
        claim = self.worker.propose(attempt, spec)

        for _ in range(self.max_repairs + 1):
            self.state = TaskState.CHALLENGING
            self.log_state(f"Critic performing adversarial challenge on Claim #{attempt}...")
            critic_obligations = self.critic.challenge(claim, spec)
            baseline_obligation = Obligation(
                id="HARNESS_TEST_PASS",
                kind="TEST_EXECUTION",
                description="Candidate must pass every specified test case without an exception.",
            )
            obligations = (baseline_obligation,) + critic_obligations

            self.state = TaskState.VERIFYING
            self.log_state(f"Verifier executing isolated candidate process for Claim #{attempt}...")
            receipt = self.verifier.verify(claim, spec, obligations)
            if receipt.is_passed:
                self.state = TaskState.PASSED
                self.log_state("[TRUST GATE] Claim verified and approved.")

                def approved_result(
                    approved_claim: Claim,
                    approved_receipt: VerificationReceipt,
                    verified_attempt: int = attempt,
                ) -> dict[str, Any]:
                    return {
                        "status": "APPROVED",
                        "final_state": self.state.value,
                        "attempts": verified_attempt,
                        "claim": approved_claim,
                        "receipt": approved_receipt,
                        "audit_trail": tuple(self.audit_trail),
                    }

                return TrustGate.propagate(
                    claim,
                    spec,
                    receipt,
                    self.verifier,
                    obligations,
                    approved_result,
                )

            if attempt > self.max_repairs:
                self.state = TaskState.REJECTED
                self.log_state("[TRUST GATE] Maximum repairs exceeded. Claim rejected.")
                return {
                    "status": "REJECTED",
                    "final_state": self.state.value,
                    "attempts": attempt,
                    "claim": claim,
                    "receipt": receipt,
                    "audit_trail": tuple(self.audit_trail),
                }

            self.state = TaskState.REPAIRING
            attempt += 1
            self.log_state(f"[TRUST GATE] Claim rejected. Starting repair attempt #{attempt}...")
            claim = self.worker.repair(attempt, spec, receipt)

        raise RuntimeError("unreachable repair-loop state")
