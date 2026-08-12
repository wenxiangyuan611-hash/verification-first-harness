"""Verification-first orchestration and trust-gate enforcement."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from verification_harness.boundary import AgentCallBoundary, ComponentCallError
from verification_harness.interfaces import Critic, Planner, Verifier, Worker
from verification_harness.policy import ChallengePolicy, ChallengePolicyError
from verification_harness.schema import (
    Claim,
    ComponentFailure,
    Evidence,
    Obligation,
    Spec,
    TaskState,
    TestCase,
    VerificationReceipt,
    canonical_json,
)


class TrustGate:
    """Validate a complete signed receipt before allowing propagation."""

    @staticmethod
    def validate_receipt(
        claim: Claim,
        spec: Spec,
        receipt: VerificationReceipt,
        verifier: Verifier,
        expected_obligations: tuple[Obligation, ...],
        *,
        require_pass: bool,
    ) -> None:
        """Validate receipt integrity for both approval and repair paths."""
        if not receipt.is_complete:
            raise ValueError("TrustGate blocked receipt: evidence is incomplete or misordered")
        if not receipt.is_final:
            raise ValueError("TrustGate blocked receipt: evidence contains a pending status")
        if receipt.claim_digest != claim.digest:
            raise ValueError("TrustGate blocked receipt: claim digest mismatch")
        if receipt.spec_digest != spec.digest:
            raise ValueError("TrustGate blocked receipt: spec digest mismatch")
        if receipt.attempt != claim.attempt:
            raise ValueError("TrustGate blocked receipt: claim attempt mismatch")
        if receipt.protocol_version != verifier.PROTOCOL_VERSION:
            raise ValueError("TrustGate blocked receipt: unsupported protocol version")
        if receipt.obligations != tuple(expected_obligations):
            raise ValueError("TrustGate blocked receipt: obligation set mismatch")
        signature_valid = verifier.verify_receipt_signature(receipt)
        if signature_valid.__class__ is not bool:
            raise TypeError("TrustGate blocked receipt: signature verifier must return bool")
        if not signature_valid:
            raise ValueError("TrustGate blocked receipt: invalid verifier signature")
        if require_pass and not receipt.is_passed:
            raise ValueError("TrustGate blocked propagation: receipt indicates verification failed")

    @staticmethod
    def propagate(
        claim: Claim,
        spec: Spec,
        receipt: VerificationReceipt,
        verifier: Verifier,
        expected_obligations: tuple[Obligation, ...],
        downstream_callback: Callable[[Claim, VerificationReceipt], Any],
    ) -> Any:
        TrustGate.validate_receipt(
            claim,
            spec,
            receipt,
            verifier,
            expected_obligations,
            require_pass=True,
        )
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
        challenge_policy: ChallengePolicy | None = None,
    ) -> None:
        if max_repairs < 0:
            raise ValueError("max_repairs must be zero or greater")
        self.planner = planner
        self.worker = worker
        self.critic = critic
        self.verifier = verifier
        self.max_repairs = max_repairs
        self.challenge_policy = challenge_policy or ChallengePolicy()
        self.state = TaskState.PLANNING
        self.audit_trail: list[dict[str, str]] = []

    def log_state(self, message: str) -> None:
        border = "=" * 60
        print(f"\n{border}\n[STATE: {self.state.value}] {message}\n{border}")
        self.audit_trail.append({"state": self.state.value, "message": message})

    @staticmethod
    def _validate_spec(spec: Spec, task_id: str) -> None:
        if spec.task_id != task_id:
            raise ValueError(
                f"planner returned task_id {spec.task_id!r}; expected {task_id!r}"
            )

    @staticmethod
    def _validate_claim(claim: Claim, attempt: int) -> None:
        if claim.attempt != attempt:
            raise ValueError(
                f"worker returned attempt {claim.attempt}; expected {attempt}"
            )

    @staticmethod
    def _snapshot_spec(spec: Spec) -> Spec:
        """Detach the authorized contract from mutable values exposed to agents."""
        data = json.loads(
            canonical_json(
                {
                    "task_id": spec.task_id,
                    "description": spec.description,
                    "requirements": spec.requirements,
                    "test_cases": spec.test_cases,
                    "entrypoint": spec.entrypoint,
                }
            )
        )
        return Spec(
            task_id=data["task_id"],
            description=data["description"],
            requirements=tuple(data["requirements"]),
            test_cases=tuple(
                TestCase(item["id"], item["input"], item["expected"])
                for item in data["test_cases"]
            ),
            entrypoint=data["entrypoint"],
        )

    @staticmethod
    def _snapshot_claim(claim: Claim) -> Claim:
        """Normalize a worker value into an engine-owned immutable claim."""
        data = json.loads(
            canonical_json(
                {
                    "worker_id": claim.worker_id,
                    "attempt": claim.attempt,
                    "code": claim.code,
                    "description": claim.description,
                }
            )
        )
        return Claim(**data)

    @staticmethod
    def _snapshot_receipt(receipt: VerificationReceipt) -> VerificationReceipt:
        """Detach repair evidence from the engine-owned authenticated receipt."""
        obligations = tuple(
            Obligation(
                obligation.id,
                obligation.kind,
                obligation.description,
                json.loads(canonical_json(obligation.payload)),
            )
            for obligation in receipt.obligations
        )
        evidence = tuple(
            Evidence(
                item.obligation_id,
                item.status,
                item.observed,
                item.expected_repr,
                item.error,
            )
            for item in receipt.evidence
        )
        return VerificationReceipt(
            run_id=receipt.run_id,
            claim_digest=receipt.claim_digest,
            spec_digest=receipt.spec_digest,
            attempt=receipt.attempt,
            protocol_version=receipt.protocol_version,
            obligations=obligations,
            evidence=evidence,
            signature=receipt.signature,
        )

    @staticmethod
    def _baseline_obligations() -> tuple[Obligation, ...]:
        return (
            Obligation(
                id="HARNESS_TEST_PASS",
                kind="TEST_EXECUTION",
                description="Candidate must pass every specified test case without an exception.",
            ),
        )

    def _reject_component_failure(
        self,
        failure: ComponentFailure,
        attempts: int,
        claim: Claim | None = None,
        receipt: VerificationReceipt | None = None,
    ) -> dict[str, Any]:
        self.state = TaskState.REJECTED
        self.log_state(
            "[TRUST GATE] Component failure contained; run rejected: "
            f"{failure.component}.{failure.operation} "
            f"({failure.error_type}: {failure.message})"
        )
        return {
            "status": "REJECTED",
            "final_state": self.state.value,
            "attempts": attempts,
            "claim": claim,
            "receipt": receipt,
            "failure": failure,
            "audit_trail": tuple(self.audit_trail),
        }

    def run(self, task_id: str) -> dict[str, Any]:
        self.state = TaskState.PLANNING
        self.audit_trail = []
        self.log_state("Initializing task specification and test requirements...")
        try:
            proposed_spec = AgentCallBoundary.invoke(
                "planner",
                "create_spec",
                lambda: self.planner.create_spec(task_id),
                Spec,
                lambda value: self._validate_spec(value, task_id),
            )
        except ComponentCallError as error:
            return self._reject_component_failure(error.failure, attempts=0)
        try:
            spec = self._snapshot_spec(proposed_spec)
        except (KeyboardInterrupt, GeneratorExit):
            raise
        except BaseException as error:  # noqa: B036 - normalize planner-owned values.
            failure = AgentCallBoundary.failure("planner", "snapshot_spec", error)
            return self._reject_component_failure(failure, attempts=0)

        attempt = 1
        self.state = TaskState.WORKING
        self.log_state(f"Worker generating initial claim (Attempt #{attempt})...")
        try:
            proposed_claim = AgentCallBoundary.invoke(
                "worker",
                "propose",
                lambda: self.worker.propose(attempt, self._snapshot_spec(spec)),
                Claim,
                lambda value: self._validate_claim(value, attempt),
            )
        except ComponentCallError as error:
            return self._reject_component_failure(error.failure, attempts=attempt)
        try:
            claim = self._snapshot_claim(proposed_claim)
        except (KeyboardInterrupt, GeneratorExit):
            raise
        except BaseException as error:  # noqa: B036 - normalize worker-owned values.
            failure = AgentCallBoundary.failure("worker", "snapshot_claim", error)
            return self._reject_component_failure(failure, attempts=attempt)

        for _ in range(self.max_repairs + 1):
            self.state = TaskState.CHALLENGING
            self.log_state(f"Critic performing adversarial challenge on Claim #{attempt}...")
            try:
                critic_obligations = AgentCallBoundary.invoke(
                    "critic",
                    "challenge",
                    lambda current_claim=claim: self.critic.challenge(
                        current_claim,
                        self._snapshot_spec(spec),
                    ),
                    tuple,
                )
                obligations = self.challenge_policy.authorize(
                    self._baseline_obligations(),
                    critic_obligations,
                )
            except ComponentCallError as error:
                return self._reject_component_failure(
                    error.failure,
                    attempts=attempt,
                    claim=claim,
                )
            except ChallengePolicyError as error:
                failure = AgentCallBoundary.failure("critic", "challenge_policy", error)
                return self._reject_component_failure(failure, attempts=attempt, claim=claim)
            except (KeyboardInterrupt, GeneratorExit):
                raise
            except BaseException as error:  # noqa: B036 - contain malformed critic data.
                failure = AgentCallBoundary.failure("critic", "challenge_policy", error)
                return self._reject_component_failure(failure, attempts=attempt, claim=claim)

            self.state = TaskState.VERIFYING
            self.log_state(f"Verifier executing isolated candidate process for Claim #{attempt}...")
            receipt: VerificationReceipt | None = None
            try:
                receipt = AgentCallBoundary.invoke(
                    "verifier",
                    "verify",
                    lambda current_claim=claim, current_obligations=obligations: (
                        self.verifier.verify(current_claim, spec, current_obligations)
                    ),
                    VerificationReceipt,
                )
                TrustGate.validate_receipt(
                    claim,
                    spec,
                    receipt,
                    self.verifier,
                    obligations,
                    require_pass=False,
                )
            except ComponentCallError as error:
                return self._reject_component_failure(
                    error.failure,
                    attempts=attempt,
                    claim=claim,
                )
            except (KeyboardInterrupt, GeneratorExit):
                raise
            except BaseException as error:  # noqa: B036 - contain verifier termination.
                failure = AgentCallBoundary.failure("verifier", "receipt_validation", error)
                return self._reject_component_failure(
                    failure,
                    attempts=attempt,
                    claim=claim,
                    receipt=receipt,
                )

            if receipt is None:
                raise RuntimeError("unreachable verifier receipt state")

            if receipt.is_passed:

                def approved_result(
                    approved_claim: Claim,
                    approved_receipt: VerificationReceipt,
                    verified_attempt: int = attempt,
                ) -> dict[str, Any]:
                    self.state = TaskState.PASSED
                    self.log_state("[TRUST GATE] Claim verified and approved.")
                    return {
                        "status": "APPROVED",
                        "final_state": self.state.value,
                        "attempts": verified_attempt,
                        "claim": approved_claim,
                        "receipt": approved_receipt,
                        "failure": None,
                        "audit_trail": tuple(self.audit_trail),
                    }

                try:
                    return TrustGate.propagate(
                        claim,
                        spec,
                        receipt,
                        self.verifier,
                        obligations,
                        approved_result,
                    )
                except (KeyboardInterrupt, GeneratorExit):
                    raise
                except BaseException as error:  # noqa: B036 - contain verifier termination.
                    failure = AgentCallBoundary.failure("trust_gate", "propagate", error)
                    return self._reject_component_failure(
                        failure,
                        attempts=attempt,
                        claim=claim,
                        receipt=receipt,
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
                    "failure": None,
                    "audit_trail": tuple(self.audit_trail),
                }

            self.state = TaskState.REPAIRING
            attempt += 1
            self.log_state(f"[TRUST GATE] Claim rejected. Starting repair attempt #{attempt}...")
            try:
                repaired_claim = AgentCallBoundary.invoke(
                    "worker",
                    "repair",
                    lambda current_attempt=attempt, failed_receipt=receipt: self.worker.repair(
                        current_attempt,
                        self._snapshot_spec(spec),
                        self._snapshot_receipt(failed_receipt),
                    ),
                    Claim,
                    lambda value, current_attempt=attempt: self._validate_claim(
                        value,
                        current_attempt,
                    ),
                )
            except ComponentCallError as error:
                return self._reject_component_failure(
                    error.failure,
                    attempts=attempt,
                    claim=claim,
                    receipt=receipt,
                )
            try:
                claim = self._snapshot_claim(repaired_claim)
            except (KeyboardInterrupt, GeneratorExit):
                raise
            except BaseException as error:  # noqa: B036 - normalize worker-owned values.
                failure = AgentCallBoundary.failure("worker", "snapshot_claim", error)
                return self._reject_component_failure(
                    failure,
                    attempts=attempt,
                    claim=claim,
                    receipt=receipt,
                )

        raise RuntimeError("unreachable repair-loop state")
