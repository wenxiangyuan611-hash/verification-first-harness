"""Deterministic worker used to demonstrate repair behavior."""

from __future__ import annotations

from verification_harness.agents.base import BaseAgent
from verification_harness.schema import Claim, Spec, VerificationReceipt


class WorkerAgent(BaseAgent):
    """Return preconfigured candidate code without requiring an LLM API key.

    Implement the structural ``Worker`` interface to connect any model provider.
    Model output remains an untrusted ``Claim`` regardless of provider.
    """

    def __init__(
        self,
        faulty_implementations: dict[str, str] | None = None,
        repaired_implementations: dict[str, str] | None = None,
    ) -> None:
        super().__init__("worker_01", "Worker")
        self.faulty_implementations = faulty_implementations or {}
        self.repaired_implementations = repaired_implementations or {}

    def propose(self, attempt: int, spec: Spec) -> Claim:
        self.log(f"Proposing candidate for '{spec.task_id}' (Attempt #{attempt})...")
        code = self.faulty_implementations.get(
            spec.task_id,
            f"def {spec.entrypoint}(value):\n    raise NotImplementedError\n",
        )
        return Claim(self.agent_id, attempt, code, "Initial implementation.")

    def repair(self, attempt: int, spec: Spec, receipt: VerificationReceipt) -> Claim:
        failed_evidence = [evidence for evidence in receipt.evidence if not evidence.is_passed]
        self.log(
            f"Repairing '{spec.task_id}' (Attempt #{attempt}) from "
            f"{len(failed_evidence)} failed obligation(s)..."
        )
        code = self.repaired_implementations.get(
            spec.task_id,
            f"def {spec.entrypoint}(value):\n    raise NotImplementedError\n",
        )
        return Claim(
            self.agent_id,
            attempt,
            code,
            f"Repair based on {len(failed_evidence)} failed obligation(s).",
        )
