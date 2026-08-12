"""Structural interfaces for model- and provider-independent agents."""

from __future__ import annotations

from typing import Protocol

from verification_harness.schema import Claim, Obligation, Spec, VerificationReceipt


class Planner(Protocol):
    """Produces a task specification proposal for an engine run."""

    def create_spec(self, task_id: str) -> Spec: ...


class Worker(Protocol):
    """Produces and repairs untrusted candidate claims."""

    def propose(self, attempt: int, spec: Spec) -> Claim: ...

    def repair(self, attempt: int, spec: Spec, receipt: VerificationReceipt) -> Claim: ...


class Critic(Protocol):
    """Attempts to falsify a claim by proposing verifier obligations."""

    def challenge(self, claim: Claim, spec: Spec) -> tuple[Obligation, ...]: ...


class Verifier(Protocol):
    """Independently evaluates obligations and authenticates receipts."""

    PROTOCOL_VERSION: str

    def verify(
        self,
        claim: Claim,
        spec: Spec,
        obligations: tuple[Obligation, ...],
    ) -> VerificationReceipt: ...

    def verify_receipt_signature(self, receipt: VerificationReceipt) -> bool: ...
