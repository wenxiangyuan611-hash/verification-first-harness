"""Public API for the verification-first agent harness."""

from verification_harness.engine import TrustGate, TrustGateEngine
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
    VerificationStatus,
)

__version__ = "0.1.1"

__all__ = [
    "ChallengePolicy",
    "ChallengePolicyError",
    "Claim",
    "ComponentFailure",
    "Evidence",
    "Obligation",
    "Spec",
    "TaskState",
    "TestCase",
    "TrustGate",
    "TrustGateEngine",
    "VerificationReceipt",
    "VerificationStatus",
    "__version__",
]
