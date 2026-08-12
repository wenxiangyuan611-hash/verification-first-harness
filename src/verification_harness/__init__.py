"""Public API for the verification-first agent harness."""

from verification_harness.engine import TrustGate, TrustGateEngine
from verification_harness.schema import (
    Claim,
    Evidence,
    Obligation,
    Spec,
    TaskState,
    TestCase,
    VerificationReceipt,
    VerificationStatus,
)

__version__ = "0.1.0"

__all__ = [
    "Claim",
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
