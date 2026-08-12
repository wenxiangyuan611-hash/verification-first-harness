"""Public API for the verification-first agent harness."""

from verification_harness.audit import AuditEvent, AuditKind, AuditSink, InMemoryAuditSink
from verification_harness.authority import (
    EvidenceAuthority,
    EvidenceVerifier,
    EvidenceVerifierView,
    HMACEvidenceAuthority,
    HMACReceiptAuthority,
    HMACSpecAuthority,
    ReceiptAuthority,
    SpecAuthority,
)
from verification_harness.decision import (
    CriterionTrace,
    Decision,
    DecisionPolicy,
    Observation,
    VerificationObligation,
)
from verification_harness.engine import TrustGate, TrustGateEngine
from verification_harness.evidence import EvidenceBundle
from verification_harness.gate import (
    InMemoryReceiptUseStore,
    ReceiptUseStore,
    ReplayError,
    TrustGate as ArtifactTrustGate,
    VerifiedArtifact,
)
from verification_harness.kernel import KernelDecision, VerificationKernel
from verification_harness.policy import ChallengePolicy, ChallengePolicyError
from verification_harness.protocol import (
    PROTOCOL_VERSION,
    AcceptanceCriterion,
    AgentRole,
    AuthorizedSpec,
    ClaimEnvelope,
    EvidenceStatus,
    RunContext,
    SpecAuthorization,
    SpecProposal,
    Verdict,
)
from verification_harness.receipts import DecisionReceipt
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

__version__ = "0.2.0"

__all__ = [
    "PROTOCOL_VERSION",
    "AcceptanceCriterion",
    "AgentRole",
    "ArtifactTrustGate",
    "AuditEvent",
    "AuditKind",
    "AuditSink",
    "AuthorizedSpec",
    "ChallengePolicy",
    "ChallengePolicyError",
    "Claim",
    "ClaimEnvelope",
    "ComponentFailure",
    "CriterionTrace",
    "Decision",
    "DecisionPolicy",
    "DecisionReceipt",
    "Evidence",
    "EvidenceAuthority",
    "EvidenceBundle",
    "EvidenceStatus",
    "EvidenceVerifier",
    "EvidenceVerifierView",
    "HMACEvidenceAuthority",
    "HMACReceiptAuthority",
    "HMACSpecAuthority",
    "InMemoryAuditSink",
    "InMemoryReceiptUseStore",
    "KernelDecision",
    "Obligation",
    "Observation",
    "ReceiptAuthority",
    "ReceiptUseStore",
    "ReplayError",
    "RunContext",
    "Spec",
    "SpecAuthorization",
    "SpecAuthority",
    "SpecProposal",
    "TaskState",
    "TestCase",
    "TrustGate",
    "TrustGateEngine",
    "Verdict",
    "VerificationKernel",
    "VerificationObligation",
    "VerificationReceipt",
    "VerificationStatus",
    "VerifiedArtifact",
    "__version__",
]
