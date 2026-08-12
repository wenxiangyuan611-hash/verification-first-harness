"""Non-agent authorities for specification approval and receipt signing."""

from __future__ import annotations

import hmac
import uuid
from collections.abc import Callable
from dataclasses import replace
from hashlib import sha256
from typing import Protocol

from verification_harness.decision import Decision, Observation, VerificationObligation
from verification_harness.evidence import EvidenceBundle
from verification_harness.protocol import (
    PROTOCOL_VERSION,
    AuthorizedSpec,
    ClaimEnvelope,
    RunContext,
    SpecAuthorization,
    SpecProposal,
)
from verification_harness.receipts import DecisionReceipt
from verification_harness.schema import canonical_json

MINIMUM_AUTHORITY_KEY_BYTES = 32
SPEC_SIGNATURE_DOMAIN = b"verification-first/spec-authorization/v3"
EVIDENCE_SIGNATURE_DOMAIN = b"verification-first/evidence-bundle/v3"
RECEIPT_SIGNATURE_DOMAIN = b"verification-first/decision-receipt/v3"


def _normalize_key(key: bytes | str) -> bytes:
    if isinstance(key, str):
        key_bytes = key.encode("utf-8")
    elif isinstance(key, bytes):
        key_bytes = key
    else:
        raise TypeError("authority key must be bytes or str")
    if len(key_bytes) < MINIMUM_AUTHORITY_KEY_BYTES:
        raise ValueError(
            f"authority key must contain at least {MINIMUM_AUTHORITY_KEY_BYTES} bytes"
        )
    return key_bytes


def _signature(key: bytes, domain: bytes, payload: object) -> str:
    encoded = domain + b"\x00" + canonical_json(payload).encode("utf-8")
    return hmac.new(key, encoded, sha256).hexdigest()


class SpecAuthority(Protocol):
    """Trusted boundary that authorizes acceptance criteria, not an agent role."""

    authority_id: str

    def authorize(self, proposal: SpecProposal) -> AuthorizedSpec: ...

    def verify(self, spec: AuthorizedSpec) -> bool: ...


class ReceiptAuthority(Protocol):
    """Trusted boundary that signs deterministic decisions, not raw agent claims."""

    authority_id: str

    def issue(
        self,
        context: RunContext,
        spec: AuthorizedSpec,
        claim: ClaimEnvelope,
        evidence: EvidenceBundle,
        decision: Decision,
    ) -> DecisionReceipt: ...

    def verify(self, receipt: DecisionReceipt) -> bool: ...


class EvidenceVerifier(Protocol):
    """Verify evidence without exposing an evidence-issuing operation."""

    verifier_id: str

    def verify(self, bundle: EvidenceBundle) -> bool: ...


class EvidenceAuthority(EvidenceVerifier, Protocol):
    """Authenticate evidence collected outside the receipt-signing boundary."""

    def issue(
        self,
        context: RunContext,
        spec: AuthorizedSpec,
        claim: ClaimEnvelope,
        obligations: tuple[VerificationObligation, ...],
        observations: tuple[Observation, ...],
    ) -> EvidenceBundle: ...


class EvidenceVerifierView:
    """A least-authority facade that intentionally exposes verification only."""

    def __init__(self, verifier: EvidenceVerifier) -> None:
        verifier_id = verifier.verifier_id
        if verifier_id.__class__ is not str or not verifier_id.strip():
            raise ValueError("evidence verifier_id must be a non-empty string")
        if not callable(verifier.verify):
            raise TypeError("evidence verifier must provide a verify operation")
        self.verifier_id = verifier_id
        self._verify = verifier.verify

    def verify(self, bundle: EvidenceBundle) -> bool:
        return self._verify(bundle)


class HMACSpecAuthority:
    """Authorize exact specification proposals with an isolated HMAC key."""

    def __init__(
        self,
        authority_id: str,
        key: bytes | str,
        approval_policy: Callable[[SpecProposal], bool],
    ) -> None:
        if authority_id.__class__ is not str or not authority_id.strip():
            raise ValueError("authority_id must be a non-empty string")
        if not callable(approval_policy):
            raise TypeError("approval_policy must be callable")
        self.authority_id = authority_id
        self._key = _normalize_key(key)
        self._approval_policy = approval_policy

    def authorize(self, proposal: SpecProposal) -> AuthorizedSpec:
        if proposal.__class__ is not SpecProposal:
            raise TypeError("proposal must be SpecProposal")
        approved = self._approval_policy(proposal)
        if approved.__class__ is not bool:
            raise TypeError("specification approval policy must return bool")
        if not approved:
            raise PermissionError("specification proposal was not authorized")
        payload = {
            "authority_id": self.authority_id,
            "proposal_digest": proposal.digest,
            "protocol_version": PROTOCOL_VERSION,
        }
        authorization = SpecAuthorization(
            authority_id=self.authority_id,
            proposal_digest=proposal.digest,
            protocol_version=PROTOCOL_VERSION,
            signature=_signature(self._key, SPEC_SIGNATURE_DOMAIN, payload),
        )
        return AuthorizedSpec(proposal=proposal, authorization=authorization)

    def verify(self, spec: AuthorizedSpec) -> bool:
        if spec.__class__ is not AuthorizedSpec:
            return False
        authorization = spec.authorization
        if authorization.authority_id != self.authority_id:
            return False
        if authorization.proposal_digest != spec.proposal.digest:
            return False
        expected = _signature(
            self._key,
            SPEC_SIGNATURE_DOMAIN,
            authorization.signing_payload,
        )
        return hmac.compare_digest(authorization.signature, expected)


class HMACEvidenceAuthority:
    """Attest observations after an independent backend completes its checks."""

    def __init__(self, verifier_id: str, key: bytes | str) -> None:
        if verifier_id.__class__ is not str or not verifier_id.strip():
            raise ValueError("verifier_id must be a non-empty string")
        self.verifier_id = verifier_id
        self._key = _normalize_key(key)

    def issue(
        self,
        context: RunContext,
        spec: AuthorizedSpec,
        claim: ClaimEnvelope,
        obligations: tuple[VerificationObligation, ...],
        observations: tuple[Observation, ...],
    ) -> EvidenceBundle:
        bundle = EvidenceBundle(
            bundle_id=uuid.uuid4().hex,
            run_id=context.run_id,
            context_digest=context.digest,
            authorized_spec_digest=spec.digest,
            claim_digest=claim.digest,
            attempt=claim.attempt,
            obligations=obligations,
            observations=observations,
            verifier_id=self.verifier_id,
            protocol_version=PROTOCOL_VERSION,
        )
        return replace(
            bundle,
            signature=_signature(
                self._key,
                EVIDENCE_SIGNATURE_DOMAIN,
                bundle.signing_payload,
            ),
        )

    def verify(self, bundle: EvidenceBundle) -> bool:
        if bundle.__class__ is not EvidenceBundle:
            return False
        if bundle.verifier_id != self.verifier_id or not bundle.signature:
            return False
        expected = _signature(
            self._key,
            EVIDENCE_SIGNATURE_DOMAIN,
            bundle.signing_payload,
        )
        return hmac.compare_digest(bundle.signature, expected)


class HMACReceiptAuthority:
    """Sign decisions after policy evaluation; verification backends never receive this key."""

    def __init__(self, authority_id: str, key: bytes | str) -> None:
        if authority_id.__class__ is not str or not authority_id.strip():
            raise ValueError("authority_id must be a non-empty string")
        self.authority_id = authority_id
        self._key = _normalize_key(key)

    def issue(
        self,
        context: RunContext,
        spec: AuthorizedSpec,
        claim: ClaimEnvelope,
        evidence: EvidenceBundle,
        decision: Decision,
    ) -> DecisionReceipt:
        receipt = DecisionReceipt(
            receipt_id=uuid.uuid4().hex,
            run_id=context.run_id,
            context_digest=context.digest,
            authorized_spec_digest=spec.digest,
            claim_digest=claim.digest,
            evidence_bundle_digest=evidence.digest,
            verifier_id=evidence.verifier_id,
            attempt=claim.attempt,
            verdict=decision.verdict,
            obligations=evidence.obligations,
            observations=evidence.observations,
            traces=decision.traces,
            authority_id=self.authority_id,
            protocol_version=PROTOCOL_VERSION,
        )
        return replace(
            receipt,
            signature=_signature(
                self._key,
                RECEIPT_SIGNATURE_DOMAIN,
                receipt.signing_payload,
            ),
        )

    def verify(self, receipt: DecisionReceipt) -> bool:
        if receipt.__class__ is not DecisionReceipt:
            return False
        if receipt.authority_id != self.authority_id or not receipt.signature:
            return False
        expected = _signature(
            self._key,
            RECEIPT_SIGNATURE_DOMAIN,
            receipt.signing_payload,
        )
        return hmac.compare_digest(receipt.signature, expected)
