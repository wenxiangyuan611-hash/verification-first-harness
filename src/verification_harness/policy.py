"""Policies that authorize untrusted challenge proposals."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from verification_harness.schema import Obligation, canonical_json


class ChallengePolicyError(ValueError):
    """Raised when a critic proposal exceeds the authorized challenge boundary."""


@dataclass(frozen=True)
class ChallengePolicy:
    """Bound critic influence before obligations reach an independent verifier."""

    max_obligations: int = 16
    max_identifier_chars: int = 128
    max_description_chars: int = 2_000
    max_payload_bytes: int = 16_384
    allowed_kinds: frozenset[str] = field(
        default_factory=lambda: frozenset({"REQUIRED_ENTRYPOINT", "FORBIDDEN_TEXT"})
    )
    reserved_id_prefixes: tuple[str, ...] = ("HARNESS_",)

    def __post_init__(self) -> None:
        if self.max_obligations < 0:
            raise ValueError("max_obligations must be zero or greater")
        if self.max_identifier_chars < 1:
            raise ValueError("max_identifier_chars must be positive")
        if self.max_description_chars < 1:
            raise ValueError("max_description_chars must be positive")
        if self.max_payload_bytes < 1:
            raise ValueError("max_payload_bytes must be positive")
        if not self.allowed_kinds or any(not kind.strip() for kind in self.allowed_kinds):
            raise ValueError("allowed_kinds must contain non-empty values")

    def authorize(
        self,
        baseline: tuple[Obligation, ...],
        proposals: tuple[Obligation, ...],
    ) -> tuple[Obligation, ...]:
        """Return baseline plus authorized critic proposals, or fail closed."""
        if len(proposals) > self.max_obligations:
            raise ChallengePolicyError(
                f"critic proposed {len(proposals)} obligations; limit is {self.max_obligations}"
            )

        baseline_ids = {obligation.id for obligation in baseline}
        seen_ids = set(baseline_ids)
        authorized: list[Obligation] = []
        for proposal in proposals:
            if proposal.__class__ is not Obligation:
                raise ChallengePolicyError(
                    f"critic obligation must be Obligation, got {type(proposal).__name__}"
                )
            string_fields = (proposal.id, proposal.kind, proposal.description)
            if any(value.__class__ is not str for value in string_fields):
                raise ChallengePolicyError("critic obligation text fields must be strings")
            if proposal.id in seen_ids:
                raise ChallengePolicyError(f"duplicate obligation ID: {proposal.id}")
            if any(proposal.id.startswith(prefix) for prefix in self.reserved_id_prefixes):
                raise ChallengePolicyError(
                    f"critic obligation ID uses a reserved prefix: {proposal.id}"
                )
            if len(proposal.id) > self.max_identifier_chars:
                raise ChallengePolicyError(f"critic obligation ID is too long: {proposal.id}")
            if proposal.kind not in self.allowed_kinds:
                raise ChallengePolicyError(
                    f"critic obligation kind is not authorized: {proposal.kind}"
                )
            if not proposal.description.strip():
                raise ChallengePolicyError("critic obligation description must be non-empty")
            if len(proposal.description) > self.max_description_chars:
                raise ChallengePolicyError(
                    f"critic obligation description exceeds {self.max_description_chars} characters"
                )
            encoded_payload = canonical_json(proposal.payload)
            payload_size = len(encoded_payload.encode("utf-8"))
            if payload_size > self.max_payload_bytes:
                raise ChallengePolicyError(
                    f"critic obligation payload exceeds {self.max_payload_bytes} bytes"
                )
            normalized_payload = json.loads(encoded_payload)
            if normalized_payload.__class__ is not dict:
                raise ChallengePolicyError("critic obligation payload must be a JSON object")
            normalized = Obligation(
                proposal.id,
                proposal.kind,
                proposal.description,
                normalized_payload,
            )
            self._validate_payload(normalized)
            seen_ids.add(proposal.id)
            authorized.append(normalized)

        return baseline + tuple(authorized)

    @staticmethod
    def _validate_payload(proposal: Obligation) -> None:
        required_field = {
            "REQUIRED_ENTRYPOINT": "name",
            "FORBIDDEN_TEXT": "text",
        }.get(proposal.kind)
        if required_field is None:
            return
        value = proposal.payload.get(required_field)
        if not isinstance(value, str) or not value:
            raise ChallengePolicyError(
                f"{proposal.kind} payload requires a non-empty string field {required_field!r}"
            )
