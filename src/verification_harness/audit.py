"""Append-only, hash-chained audit events for trust-kernel decisions."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from verification_harness.schema import canonical_json, digest_value


class AuditKind(Enum):
    RUN_OPENED = "RUN_OPENED"
    CLAIM_QUARANTINED = "CLAIM_QUARANTINED"
    DECISION_ISSUED = "DECISION_ISSUED"
    ARTIFACT_PROPAGATED = "ARTIFACT_PROPAGATED"
    PROPAGATION_BLOCKED = "PROPAGATION_BLOCKED"
    RUN_REJECTED = "RUN_REJECTED"


@dataclass(frozen=True, init=False)
class AuditEvent:
    sequence: int
    context_id: str
    kind: AuditKind
    subject_digest: str
    previous_digest: str
    _details_json: str = field(repr=False)

    def __init__(
        self,
        sequence: int,
        context_id: str,
        kind: AuditKind,
        subject_digest: str,
        previous_digest: str,
        details: Any | None = None,
    ) -> None:
        if sequence.__class__ is not int or sequence < 1:
            raise ValueError("audit sequence must be a positive integer")
        for name, value in (
            ("context_id", context_id),
            ("subject_digest", subject_digest),
        ):
            if value.__class__ is not str or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if kind.__class__ is not AuditKind:
            raise TypeError("audit kind must be AuditKind")
        if previous_digest.__class__ is not str:
            raise TypeError("previous_digest must be a string")
        object.__setattr__(self, "sequence", sequence)
        object.__setattr__(self, "context_id", context_id)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "subject_digest", subject_digest)
        object.__setattr__(self, "previous_digest", previous_digest)
        detached_details = {} if details is None else details
        object.__setattr__(self, "_details_json", canonical_json(detached_details))

    @property
    def details(self) -> Any:
        return json.loads(self._details_json)

    @property
    def digest(self) -> str:
        return digest_value(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "context_id": self.context_id,
            "kind": self.kind.value,
            "subject_digest": self.subject_digest,
            "previous_digest": self.previous_digest,
            "details": self.details,
        }


class AuditSink(Protocol):
    def append(
        self,
        context_id: str,
        kind: AuditKind,
        subject_digest: str,
        details: Any | None = None,
    ) -> AuditEvent: ...


class InMemoryAuditSink:
    """Reference append-only sink; production implementations may use durable storage."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._lock = threading.Lock()

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return self.snapshot()

    def snapshot(self, context_id: str | None = None) -> tuple[AuditEvent, ...]:
        with self._lock:
            if context_id is None:
                return tuple(self._events)
            return tuple(event for event in self._events if event.context_id == context_id)

    def append(
        self,
        context_id: str,
        kind: AuditKind,
        subject_digest: str,
        details: Any | None = None,
    ) -> AuditEvent:
        with self._lock:
            previous_digest = self._events[-1].digest if self._events else ""
            event = AuditEvent(
                sequence=len(self._events) + 1,
                context_id=context_id,
                kind=kind,
                subject_digest=subject_digest,
                previous_digest=previous_digest,
                details=details,
            )
            self._events.append(event)
            return event

    def verify_chain(self) -> bool:
        events = self.snapshot()
        previous_digest = ""
        for sequence, event in enumerate(events, start=1):
            if event.sequence != sequence or event.previous_digest != previous_digest:
                return False
            previous_digest = event.digest
        return True
