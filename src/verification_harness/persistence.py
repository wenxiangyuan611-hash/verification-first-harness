"""SQLite-backed durable run records and single-use receipt consumption."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from verification_harness.evidence import EvidenceBundle
from verification_harness.gate import ReplayError, VerifiedArtifact
from verification_harness.protocol import AuthorizedSpec, ClaimEnvelope, RunContext
from verification_harness.receipts import DecisionReceipt
from verification_harness.schema import canonical_json, digest_value


class RunRecordKind(Enum):
    AUTHORIZED_SPEC = "AUTHORIZED_SPEC"
    CLAIM = "CLAIM"
    EVIDENCE = "EVIDENCE"
    RECEIPT = "RECEIPT"
    ARTIFACT = "ARTIFACT"


class TrustLabel(Enum):
    AUTHORIZED = "AUTHORIZED"
    QUARANTINED = "QUARANTINED"
    AUTHENTICATED_EVIDENCE = "AUTHENTICATED_EVIDENCE"
    DECISION_ONLY = "DECISION_ONLY"
    VERIFIED = "VERIFIED"


@dataclass(frozen=True, init=False)
class StoredRunRecord:
    """A detached durable record with an explicit trust label."""

    sequence: int
    run_id: str
    kind: RunRecordKind
    subject_id: str
    trust_label: TrustLabel
    payload_digest: str
    _payload_json: str = field(repr=False)

    def __init__(
        self,
        *,
        sequence: int,
        run_id: str,
        kind: RunRecordKind,
        subject_id: str,
        trust_label: TrustLabel,
        payload: Any,
        payload_digest: str,
    ) -> None:
        if sequence.__class__ is not int or sequence < 1:
            raise ValueError("stored record sequence must be a positive integer")
        for name, value in (
            ("run_id", run_id),
            ("subject_id", subject_id),
            ("payload_digest", payload_digest),
        ):
            if value.__class__ is not str or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if kind.__class__ is not RunRecordKind:
            raise TypeError("stored record kind must be RunRecordKind")
        if trust_label.__class__ is not TrustLabel:
            raise TypeError("stored record trust_label must be TrustLabel")
        payload_json = canonical_json(payload)
        if digest_value(json.loads(payload_json)) != payload_digest:
            raise ValueError("stored record payload digest mismatch")
        object.__setattr__(self, "sequence", sequence)
        object.__setattr__(self, "run_id", run_id)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "subject_id", subject_id)
        object.__setattr__(self, "trust_label", trust_label)
        object.__setattr__(self, "payload_digest", payload_digest)
        object.__setattr__(self, "_payload_json", payload_json)

    @property
    def payload(self) -> Any:
        return json.loads(self._payload_json)


class SQLiteRunStore:
    """Append protocol records without upgrading their trust during persistence."""

    def __init__(self, path: str | Path) -> None:
        if isinstance(path, Path):
            database_path = path
        elif path.__class__ is str and path.strip():
            database_path = Path(path)
        else:
            raise ValueError("SQLite store path must be a non-empty path")
        if str(database_path) == ":memory:":
            raise ValueError("SQLiteRunStore requires a durable file path")
        database_path.parent.mkdir(parents=True, exist_ok=True)
        self._database_path = str(database_path)
        self._initialize()

    @property
    def path(self) -> str:
        return self._database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database_path, timeout=5.0)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._session() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    context_json TEXT NOT NULL,
                    context_digest TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS run_records (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    trust_label TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_digest TEXT NOT NULL,
                    UNIQUE (run_id, kind, subject_id),
                    FOREIGN KEY (run_id) REFERENCES runs(run_id)
                );
                CREATE TABLE IF NOT EXISTS receipt_uses (
                    receipt_id TEXT PRIMARY KEY,
                    receipt_digest TEXT NOT NULL,
                    run_id TEXT NOT NULL
                );
                """
            )

    def save_context(self, context: RunContext) -> None:
        if context.__class__ is not RunContext:
            raise TypeError("run store requires RunContext")
        context_json = canonical_json(context.to_dict())
        with self._session() as connection:
            existing = connection.execute(
                "SELECT context_json, context_digest FROM runs WHERE run_id = ?",
                (context.run_id,),
            ).fetchone()
            if existing is not None:
                if existing != (context_json, context.digest):
                    raise ValueError("run ID already exists with different context")
                return
            connection.execute(
                "INSERT INTO runs(run_id, context_json, context_digest) VALUES (?, ?, ?)",
                (context.run_id, context_json, context.digest),
            )

    def load_context(self, run_id: str) -> RunContext:
        if run_id.__class__ is not str or not run_id.strip():
            raise ValueError("run_id must be a non-empty string")
        with self._session() as connection:
            row = connection.execute(
                "SELECT context_json, context_digest FROM runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        if row is None:
            raise KeyError(run_id)
        context = RunContext.from_dict(json.loads(row[0]))
        if context.digest != row[1]:
            raise ValueError("stored run context digest mismatch")
        return context

    def _append(
        self,
        *,
        run_id: str,
        kind: RunRecordKind,
        subject_id: str,
        trust_label: TrustLabel,
        payload: Any,
    ) -> None:
        payload_json = canonical_json(payload)
        payload_digest = digest_value(json.loads(payload_json))
        with self._session() as connection:
            existing = connection.execute(
                """
                SELECT trust_label, payload_json, payload_digest
                FROM run_records WHERE run_id = ? AND kind = ? AND subject_id = ?
                """,
                (run_id, kind.value, subject_id),
            ).fetchone()
            if existing is not None:
                if existing != (trust_label.value, payload_json, payload_digest):
                    raise ValueError("stored protocol subject was reused with different contents")
                return
            connection.execute(
                """
                INSERT INTO run_records(
                    run_id, kind, subject_id, trust_label, payload_json, payload_digest
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    kind.value,
                    subject_id,
                    trust_label.value,
                    payload_json,
                    payload_digest,
                ),
            )

    def save_authorized_spec(self, run_id: str, spec: AuthorizedSpec) -> None:
        if spec.__class__ is not AuthorizedSpec:
            raise TypeError("run store requires AuthorizedSpec")
        self._append(
            run_id=run_id,
            kind=RunRecordKind.AUTHORIZED_SPEC,
            subject_id=spec.digest,
            trust_label=TrustLabel.AUTHORIZED,
            payload=spec.to_dict(),
        )

    def quarantine_claim(self, claim: ClaimEnvelope) -> None:
        if claim.__class__ is not ClaimEnvelope:
            raise TypeError("run store requires ClaimEnvelope")
        self._append(
            run_id=claim.run_id,
            kind=RunRecordKind.CLAIM,
            subject_id=claim.claim_id,
            trust_label=TrustLabel.QUARANTINED,
            payload=claim.to_dict(),
        )

    def save_evidence(self, evidence: EvidenceBundle) -> None:
        if evidence.__class__ is not EvidenceBundle:
            raise TypeError("run store requires EvidenceBundle")
        self._append(
            run_id=evidence.run_id,
            kind=RunRecordKind.EVIDENCE,
            subject_id=evidence.bundle_id,
            trust_label=TrustLabel.AUTHENTICATED_EVIDENCE,
            payload=evidence.to_dict(),
        )

    def save_receipt(self, receipt: DecisionReceipt) -> None:
        if receipt.__class__ is not DecisionReceipt:
            raise TypeError("run store requires DecisionReceipt")
        self._append(
            run_id=receipt.run_id,
            kind=RunRecordKind.RECEIPT,
            subject_id=receipt.receipt_id,
            trust_label=TrustLabel.DECISION_ONLY,
            payload=receipt.to_dict(),
        )

    def save_artifact(self, artifact: VerifiedArtifact) -> None:
        if artifact.__class__ is not VerifiedArtifact:
            raise TypeError("run store requires VerifiedArtifact")
        self._append(
            run_id=artifact.run_id,
            kind=RunRecordKind.ARTIFACT,
            subject_id=artifact.receipt_id,
            trust_label=TrustLabel.VERIFIED,
            payload=artifact.to_dict(),
        )

    def records(self, run_id: str) -> tuple[StoredRunRecord, ...]:
        if run_id.__class__ is not str or not run_id.strip():
            raise ValueError("run_id must be a non-empty string")
        with self._session() as connection:
            rows = connection.execute(
                """
                SELECT sequence, run_id, kind, subject_id, trust_label,
                       payload_json, payload_digest
                FROM run_records WHERE run_id = ? ORDER BY sequence
                """,
                (run_id,),
            ).fetchall()
        return tuple(
            StoredRunRecord(
                sequence=row[0],
                run_id=row[1],
                kind=RunRecordKind(row[2]),
                subject_id=row[3],
                trust_label=TrustLabel(row[4]),
                payload=json.loads(row[5]),
                payload_digest=row[6],
            )
            for row in rows
        )


class SQLiteReceiptUseStore:
    """Persist single-use receipt consumption across controller restarts."""

    def __init__(self, store: SQLiteRunStore) -> None:
        if store.__class__ is not SQLiteRunStore:
            raise TypeError("SQLiteReceiptUseStore requires SQLiteRunStore")
        self._store = store

    def consume(self, receipt: DecisionReceipt) -> None:
        if receipt.__class__ is not DecisionReceipt:
            raise TypeError("receipt use store requires DecisionReceipt")
        connection = self._store._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT receipt_digest FROM receipt_uses WHERE receipt_id = ?",
                (receipt.receipt_id,),
            ).fetchone()
            if existing is not None:
                if existing[0] != receipt.digest:
                    raise ReplayError("receipt ID was reused with different contents")
                raise ReplayError("receipt has already been consumed")
            connection.execute(
                """
                INSERT INTO receipt_uses(receipt_id, receipt_digest, run_id)
                VALUES (?, ?, ?)
                """,
                (receipt.receipt_id, receipt.digest, receipt.run_id),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
