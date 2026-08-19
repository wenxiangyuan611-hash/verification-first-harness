# Verification Runtime

The 0.3.0 alpha runtime composes an untrusted agent provider with an action policy,
quarantine store, independent verifier plugins, and the 0.2.0 trust kernel.

## Run the reference flow

```bash
python -m pip install -e .
verification-harness-runtime demo
```

The demo deliberately produces `41`, receives a deterministic rejection, repairs to
`42`, re-verifies, and emits a `VerifiedArtifact`. It also prints the SQLite path and
`run_id`. Use both to inspect the durable trust labels:

```bash
verification-harness-runtime --database PATH inspect RUN_ID
```

## Provider wire contract

`CommandAgentProvider` starts an argv tuple with `shell=False` and sends one canonical
JSON request on stdin. The request includes:

```json
{
  "run_id": "...",
  "task_id": "...",
  "context_digest": "...",
  "authorized_spec_digest": "...",
  "role": "WORKER",
  "attempt": 1,
  "parent_claim_ids": [],
  "input": {
    "authorized_spec": {},
    "task_input": {}
  },
  "feedback": {}
}
```

The command must write exactly this shape to stdout:

```json
{
  "payload_type": "application/json",
  "payload": {"candidate": "value"}
}
```

Extra top-level fields, duplicate JSON keys, non-JSON output, non-zero exit status,
timeouts, and oversized output fail before claim creation. The provider cannot mark
its output verified.

SDK integrations should use `CallableAgentProvider` and return an `AgentOutput`.
Their own timeout, credential, and isolation controls remain the integrator's
responsibility.

## Command verifier obligation

The alpha command verifier supports `command.exit_code` obligations:

```python
VerificationObligation(
    id="acceptance-check",
    kind="command.exit_code",
    description="Run an independent deterministic check.",
    criterion_ids=("criterion-id",),
    payload={
        "argv": ["python", "verify.py"],
        "expected_exit_code": 0,
    },
)
```

The verifier receives the canonical `ClaimEnvelope` on stdin. It runs without a
shell and produces `PASSED`, `FAILED`, or `ERROR` evidence. Obligation definitions
belong to trusted configuration; never build `argv` by interpolating agent output.

## Trust zones

- `AUTHORIZED`: the exact acceptance contract approved by `SpecAuthority`.
- `QUARANTINED`: raw provider claims, including repair attempts.
- `AUTHENTICATED_EVIDENCE`: signed observations from the evidence boundary.
- `DECISION_ONLY`: signed decisions that do not themselves carry claim payload.
- `VERIFIED`: a `VerifiedArtifact` issued after full gate validation.

Failed claim payloads may return to the same untrusted provider as repair feedback,
but failed `RuntimeAttempt` results expose only IDs, digests, evidence, and receipts.
This allows repair inside the work zone without treating the failed payload as a
trusted downstream fact.

## Alpha security boundary

The command provider and command verifier are local subprocess adapters, not hostile
code sandboxes. They inherit the configured environment, can access ambient host
resources, and apply output limits after capture. Use a container, microVM, VM, or
remote service boundary before running hostile providers or candidate code.

SQLite protects local transactional receipt use and checks stored payload digests.
It does not prevent a host administrator from rolling back or coherently rewriting
the database. See the [threat model](threat-model.md) for production requirements.
