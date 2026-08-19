# Verification Runtime

The 0.3.0 beta runtime composes an untrusted agent provider with an action policy,
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

## First-party Codex SDK provider

Install the optional dependency and import the provider directly:

```bash
python -m pip install -e ".[codex]"
```

```python
from pathlib import Path

from verification_harness import CodexAgentProvider, CodexSandbox

provider = CodexAgentProvider(
    provider_id="codex/worker",
    cwd=Path.cwd(),
    sandbox=CodexSandbox.READ_ONLY,
)
```

`CodexAgentProvider` uses the official
[`openai-codex` Python SDK](https://developers.openai.com/codex/sdk) and its existing
local authentication. The beta extra is constrained to the tested `0.147.x` SDK
line. It creates a fresh ephemeral thread for every
`AgentRequest`, passes a fixed JSON Schema to `thread.run(output_schema=...)`, and
then independently applies the harness's duplicate-key and exact-shape parser to
`final_response`. Missing responses, SDK errors, extra fields, duplicate keys,
oversized responses, and malformed runner values fail before claim creation.

The runner also selects `ApprovalMode.deny_all` and applies restrictive Codex
configuration overrides: web search, apps, subagents, skill dependency installation,
workspace network access, login shells, history persistence, and startup update
checks are disabled; shell environment inheritance is reduced to `core`. These are
defense-in-depth controls, not a complete outer sandbox. In particular, current
Codex config merging cannot reliably replace an inherited table of individually
named MCP servers. Use a clean Codex profile/home or an external execution boundary
when local MCP configuration is outside the controller's trust policy.

The default is `CodexSandbox.READ_ONLY`. `WORKSPACE_WRITE` requires an explicit
existing `cwd`; point it only at a disposable or quarantined worktree. The adapter
does not expose `full_access`. A writable Codex thread may change files before its
final claim is verified, so those files must remain outside trusted downstream
state until an independent verifier accepts the claim and the gate issues a
`VerifiedArtifact`.

The synchronous adapter currently relies on the SDK for cancellation and app-server
termination. A production controller still needs a process, container, VM, or
remote-service boundary with an external wall-clock deadline.

A complete live example is available at
[`examples/codex_runtime.py`](../examples/codex_runtime.py). It uses a read-only
Codex provider, quarantines the candidate, checks it in an independent Python
process, and prints payload only from the resulting verified artifact. Running it
makes a real Codex model call using the caller's existing account:

```bash
python examples/codex_runtime.py
```

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

## Beta security boundary

The command provider and command verifier are local subprocess adapters, not hostile
code sandboxes. They inherit the configured environment, can access ambient host
resources, and apply output limits after capture. Use a container, microVM, VM, or
remote service boundary before running hostile providers or candidate code.

SQLite protects local transactional receipt use and checks stored payload digests.
It does not prevent a host administrator from rolling back or coherently rewriting
the database. See the [threat model](threat-model.md) for production requirements.
