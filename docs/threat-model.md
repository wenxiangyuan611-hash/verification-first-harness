# Threat Model

## Protected properties

- An unverified or failed claim must not be approved.
- A receipt must be bound to the exact claim, spec, attempt, obligations, and evidence.
- Receipt tampering must be detectable.
- Failed evidence must be authenticated before it can influence a repair.
- One untrusted component failure must not terminate or bypass the controller.
- Ordinary candidate failure must not terminate the controller.
- Candidate non-termination must be bounded by a controller-side timeout.

## Adversaries

The design assumes Planner, Worker, Critic, Reviewer, model provider, prompt, and
candidate output may be incorrect or adversarial. It also assumes a downstream
consumer may accidentally receive stale or mismatched artifacts.

## Current defenses

- canonical serialization and SHA-256 content digests;
- HMAC-SHA-256 signed complete receipts;
- exact ordered obligation/evidence matching;
- fresh child process per test case;
- isolated Python mode (`-I`), minimized environment, and parent timeout;
- fail-closed handling for unknown obligation types.
- strict component return-type and task/attempt identity checks;
- bounded critic obligation kinds, identifiers, counts, descriptions, and payloads;
- containment of component exceptions and `SystemExit` as structured rejection.

## Out of scope for the built-in runner

The subprocess runner does not defend against hostile filesystem access, network
access, cloud metadata access, process spawning, disk exhaustion, kernel attacks,
or sandbox escape. The response-size check is post-execution and is not an OS
resource quota. Child process descendants may require platform-specific process
group termination.

Production execution should use a disposable sandbox per claim with:

- no host or model credentials;
- read-only inputs and a bounded writable scratch directory;
- default-deny network policy;
- CPU, memory, disk, output, process-count, and wall-clock limits;
- non-root identity and no privileged capabilities;
- destruction after receipt evidence is collected.

The signing key must never enter this execution environment.

## Residual risks

- Weak or malicious acceptance criteria can approve an incorrect solution.
- Deterministic tests prove only the properties they encode.
- HMAC verification requires controller instances to share a protected secret.
- A compromised verifier or TrustGate remains inside the trusted computing base.
- In-process agent calls cannot be forcibly terminated safely; provider adapters
  must enforce request timeouts and production isolation boundaries.
