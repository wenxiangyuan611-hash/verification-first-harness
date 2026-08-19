# Threat Model

## Protected properties

- A raw, rejected, inconclusive, or errored claim must not acquire propagation authority.
- Acceptance criteria must be authorized independently from the proposing agent.
- Evidence and decisions must be bound to one exact run, spec, claim, and attempt.
- Evidence and receipt tampering must be detectable.
- A successful receipt must be consumable at most once.
- Failed evidence must be authenticated before it may influence repair.
- One untrusted component failure must fail closed instead of bypassing the controller.
- A denied or approval-required action must not invoke its controlled operation.
- Persistence must not upgrade a quarantined value into a verified value.
- Audit events must expose decision and propagation history without claim promotion.

## Adversaries and faults

The design assumes any Planner, Worker, Critic, Reviewer, Master, Sub-Agent, model
provider, prompt, or candidate output may be incorrect, stale, malformed, compromised,
or adversarial. This does not imply model vendors intend to attack users. The same
controls defend against hallucination, prompt injection, adapter bugs, stale state,
correlated mistakes, accidental mutation, forged test results, and confused-deputy
errors.

A downstream consumer may also accidentally reuse a stale receipt or treat a
diagnostic claim as approved. The artifact boundary addresses this second class of
integration errors.

## Current defenses

- canonical JSON detachment and SHA-256 content digests;
- independent authorization of exact specification proposals;
- role-neutral claims with explicit parent lineage and attempt number;
- separate HMAC authorities for specification, evidence, and decision receipts;
- exact ordered obligation/observation matching and full criterion traceability;
- explicit deterministic verdict precedence;
- full receipt revalidation before propagation;
- fresh context nonce plus atomic single-use receipt consumption;
- no raw claim in generic failed `KernelDecision` values;
- provider output is converted to a quarantined claim before verification;
- default-deny action policy before agent and verifier invocation;
- verifier plugin exceptions and unsupported kinds become `ERROR` evidence;
- durable SQLite trust labels with payload-digest validation on read;
- transactional single-use receipt consumption across local process restarts;
- hash-chained, lock-serialized audit events;
- fail-closed component shape, identity, signature, and policy checks;
- bounded critic obligation types and payloads in the Python adapter;
- fresh child process per Python test and parent-enforced timeout.

## Trust assumptions

The kernel cannot prove a false or incomplete acceptance contract is correct. It can
only prove that the configured authority authorized that exact contract and that the
evidence satisfies it. Weak criteria therefore remain a primary residual risk.

Likewise, an evidence authority is trusted to attest what its backend actually
observed. Separating its key from the receipt authority limits key scope but does not
make a compromised verifier truthful. Production systems should diversify tools,
isolate backends, protect keys, and make verifier provenance auditable.

## In-process limitations

Python object capabilities are architectural guardrails, not a security boundary
against code running in the same interpreter. Same-process hostile code can inspect
memory, import private names, or monkey-patch modules. `VerifiedArtifact` prevents
ordinary callers from constructing an approved value through the public constructor,
but process isolation is required against a malicious local module.

Command providers have request timeouts, but callable SDK adapters still depend on
the SDK or isolation boundary to honor cancellation. The controller can contain a
reported `TimeoutError`, but cannot safely kill an arbitrary in-process thread that
ignores cancellation. An untrusted provider with ambient host authority can also act
outside `ActionGate`; complete mediation requires process or service isolation.

The Codex adapter reduces ambient authority by defaulting to read-only and omitting
full-access mode. It also selects deny-all approval and disables web search, apps,
subagents, dependency installation, and workspace network access through supported
configuration overrides. Named MCP servers inherited from local Codex configuration
may still remain available because configuration tables merge rather than replace.
Its explicit workspace-write mode is still an SDK sandbox, not a proof that the
selected directory is disposable or isolated from trusted state.
The controller must create and police that quarantine boundary out of band, and must
not treat resulting filesystem changes as verified propagation.

## Built-in Python runner limitations

The subprocess runner is a reliability boundary, not a hostile-code sandbox. It does
not block filesystem or network access, cloud metadata, process spawning, disk
exhaustion, kernel attacks, or sandbox escape. Response size is checked after process
execution and is not an OS quota. Descendant processes may require platform-specific
group termination.

Production candidate execution should use a disposable sandbox per claim with:

- no host, model, verifier, or signing credentials;
- read-only inputs and a bounded writable scratch directory;
- default-deny network policy;
- CPU, memory, disk, output, process-count, and wall-clock limits;
- non-root identity and no privileged capabilities;
- destruction after evidence collection.

Authority keys must never enter candidate or agent execution environments.

## Persistence and distributed deployment

`SQLiteReceiptUseStore` protects local receipt consumption across process restarts,
and `SQLiteRunStore` detects simple payload changes when records are read. They do
not prevent database rollback, direct coordinated rewriting of payload and digest,
multiple hosts using copied database files, or host compromise. The hash-chained
audit sink remains in memory. Production deployments require protected transactional
storage, authenticated append-only audit persistence, external key management, and
explicit failure behavior when those dependencies are unavailable.

## Residual risks

- weak, malicious, or incomplete acceptance criteria;
- incorrect deterministic tools or poisoned external data sources;
- compromised authorities, controller runtime, or isolation platform;
- correlated verifier failures that pass the same wrong assumption;
- denial of service through expensive workloads or unavailable dependencies;
- privacy leakage if claims, evidence, or audit details contain sensitive data;
- action-policy bypass through execution paths not mediated by `ActionGate`;
- false confidence from treating `INCONCLUSIVE` as success outside the kernel.
