"""Independent execution and receipt signing.

The built-in subprocess runner is a reliability boundary, not a hostile-code
sandbox. See SECURITY.md and docs/threat-model.md before production use.
"""

from __future__ import annotations

import ast
import base64
import hmac
import json
import os
import secrets
import subprocess
import sys
import tempfile
import uuid
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import Any, TypedDict

from verification_harness.agents.base import BaseAgent
from verification_harness.schema import (
    Claim,
    Evidence,
    Obligation,
    Spec,
    VerificationReceipt,
    VerificationStatus,
    canonical_json,
)


class ExecutionResult(TypedDict):
    ok: bool
    output: Any
    error: str


class VerifierAgent(BaseAgent):
    """Evaluate obligations and sign complete receipts with HMAC-SHA-256."""

    PROTOCOL_VERSION = "2.0"
    MINIMUM_KEY_BYTES = 32

    def __init__(
        self,
        signing_key: bytes | str | None = None,
        execution_timeout_seconds: float = 2.0,
        max_response_bytes: int = 1_000_000,
    ) -> None:
        super().__init__("verifier_01", "Verifier")
        if execution_timeout_seconds <= 0:
            raise ValueError("execution_timeout_seconds must be positive")
        if max_response_bytes < 1:
            raise ValueError("max_response_bytes must be positive")

        configured_key = signing_key or os.environ.get("VERIFICATION_HARNESS_SIGNING_KEY")
        if configured_key is None:
            # A random process-local key is convenient for demos. Production callers
            # should inject a stable key from a secret manager into the controller.
            configured_key = secrets.token_bytes(self.MINIMUM_KEY_BYTES)
        key_bytes = (
            configured_key.encode("utf-8")
            if isinstance(configured_key, str)
            else configured_key
        )
        if len(key_bytes) < self.MINIMUM_KEY_BYTES:
            raise ValueError(f"signing_key must contain at least {self.MINIMUM_KEY_BYTES} bytes")

        self._signing_key = key_bytes
        self.execution_timeout_seconds = execution_timeout_seconds
        self.max_response_bytes = max_response_bytes

    def sign_receipt(self, receipt: VerificationReceipt) -> str:
        payload = canonical_json(receipt.signing_payload).encode("utf-8")
        return hmac.new(self._signing_key, payload, sha256).hexdigest()

    def verify_receipt_signature(self, receipt: VerificationReceipt) -> bool:
        return hmac.compare_digest(receipt.signature, self.sign_receipt(receipt))

    def verify(
        self,
        claim: Claim,
        spec: Spec,
        obligations: tuple[Obligation, ...],
    ) -> VerificationReceipt:
        self.log(f"Executing verification suite for Attempt #{claim.attempt}...")
        obligations = tuple(obligations)
        self._validate_obligations(obligations)
        evidence = tuple(
            self._verify_obligation(claim, spec, obligation) for obligation in obligations
        )
        unsigned_receipt = VerificationReceipt(
            run_id=uuid.uuid4().hex,
            claim_digest=claim.digest,
            spec_digest=spec.digest,
            attempt=claim.attempt,
            protocol_version=self.PROTOCOL_VERSION,
            obligations=obligations,
            evidence=evidence,
            signature="",
        )
        receipt = replace(unsigned_receipt, signature=self.sign_receipt(unsigned_receipt))
        if receipt.is_passed:
            self.log("[PASS] Verification passed: all obligations satisfied.")
        else:
            failed_count = sum(not item.is_passed for item in evidence)
            self.log(f"[FAIL] Verification failed: {failed_count} obligation(s) failed.")
        return receipt

    @staticmethod
    def _validate_obligations(obligations: tuple[Obligation, ...]) -> None:
        if not obligations:
            raise ValueError("verification requires at least one obligation")
        ids = [obligation.id for obligation in obligations]
        if len(ids) != len(set(ids)):
            raise ValueError("obligation IDs must be unique")

    def _verify_obligation(self, claim: Claim, spec: Spec, obligation: Obligation) -> Evidence:
        if obligation.kind == "TEST_EXECUTION":
            return self._verify_test_execution(claim, spec, obligation)
        if obligation.kind == "REQUIRED_ENTRYPOINT":
            return self._verify_entrypoint(claim, obligation)
        if obligation.kind == "FORBIDDEN_TEXT":
            return self._verify_forbidden_text(claim, obligation)
        return Evidence(
            obligation_id=obligation.id,
            status=VerificationStatus.FAILED,
            observed="Unknown obligation kind",
            expected_repr="A verifier-supported obligation kind",
            error=f"Unknown obligation kind: {obligation.kind}",
        )

    def _verify_test_execution(self, claim: Claim, spec: Spec, obligation: Obligation) -> Evidence:
        for test_case in spec.test_cases:
            result = self._execute_case(claim.code, spec.entrypoint, test_case.input)
            if not result["ok"]:
                return Evidence(
                    obligation_id=obligation.id,
                    status=VerificationStatus.FAILED,
                    observed=f"Test case {test_case.id} did not complete",
                    expected_repr="All test cases pass",
                    error=result["error"],
                )
            if result["output"] != test_case.expected:
                return Evidence(
                    obligation_id=obligation.id,
                    status=VerificationStatus.FAILED,
                    observed=f"Test case {test_case.id} returned {result['output']!r}",
                    expected_repr=repr(test_case.expected),
                    error="Unexpected result",
                )
        return Evidence(
            obligation_id=obligation.id,
            status=VerificationStatus.PASSED,
            observed="All test cases passed in fresh subprocesses",
            expected_repr="All test cases pass",
        )

    @staticmethod
    def _verify_entrypoint(claim: Claim, obligation: Obligation) -> Evidence:
        name = obligation.payload.get("name", "")
        try:
            tree = ast.parse(claim.code)
            found = any(
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
                for node in ast.walk(tree)
            )
        except SyntaxError as error:
            return Evidence(
                obligation_id=obligation.id,
                status=VerificationStatus.FAILED,
                observed="Candidate is not valid Python syntax",
                expected_repr=f"Defines callable '{name}'",
                error=str(error),
            )
        return Evidence(
            obligation_id=obligation.id,
            status=VerificationStatus.PASSED if found else VerificationStatus.FAILED,
            observed=f"Entrypoint '{name}' {'found' if found else 'not found'}",
            expected_repr=f"Defines callable '{name}'",
            error="Entrypoint missing" if not found else "",
        )

    @staticmethod
    def _verify_forbidden_text(claim: Claim, obligation: Obligation) -> Evidence:
        text = obligation.payload.get("text", "")
        found = bool(text) and text in claim.code
        return Evidence(
            obligation_id=obligation.id,
            status=VerificationStatus.FAILED if found else VerificationStatus.PASSED,
            observed=f"Forbidden text {text!r} {'found' if found else 'not found'}",
            expected_repr=f"Does not contain {text!r}",
            error="Forbidden text found" if found else "",
        )

    def _execute_case(self, code: str, entrypoint: str, value: Any) -> ExecutionResult:
        """Run one case in a fresh child process with a parent-side timeout."""
        try:
            request_json = canonical_json({"entrypoint": entrypoint, "input": value})
        except (TypeError, ValueError) as error:
            return {"ok": False, "output": None, "error": f"Invalid test input: {error}"}

        with tempfile.TemporaryDirectory(prefix="verification_harness_") as directory:
            runner_path = Path(directory) / "runner.py"
            runner_path.write_text(self._runner_source(code), encoding="utf-8")
            try:
                completed = subprocess.run(
                    [sys.executable, "-I", str(runner_path)],
                    input=request_json,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    cwd=directory,
                    env=self._child_environment(),
                    timeout=self.execution_timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return {
                    "ok": False,
                    "output": None,
                    "error": f"Timed out after {self.execution_timeout_seconds:.2f} seconds",
                }
            except OSError as error:
                return {
                    "ok": False,
                    "output": None,
                    "error": f"Could not start candidate process: {error}",
                }

        if completed.returncode != 0:
            return {
                "ok": False,
                "output": None,
                "error": f"Candidate process exited with code {completed.returncode}",
            }
        if len(completed.stdout.encode("utf-8")) > self.max_response_bytes:
            return {"ok": False, "output": None, "error": "Runner response exceeded size limit"}
        try:
            response = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            return {"ok": False, "output": None, "error": f"Invalid runner response: {error}"}
        if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
            return {"ok": False, "output": None, "error": "Runner response has an invalid shape"}
        if not response["ok"]:
            return {
                "ok": False,
                "output": None,
                "error": str(response.get("error", "Candidate execution failed")),
            }
        return {"ok": True, "output": response.get("output"), "error": ""}

    @staticmethod
    def _child_environment() -> dict[str, str]:
        """Minimize ambient configuration visible to the child process."""
        environment = {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUNBUFFERED": "1",
        }
        system_root = os.environ.get("SYSTEMROOT")
        if os.name == "nt" and system_root:
            environment["SystemRoot"] = system_root
        return environment

    @staticmethod
    def _runner_source(code: str) -> str:
        encoded_code = base64.b64encode(code.encode("utf-8")).decode("ascii")
        return f'''import base64
import json
import sys

CANDIDATE_CODE = base64.b64decode({encoded_code!r}).decode("utf-8")
rpc_stdout = sys.stdout
sys.stdout = sys.stderr

def report(payload):
    rpc_stdout.write(json.dumps(payload, ensure_ascii=False, allow_nan=False))
    rpc_stdout.flush()

try:
    request = json.load(sys.stdin)
    namespace = {{"__name__": "__candidate__"}}
    exec(compile(CANDIDATE_CODE, "<candidate>", "exec"), namespace, namespace)
    function = namespace.get(request["entrypoint"])
    if not callable(function):
        raise NameError(f"Entrypoint {{request['entrypoint']!r}} is not callable")
    report({{"ok": True, "output": function(request["input"])}})
except BaseException as error:
    report({{"ok": False, "error": f"{{type(error).__name__}}: {{error}}"}})
'''
