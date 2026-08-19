import importlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from verification_harness.codex_provider import (
    CodexAgentProvider,
    CodexRunResult,
    CodexSandbox,
    OfficialCodexRunner,
)
from verification_harness.protocol import AgentRole, RunContext
from verification_harness.providers import AgentRequest


class RecordingRunner:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls: list[dict[str, Any]] = []

    def run(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return self.result


class CodexProviderTests(unittest.TestCase):
    def request(self) -> AgentRequest:
        return AgentRequest(
            context=RunContext("run-codex", "task-codex", "nonce-codex"),
            authorized_spec_digest="spec-digest",
            role=AgentRole.WORKER,
            attempt=2,
            input_payload={"question": "six times seven"},
            feedback={"prior_answer": 41},
            parent_claim_ids=("claim-1",),
        )

    def test_provider_uses_fresh_strict_contract_and_returns_detached_output(self) -> None:
        runner = RecordingRunner(
            CodexRunResult(
                final_response=json.dumps(
                    {
                        "payload_type": "application/json",
                        "payload": {"answer": 42},
                    }
                )
            )
        )
        provider = CodexAgentProvider(model="gpt-test", runner=runner)

        output = provider.invoke(self.request())

        self.assertEqual("openai-codex/gpt-test", provider.provider_id)
        self.assertEqual({"answer": 42}, output.payload)
        output.payload["answer"] = 0
        self.assertEqual(42, output.payload["answer"])
        self.assertEqual(1, len(runner.calls))
        call = runner.calls[0]
        self.assertIs(CodexSandbox.READ_ONLY, call["sandbox"])
        self.assertIsNone(call["cwd"])
        self.assertIsNone(call["codex_home"])
        self.assertIsNone(call["sqlite_home"])
        self.assertEqual("gpt-test", call["model"])
        self.assertFalse(call["output_schema"]["additionalProperties"])
        self.assertEqual(
            ["payload_type", "payload"], call["output_schema"]["required"]
        )
        self.assertIn("untrusted candidate generator", call["prompt"])
        self.assertIn('"attempt":2', call["prompt"])
        self.assertIn('"prior_answer":41', call["prompt"])

    def test_output_schema_is_detached_from_an_untrusted_runner(self) -> None:
        response = CodexRunResult(
            final_response='{"payload_type":"application/json","payload":42}'
        )

        observed_values: list[bool] = []

        class MutatingRunner(RecordingRunner):
            def run(self, **kwargs: Any) -> Any:
                result = super().run(**kwargs)
                observed_values.append(kwargs["output_schema"]["additionalProperties"])
                kwargs["output_schema"]["additionalProperties"] = True
                return result

        runner = MutatingRunner(response)
        provider = CodexAgentProvider(runner=runner)
        provider.invoke(self.request())
        provider.invoke(self.request())
        self.assertEqual([False, False], observed_values)

    def test_workspace_write_requires_an_explicit_existing_directory(self) -> None:
        runner = RecordingRunner(
            CodexRunResult(final_response='{"payload_type":"text/plain","payload":"ok"}')
        )
        with self.assertRaisesRegex(ValueError, "explicit cwd"):
            CodexAgentProvider(
                sandbox=CodexSandbox.WORKSPACE_WRITE,
                runner=runner,
            )
        with self.assertRaisesRegex(TypeError, "CodexSandbox"):
            CodexAgentProvider(sandbox="workspace_write", runner=runner)  # type: ignore[arg-type]

        with tempfile.TemporaryDirectory() as directory:
            provider = CodexAgentProvider(
                sandbox=CodexSandbox.WORKSPACE_WRITE,
                cwd=directory,
                runner=runner,
            )
            provider.invoke(self.request())
            self.assertEqual(str(Path(directory).resolve()), runner.calls[-1]["cwd"])

    def test_runtime_directories_are_explicit_existing_paths(self) -> None:
        runner = RecordingRunner(
            CodexRunResult(final_response='{"payload_type":"text/plain","payload":"ok"}')
        )
        with tempfile.TemporaryDirectory() as directory:
            provider = CodexAgentProvider(
                codex_home=directory,
                sqlite_home=directory,
                runner=runner,
            )
            provider.invoke(self.request())
            resolved = str(Path(directory).resolve())
            self.assertEqual(resolved, runner.calls[-1]["codex_home"])
            self.assertEqual(resolved, runner.calls[-1]["sqlite_home"])

        with self.assertRaisesRegex((FileNotFoundError, OSError), "does-not-exist"):
            CodexAgentProvider(codex_home="does-not-exist", runner=runner)
        with self.assertRaisesRegex(TypeError, "Codex SQLite home must be a path"):
            CodexAgentProvider(sqlite_home=object(), runner=runner)  # type: ignore[arg-type]

    def test_provider_fails_closed_on_invalid_sdk_results(self) -> None:
        cases = (
            (CodexRunResult(final_response=None), "without a final response"),
            (CodexRunResult(final_response="   "), "without a final response"),
            (CodexRunResult(final_response="{}", error="cancelled"), "turn failed"),
            (CodexRunResult(final_response="not-json"), "Expecting value"),
            (CodexRunResult(final_response="[]"), "must be a JSON object"),
            (
                CodexRunResult(
                    final_response=(
                        '{"payload_type":"text/plain","payload":1,"verified":true}'
                    )
                ),
                "exactly payload_type and payload",
            ),
            (
                CodexRunResult(
                    final_response=(
                        '{"payload_type":"text/plain","payload":1,"payload":2}'
                    )
                ),
                "duplicate JSON object key",
            ),
        )
        for result, message in cases:
            with self.subTest(message=message):
                provider = CodexAgentProvider(runner=RecordingRunner(result))
                with self.assertRaisesRegex((ValueError, RuntimeError), message):
                    provider.invoke(self.request())

        oversized = CodexAgentProvider(
            max_output_bytes=10,
            runner=RecordingRunner(
                CodexRunResult(
                    final_response='{"payload_type":"text/plain","payload":"large"}'
                )
            ),
        )
        with self.assertRaisesRegex(ValueError, "exceeded"):
            oversized.invoke(self.request())

        invalid = CodexAgentProvider(runner=RecordingRunner(object()))
        with self.assertRaisesRegex(TypeError, "invalid result"):
            invalid.invoke(self.request())

    def test_official_runner_maps_sdk_sandbox_and_uses_ephemeral_thread(self) -> None:
        records: dict[str, Any] = {}
        deny_all = object()
        read_only = object()

        class FakeSandbox:
            pass

        FakeSandbox.read_only = read_only
        FakeSandbox.workspace_write = object()

        class FakeApprovalMode:
            pass

        FakeApprovalMode.deny_all = deny_all

        class FakeCodexConfig:
            def __init__(self, **kwargs: Any) -> None:
                records["config"] = kwargs

        class FakeThread:
            def run(self, prompt: str, **kwargs: Any) -> object:
                records["run"] = {"prompt": prompt, **kwargs}
                return SimpleNamespace(
                    final_response='{"payload_type":"text/plain","payload":"ok"}',
                    error=None,
                )

        class FakeCodex:
            def __init__(self, config: object) -> None:
                records["codex_config"] = config

            def __enter__(self) -> Any:
                records["entered"] = True
                return self

            def __exit__(self, *args: object) -> None:
                records["exited"] = True

            def thread_start(self, **kwargs: Any) -> FakeThread:
                records["thread_start"] = kwargs
                return FakeThread()

        sdk = SimpleNamespace(
            ApprovalMode=FakeApprovalMode,
            Codex=FakeCodex,
            CodexConfig=FakeCodexConfig,
            Sandbox=FakeSandbox,
        )
        schema = {"type": "object"}
        with patch.object(importlib, "import_module", return_value=sdk):
            result = OfficialCodexRunner().run(
                prompt="candidate request",
                model="gpt-test",
                cwd="C:\\quarantine",
                sandbox=CodexSandbox.READ_ONLY,
                output_schema=schema,
                codex_home="C:\\codex-home",
                sqlite_home="C:\\codex-state",
            )

        self.assertIsNone(result.error)
        self.assertIn("payload_type", result.final_response or "")
        self.assertTrue(records["entered"])
        self.assertTrue(records["exited"])
        overrides = records["config"]["config_overrides"]
        self.assertEqual(
            {
                "CODEX_HOME": "C:\\codex-home",
                "CODEX_SQLITE_HOME": "C:\\codex-state",
            },
            records["config"]["env"],
        )
        self.assertIn('web_search="disabled"', overrides)
        self.assertIn("apps._default.enabled=false", overrides)
        self.assertIn("agents.enabled=false", overrides)
        self.assertIn("sandbox_workspace_write.network_access=false", overrides)
        self.assertEqual(
            {
                "approval_mode": deny_all,
                "model": "gpt-test",
                "cwd": "C:\\quarantine",
                "sandbox": read_only,
                "ephemeral": True,
            },
            records["thread_start"],
        )
        self.assertEqual(schema, records["run"]["output_schema"])
        self.assertIs(deny_all, records["run"]["approval_mode"])
        self.assertIs(read_only, records["run"]["sandbox"])

    def test_official_runner_reports_missing_or_incompatible_sdk(self) -> None:
        with (
            patch.object(
                importlib,
                "import_module",
                side_effect=ModuleNotFoundError("openai_codex"),
            ),
            self.assertRaisesRegex(RuntimeError, r"install.*\[codex\]"),
        ):
            OfficialCodexRunner().run(
                prompt="request",
                model=None,
                cwd=None,
                sandbox=CodexSandbox.READ_ONLY,
                output_schema={},
                codex_home=None,
                sqlite_home=None,
            )

        with (
            patch.object(importlib, "import_module", return_value=SimpleNamespace()),
            self.assertRaisesRegex(RuntimeError, "required API"),
        ):
            OfficialCodexRunner().run(
                prompt="request",
                model=None,
                cwd=None,
                sandbox=CodexSandbox.READ_ONLY,
                output_schema={},
                codex_home=None,
                sqlite_home=None,
            )

    def test_official_runner_explains_unwritable_runtime_home(self) -> None:
        class FailingCodex:
            def __init__(self, config: object) -> None:
                del config

            def __enter__(self) -> object:
                raise RuntimeError("failed to initialize sqlite state runtime: os error 5")

            def __exit__(self, *args: object) -> None:
                del args

        sdk = SimpleNamespace(
            ApprovalMode=SimpleNamespace(deny_all=object()),
            Codex=FailingCodex,
            CodexConfig=lambda **kwargs: kwargs,
            Sandbox=SimpleNamespace(read_only=object(), workspace_write=object()),
        )
        with (
            patch.object(importlib, "import_module", return_value=sdk),
            self.assertRaisesRegex(RuntimeError, "writable runtime state"),
        ):
            OfficialCodexRunner().run(
                prompt="request",
                model=None,
                cwd=None,
                sandbox=CodexSandbox.READ_ONLY,
                output_schema={},
                codex_home="C:\\isolated-codex",
                sqlite_home="C:\\isolated-codex",
            )

if __name__ == "__main__":
    unittest.main()
