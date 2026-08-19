import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from verification_harness.opencode_provider import (
    OfficialOpenCodeRunner,
    OpenCodeAgentProvider,
    OpenCodePermissionProfile,
    OpenCodeRunResult,
)
from verification_harness.protocol import AgentRole, RunContext
from verification_harness.providers import AgentRequest


def text_event(text: str) -> str:
    return json.dumps(
        {"type": "text", "part": {"type": "text", "text": text}},
        separators=(",", ":"),
    )


class RecordingRunner:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls: list[dict[str, Any]] = []

    def run(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return self.result


class OpenCodeProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cwd = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def request(self, role: AgentRole = AgentRole.WORKER) -> AgentRequest:
        return AgentRequest(
            context=RunContext("run-opencode", "task-opencode", "nonce-opencode"),
            authorized_spec_digest="spec-digest",
            role=role,
            attempt=2,
            input_payload={"question": "six times seven"},
            feedback={"prior_answer": 41},
            parent_claim_ids=("claim-1",),
        )

    def test_provider_parses_json_events_and_returns_detached_output(self) -> None:
        response = '{"payload_type":"application/json","payload":{"answer":42}}'
        runner = RecordingRunner(
            OpenCodeRunResult(
                stdout="\n".join(
                    (
                        '{"type":"step_start","part":{"type":"step-start"}}',
                        text_event(response[:30]),
                        text_event(response[30:]),
                    )
                )
            )
        )
        provider = OpenCodeAgentProvider(
            cwd=self.cwd,
            model="provider/model",
            runner=runner,
        )

        output = provider.invoke(self.request())

        self.assertEqual("opencode/provider/model", provider.provider_id)
        self.assertEqual({"answer": 42}, output.payload)
        output.payload["answer"] = 0
        self.assertEqual(42, output.payload["answer"])
        call = runner.calls[0]
        self.assertEqual("provider/model", call["model"])
        self.assertEqual(str(self.cwd.resolve()), call["cwd"])
        self.assertIs(OpenCodePermissionProfile.DENY_ALL, call["profile"])
        self.assertIn("untrusted candidate generator", call["prompt"])
        self.assertIn('"role":"WORKER"', call["prompt"])
        self.assertNotIn("--auto", call["prompt"])

    def test_critic_prompt_requires_falsification_and_bounded_selection(self) -> None:
        final = json.dumps(
            {
                "payload_type": (
                    "application/vnd.verification-first.challenge-selection+json"
                ),
                "payload": {
                    "selected_obligation_ids": [],
                    "rationale": "No additional check selected.",
                },
            }
        )
        runner = RecordingRunner(OpenCodeRunResult(stdout=text_event(final)))
        OpenCodeAgentProvider(cwd=self.cwd, runner=runner).invoke(
            self.request(AgentRole.CRITIC)
        )
        self.assertIn("actively try to falsify", runner.calls[0]["prompt"])
        self.assertIn('"role":"CRITIC"', runner.calls[0]["prompt"])

    def test_provider_fails_closed_on_invalid_events_and_results(self) -> None:
        cases = (
            (OpenCodeRunResult(stdout="not-json"), "Expecting value"),
            (OpenCodeRunResult(stdout='{"type":"step_finish"}'), "without a text"),
            (
                OpenCodeRunResult(stdout='{"type":"error","error":"cancelled"}'),
                "error event",
            ),
            (
                OpenCodeRunResult(
                    stdout=text_event(
                        '{"payload_type":"text/plain","payload":1,"verified":true}'
                    )
                ),
                "exactly payload_type and payload",
            ),
            (OpenCodeRunResult(stdout=text_event("[]")), "must be a JSON object"),
            (OpenCodeRunResult(stdout="", returncode=9, stderr="failed"), "exited with 9"),
        )
        for result, message in cases:
            with self.subTest(message=message):
                provider = OpenCodeAgentProvider(
                    cwd=self.cwd,
                    runner=RecordingRunner(result),
                )
                with self.assertRaisesRegex((ValueError, RuntimeError), message):
                    provider.invoke(self.request())

        invalid = OpenCodeAgentProvider(cwd=self.cwd, runner=RecordingRunner(object()))
        with self.assertRaisesRegex(TypeError, "invalid result"):
            invalid.invoke(self.request())

    def test_provider_requires_explicit_existing_directory_and_bounds(self) -> None:
        runner = RecordingRunner(
            OpenCodeRunResult(
                stdout=text_event('{"payload_type":"text/plain","payload":"ok"}')
            )
        )
        with self.assertRaises((FileNotFoundError, OSError)):
            OpenCodeAgentProvider(cwd=self.cwd / "missing", runner=runner)
        with self.assertRaisesRegex(TypeError, "OpenCodePermissionProfile"):
            OpenCodeAgentProvider(
                cwd=self.cwd,
                profile="read_only",  # type: ignore[arg-type]
                runner=runner,
            )
        provider = OpenCodeAgentProvider(cwd=self.cwd, max_events=1, runner=runner)
        provider.invoke(self.request())
        too_many = OpenCodeRunResult(
            stdout="\n".join((text_event("{"), text_event("}")))
        )
        provider = OpenCodeAgentProvider(
            cwd=self.cwd,
            max_events=1,
            runner=RecordingRunner(too_many),
        )
        with self.assertRaisesRegex(ValueError, "too many"):
            provider.invoke(self.request())

    def test_official_runner_uses_json_mode_named_agent_and_deny_config(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=text_event('{"payload_type":"text/plain","payload":"ok"}'),
            stderr="",
        )
        with patch("verification_harness.opencode_provider.subprocess.run") as run:
            run.return_value = completed
            result = OfficialOpenCodeRunner().run(
                prompt="candidate request",
                executable="C:\\tools\\opencode.exe",
                model="provider/model",
                cwd=str(self.cwd),
                profile=OpenCodePermissionProfile.DENY_ALL,
                timeout_seconds=15,
                max_output_bytes=10_000,
                env={"PATH": "controlled"},
            )

        self.assertEqual(0, result.returncode)
        call = run.call_args
        argv = call.args[0]
        self.assertEqual("C:\\tools\\opencode.exe", argv[0])
        self.assertEqual("run", argv[1])
        self.assertIn("json", argv)
        self.assertIn("verification-harness", argv)
        self.assertIn("provider/model", argv)
        self.assertNotIn("--auto", argv)
        self.assertFalse(call.kwargs["shell"])
        config = json.loads(call.kwargs["env"]["OPENCODE_CONFIG_CONTENT"])
        self.assertEqual("disabled", config["share"])
        self.assertEqual("deny", config["permission"]["*"])
        self.assertEqual(
            "deny",
            config["agent"]["verification-harness"]["permission"]["*"],
        )

    def test_read_only_profile_allows_only_non_mutating_tools(self) -> None:
        completed = subprocess.CompletedProcess([], 0, "", "")
        with patch("verification_harness.opencode_provider.subprocess.run") as run:
            run.return_value = completed
            OfficialOpenCodeRunner().run(
                prompt="request",
                executable="opencode",
                model=None,
                cwd=str(self.cwd),
                profile=OpenCodePermissionProfile.READ_ONLY,
                timeout_seconds=15,
                max_output_bytes=10_000,
                env={},
            )
        config = json.loads(run.call_args.kwargs["env"]["OPENCODE_CONFIG_CONTENT"])
        self.assertEqual("deny", config["permission"]["*"])
        self.assertEqual("allow", config["permission"]["read"])
        allowed = {
            key for key, value in config["permission"].items() if value == "allow"
        }
        self.assertNotIn("bash", allowed)
        self.assertNotIn("edit", config["permission"])


if __name__ == "__main__":
    unittest.main()
