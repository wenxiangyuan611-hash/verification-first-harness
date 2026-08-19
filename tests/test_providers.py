import json
import sys
import unittest

from verification_harness.protocol import AgentRole, RunContext
from verification_harness.providers import (
    AgentOutput,
    AgentRequest,
    CallableAgentProvider,
    CommandAgentProvider,
)


class ProviderTests(unittest.TestCase):
    def request(self, feedback: object | None = None) -> AgentRequest:
        return AgentRequest(
            context=RunContext("run-1", "task-1", "nonce-1"),
            authorized_spec_digest="spec-digest",
            role=AgentRole.WORKER,
            attempt=1,
            input_payload={"question": "six times seven"},
            feedback=feedback,
        )

    def test_command_provider_receives_request_and_returns_detached_claim(self) -> None:
        code = (
            "import json,sys; r=json.load(sys.stdin); "
            "json.dump({'payload_type':'application/json',"
            "'payload':{'answer':42,'attempt':r['attempt']}},sys.stdout)"
        )
        provider = CommandAgentProvider("local-agent", (sys.executable, "-c", code))
        output = provider.invoke(self.request())
        self.assertEqual("application/json", output.payload_type)
        self.assertEqual({"answer": 42, "attempt": 1}, output.payload)
        exposed = output.payload
        exposed["answer"] = 0
        self.assertEqual(42, output.payload["answer"])

    def test_command_provider_rejects_failure_malformed_and_oversized_output(self) -> None:
        failing = CommandAgentProvider(
            "failing",
            (sys.executable, "-c", "import sys; print('bad',file=sys.stderr);sys.exit(7)"),
        )
        with self.assertRaisesRegex(RuntimeError, "exited with 7"):
            failing.invoke(self.request())

        malformed = CommandAgentProvider(
            "malformed",
            (sys.executable, "-c", "print('not-json')"),
        )
        with self.assertRaises(ValueError):
            malformed.invoke(self.request())

        duplicate = CommandAgentProvider(
            "duplicate",
            (sys.executable, "-c", "print('{\"payload_type\":\"a\",\"payload\":1,\"payload\":2}')"),
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
            duplicate.invoke(self.request())

        large_code = (
            "import json;"
            "print(json.dumps({'payload_type':'text/plain','payload':'x'*100}))"
        )
        oversized = CommandAgentProvider(
            "oversized",
            (sys.executable, "-c", large_code),
            max_output_bytes=20,
        )
        with self.assertRaisesRegex(ValueError, "stdout exceeded"):
            oversized.invoke(self.request())

    def test_callable_provider_and_request_preserve_falsy_feedback(self) -> None:
        provider = CallableAgentProvider(
            "sdk-agent",
            lambda request: AgentOutput(
                payload_type="application/json",
                payload={"feedback": request.feedback},
            ),
        )
        request = self.request(feedback=False)
        output = provider.invoke(request)
        self.assertEqual(False, output.payload["feedback"])
        restored = json.loads(request.to_json())
        self.assertEqual(False, restored["feedback"])

    def test_agent_output_requires_exact_wire_shape(self) -> None:
        with self.assertRaisesRegex(ValueError, "exactly"):
            AgentOutput.from_dict(
                {"payload_type": "application/json", "payload": {}, "trusted": True}
            )


if __name__ == "__main__":
    unittest.main()
