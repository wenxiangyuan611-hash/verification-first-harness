import unittest

from verification_harness.actions import (
    ActionDecision,
    ActionDenied,
    ActionGate,
    ActionRequest,
    ActionVerdict,
    AllowListActionPolicy,
)


class Approval:
    def __init__(self, approved: object) -> None:
        self.approved = approved

    def approve(self, request: ActionRequest, decision: ActionDecision) -> bool:
        del request, decision
        return self.approved  # type: ignore[return-value]


class BrokenPolicy:
    policy_id = "broken"

    def decide(self, request: ActionRequest) -> ActionDecision:
        del request
        raise RuntimeError("policy unavailable")


class WrongDecisionPolicy:
    policy_id = "wrong"

    def decide(self, request: ActionRequest) -> ActionDecision:
        del request
        return object()  # type: ignore[return-value]


class UnreadableError(Exception):
    def __str__(self) -> str:
        raise RuntimeError("cannot render")


class UnreadablePolicy:
    policy_id = "unreadable"

    def decide(self, request: ActionRequest) -> ActionDecision:
        del request
        raise UnreadableError()


class ActionGateTests(unittest.TestCase):
    def request(self, kind: str = "agent.invoke") -> ActionRequest:
        return ActionRequest.create(
            run_id="run-1",
            actor_id="worker-1",
            kind=kind,
            target="provider-1",
            payload={"value": 1},
        )

    def test_allow_list_executes_only_explicitly_allowed_action(self) -> None:
        calls = 0

        def operation() -> str:
            nonlocal calls
            calls += 1
            return "executed"

        gate = ActionGate(AllowListActionPolicy(frozenset({"agent.invoke"})))
        self.assertEqual("executed", gate.execute(self.request(), operation))
        with self.assertRaisesRegex(ActionDenied, "not allowed"):
            gate.execute(self.request("tool.delete"), operation)
        self.assertEqual(1, calls)

    def test_approval_required_fails_closed_without_positive_resolver(self) -> None:
        policy = AllowListActionPolicy(
            frozenset(),
            approval_kinds=frozenset({"release.publish"}),
        )
        request = self.request("release.publish")
        with self.assertRaisesRegex(ActionDenied, "no resolver"):
            ActionGate(policy).execute(request, lambda: "published")
        with self.assertRaisesRegex(ActionDenied, "denied"):
            ActionGate(policy, Approval(False)).execute(request, lambda: "published")
        self.assertEqual(
            "published",
            ActionGate(policy, Approval(True)).execute(request, lambda: "published"),
        )
        with self.assertRaisesRegex(ActionDenied, "invalid"):
            ActionGate(policy, Approval("yes")).execute(request, lambda: "published")

    def test_policy_failure_and_malformed_decision_never_execute_operation(self) -> None:
        calls = 0

        def operation() -> None:
            nonlocal calls
            calls += 1

        with self.assertRaisesRegex(ActionDenied, "failed closed"):
            ActionGate(BrokenPolicy()).execute(self.request(), operation)
        with self.assertRaisesRegex(ActionDenied, "invalid decision"):
            ActionGate(WrongDecisionPolicy()).execute(self.request(), operation)
        with self.assertRaisesRegex(ActionDenied, "unreadable error"):
            ActionGate(UnreadablePolicy()).execute(self.request(), operation)
        self.assertEqual(0, calls)

    def test_action_values_are_detached_and_policy_identity_is_bound(self) -> None:
        payload = {"items": [1]}
        request = ActionRequest(
            action_id="action-1",
            run_id="run-1",
            actor_id="actor-1",
            kind="agent.invoke",
            target="provider-1",
            payload=payload,
        )
        payload["items"].append(2)
        exposed = request.payload
        exposed["items"].append(3)
        self.assertEqual({"items": [1]}, request.payload)
        self.assertEqual(request.digest, request.digest)

        class MismatchedPolicy:
            policy_id = "expected"

            def decide(self, value: ActionRequest) -> ActionDecision:
                del value
                return ActionDecision(ActionVerdict.ALLOW, "other", "allow")

        with self.assertRaisesRegex(ActionDenied, "identity mismatch"):
            ActionGate(MismatchedPolicy()).execute(request, lambda: None)


if __name__ == "__main__":
    unittest.main()
