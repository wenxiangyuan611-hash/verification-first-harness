"""Generic falsification-oriented static critic."""

from __future__ import annotations

import ast

from verification_harness.agents.base import BaseAgent
from verification_harness.schema import Claim, Obligation, Spec


class CriticAgent(BaseAgent):
    """Propose obligations for obvious structural defects.

    This reference critic is intentionally small. Its output is itself untrusted:
    only the independent verifier may turn an obligation into evidence.
    """

    def __init__(self) -> None:
        super().__init__("critic_01", "Critic")

    def challenge(self, claim: Claim, spec: Spec) -> tuple[Obligation, ...]:
        self.log(f"Challenging Claim #{claim.attempt} for task '{spec.task_id}'...")
        challenges: list[Obligation] = []
        try:
            tree = ast.parse(claim.code)
            function_names = {
                node.name
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
        except SyntaxError:
            function_names = set()

        if spec.entrypoint not in function_names:
            challenges.append(
                Obligation(
                    id="CRITIC_ENTRYPOINT",
                    kind="REQUIRED_ENTRYPOINT",
                    description=f"Candidate must define callable entrypoint '{spec.entrypoint}'.",
                    payload={"name": spec.entrypoint},
                )
            )
        if "raise NotImplementedError" in claim.code:
            challenges.append(
                Obligation(
                    id="CRITIC_NO_STUB",
                    kind="FORBIDDEN_TEXT",
                    description="Candidate must not contain a NotImplementedError stub.",
                    payload={"text": "raise NotImplementedError"},
                )
            )

        if challenges:
            self.log(f"[CHALLENGE] Critic issued {len(challenges)} obligation(s).")
        else:
            self.log("[PASS] Critic found no generic structural flaws.")
        return tuple(challenges)
