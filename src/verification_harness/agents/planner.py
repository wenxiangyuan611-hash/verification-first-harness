"""Deterministic task-registry planner used by the example."""

from __future__ import annotations

from dataclasses import dataclass

from verification_harness.agents.base import BaseAgent
from verification_harness.schema import Spec, TestCase


@dataclass(frozen=True)
class RegisteredTask:
    description: str
    requirements: tuple[str, ...]
    test_cases: tuple[TestCase, ...]
    entrypoint: str


class PlannerAgent(BaseAgent):
    """Store task contracts for the deterministic reference workflow.

    Production systems should authorize a planner's proposed spec through an
    independent policy or human-controlled acceptance-criteria boundary.
    """

    def __init__(self) -> None:
        super().__init__("planner_01", "Planner")
        self.task_registry: dict[str, RegisteredTask] = {}

    def register_task(
        self,
        task_id: str,
        description: str,
        requirements: tuple[str, ...],
        test_cases: tuple[TestCase, ...],
        entrypoint: str,
    ) -> None:
        task = RegisteredTask(description, requirements, test_cases, entrypoint)
        # Construct once now so invalid contracts fail at registration time.
        Spec(task_id, task.description, task.requirements, task.test_cases, task.entrypoint)
        self.task_registry[task_id] = task

    def create_spec(self, task_id: str) -> Spec:
        self.log(f"Generating task specification for task '{task_id}'...")
        try:
            task = self.task_registry[task_id]
        except KeyError as error:
            raise ValueError(f"Planner has no knowledge of task_id: {task_id}") from error
        return Spec(task_id, task.description, task.requirements, task.test_cases, task.entrypoint)
