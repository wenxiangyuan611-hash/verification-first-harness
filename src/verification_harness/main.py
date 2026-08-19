"""Command-line demonstration for the verification-first loop."""

from __future__ import annotations

from verification_harness.agents import CriticAgent, PlannerAgent, VerifierAgent, WorkerAgent
from verification_harness.demo_task import (
    DEMO_SPEC,
    FAULTY_CODE,
    PERSISTENT_BUG_CODE,
    PROCESS_EXIT_CODE,
    REPAIRED_CODE,
)
from verification_harness.engine import TrustGateEngine


def _planner() -> PlannerAgent:
    planner = PlannerAgent()
    planner.register_task(
        DEMO_SPEC.task_id,
        DEMO_SPEC.description,
        DEMO_SPEC.requirements,
        DEMO_SPEC.test_cases,
        DEMO_SPEC.entrypoint,
    )
    return planner


def _run_scenario(title: str, initial_code: str, repaired_code: str, max_repairs: int) -> None:
    print(f"\n{'#' * 70}\n{title}\n{'#' * 70}")
    task_id = DEMO_SPEC.task_id
    engine = TrustGateEngine(
        planner=_planner(),
        worker=WorkerAgent(
            faulty_implementations={task_id: initial_code},
            repaired_implementations={task_id: repaired_code},
        ),
        critic=CriticAgent(),
        verifier=VerifierAgent(),
        max_repairs=max_repairs,
    )
    result = engine.run(task_id)
    print(f"\nStatus: {result['status']}")
    print(f"Final state: {result['final_state']}")
    print(f"Attempts: {result['attempts']}")
    print(f"Kernel verdict: {result['verdict']}")
    print(f"Verified artifact issued: {result['artifact'] is not None}")
    decision_receipt = result["decision_receipt"]
    if decision_receipt is not None:
        print(f"Decision receipt: {decision_receipt.receipt_id}")
    receipt = result["receipt"]
    if receipt is not None:
        for evidence in receipt.evidence:
            print(f" - {evidence.obligation_id}: {evidence.status.value} {evidence.error}")


def main() -> None:
    _run_scenario(
        "SCENARIO 1: FAIL, REPAIR, RE-VERIFY, PASS",
        FAULTY_CODE,
        REPAIRED_CODE,
        max_repairs=2,
    )
    _run_scenario(
        "SCENARIO 2: PERSISTENT FAILURE IS REJECTED",
        PERSISTENT_BUG_CODE,
        PERSISTENT_BUG_CODE,
        max_repairs=2,
    )
    _run_scenario(
        "SCENARIO 3: PROCESS EXIT IS REJECTED",
        PROCESS_EXIT_CODE,
        PROCESS_EXIT_CODE,
        max_repairs=1,
    )


if __name__ == "__main__":
    main()
