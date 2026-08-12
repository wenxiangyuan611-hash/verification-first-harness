"""Deterministic task data for the command-line demonstration."""

from verification_harness.schema import Spec, TestCase

DEMO_SPEC = Spec(
    task_id="flatten_nested_sequence",
    description="Flatten deeply nested lists and tuples into one list.",
    requirements=(
        "Flatten nested lists and tuples of arbitrary depth.",
        "Preserve the order of non-container elements.",
        "Return an empty list for an empty sequence.",
    ),
    entrypoint="flatten",
    test_cases=(
        TestCase("case_1", [1, 2, 3], [1, 2, 3]),
        TestCase("case_2", [1, [2, [3, 4], 5], 6], [1, 2, 3, 4, 5, 6]),
        TestCase("case_3", [], []),
        TestCase("case_4", [[], [[]], [1, []]], [1]),
    ),
)

FAULTY_CODE = """def flatten(sequence):
    result = []
    for item in sequence:
        if isinstance(item, list):
            result.extend(item)
        else:
            result.append(item)
    return result
"""

REPAIRED_CODE = """def flatten(sequence):
    result = []
    for item in sequence:
        if isinstance(item, (list, tuple)):
            result.extend(flatten(item))
        else:
            result.append(item)
    return result
"""

PERSISTENT_BUG_CODE = """def flatten(sequence):
    return [1, 2, 3]
"""

PROCESS_EXIT_CODE = """import sys
sys.exit(0)
"""
