"""Contain failures and malformed values returned by untrusted components."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from verification_harness.schema import ComponentFailure

T = TypeVar("T")


class ComponentCallError(RuntimeError):
    """A normalized failure raised at an untrusted component boundary."""

    def __init__(self, failure: ComponentFailure) -> None:
        super().__init__(failure.message)
        self.failure = failure


class AgentCallBoundary:
    """Invoke one component and reject exceptions or unexpected result types."""

    MAX_ERROR_MESSAGE_CHARS = 500

    @classmethod
    def invoke(
        cls,
        component: str,
        operation: str,
        callback: Callable[[], object],
        expected_type: type[T],
        validator: Callable[[T], None] | None = None,
    ) -> T:
        try:
            result = callback()
            if result.__class__ is not expected_type:
                raise TypeError(
                    f"expected {expected_type.__name__}, got {type(result).__name__}"
                )
            typed_result = result
            if validator is not None:
                validator(typed_result)
            return typed_result
        except (KeyboardInterrupt, GeneratorExit):
            raise
        except BaseException as error:  # noqa: B036 - SystemExit is untrusted input here.
            failure = cls.failure(component, operation, error)
            raise ComponentCallError(failure) from error

    @classmethod
    def failure(
        cls,
        component: str,
        operation: str,
        error: BaseException,
    ) -> ComponentFailure:
        """Normalize a policy or validation error at a component boundary."""
        return ComponentFailure(
            component=component,
            operation=operation,
            error_type=type(error).__name__,
            message=cls._safe_message(error),
        )

    @classmethod
    def _safe_message(cls, error: BaseException) -> str:
        try:
            raw_message = str(error) or "component failed without an error message"
        except BaseException:  # noqa: B036 - exception formatting is also untrusted.
            raw_message = "component raised an error with an unreadable message"
        single_line = " ".join(raw_message.splitlines())
        printable = "".join(
            character if character.isprintable() else "?" for character in single_line
        )
        if len(printable) <= cls.MAX_ERROR_MESSAGE_CHARS:
            return printable
        return f"{printable[: cls.MAX_ERROR_MESSAGE_CHARS]}..."
