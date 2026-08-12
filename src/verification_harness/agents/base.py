"""Common behavior for the reference agents."""

from __future__ import annotations

from collections.abc import Callable


class BaseAgent:
    """Small base class with injectable output for demos and tests."""

    def __init__(
        self,
        agent_id: str,
        name: str,
        output: Callable[[str], None] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.name = name
        self._output: Callable[[str], None] = output or print

    def log(self, message: str) -> None:
        try:
            self._output(f"[{self.name}] {message}")
        except UnicodeEncodeError:
            clean_message = message.encode("ascii", errors="ignore").decode("ascii")
            self._output(f"[{self.name}] {clean_message}")
