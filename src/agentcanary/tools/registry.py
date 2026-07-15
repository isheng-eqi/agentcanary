"""Tool registry — Hermes-style tool system."""

from dataclasses import dataclass
from typing import Callable, Awaitable


@dataclass
class ToolResult:
    tool_name: str
    success: bool
    output: str
    error: str = ""


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict  # {name: description}
    func: Callable[..., Awaitable[ToolResult]] = None
    required: list[str] | None = None  # which params required (None = first only)


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool):
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def list_all(self) -> list[Tool]:
        return list(self._tools.values())

    def describe(self) -> str:
        lines = []
        for t in self._tools.values():
            params = ", ".join(f"{k}" for k in t.parameters)
            lines.append(f"- {t.name}({params}): {t.description}")
        return "\n".join(lines)
