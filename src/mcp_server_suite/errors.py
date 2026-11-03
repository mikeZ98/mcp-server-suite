"""Exceptions shared across layers (kept import-light to avoid cycles)."""

from mcp_server_suite.schemas import ProblemDetail

__all__ = ["ToolError"]


class ToolError(Exception):
    """A tool execution failure reported to the client in-band as an RFC 9457 problem."""

    def __init__(self, problem: ProblemDetail) -> None:
        super().__init__(problem.detail)
        self.problem = problem
