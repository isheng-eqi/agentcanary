"""Security layer — dual injection scan, execution boundary, death-loop prevention.

Hard-coded, always on, cannot be disabled.
"""

INJECTION_PATTERNS = [
    "ignore all previous instructions",
    "ignore previous instructions",
    "system prompt",
    "you are now",
    "new instructions:",
    "forget everything",
    "disregard",
    "<function_calls>",
    "<tool_call>",
    "exfiltrate",
    "send to http",
    "curl http",
    "attacker@",
]


def scan_content(text: str) -> str | None:
    """Scan content for injection patterns. Returns error message if found."""
    lower = text.lower()
    for pattern in INJECTION_PATTERNS:
        if pattern in lower:
            return f"Injection pattern detected: '{pattern}'"
    return None


def sanitize_for_snapshot(entries: list[dict]) -> list[dict]:
    """Sanitize memory entries before injecting into system prompt."""
    clean = []
    for e in entries:
        if scan_content(e.get("content", "")):
            clean.append({**e, "content": "[BLOCKED — injection detected]"})
        else:
            clean.append(e)
    return clean


class ExecutionBoundary:
    """Execution boundary: validate tool calls before they execute."""

    def __init__(self, allowed_urls: set = None):
        self.allowed_urls = allowed_urls or set()

    def allow_url(self, url: str):
        self.allowed_urls.add(url)

    def validate(self, tool_name: str, params: dict) -> str | None:
        """Validate a tool call. Returns error or None."""
        # Target URL must be in allowlist
        url = params.get("target_url") or params.get("url")
        if url and self.allowed_urls and url not in self.allowed_urls:
            return f"URL '{url}' not in allowed targets. Ask user to confirm."
        # Prevent self-attack
        if url and ("localhost" in url or "127.0.0.1" in url):
            for p in params.values():
                if isinstance(p, str) and scan_content(p):
                    return "Payload contains injection pattern — blocked."
        return None
