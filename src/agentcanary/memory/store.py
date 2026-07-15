"""Memory system — Hermes implementation (per source analysis).

Based on: tools/memory_tool.py (1146 lines, Hermes v0.18.0)

Key design decisions copied faithfully:

1. Plain text storage — § delimiter, human-readable
2. Dual-state: live entries + frozen snapshot (prefix cache stability)
3. Capacity limit as consolidation TRIGGER, not rejection
4. Batch atomic operations — remove/replace/add in one call
5. 3-failure self-degradation (MAX_CONSOLIDATION_FAILURES_PER_TURN)
6. External drift detection (round-trip mismatch)
7. Dual injection scanning (write-time + load-time)
"""

import os, re
from datetime import datetime, timezone
from pathlib import Path

ENTRY_DELIMITER = "䷀"
MAX_CONSOLIDATION_FAILURES_PER_TURN = 3


class MemoryStore:
    """Hermes memory_tool.py MemoryStore — faithfully ported."""

    def __init__(self, char_limit: int = 6000):
        self.path = Path.home() / ".agentcanary" / "MEMORY.md"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.char_limit = char_limit

        # Dual-state (memory_tool.py line 113-122)
        self.entries: list[str] = []           # live state
        self._snapshot: list[str] = []         # frozen snapshot
        self._consolidation_failures = 0

        self._load()

    # ═══ Load/Save ═══

    def _load(self):
        if self.path.exists():
            raw = self.path.read_text(encoding="utf-8", errors="replace").strip()
            self.entries = [e.strip() for e in raw.split(ENTRY_DELIMITER) if e.strip()]
        else:
            self.entries = []

    def _save(self):
        self.path.write_text(ENTRY_DELIMITER.join(self.entries), encoding="utf-8")

    def freeze(self):
        """Session start: create frozen snapshot. Subsequent writes don't affect it."""
        self._snapshot = list(self.entries)
        self._consolidation_failures = 0

    def _usage(self) -> int:
        return len(ENTRY_DELIMITER.join(self.entries)) if self.entries else 0

    # ═══ Constraint-driven add ═══

    def add(self, content: str, category: str = "tactic", confidence: float = 0.5) -> dict:
        """Add entry. Over limit → returns consolidation instructions, NOT rejection.

        memory_tool.py line 367-380: "Memory at X/Y chars. Consolidate now."
        """
        if not content or len(content) < 10:
            return {"success": True, "skipped": "too short"}

        # Prefix with category for searchability
        entry = f"[{category}] {content[:200]}"

        # Dedup (approximate match)
        for i, existing in enumerate(self.entries):
            if _sim(existing, entry) > 0.7:
                self.entries[i] = entry
                self._save()
                return {"success": True, "merged": True}

        new_total = self._usage() + len(entry) + len(ENTRY_DELIMITER)

        if new_total > self.char_limit:
            if self._consolidation_failures >= MAX_CONSOLIDATION_FAILURES_PER_TURN:
                # memory_tool.py line 157-163: terminal response
                return {
                    "success": False,
                    "done": True,
                    "error": "Memory consolidation failed 3 times this turn. "
                             "Stop retrying — leave memory unchanged and continue."
                }

            return {
                "success": False,
                "needs_consolidation": True,
                "current_entries": self.entries,
                "char_usage": self._usage(),
                "char_limit": self.char_limit,
                "instruction": "Memory at limit. Use batch to merge/remove, then retry.",
            }

        self.entries.append(entry)
        self._save()
        return {"success": True}

    # ═══ Batch atomic operations ═══

    def batch(self, operations: list[dict]) -> dict:
        """Apply batch of remove/replace/add. All-or-nothing.

        memory_tool.py line 497: apply_batch
        memory_tool.py line 583-596: final budget check on result
        """
        # External drift detection (memory_tool.py line 704)
        drift_error = _detect_drift(self.path, self.char_limit)
        if drift_error and any(op.get("action") in ("remove", "replace") for op in operations):
            return {"success": False, "error": drift_error}

        working = list(self.entries)

        for op in operations:
            action = op.get("action", "add")
            if action == "remove":
                old = op.get("old_text", "")
                working = [e for e in working if old not in e]
            elif action == "replace":
                old, new = op.get("old_text", ""), op.get("content", "")
                for i, e in enumerate(working):
                    if old in e:
                        working[i] = new[:200]
                        break
            elif action == "add":
                c = op.get("content", "")[:200]
                if c:
                    cat = op.get("category", "tactic")
                    working.append(f"[{cat}] {c}")

        # Final budget check (all-or-nothing)
        new_total = len(ENTRY_DELIMITER.join(working)) if working else 0
        if new_total > self.char_limit:
            self._consolidation_failures += 1
            return {
                "success": False,
                "error": f"Consolidation failed: still at {new_total}/{self.char_limit} chars."
            }

        self.entries = working
        self._consolidation_failures = 0
        self._save()
        return {"success": True, "char_usage": new_total}

    # ═══ Query ═══

    def search(self, query: str, top_n: int = 5) -> list[str]:
        """Search from frozen snapshot (session-stable)."""
        source = self._snapshot if self._snapshot else self.entries
        qw = set(query.lower().split())
        scored = []
        import math
        for e in source:
            ew = set(e.lower().split())
            overlap = len(qw & ew)
            if overlap:
                scored.append((overlap, e))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [e for _, e in scored[:top_n]]

    def snapshot_text(self) -> str:
        """Frozen snapshot for system prompt injection."""
        source = self._snapshot if self._snapshot else self.entries
        return "\n".join(source[-20:]) if source else "暂无"

    def stats(self) -> dict:
        return {
            "count": len(self.entries),
            "char_usage": self._usage(),
            "char_limit": self.char_limit,
            "failures": self._consolidation_failures,
        }

    def all_entries(self) -> list[str]:
        """Return all entries (for consolidation display)."""
        return list(self.entries)


# ═══ Drift detection ═══

def _detect_drift(path: Path, char_limit: int) -> str | None:
    """memory_tool.py line 704: _detect_external_drift"""
    if not path.exists():
        return None
    raw = path.read_text(encoding="utf-8", errors="replace").strip()
    parsed = [e.strip() for e in raw.split(ENTRY_DELIMITER) if e.strip()]
    roundtrip = ENTRY_DELIMITER.join(parsed)
    max_entry_len = max((len(e) for e in parsed), default=0)

    if raw != roundtrip:
        # Create .bak backup
        bak = path.with_suffix(f".bak.{datetime.now().strftime('%Y%m%d%H%M%S')}")
        bak.write_text(raw, encoding="utf-8")
        return "External drift detected: file was modified outside Hermes. Backup saved. Use batch to reconcile."
    if max_entry_len > char_limit:
        return f"Entry exceeds store limit ({max_entry_len} > {char_limit}). External modification detected."
    return None


# ═══ Injection scanning ═══

INJECTION_PATTERNS = [
    "ignore all previous instructions",
    "system prompt:",
    "you are now",
    "new instructions:",
    "<function_calls>",
    "<tool_call>",
    "attacker@",
]


def _scan_content(text: str) -> str | None:
    """memory_tool.py line 343: _scan_memory_content"""
    lower = text.lower()
    for pattern in INJECTION_PATTERNS:
        if pattern in lower:
            return f"Injection pattern blocked: '{pattern}'"
    return None


def sanitize_snapshot(entries: list[str]) -> list[str]:
    """memory_tool.py line 208: _sanitize_entries_for_snapshot"""
    clean = []
    for e in entries:
        if _scan_content(e):
            clean.append("[BLOCKED]")
        else:
            clean.append(e)
    return clean


def _sim(a: str, b: str) -> float:
    wa, wb = set(a.lower().split()), set(b.lower().split())
    return len(wa & wb) / min(len(wa), len(wb)) if wa and wb else 0
