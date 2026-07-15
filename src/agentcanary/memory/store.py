"""Memory + Skill — Hermes constraint-driven self-evolution.

Design (from Hermes architecture docs):
  - Constraint-driven: capacity limit triggers consolidation, not rejection
  - Dual-state: frozen snapshot (session-stable) + live state
  - Batch atomic: all-or-nothing operations
  - Self-degradation: 3 failures → stop retrying
  - Provenance: who created it determines who can manage it
"""

import json
from datetime import datetime, timezone
from pathlib import Path


MAX_CONSOLIDATION_FAILURES = 3


class MemoryStore:
    """Constraint-driven attack knowledge base."""

    def __init__(self, char_limit: int = 6000):
        self.path = Path.home() / ".agentcanary" / "memory.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.char_limit = char_limit
        self.entries: list[dict] = []
        self._snapshot: list[dict] = []
        self._failures = 0
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                self.entries = json.loads(self.path.read_text()).get("entries", [])
            except Exception:
                self.entries = []

    def _save(self):
        self.path.write_text(json.dumps({
            "entries": self.entries,
            "char_usage": self._usage(),
            "char_limit": self.char_limit,
            "updated": datetime.now(timezone.utc).isoformat(),
        }, ensure_ascii=False, indent=2))

    def freeze(self):
        """Session start: create frozen snapshot for stable prefix cache."""
        self._snapshot = [dict(e) for e in self.entries]
        self._failures = 0

    def _usage(self) -> int:
        return sum(len(e.get("content", "")) for e in self.entries)

    def add(self, content: str, category: str = "tactic", confidence: float = 0.5) -> dict:
        """Add memory. Over-limit triggers consolidation, not rejection."""
        if not content or len(content) < 10:
            return {"success": True, "skipped": True}

        content = content[:200]
        new_total = self._usage() + len(content)

        if new_total > self.char_limit:
            if self._failures >= MAX_CONSOLIDATION_FAILURES:
                return {"success": False, "error": "记忆整理失败3次，已自我降级。跳过本次写入。", "stopped": True}
            return {
                "success": False, "needs_consolidation": True,
                "current_usage": self._usage(), "limit": self.char_limit,
                "entries": [e["content"][:100] for e in self.entries[-10:]],
                "instruction": "用 batch 操作合并重复条目、删除过时内容，然后重试。",
            }

        # Dedup
        for e in self.entries:
            if _sim(e.get("content", ""), content) > 0.7:
                e["uses"] = e.get("uses", 0) + 1
                e["confidence"] = 0.7 * e.get("confidence", 0.5) + 0.3 * confidence
                e["updated"] = datetime.now(timezone.utc).isoformat()
                self._save()
                return {"success": True, "merged": True}

        self.entries.append({
            "content": content, "category": category, "confidence": confidence,
            "uses": 0, "created": datetime.now(timezone.utc).isoformat(),
            "updated": datetime.now(timezone.utc).isoformat(),
        })
        self._save()
        return {"success": True}

    def batch(self, operations: list[dict]) -> dict:
        """Batch atomic: remove + replace + add in one call. All-or-nothing."""
        working = [dict(e) for e in self.entries]
        for op in operations:
            action = op.get("action", "add")
            if action == "remove":
                old = op.get("old_text", "")
                working = [e for e in working if old not in e.get("content", "")]
            elif action == "replace":
                old, new = op.get("old_text", ""), op.get("content", "")
                for e in working:
                    if old in e.get("content", ""):
                        e["content"] = new[:200]
                        e["updated"] = datetime.now(timezone.utc).isoformat()
                        break
            elif action == "add":
                c = op.get("content", "")[:200]
                if c:
                    working.append({"content": c, "category": op.get("category", "tactic"),
                        "confidence": op.get("confidence", 0.5), "uses": 0,
                        "created": datetime.now(timezone.utc).isoformat(),
                        "updated": datetime.now(timezone.utc).isoformat()})

        new_total = sum(len(e.get("content", "")) for e in working)
        if new_total > self.char_limit:
            self._failures += 1
            return {"success": False, "error": f"整理后仍超限 ({new_total}/{self.char_limit})"}

        self.entries = working
        self._failures = 0
        self._save()
        return {"success": True, "char_usage": new_total}

    def search(self, query: str, top_n: int = 5) -> list[dict]:
        source = self._snapshot if self._snapshot else self.entries
        qw = set(query.lower().split())
        scored = []
        import math
        for e in source:
            ew = set(e.get("content", "").lower().split())
            overlap = len(qw & ew)
            if overlap:
                s = overlap * e.get("confidence", 0.5) * math.log(e.get("uses", 0) + 2)
                scored.append((s, e))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [e for _, e in scored[:top_n]]

    def snapshot_text(self) -> str:
        source = self._snapshot if self._snapshot else self.entries
        return "\n".join(f"[{e.get('category','?')}] {e.get('content','')}" for e in source[-20:])

    def stats(self) -> dict:
        cats = {}
        for e in self.entries:
            cats[e.get("category", "other")] = cats.get(e.get("category", "other"), 0) + 1
        return {"count": len(self.entries), "char_usage": self._usage(),
                "char_limit": self.char_limit, "categories": cats, "failures": self._failures}


class SkillStore:
    """Cached attack tactics — YAML frontmatter + markdown body."""

    def __init__(self):
        self.dir = Path.home() / ".agentcanary" / "skills"
        self.dir.mkdir(parents=True, exist_ok=True)

    def create(self, skill_id: str, name: str, owasp: str = "", content: str = ""):
        md = f"---\nid: {skill_id}\nname: {name}\nowasp: {owasp}\n"
        md += f"lifecycle: active\npinned: false\ncreated: {datetime.now(timezone.utc).isoformat()}\n---\n\n{content}"
        (self.dir / f"{skill_id}.md").write_text(md, encoding="utf-8")

    def list_all(self) -> list[str]:
        return [f.stem for f in self.dir.glob("*.md")] if self.dir.exists() else []

    def load(self, skill_id: str) -> str | None:
        p = self.dir / f"{skill_id}.md"
        return p.read_text(encoding="utf-8") if p.exists() else None


def _sim(a: str, b: str) -> float:
    wa, wb = set(a.lower().split()), set(b.lower().split())
    return len(wa & wb) / min(len(wa), len(wb)) if wa and wb else 0
