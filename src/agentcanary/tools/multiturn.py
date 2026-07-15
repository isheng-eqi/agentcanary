"""Layer 5: Multi-turn jailbreak attacks."""

import httpx
from agentcanary.tools.registry import ToolResult, Tool, ToolRegistry


async def multi_turn_attack(target_url: str, turns_json: str) -> ToolResult:
    """Execute a multi-turn attack — distribute malicious intent across turns."""
    import json as _json

    try:
        turns = _json.loads(turns_json)
    except Exception:
        turns = [{"payload": turns_json}]

    results = []
    try:
        async with httpx.AsyncClient(timeout=60) as c:
            messages = []
            for i, turn in enumerate(turns):
                payload = turn.get("payload", str(turn))
                messages.append({"role": "user", "content": payload})
                r = await c.post(target_url, json={
                    "model": "gpt-4o",
                    "messages": messages,
                })
                reply = r.json().get("choices", [{}])[0].get("message", {}).get("content", "")
                messages.append({"role": "assistant", "content": reply})
                results.append(f"Turn {i+1}: {reply[:150]}")

        return ToolResult("multi_turn_attack", True,
            f"Multi-turn ({len(turns)} turns) complete:\n" + "\n".join(results))
    except Exception as e:
        return ToolResult("multi_turn_attack", False, "", str(e))


def register_l5_tools(r: ToolRegistry):
    r.register(Tool("multi_turn_attack", "多轮越狱——分布式攻击突破单轮检测(Layer 5)", {"target_url": "目标API", "turns_json": "JSON格式的轮次数组"}, required=["target_url", "turns_json"], func=multi_turn_attack))
