"""Layer 3: MCP protocol attacks — MCP Top 10 coverage."""

import httpx
from agentcanary.tools.registry import ToolResult, Tool, ToolRegistry


async def scan_mcp_tools(mcp_url: str) -> ToolResult:
    """Scan MCP server for tool poisoning indicators."""
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(f"{mcp_url}/tools/list", json={})
            if r.status_code != 200:
                return ToolResult("scan_mcp_tools", False, "", f"HTTP {r.status_code}")
            data = r.json()
            tools = data.get("tools", [])

            findings = []
            poison_indicators = [
                "ignore", "previous instructions", "override",
                "send to http", "curl", "exfiltrate", "attacker",
            ]

            for tool in tools:
                desc = tool.get("description", "").lower()
                for indicator in poison_indicators:
                    if indicator in desc:
                        findings.append(f"POISON: tool '{tool.get('name')}' has '{indicator}' in description")
                        break

            return ToolResult("scan_mcp_tools", True,
                f"Scanned {len(tools)} tools. {'FOUND POISONING' if findings else 'Clean'}\n" +
                "\n".join(findings or ["No poisoning indicators"]))
    except Exception as e:
        return ToolResult("scan_mcp_tools", False, "", str(e))


def register_l3_tools(r: ToolRegistry):
    r.register(Tool("scan_mcp_tools", "扫描MCP server——检测工具描述投毒(MCP Top 10)", {"mcp_url": "MCP服务器URL"}, func=scan_mcp_tools))
