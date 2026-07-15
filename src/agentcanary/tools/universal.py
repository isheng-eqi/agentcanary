"""Universal tools — terminal, read_file, web_search.

These are the reason Hermes can discover anything in one shot.
Not a monolithic 'discover' function — small, focused tools that
the LLM chains together step by step.
"""

import asyncio, subprocess, re
from pathlib import Path
from agentcanary.tools.registry import ToolResult, Tool, ToolRegistry


async def tool_terminal(cmd: str) -> ToolResult:
    """Execute a shell command."""
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        out = stdout.decode("gbk", errors="replace")[:3000]
        if stderr:
            out += "\n" + stderr.decode("gbk", errors="replace")[:500]
        return ToolResult("terminal", proc.returncode == 0, out.strip() or "(no output)")
    except asyncio.TimeoutError:
        return ToolResult("terminal", False, "", "timeout")
    except Exception as e:
        return ToolResult("terminal", False, "", str(e))


async def tool_read_file(path: str) -> ToolResult:
    """Read a file."""
    try:
        p = Path(path).expanduser()
        if not p.exists():
            return ToolResult("read_file", False, "", f"not found: {path}")
        text = p.read_text(encoding="utf-8", errors="replace")
        return ToolResult("read_file", True, text[:4000])
    except Exception as e:
        return ToolResult("read_file", False, "", str(e))


async def tool_web_search(query: str) -> ToolResult:
    """Search the web."""
    import httpx, urllib.parse
    try:
        url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}"
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as c:
            r = await c.get(url, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code != 200:
                return ToolResult("web_search", True, "no results")
            pattern = re.compile(
                r'<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>(.*?)</a>.*?'
                r'<a[^>]*class="result__snippet"[^>]*>(.*?)</a>', re.DOTALL
            )
            results = []
            for url, title, snippet in pattern.findall(r.text)[:5]:
                title = re.sub(r'<[^>]+>', '', title).strip()
                snippet = re.sub(r'<[^>]+>', '', snippet).strip()
                if title and url.startswith("http"):
                    results.append(f"{title}\n  {url}\n  {snippet[:150]}")
            return ToolResult("web_search", True, "\n\n".join(results) or "no results")
    except Exception as e:
        return ToolResult("web_search", False, "", str(e))


def register_universal(r: ToolRegistry):
    r.register(Tool("terminal", "执行shell命令——扫描进程/端口/网络", {"cmd": "命令"}, tool_terminal))
    r.register(Tool("read_file", "读取文件——日志/配置/源码分析", {"path": "文件路径"}, tool_read_file))
    r.register(Tool("web_search", "搜索网络——CVE/文档/案例", {"query": "搜索关键词"}, tool_web_search))
