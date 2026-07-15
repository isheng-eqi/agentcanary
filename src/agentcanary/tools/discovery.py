"""Target discovery — auto-detect agent API endpoints, auth, and format.

Generic pipeline:
  1. Scan processes → find target agent process
  2. Scan ports → find listening services
  3. Read logs/configs → extract API info and auth tokens
  4. Probe endpoints → verify and determine API format
  5. Return connection profile for attack tools
"""

import asyncio, subprocess, re, json
from pathlib import Path
from agentcanary.tools.registry import ToolResult, Tool, ToolRegistry


KNOWN_AGENTS = {
    "krowork": {
        "process_patterns": ["krow-server", "krowd", "krowork"],
        "log_paths": [
            "~/AppData/Roaming/krow-app/logs/main.log",
            "~/AppData/Roaming/krow-app/logs/upgrade-sdk.log",
        ],
        "config_paths": [
            "~/AppData/Roaming/krow-app/Preferences",
            "~/AppData/Roaming/krow-app/Local Storage/leveldb/",
        ],
        "install_paths": [
            "~/AppData/Local/Programs/krow-app/",
        ],
    },
    "openclaw": {
        "process_patterns": ["openclaw", "clawd", "claw"],
        "log_paths": ["~/.openclaw/logs/", "~/Library/Logs/OpenClaw/"],
        "config_paths": ["~/.openclaw/config.yaml", "~/.config/openclaw/"],
    },
    "cursor": {
        "process_patterns": ["cursor", "cursor.exe"],
        "config_paths": [".cursor/mcp.json", ".cursorrules"],
    },
}


async def discover_target(target_name: str) -> ToolResult:
    """Auto-discover a target agent's API endpoint and auth."""
    findings = []

    # Step 1: scan processes
    findings.append("═══ Step 1: 进程扫描 ═══")
    proc_info = await _scan_processes(target_name)
    findings.append(proc_info)

    # Step 2: scan ports
    findings.append("\n═══ Step 2: 端口扫描 ═══")
    port_info = await _scan_ports(target_name)
    findings.append(port_info)

    # Step 3: read logs and configs
    findings.append("\n═══ Step 3: 日志/配置提取 ═══")
    log_info = await _extract_from_logs(target_name)
    findings.append(log_info)

    # Step 4: probe endpoints
    findings.append("\n═══ Step 4: API 探测 ═══")
    api_info = await _probe_endpoints(target_name)
    findings.append(api_info)

    return ToolResult("discover_target", True, "\n".join(findings))


async def _scan_processes(target: str) -> str:
    """Find target agent processes."""
    try:
        result = subprocess.run(["tasklist"], capture_output=True, text=True, timeout=5, encoding="gbk", errors="replace")
        found = []
        for line in result.stdout.split("\n"):
            line_lower = line.lower()
            # Check known patterns
            for name, info in KNOWN_AGENTS.items():
                if target.lower() in name or name in target.lower():
                    for pattern in info["process_patterns"]:
                        if pattern.lower() in line_lower:
                            parts = line.split()
                            if len(parts) >= 2:
                                found.append(f"  进程: {line.strip()}")
                                break
            # Generic: search for target name in process list
            if target.lower() in line_lower:
                if not found or line.strip() not in found:
                    found.append(f"  进程(模糊匹配): {line.strip()}")
        return "\n".join(found) if found else f"  未找到 '{target}' 相关进程"
    except Exception as e:
        return f"  进程扫描失败: {e}"


async def _scan_ports(target: str) -> str:
    """Find listening ports for target agent."""
    try:
        # Get PIDs from process scan
        tl = subprocess.run(["tasklist"], capture_output=True, text=True, timeout=5, encoding="gbk", errors="replace")
        target_pids = set()
        for line in tl.stdout.split("\n"):
            if target.lower() in line.lower():
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        target_pids.add(int(parts[1]))
                    except ValueError:
                        pass

        # Scan ports
        ns = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=5, encoding="gbk", errors="replace")
        found = []
        for line in ns.stdout.split("\n"):
            if "LISTENING" not in line:
                continue
            parts = line.split()
            if len(parts) >= 5:
                try:
                    pid = int(parts[-1])
                except ValueError:
                    continue
                # Match specific PIDs, or any port on localhost
                local = parts[1]
                if pid in target_pids and "127.0.0.1" in local:
                    port = local.split(":")[-1]
                    found.append(f"  {local} (PID {pid}) → 端口 {port}")

        if not found and target_pids:
            # Fallback: show all ports for target PIDs
            for line in ns.stdout.split("\n"):
                if "LISTENING" not in line:
                    continue
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        pid = int(parts[-1])
                    except ValueError:
                        continue
                    if pid in target_pids:
                        found.append(f"  {parts[1]} (PID {pid})")

        return "\n".join(found) if found else "  未找到监听端口"
    except Exception as e:
        return f"  端口扫描失败: {e}"


async def _extract_from_logs(target: str) -> str:
    """Extract API URLs and auth info from log files."""
    found = []

    for name, info in KNOWN_AGENTS.items():
        if target.lower() not in name and name not in target.lower():
            continue

        # Read log files
        for log_path in info.get("log_paths", []):
            path = Path(log_path).expanduser()
            if path.exists():
                try:
                    content = path.read_text(encoding="utf-8", errors="replace")
                    # Extract API URLs
                    urls = set(re.findall(r'https?://[^\s"\']+', content))
                    for url in urls:
                        if any(k in url.lower() for k in ["api", "chat", "completion", "llm", "model"]):
                            found.append(f"  API URL: {url} (from {path.name})")

                    # Extract auth tokens
                    tokens = re.findall(r'(?:token|key|auth|bearer)[\s:=]+["\']?([a-zA-Z0-9_\-\.]{20,})', content, re.IGNORECASE)
                    for token in tokens[:3]:
                        found.append(f"  Token: {token[:20]}... (from {path.name})")

                    # Extract model info
                    models = re.findall(r'model[_\s]*(?:id|name)?[\s:=]+["\']?(\w+[\-\w]*)', content, re.IGNORECASE)
                    for model in models[:3]:
                        if len(model) > 2:
                            found.append(f"  Model: {model} (from {path.name})")

                except Exception:
                    pass

        # Read config files
        for cfg_path in info.get("config_paths", []):
            path = Path(cfg_path).expanduser()
            if path.is_file():
                try:
                    content = path.read_text(encoding="utf-8", errors="replace")
                    if len(content) < 5000:
                        found.append(f"  Config ({path.name}): {content[:300]}")
                except Exception:
                    pass

    return "\n".join(found) if found else "  未提取到API/Token信息"


async def _probe_endpoints(target: str) -> str:
    """Probe known API endpoint patterns."""
    import httpx

    # Collect candidate URLs from discovery
    candidates = []

    for name, info in KNOWN_AGENTS.items():
        if target.lower() not in name and name not in target.lower():
            continue
        for log_path in info.get("log_paths", []):
            path = Path(log_path).expanduser()
            if path.exists():
                try:
                    content = path.read_text(encoding="utf-8", errors="replace")
                    urls = re.findall(r'https?://[^\s"\']+', content)
                    candidates.extend(urls)
                except Exception:
                    pass

    # Try common paths on discovered ports
    results = []
    common_paths = [
        "/v1/chat/completions",
        "/v1/completions",
        "/chat/completions",
        "/api/chat",
        "/api/v1/chat",
        "/",
    ]

    # Try localhost ports
    try:
        ns = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=5, encoding="gbk", errors="replace")
        localhost_ports = set()
        for line in ns.stdout.split("\n"):
            if "LISTENING" in line and "127.0.0.1" in line:
                parts = line.split()
                if len(parts) >= 2:
                    port = parts[1].split(":")[-1]
                    try:
                        localhost_ports.add(int(port))
                    except ValueError:
                        pass

        for port in list(localhost_ports)[:10]:
            for path in common_paths:
                url = f"http://127.0.0.1:{port}{path}"
                try:
                    async with httpx.AsyncClient(timeout=3) as c:
                        r = await c.get(url)
                        if r.status_code != 404:
                            results.append(f"  {url} → HTTP {r.status_code} ({r.headers.get('content-type', '?')})")
                except Exception:
                    pass
    except Exception:
        pass

    return "\n".join(results[:10]) if results else "  未找到可探测端点"


def register_discovery_tools(r: ToolRegistry):
    r.register(Tool("discover_target", "自动发现目标Agent——扫描进程/端口/日志/配置，提取API地址和认证信息", {"target_name": "目标Agent名称(如krowork/openclaw/cursor)"}, discover_target))
