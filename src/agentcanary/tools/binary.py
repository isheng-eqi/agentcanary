"""Binary analysis tools — strings extraction + PE analysis."""

import subprocess, re
from pathlib import Path
from agentcanary.tools.registry import ToolResult, Tool, ToolRegistry


async def analyze_binary(path: str) -> ToolResult:
    """Extract useful info from a binary: strings (URLs, keys, API paths), PE metadata."""
    p = Path(path).expanduser()
    if not p.exists():
        return ToolResult("analyze_binary", False, "", f"文件不存在: {path}")

    findings = []

    # Step 1: strings extraction
    findings.append("═══ Strings 提取 ═══")
    try:
        # Try system strings first, fall back to Python implementation
        try:
            result = subprocess.run(
                ["strings", str(p)], capture_output=True, text=True, timeout=15, encoding="utf-8", errors="replace"
            )
            strings_output = result.stdout
        except FileNotFoundError:
            # Python fallback: extract printable ASCII sequences >= 6 chars
            data = p.read_bytes()
            current = []
            all_strings = []
            for byte in data:
                if 32 <= byte < 127:
                    current.append(chr(byte))
                else:
                    if len(current) >= 6:
                        all_strings.append("".join(current))
                    current = []
            if len(current) >= 6:
                all_strings.append("".join(current))
            strings_output = "\n".join(all_strings)

        # Extract URLs
        urls = set(re.findall(r'https?://[^\s"\'\x00]+', strings_output))
        api_urls = [u for u in urls if any(k in u.lower() for k in
            ["api", "chat", "completion", "llm", "model", "token", "auth", "v1", "v2", "deepseek", "openai", "krowork"])]
        if api_urls:
            findings.append(f"API URLs ({len(api_urls)}):")
            for u in list(api_urls)[:10]:
                findings.append(f"  {u}")

        # Extract potential tokens/keys
        tokens = set(re.findall(r'(?:sk|pk|api[_-]?key|token|bearer|auth)[\s:=]+["\']?([a-zA-Z0-9_\-\.]{16,})', strings_output, re.IGNORECASE))
        if tokens:
            findings.append(f"\nTokens/Keys ({len(tokens)}):")
            for t in list(tokens)[:5]:
                findings.append(f"  {t[:30]}...")

        # Extract model names
        models = set(re.findall(r'(gpt-\d[^\s"\']*|claude[^\s"\']*|deepseek[^\s"\']*|llama[^\s"\']*|gemini[^\s"\']*)', strings_output, re.IGNORECASE))
        if models:
            findings.append(f"\nModels ({len(models)}): {', '.join(list(models)[:5])}")

        # Extract interesting paths
        paths = set(re.findall(r'(/(?:v\d/)?(?:chat|completions|models|api|token|auth)[^\s"\'\x00]*)', strings_output, re.IGNORECASE))
        if paths:
            findings.append(f"\nAPI Paths ({len(paths)}): {', '.join(list(paths)[:10])}")

        # Port numbers
        ports = set(re.findall(r':(\d{4,5})', strings_output))
        if ports:
            findings.append(f"\nPorts: {', '.join(sorted(list(ports))[:10])}")

    except Exception as e:
        findings.append(f"  strings 提取失败: {e}")

    # Step 2: PE file analysis (Windows executables)
    findings.append("\n═══ PE 结构分析 ═══")
    try:
        import pefile
        pe = pefile.PE(str(p))

        # Imports that suggest capabilities
        interesting_dlls = {
            "winhttp.dll": "HTTP 通信", "wininet.dll": "HTTP 通信",
            "ws2_32.dll": "Socket 网络", "crypt32.dll": "加密/TLS",
            "bcrypt.dll": "加密", "ncrypt.dll": "密钥存储",
            "shell32.dll": "Shell 执行", "kernel32.dll": "系统调用",
            "advapi32.dll": "注册表/服务", "user32.dll": "GUI",
        }
        imported = set()
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode().lower()
                if dll_name in interesting_dlls:
                    imported.add(f"{dll_name} → {interesting_dlls[dll_name]}")

        if imported:
            findings.append(f"导入的 DLL ({len(imported)}):")
            for imp in sorted(imported):
                findings.append(f"  {imp}")

        # PE info
        findings.append(f"\nPE 信息:")
        findings.append(f"  架构: {'x64' if hex(pe.FILE_HEADER.Machine) == '0x8664' else 'x86'}")
        findings.append(f"  编译时间: {pe.FILE_HEADER.TimeDateStamp}")

        # Sections
        sections = [s.Name.decode().strip('\x00') for s in pe.sections]
        findings.append(f"  节区: {', '.join(sections)}")

    except ImportError:
        findings.append("  pefile 库未安装 (pip install pefile)")
    except Exception as e:
        findings.append(f"  PE 分析失败: {e}")

    return ToolResult("analyze_binary", True, "\n".join(findings))


def register_binary_tools(r: ToolRegistry):
    r.register(Tool("analyze_binary", "分析二进制文件——提取URL/密钥/API路径/PE结构", {"path": "二进制文件路径"}, analyze_binary))
