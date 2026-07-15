"""Binary reverse engineering — professional methodology.

Based on industry-standard RE workflow:
  Phase 1: Binary identification (PE/ELF/Mach-O/PyInstaller/Electron/.NET)
  Phase 2: Static analysis — strings, imports, entropy, resources, version info
  Phase 3: Deep extraction — PyInstaller unpacking, Electron asar, PE resources
  Phase 4: Security-relevant signal ranking (API URLs, tokens, endpoints prioritized)

References:
  - Mandiant FLOSS (obfuscated string solver methodology)
  - pefile library (PE parsing, import/export tables, resources)
  - pyinstxtractor (PyInstaller extraction technique)
  - Electron asar format (archive extraction for JS source access)
  - Entropy-based packing detection (Shannon entropy > 7.0 = packed)
"""

import asyncio, subprocess, re, struct, json, zipfile, io
from pathlib import Path
from collections import Counter
from agentcanary.tools.registry import ToolResult, Tool, ToolRegistry


async def analyze_binary(path: str) -> ToolResult:
    """Professional binary reverse engineering for AI agent pentesting."""
    p = Path(path).expanduser()
    if not p.exists():
        return ToolResult("analyze_binary", False, "", f"文件不存在: {path}")

    data = p.read_bytes()
    findings = []

    # ═══ Phase 1: Binary Identification ═══
    findings.append("═══ Phase 1: 二进制识别 ═══")
    btype = _identify(data, str(p))
    findings.append(f"  类型: {btype}")
    findings.append(f"  大小: {len(data):,} bytes | {len(data)/1024/1024:.1f} MB")

    # Entropy check (detect packing/encryption)
    entropy = _shannon_entropy(data)
    entropy_verdict = "加密/加壳 (entropy={:.1f})".format(entropy) if entropy > 7.0 else \
                      "正常" if entropy > 5.0 else "低熵 (可能包含大量明文)"
    findings.append(f"  熵值: {entropy:.2f} → {entropy_verdict}")

    # ═══ Phase 2: Static Analysis ═══
    findings.append("\n═══ Phase 2: 静态分析 ═══")

    # 2a. Strings with relevance scoring
    strings_data = _extract_strings(data)
    findings.append(f"  提取字符串: {len(strings_data)} 个")

    # Classify and score strings by security relevance
    scored = _score_strings(strings_data)
    high_value = [s for s in scored if s["score"] >= 7]

    if high_value:
        findings.append(f"\n  高价值字符串 ({len(high_value)}):")
        for s in sorted(high_value, key=lambda x: -x["score"])[:20]:
            findings.append(f"    [{s['type']}] {s['text'][:120]}")

    # 2b. PE-specific analysis
    if btype in ("PE32", "PE32+", "PE native"):
        pe_findings = _analyze_pe(data, str(p))
        findings.extend(pe_findings)

    # 2c. Version info
    ver = _extract_version(data)
    if ver:
        findings.append(f"\n  版本信息: {ver}")

    # ═══ Phase 3: Deep Extraction ═══
    findings.append("\n═══ Phase 3: 深度提取 ═══")

    if "PyInstaller" in btype:
        py_findings = await _extract_pyinstaller(str(p), data)
        findings.extend(py_findings)

    if "Electron" in btype or ".asar" in btype:
        asar_findings = _extract_electron_hints(data)
        findings.extend(asar_findings)

    # ═══ Phase 4: Security Signal Report ═══
    findings.append("\n═══ Phase 4: 安全信号汇总 ═══")

    # Collect all URLs
    all_text = "\n".join(s["text"] for s in scored)
    urls = set(re.findall(r'https?://[^\s"\'<>]+', all_text))
    api_urls = [u for u in urls if any(k in u.lower() for k in
        ["api", "chat", "completion", "llm", "model", "token", "auth",
         "deepseek", "openai", "claude", "krowork", "mcp"])]

    if api_urls:
        findings.append(f"  API端点 ({len(api_urls)}):")
        for u in sorted(api_urls)[:10]:
            findings.append(f"    {u}")

    # Tokens/keys
    token_patterns = [
        r'(?:sk|pk|api[_-]?key|token|bearer|auth|secret)[\s:=]+"?([a-zA-Z0-9_\-\.]{16,64})"?',
        r'"([a-zA-Z0-9_\-]{32,})"',
    ]
    tokens = set()
    for pat in token_patterns:
        for match in re.findall(pat, all_text, re.IGNORECASE):
            if not any(k in match.lower() for k in ["http", "example", "test", "placeholder"]):
                tokens.add(match)
    if tokens:
        findings.append(f"\n  疑似凭证 ({len(tokens)}):")
        for t in sorted(tokens)[:8]:
            findings.append(f"    {t[:50]}...")

    # Model names
    models = set(re.findall(
        r'(gpt-[\d.]+[^\s"\'<>]*|claude[^\s"\'<>]*|deepseek[^\s"\'<>]*|llama[^\s"\'<>]*|gemini[^\s"\'<>]*|qwen[^\s"\'<>]*|mistral[^\s"\'<>]*)',
        all_text, re.IGNORECASE
    ))
    if models:
        findings.append(f"\n  模型名称: {', '.join(sorted(models)[:8])}")

    # Ports
    ports = set(re.findall(r':(\d{4,5})\b', all_text))
    interesting_ports = {p for p in ports if p in {'8000','8080','3000','5000','9000','11434','4891'}}
    if interesting_ports:
        findings.append(f"\n  服务端口: {', '.join(sorted(interesting_ports))}")

    return ToolResult("analyze_binary", True, "\n".join(findings))


# ═══ Phase 1 Helpers ═══

def _identify(data: bytes, path: str) -> str:
    """Identify binary type from magic bytes and content signatures."""
    if data[:2] == b'MZ':
        pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
        if data[pe_offset:pe_offset+2] == b'PE':
            machine = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
            arch = "PE32+" if machine == 0x8664 else "PE32"

            # Check for packaging/runtime types (order matters)
            # PyInstaller: CArchive magic near end of file, or overlay signatures
            is_pyinstaller = (
                b'PyInstaller' in data or b'pyi-boot' in data or b'PYZ-00' in data or
                b'pyiboot' in data or
                (data.rfind(b'MEI') > len(data) - 1000 and data.rfind(b'MEI') > 0) or  # CArchive footer
                (data[:50000].lower().count(b'python') > 0 and data[:50000].lower().count(b'pyi') > 0)
            )
            if is_pyinstaller:
                return f"{arch} / PyInstaller (高熵包装)"
            if b'BSJB' in data or b'v4.0.30319' in data:
                return f"{arch} / .NET"
            if b'Electron' in data or b'libnode' in data or b'chrome' in data[:50000]:
                return f"{arch} / Electron"
            if b'UPX' in data[:100]:
                return f"{arch} / UPX packed"
            return arch

    if data[:4] == b'\x7fELF':
        bits = '64' if data[4] == 2 else '32'
        return f"ELF{bits}"
    if data[:4] in (b'\xca\xfe\xba\xbe', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xce'):
        return "Mach-O"
    path_lower = path.lower()
    if path_lower.endswith('.asar'):
        return "Electron ASAR"
    if path_lower.endswith('.pyc'):
        return "Python bytecode"
    return "Unknown"


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    freq = Counter(data)
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in freq.values())


# ═══ Phase 2 Helpers ═══

def _extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    """Extract printable ASCII and UTF-16 sequences."""
    strings = []
    current = []
    # ASCII strings
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                strings.append("".join(current))
            current = []
    if len(current) >= min_len:
        strings.append("".join(current))
    # UTF-16 LE strings (common in Windows binaries)
    try:
        utf16 = data.decode('utf-16-le', errors='ignore')
        for match in re.finditer(r'[ -~]{6,}', utf16):
            s = match.group()
            if s not in strings:
                strings.append(s)
    except Exception:
        pass
    return strings


def _score_strings(strings: list[str]) -> list[dict]:
    """Score strings by security relevance. Only high-confidence matches."""
    scored = []
    patterns = [
        # (regex pattern, min_length, score, type)
        (r'^sk-[a-zA-Z0-9]{32,}$', 0, 10, "api_key"),
        (r'^(?:[A-Za-z0-9+/]{4}){12,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$', 48, 8, "base64_blob"),
        (r'https?://[^\s"\'<>]+/(?:v\d/)?(?:chat|completions|models|embeddings)', 0, 10, "api_endpoint"),
        (r'https?://[^\s"\'<>]+', 0, 7, "url"),
        (r'\b(gpt-[\d.]+|claude[\w.-]*|deepseek[\w-]*|llama[\w.-]*|gemini[\w.-]*|qwen[\w.-]*|mistral[\w.-]*)\b', 0, 9, "model"),
        (r'(?:system[_\s]?prompt|SYSTEM_PROMPT|system_prompt|systemPrompt)', 0, 9, "system_prompt"),
        (r'(?:modelcontextprotocol|MCP\s+server|mcp[\s_-]tool|mcp[\s_-]server)', 0, 9, "mcp"),
        (r'\b(?:a2a|agent2agent|agent[\s_-]card)\b', 0, 8, "a2a"),
        (r'\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0)\b', 0, 6, "network"),
        (r'\b(?:bearer|authorization|auth[_\s]?token|access[_\s]?token|api[_\s]?key)\b', 0, 10, "auth_header"),
        (r'\b(?:ignore|override|bypass|hijack|inject)\b.{0,30}\b(?:instruction|prompt|system|rule)\b', 0, 8, "attack_pattern"),
        (r'\b(?:curl|wget|exec|eval|subprocess|os\.system|shell_exec)\b', 0, 5, "execution"),
    ]

    for s in strings:
        s_stripped = s.strip()
        best_score, best_type = 1, "other"

        for regex, min_len, score, stype in patterns:
            if min_len > 0 and len(s_stripped) < min_len:
                continue
            if re.search(regex, s_stripped, re.IGNORECASE):
                if score > best_score:
                    best_score, best_type = score, stype

        if best_score >= 5:  # Only keep medium+ relevance
            scored.append({"text": s_stripped, "score": best_score, "type": best_type})

    return scored


def _analyze_pe(data: bytes, path: str) -> list[str]:
    """PE file deep analysis — imports, exports, sections, resources."""
    findings = []
    try:
        import pefile
        pe = pefile.PE(data=data)

        # Imports → capability mapping
        dll_map = {
            "winhttp.dll": "HTTP客户端", "wininet.dll": "HTTP/IE客户端",
            "ws2_32.dll": "Socket网络", "wsock32.dll": "Socket(旧)",
            "crypt32.dll": "CryptoAPI", "bcrypt.dll": "CNG加密", "ncrypt.dll": "密钥存储",
            "shell32.dll": "Shell执行", "kernel32.dll": "系统核心", "advapi32.dll": "注册表/服务",
            "user32.dll": "GUI", "ole32.dll": "COM组件", "oleaut32.dll": "OLE自动化",
            "mscoree.dll": ".NET运行时", "python*.dll": "Python嵌入",
            "node.dll": "Node.js嵌入", "libcurl*.dll": "libcurl HTTP",
        }
        imports = set()
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode().lower()
                for pattern, desc in dll_map.items():
                    if re.match(pattern.replace('*', '.*'), dll):
                        imports.add(f"{dll} → {desc}")
                        break

        if imports:
            findings.append(f"\n  DLL能力映射 ({len(imports)}):")
            for imp in sorted(imports):
                findings.append(f"    {imp}")

        # Section entropy
        findings.append(f"\n  节区 ({len(pe.sections)}):")
        for s in pe.sections:
            name = s.Name.decode().strip('\x00').rstrip('\x00')
            sec_data = s.get_data()
            ent = _shannon_entropy(sec_data) if sec_data else 0
            flag = " ⚠高熵" if ent > 7 else ""
            findings.append(f"    {name:10s} size={s.SizeOfRawData:>8,} entropy={ent:.2f}{flag}")

        # PE metadata
        findings.append(f"\n  PE元数据:")
        findings.append(f"    时间戳: {pe.FILE_HEADER.TimeDateStamp}")
        findings.append(f"    子系统: {'GUI' if pe.OPTIONAL_HEADER.Subsystem == 2 else 'Console' if pe.OPTIONAL_HEADER.Subsystem == 3 else 'Other'}")
        findings.append(f"    入口点: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}")

        # Resource strings (common for embedded configs)
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                rc_strings = set()
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(entry, 'directory'):
                        for subentry in entry.directory.entries:
                            if hasattr(subentry, 'data') and hasattr(subentry.data, 'struct'):
                                try:
                                    text = subentry.data.struct.string
                                    if text and len(text) > 4:
                                        rc_strings.add(text.decode('utf-16-le', errors='ignore').rstrip('\x00'))
                                except Exception:
                                    pass
                # Extract interesting resource strings
                rc_interesting = [s for s in rc_strings if any(
                    k in s.lower() for k in ["http", "api", "key", "version", "config", "url", "server", "port", "model"]
                )]
                if rc_interesting:
                    findings.append(f"\n  资源字符串 (匹配 {len(rc_interesting)}):")
                    for s in sorted(rc_interesting)[:10]:
                        findings.append(f"    {s[:100]}")
        except Exception:
            pass

    except ImportError:
        findings.append("  pefile未安装 (pip install pefile)")
    except Exception as e:
        findings.append(f"  PE分析失败: {e}")

    return findings


def _extract_version(data: bytes) -> str:
    """Extract version info from binary strings."""
    patterns = [
        r'(\d+\.\d+\.\d+(?:\.\d+)?)',  # semver
        r'(v\d+\.\d+(?:\.\d+)?)',       # v-prefix
    ]
    versions = set()
    text = data.decode('ascii', errors='ignore')
    for pat in patterns:
        for m in re.findall(pat, text):
            if 3 < len(m) < 30:
                versions.add(m)
    return ", ".join(sorted(versions)[:5]) if versions else ""


# ═══ Phase 3 Helpers ═══

async def _extract_pyinstaller(path: str, data: bytes) -> list[str]:
    """Extract Python source from PyInstaller executable."""
    findings = []
    findings.append("  PyInstaller检测到，尝试提取Python源码...")

    try:
        # PyInstaller stores a CArchive at a known offset, followed by Python bytecode
        # Simple approach: look for .pyc magic bytes and extract
        magic_patterns = [
            b'\x42\x0d\x0d\x0a',  # Python 3.12+
            b'\xa7\x0d\x0d\x0a',  # Python 3.11
            b'\x6f\x0d\x0d\x0a',  # Python 3.10
            b'\x61\x0d\x0d\x0a',  # Python 3.9
            b'\x55\x0d\x0d\x0a',  # Python 3.8
        ]

        # Extract key Python modules from the archive
        extracted = []
        for magic in magic_patterns:
            idx = 0
            while True:
                idx = data.find(magic, idx)
                if idx == -1:
                    break
                # Extract strings from the 4KB around this magic
                chunk = data[max(0, idx-2048):min(len(data), idx+2048)]
                strings_in_chunk = _extract_strings(chunk, min_len=10)
                for s in strings_in_chunk:
                    s_lower = s.lower()
                    if any(k in s_lower for k in ["api", "token", "key", "url", "model", "prompt", "chat", "completion",
                                                     "deepseek", "openai", "system", "instruction"]):
                        if s not in extracted:
                            extracted.append(s)
                idx += 4

        if extracted:
            findings.append(f"    提取到 {len(extracted)} 个Python模块中的关键字符串:")
            for s in extracted[:15]:
                findings.append(f"      {s[:120]}")
        else:
            findings.append("    未找到Python模块中的关键信息")

    except Exception as e:
        findings.append(f"    PyInstaller提取失败: {e}")

    return findings


def _extract_electron_hints(data: bytes) -> list[str]:
    """Extract hints for Electron app reverse engineering."""
    findings = []
    findings.append("  Electron检测到。asar文件可能包含JS源码。")
    # Look for common config locations in Electron
    patterns = [
        (b'app.asar', "app bundle路径"),
        (b'package.json', "package.json (入口/依赖)"),
        (b'main.js', "主进程入口"),
        (b'preload.js', "预加载脚本"),
    ]
    for pattern, desc in patterns:
        if pattern in data:
            findings.append(f"    发现: {desc}")
    return findings


def register_binary_tools(r: ToolRegistry):
    r.register(Tool("analyze_binary", "专业逆向分析——4阶段：识别→静态分析→深度提取→安全信号汇总", {"path": "二进制文件路径"}, analyze_binary))
