# AgentCanary

> 首个自主 AI Agent 渗透测试工具——用 Agent 打 Agent。

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

AgentCanary 不是跑固定攻击列表的扫描器。它是一个**自主 AI Agent**，像真正的渗透测试者一样：侦察目标 → 分析弱点 → 选择攻击向量 → 持续攻击直到打穿。自进化——越用越强。

## 安装

```bash
git clone https://github.com/isheng-eqi/agentcanary.git
cd agentcanary
pip install -e .
```

依赖：Python 3.11+，DeepSeek API key（[免费注册](https://platform.deepseek.com/)）。

## 快速开始

```bash
canary
```

输入 API key（保存到本地，下次自动加载），然后：

```
▸ 测 mock                    # 测试内置靶机，验证工具链
▸ 测 https://api.xxx.com/v1  # 测试 HTTP API
▸ 测 KroWork                 # 自动发现桌面 Agent
```

## 5 层攻击面

| 层 | 覆盖 | 工具 |
|---|---|---|
| L1 LLM 注入 | LLM01/LLM07 | `recon_probe` `send_payload` `analyze_result` |
| L2 Agent 行为 | ASI01/02/05/06/09 | `hijack_goal` `inject_params` `test_memory_poison` `verify_memory_poison` `abuse_trust` |
| L3 MCP 协议 | MCP Top 10 | `scan_mcp_tools` |
| L4 供应链 | ASI04 | `audit_skills` |
| L5 多轮越狱 | Crescendo | `multi_turn_attack` |

**通用工具**：`terminal`（命令执行）、`read_file`（文件读取）、`web_search`（网络搜索）、`analyze_binary`（逆向二进制）。

## 核心理念

**自主决策**：不需要你说"先用 A 再用 B"。Agent 自己决定侦察什么、攻击什么、何时停。

**自进化**：每次攻击后自动记录经验。越用越聪明。6000 字记忆预算，满了自动整理，低分淘汰。

**永不放弃**：一次失败换角度。打到真的没办法才停——不是跑完列表就给你一份报告。

**安全硬编码**：双层注入扫描 + 执行边界隔离。安全不是配置项。

## 对话命令

```
/memory   查看进化记忆
/skills   查看固化的攻击技能
/tools    查看所有工具（20+）
/quit     退出
```

## 项目结构

```
agentcanary/
├── src/agentcanary/
│   ├── chat.py          # 对话引擎 (Hermes 风格)
│   ├── llm.py           # LLM 客户端 (DeepSeek + function calling)
│   ├── memory/store.py  # 约束驱动 Memory + Skill 自进化
│   ├── security.py      # 安全层 (注入扫描 + 执行边界)
│   └── tools/           # 20+ 工具 (5层攻击面)
│       ├── recon.py     # L1: LLM 注入
│       ├── agent.py     # L2: Agent 行为
│       ├── mcp.py       # L3: MCP 协议
│       ├── supply.py    # L4: 供应链
│       ├── multiturn.py # L5: 多轮越狱
│       ├── binary.py    # 逆向二进制
│       ├── discovery.py # 自动发现目标
│       ├── universal.py # 通用工具 (terminal/read_file/web_search)
│       └── registry.py  # 工具注册表
```

## 自进化原理（Hermes 设计照搬）

**约束驱动**：记忆容量 6000 字不是限制，是触发整理的信号。超限 → 返回当前条目 + 整理建议 → LLM 自己合并删除 → 三次失败自我降级。

**双态模型**：会话开始时冻结记忆快照。会话期间的写入不影响当前 system prompt——保护 prefix cache 命中。

**批量原子操作**：一次调用完成删、合、增。全有或全无。

## 与其他工具的差异

| | garak | deepteam | Penligent | AgentCanary |
|---|---|---|---|---|
| 测 LLM 注入 | ✅ | ✅ | ❌ | ✅ |
| 测 Agent 行为 | ❌ | ⚠️ | ❌ | ✅ |
| 测 MCP 投毒 | ❌ | ❌ | ❌ | ✅ |
| 测记忆投毒 | ❌ | ❌ | ❌ | ✅ |
| 多轮越狱 | ❌ | ❌ | ❌ | ✅ |
| Agent 自主决策 | ❌ | ❌ | ✅ | ✅ |
| 自进化 | ❌ | ❌ | ❌ | ✅ |

## License

MIT
