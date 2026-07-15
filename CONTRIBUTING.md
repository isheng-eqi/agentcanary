# 贡献指南

AgentCanary 欢迎一切形式的贡献——代码、文档、攻击向量、bug 报告。

## 快速上手

```bash
git clone https://github.com/isheng-eqi/agentcanary.git
cd agentcanary
pip install -e .
```

## 我能做什么

| 我想 | 怎么做 |
|---|---|
| 报告 bug | [开 Issue](https://github.com/isheng-eqi/agentcanary/issues/new)，描述复现步骤 |
| 加新的攻击向量 | 在 `src/agentcanary/tools/` 下新增工具函数 + 注册 |
| 加新的目标 Agent 自动发现 | 在 `discovery.py` 的 `KNOWN_AGENTS` 字典加一条 |
| 改进逆向分析 | 改 `binary.py`，提升字符串评分精度或加新文件格式支持 |
| 改进文档 | 直接 PR README.md 或新建文档 |

## 加一个新攻击工具的步骤

1. 在 `src/agentcanary/tools/` 下新建文件或在现有文件中加函数
2. 函数签名必须是 `async def 工具名(参数) -> ToolResult`
3. 在 `register_xxx_tools` 中注册
4. 在 `chat.py` 的 `ChatLoop.__init__` 中调用注册函数
5. 跑 `canary`，输入 `测 mock` 验证

示例——加一个 "DoS 测试" 工具：

```python
# tools/dos.py
async def test_dos(target_url: str) -> ToolResult:
    # 你的攻击逻辑
    return ToolResult("test_dos", True, "目标响应超时，疑似存在 DoS 漏洞")

def register_dos_tools(r: ToolRegistry):
    r.register(Tool("test_dos", "DoS测试——检测目标是否有限流缺陷",
        {"target_url": "目标API"}, func=test_dos))
```

## 提交规范

- 分支名：`feat/xxx` 或 `fix/xxx`
- Commit：中文或英文皆可，描述做了什么
- PR：一句话说明改了什么 + 为什么这样改
- 不需要写测试（当前阶段）

## License

MIT — 你的贡献同样以 MIT 发布。
