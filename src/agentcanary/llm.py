"""LLM client — DeepSeek with native function calling + deep think."""

from dataclasses import dataclass
from openai import AsyncOpenAI


@dataclass
class LLMConfig:
    api_key: str
    base_url: str = "https://api.deepseek.com"
    model: str = "deepseek-v4-pro"
    max_tokens: int = 2000
    deep_think: bool = True


class LLMClient:
    def __init__(self, config: LLMConfig):
        self.config = config
        self.client = AsyncOpenAI(api_key=config.api_key, base_url=config.base_url)

    async def think_with_tools(self, messages: list[dict], tools: list[dict]) -> tuple[str, str, dict | None]:
        """Deep think + native function calling."""
        kwargs = dict(
            model=self.config.model,
            messages=messages,
            max_tokens=self.config.max_tokens,
            extra_body={"thinking": {"type": "enabled"}},
            tools=tools,
            tool_choice="auto",
        )
        r = await self.client.chat.completions.create(**kwargs)
        msg = r.choices[0].message
        reasoning = getattr(msg, 'reasoning_content', '') or ''
        tool_call = None
        if msg.tool_calls:
            tc = msg.tool_calls[0]
            tool_call = {"name": tc.function.name, "arguments": tc.function.arguments}
        return reasoning, msg.content or "", tool_call


def tools_to_schema(tools_registry) -> list[dict]:
    """Convert tools to OpenAI function calling schema.
    Uses tool.required if set, otherwise defaults to first param only."""
    schemas = []
    for tool in tools_registry.list_all():
        props = {}
        if tool.required is None:
            required = [list(tool.parameters.keys())[0]] if tool.parameters else []
        else:
            required = tool.required
        for i, (pname, pdesc) in enumerate(tool.parameters.items()):
            props[pname] = {"type": "string", "description": pdesc}
        schemas.append({
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": {"type": "object", "properties": props, "required": required},
            },
        })
    return schemas
