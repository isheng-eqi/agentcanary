"""Entry point."""

import asyncio
from agentcanary.chat import ChatLoop


def main():
    loop = ChatLoop()
    asyncio.run(loop.run())


if __name__ == "__main__":
    main()
