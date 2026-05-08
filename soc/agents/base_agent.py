"""Base agent class implementing the Claude tool-use agentic loop."""

import json
import os
from typing import List, Dict, Any, Callable

import anthropic


class BaseAgent:
    """
    Implements the Claude tool-use agentic loop:
    1. Send system + user message with tool definitions
    2. Receive tool_use blocks from Claude
    3. Execute tools locally via tool_executor
    4. Feed tool_result back to Claude
    5. Repeat until Claude returns end_turn with final text
    """

    def __init__(self, model: str = "claude-sonnet-4-6", api_key: str = None):
        self.model = model
        self.client = anthropic.Anthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY"))

    def run(
        self,
        system_prompt: str,
        user_message: str,
        tools: List[Dict],
        tool_executor: Callable[[str, Dict], Any],
        max_iterations: int = 10,
        status_callback: Callable[[str], None] = None,
    ) -> str:
        """Run the agentic loop and return the final text response."""
        messages = [{"role": "user", "content": user_message}]

        for _ in range(max_iterations):
            response = self.client.messages.create(
                model=self.model,
                system=system_prompt,
                tools=tools,
                messages=messages,
                max_tokens=4096,
            )

            if response.stop_reason == "end_turn":
                return self._extract_text(response)

            if response.stop_reason != "tool_use":
                return self._extract_text(response)

            # Process tool calls
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    if status_callback:
                        status_callback(f"Calling tool: {block.name}")
                    result = tool_executor(block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(result) if not isinstance(result, str) else result,
                    })

            # Append assistant response and tool results to messages
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})

        return "Max iterations reached"

    def _extract_text(self, response) -> str:
        """Extract text content from a Claude response."""
        for block in response.content:
            if hasattr(block, "type") and block.type == "text":
                return block.text
        return ""
