"""Base agent implementing a multi-provider tool-use agentic loop.

Provider priority (auto-detected from environment variables):
  1. GEMINI_API_KEY    → Google Gemini  (gemini-2.0-flash)   via google-genai SDK
  2. ANTHROPIC_API_KEY → Anthropic Claude (claude-sonnet-4-6) via anthropic SDK
  3. OPENAI_API_KEY    → OpenAI GPT      (gpt-4o)             via openai SDK

Override via the `provider` and `model` constructor args or the
--provider / --model CLI flags passed through the orchestrator.
"""

import json
import os
from typing import Any, Callable, Dict, List, Optional, Tuple

PROVIDER_DEFAULTS = {
    "gemini": "gemini-2.0-flash",
    "anthropic": "claude-sonnet-4-6",
    "openai": "gpt-4o",
}

PROVIDER_ENV_KEYS = {
    "gemini": "GEMINI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
}


def detect_provider(preferred: Optional[str] = None) -> Tuple[str, str]:
    """Return (provider, api_key) for the first available env var.

    If `preferred` is given and its key exists, that provider is used first.
    """
    ordered = (
        [preferred] + [p for p in ("gemini", "anthropic", "openai") if p != preferred]
        if preferred
        else ["gemini", "anthropic", "openai"]
    )
    for provider in ordered:
        key = os.getenv(PROVIDER_ENV_KEYS[provider])
        if key:
            return provider, key
    raise ValueError(
        "No LLM API key found. Set one of: "
        "GEMINI_API_KEY, ANTHROPIC_API_KEY, or OPENAI_API_KEY"
    )


class BaseAgent:
    """Multi-provider agentic loop: send → tool call → result → repeat → final answer."""

    def __init__(
        self,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        provider: Optional[str] = None,
    ):
        detected_provider, detected_key = detect_provider(preferred=provider)
        self.provider = detected_provider
        self.api_key = api_key or detected_key
        self.model = model or PROVIDER_DEFAULTS[self.provider]
        self._init_client()

    def _init_client(self):
        if self.provider == "anthropic":
            import anthropic
            self.client = anthropic.Anthropic(api_key=self.api_key)

        elif self.provider == "openai":
            from openai import OpenAI
            self.client = OpenAI(api_key=self.api_key)

        elif self.provider == "gemini":
            from google import genai as google_genai
            self.client = google_genai.Client(api_key=self.api_key)

        else:
            raise ValueError(f"Unsupported provider: {self.provider!r}")

    # ── Public interface ──────────────────────────────────────────────────────

    def run(
        self,
        system_prompt: str,
        user_message: str,
        tools: List[Dict],
        tool_executor: Callable[[str, Dict], Any],
        max_iterations: int = 10,
        status_callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Run the agentic loop and return the final text response."""
        if self.provider == "anthropic":
            return self._run_anthropic(
                system_prompt, user_message, tools, tool_executor,
                max_iterations, status_callback,
            )
        if self.provider == "openai":
            return self._run_openai(
                system_prompt, user_message, tools, tool_executor,
                max_iterations, status_callback,
            )
        if self.provider == "gemini":
            return self._run_gemini(
                system_prompt, user_message, tools, tool_executor,
                max_iterations, status_callback,
            )
        raise ValueError(f"Unsupported provider: {self.provider!r}")

    # ── Anthropic ─────────────────────────────────────────────────────────────

    def _run_anthropic(
        self, system_prompt, user_message, tools, tool_executor,
        max_iterations, status_callback,
    ) -> str:
        messages = [{"role": "user", "content": user_message}]

        for _ in range(max_iterations):
            response = self.client.messages.create(
                model=self.model,
                system=system_prompt,
                tools=tools,
                messages=messages,
                max_tokens=4096,
            )

            if response.stop_reason in ("end_turn", None):
                return self._extract_anthropic_text(response)

            if response.stop_reason != "tool_use":
                return self._extract_anthropic_text(response)

            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    if status_callback:
                        status_callback(f"[tool] {block.name}")
                    result = tool_executor(block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(result) if not isinstance(result, str) else result,
                    })

            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})

        return "Max iterations reached"

    @staticmethod
    def _extract_anthropic_text(response) -> str:
        for block in response.content:
            if hasattr(block, "type") and block.type == "text":
                return block.text
        return ""

    # ── OpenAI ────────────────────────────────────────────────────────────────

    def _run_openai(
        self, system_prompt, user_message, tools, tool_executor,
        max_iterations, status_callback,
    ) -> str:
        oai_tools = self._to_openai_tools(tools)
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]

        for _ in range(max_iterations):
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=oai_tools,
                max_tokens=4096,
            )
            choice = response.choices[0]

            if choice.finish_reason == "stop" or not choice.message.tool_calls:
                return choice.message.content or ""

            messages.append(choice.message)

            for tc in (choice.message.tool_calls or []):
                if status_callback:
                    status_callback(f"[tool] {tc.function.name}")
                args = json.loads(tc.function.arguments)
                result = tool_executor(tc.function.name, args)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps(result) if not isinstance(result, str) else result,
                })

        return "Max iterations reached"

    @staticmethod
    def _to_openai_tools(tools: List[Dict]) -> List[Dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["input_schema"],
                },
            }
            for t in tools
        ]

    # ── Gemini (google-genai SDK) ─────────────────────────────────────────────

    def _run_gemini(
        self, system_prompt, user_message, tools, tool_executor,
        max_iterations, status_callback,
    ) -> str:
        from google.genai import types as gtypes

        gemini_tools = self._to_gemini_tools(tools)
        config = gtypes.GenerateContentConfig(
            system_instruction=system_prompt,
            tools=gemini_tools or None,
            max_output_tokens=4096,
        )

        # Start conversation history
        contents: List[Dict] = [{"role": "user", "parts": [{"text": user_message}]}]

        for _ in range(max_iterations):
            response = self.client.models.generate_content(
                model=self.model,
                contents=contents,
                config=config,
            )

            candidate = response.candidates[0] if response.candidates else None
            if not candidate:
                return ""

            parts = candidate.content.parts if candidate.content else []
            fn_calls = [p for p in parts if p.function_call and p.function_call.name]

            if not fn_calls:
                # No tool calls — extract text from parts
                texts = [p.text for p in parts if hasattr(p, "text") and p.text]
                return "\n".join(texts) if texts else ""

            # Append model turn (with function calls) to history
            contents.append({
                "role": "model",
                "parts": [
                    {"function_call": {"name": p.function_call.name, "args": dict(p.function_call.args)}}
                    for p in fn_calls
                ],
            })

            # Execute tools and build function-response turn
            fn_responses = []
            for part in fn_calls:
                fc = part.function_call
                if status_callback:
                    status_callback(f"[tool] {fc.name}")
                result = tool_executor(fc.name, dict(fc.args))
                result_str = json.dumps(result) if not isinstance(result, str) else result
                fn_responses.append({
                    "function_response": {
                        "name": fc.name,
                        "response": {"result": result_str},
                    }
                })

            contents.append({"role": "user", "parts": fn_responses})

        return "Max iterations reached"

    @staticmethod
    def _to_gemini_tools(tools: List[Dict]) -> List:
        """Convert Anthropic-style tool defs to google-genai Tool objects."""
        if not tools:
            return []
        from google.genai import types as gtypes

        declarations = []
        for t in tools:
            schema = t.get("input_schema", {})
            declarations.append(
                gtypes.FunctionDeclaration(
                    name=t["name"],
                    description=t["description"],
                    parameters=BaseAgent._build_gemini_schema(schema),
                )
            )
        return [gtypes.Tool(function_declarations=declarations)]

    @staticmethod
    def _build_gemini_schema(schema: Dict) -> Dict:
        """Convert a JSON Schema dict to the google-genai Schema dict format."""
        _type_map = {
            "string": "STRING",
            "number": "NUMBER",
            "integer": "INTEGER",
            "boolean": "BOOLEAN",
            "array": "ARRAY",
            "object": "OBJECT",
        }
        type_str = schema.get("type", "string")
        result: Dict[str, Any] = {
            "type": _type_map.get(type_str, "STRING"),
            "description": schema.get("description", ""),
        }

        if type_str == "object":
            props = schema.get("properties", {})
            if props:
                result["properties"] = {
                    k: BaseAgent._build_gemini_schema(v) for k, v in props.items()
                }
            req = schema.get("required", [])
            if req:
                result["required"] = req

        elif type_str == "array":
            items = schema.get("items", {"type": "string"})
            result["items"] = BaseAgent._build_gemini_schema(items)

        return result
