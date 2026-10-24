import asyncio
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

_TESTS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _TESTS_DIR.parent
for _p in (str(_REPO_ROOT), str(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import test_assistant  # type: ignore[import-not-found,import-untyped]

from malware_scanner.assistant import assist, make_request, validate_advice
from malware_scanner.mcp_server import create_server, evidence_for
from malware_scanner.providers import KEY_ENV, configuration, normalize, payload


class ProviderTests(test_assistant.AssistantBase):
    def test_all_native_transports_and_validation(self):
        advice_text = self.response()["output"][0]["content"][0]["text"]
        envelopes = {
            "openai": self.response(),
            "anthropic": {
                "stop_reason": "end_turn",
                "content": [{"type": "text", "text": advice_text}],
            },
            "gemini": {
                "candidates": [
                    {"finishReason": "STOP", "content": {"parts": [{"text": advice_text}]}}
                ]
            },
            "openai-compatible": {
                "choices": [{"finish_reason": "stop", "message": {"content": advice_text}}]
            },
        }
        for provider, envelope in envelopes.items():
            with self.subTest(provider=provider):
                http = Mock(status_code=200)
                http.iter_content.return_value = [json.dumps(envelope).encode()]
                http.__enter__ = Mock(return_value=http)
                http.__exit__ = Mock(return_value=False)
                base = "http://127.0.0.1:8000/v1" if provider == "openai-compatible" else None
                with (
                    patch.dict(os.environ, {KEY_ENV[provider]: "SECRET"}, clear=True),
                    patch("malware_scanner.assistant.requests.post", return_value=http) as post,
                ):
                    output = self.root / provider
                    status = assist(
                        self.run_dir,
                        output,
                        "test-model",
                        send=True,
                        provider=provider,
                        base_url=base,
                    )
                self.assertEqual(status["status"], "advice_unvalidated")
                self.assertFalse(post.call_args.kwargs["allow_redirects"])
                self.assertNotIn("SECRET", "".join(p.read_text() for p in output.iterdir()))
                self.assertEqual(
                    post.call_args.args[0], configuration(provider, "test-model", base)
                )
                self.assertEqual(
                    json.loads((output / "advice.json").read_text())["summary"],
                    "A benign sample matched.",
                )

    def test_credentials_never_fallback_to_openai(self):
        for provider in ("anthropic", "gemini", "openai-compatible"):
            with (
                patch.dict(os.environ, {"OPENAI_API_KEY": "SECRET"}, clear=True),
                patch("malware_scanner.assistant.requests.post") as post,
            ):
                with self.assertRaises(ValueError):
                    assist(
                        self.run_dir,
                        self.root / provider,
                        "test",
                        send=True,
                        provider=provider,
                        base_url="https://example.org/v1"
                        if provider == "openai-compatible"
                        else None,
                    )
                post.assert_not_called()
                self.assertFalse((self.root / provider).exists())

    def test_endpoint_restrictions(self):
        for url in (
            "http://example.com/v1",
            "https://user:password@example.com",
            "https://example.com/?key=secret",
            "file:///tmp",
            "https://example.com/#key",
        ):
            with self.assertRaises(ValueError):
                configuration("openai-compatible", "test", url)
        with self.assertRaises(ValueError):
            configuration("openai", "test", "https://other.example")
        self.assertTrue(
            configuration("openai-compatible", "vendor/model", "http://[::1]:8000/v1").endswith(
                "/chat/completions"
            )
        )

    def test_structured_payloads_and_incomplete_rejection(self):
        request = make_request({}, "vendor/model")
        self.assertIn("output_config", payload(request, "anthropic"))
        self.assertIn("responseJsonSchema", payload(request, "gemini")["generationConfig"])
        self.assertEqual(
            payload(request, "openai-compatible")["response_format"]["type"], "json_schema"
        )
        for provider, envelope in (
            ("anthropic", {"stop_reason": "max_tokens"}),
            ("gemini", {"candidates": [{"finishReason": "SAFETY"}]}),
            ("openai-compatible", {"choices": [{"finish_reason": "length"}]}),
        ):
            with self.assertRaises(ValueError):
                normalize(envelope, provider)
        for provider in KEY_ENV:
            with self.assertRaises(ValueError):
                validate_advice(normalize({}, provider), {"sample-000001"})


@unittest.skipUnless(
    importlib.util.find_spec("mcp") and sys.version_info >= (3, 11),
    "Optional MCP extra requires Python 3.11+",
)
class MCPTests(test_assistant.AssistantBase):
    def test_confined_evidence_and_heldout(self):
        result = evidence_for(self.root, "run")
        self.assertNotIn("private-client", json.dumps(result))
        with self.assertRaises(ValueError):
            evidence_for(self.root, "../outside")
        self.report["samples"][0]["split"] = "held-out"
        self.save_report()
        with self.assertRaises(ValueError):
            evidence_for(self.root, "run")

    def test_stdio_client_discovers_and_calls_tools(self):
        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        async def check():
            params = StdioServerParameters(
                command=sys.executable,
                args=["-m", "malware_scanner.mcp_server", "--workspace", str(self.root)],
            )
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as client:
                    await client.initialize()
                    tools = await client.list_tools()
                    self.assertEqual([tool.name for tool in tools.tools], ["development_evidence"])
                    result = await client.call_tool(
                        "development_evidence", {"run_directory": "run"}
                    )
                    self.assertFalse(result.isError)
                    structured = getattr(result, "structuredContent", None) or getattr(
                        result, "structured_content", None
                    )
                    if structured:
                        self.assertEqual(structured["evidence"]["total_samples"], 1)
                    else:
                        text = getattr(result.content[0], "text", "")
                        self.assertIn('"total_samples": 1', text)

                    denied = await client.call_tool(
                        "development_evidence", {"run_directory": "../outside"}
                    )
                    self.assertTrue(denied.isError)

        asyncio.run(check())

    def test_network_gate(self):
        async def check():
            server = create_server(self.root, True, "anthropic", "test")
            tools = await server.list_tools()
            self.assertEqual(len(tools), 2)
            with patch("malware_scanner.mcp_server.assist") as send:
                from mcp.server.fastmcp.exceptions import ToolError

                with self.assertRaises(ToolError):
                    await server.call_tool("request_advice", {"run_directory": "run"})
                send.assert_not_called()

        asyncio.run(check())
