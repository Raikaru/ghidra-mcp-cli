#!/usr/bin/env python3
"""Offline tests for gmcp: no Ghidra, no network, no dependencies.

A stub HTTP server serves a /mcp/schema in the real shape and echoes every
request back, so the tests assert the thing that actually matters and is easy to
get wrong: how a command line becomes an HTTP request. Per-parameter query-vs-body
routing, type coercion, dry-run's dual sink, and the exit-code contract.

    python tests/test_gmcp.py          # or: python -m unittest discover tests
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
GMCP = os.path.join(os.path.dirname(HERE), "gmcp.py")

# Mirrors AnnotationScanner.generateSchema(): a "tools" array of
# {path, method, description, category, params[{name,type,source,required,...}]}.
SCHEMA = {
    "count": 4,
    "tools": [
        {
            "path": "/decompile_function",
            "method": "GET",
            "description": "Decompile a function to C.",
            "category": "function",
            "params": [
                {"name": "address", "type": "string", "source": "query", "required": True},
                {"name": "include_line_numbers", "type": "boolean", "source": "query",
                 "required": False, "default": "false"},
            ],
        },
        {
            "path": "/rename_function",
            "method": "POST",
            "description": "Rename a function.",
            "category": "function",
            "params": [
                {"name": "old_name", "type": "string", "source": "body", "required": True},
                {"name": "new_name", "type": "string", "source": "body", "required": True},
                {"name": "program", "type": "string", "source": "query", "required": False},
            ],
        },
        {
            "path": "/batch_set_comments",
            "method": "POST",
            "description": "Bulk comments.",
            "category": "comment",
            "params": [
                {"name": "comments", "type": "json", "source": "body", "required": True},
                {"name": "limit", "type": "integer", "source": "body", "required": False,
                 "default": "100"},
            ],
        },
        {
            "path": "/server/version_history",
            "method": "GET",
            "description": "Version history.",
            "category": "server",
            "params": [
                {"name": "path", "type": "string", "source": "query", "required": True},
            ],
        },
    ],
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_a):  # keep the test output clean
        pass

    def _serve(self, method: str) -> None:
        url = urlparse(self.path)
        size = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(size).decode() if size else ""
        echo = {
            "method": method,
            "path": url.path,
            "query": parse_qs(url.query),
            "body": json.loads(raw) if raw else None,
            "auth": self.headers.get("Authorization"),
        }
        status = 200
        if url.path == "/mcp/schema":
            out = json.dumps(SCHEMA)
        elif url.path == "/check_connection":
            out = "Connected: GhidraMCP plugin running"
        elif url.path == "/mcp/health":
            out = '{"status": "ok"}'
        elif url.path == "/boom":
            out = '{"error": "no program loaded"}'
        elif url.path == "/plain":
            out = "Program Name: x\r\nArchitecture: y\r\n"
        elif url.path == "/gone":
            # What an older plugin build does for a route it does not have:
            # an HTML body with no "error" key, behind a 404.
            status, out = 404, "<h1>404 Not Found</h1>No context found for request"
        else:
            out = json.dumps({"echo": echo})
        payload = out.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._serve("GET")

    def do_POST(self):
        self._serve("POST")


class GmcpTest(unittest.TestCase):
    server: HTTPServer
    url: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        cls.url = "http://127.0.0.1:%d" % cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def gmcp(self, *args: str, url: str | None = None, env_extra: dict | None = None):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GHIDRA_MCP_")}
        env["GHIDRA_MCP_URL"] = url if url is not None else self.url
        env.update(env_extra or {})
        proc = subprocess.run(
            [sys.executable, "-S", "-E", GMCP, *args],
            capture_output=True, text=True, env=env,
        )
        return proc

    def echo(self, *args: str) -> dict:
        proc = self.gmcp(*args)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)["echo"]

    # -- discovery ---------------------------------------------------------

    def test_tools_lists_every_schema_entry(self):
        proc = self.gmcp("--refresh", "tools")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for name in ("decompile_function", "rename_function", "server/version_history"):
            self.assertIn(name, proc.stdout)

    def test_cats_counts_by_category(self):
        proc = self.gmcp("cats")
        self.assertIn("function", proc.stdout)
        self.assertRegex(proc.stdout, r"2\s+function")

    def test_help_shows_required_positionals_in_schema_order(self):
        proc = self.gmcp("help", "rename_function")
        self.assertIn("usage: gmcp rename_function <old_name> <new_name>", proc.stdout)

    # -- argument binding --------------------------------------------------

    def test_get_params_go_to_query_string(self):
        echo = self.echo("decompile_function", "0x401000")
        self.assertEqual(echo["method"], "GET")
        self.assertEqual(echo["query"]["address"], ["0x401000"])
        self.assertIsNone(echo["body"])

    def test_boolean_flag_without_value(self):
        echo = self.echo("decompile_function", "0x401000", "--include_line_numbers")
        self.assertEqual(echo["query"]["include_line_numbers"], ["true"])

    def test_kebab_case_alias_for_snake_case_param(self):
        echo = self.echo("decompile_function", "0x401000", "--include-line-numbers")
        self.assertEqual(echo["query"]["include_line_numbers"], ["true"])

    def test_no_prefix_negates_a_boolean(self):
        echo = self.echo("decompile_function", "0x401000", "--no-include-line-numbers")
        self.assertEqual(echo["query"]["include_line_numbers"], ["false"])

    def test_post_splits_body_and_query_per_param_source(self):
        echo = self.echo("rename_function", "FUN_1", "Foo", "--program", "a.exe")
        self.assertEqual(echo["method"], "POST")
        self.assertEqual(echo["body"], {"old_name": "FUN_1", "new_name": "Foo"})
        self.assertEqual(echo["query"]["program"], ["a.exe"])

    def test_integer_and_json_params_are_typed(self):
        echo = self.echo("batch_set_comments", '[{"a": 1}]', "--limit", "5")
        self.assertEqual(echo["body"]["limit"], 5)  # int, not "5"
        self.assertEqual(json.loads(echo["body"]["comments"]), [{"a": 1}])

    def test_integer_param_accepts_hex(self):
        echo = self.echo("batch_set_comments", "[]", "--limit", "0x10")
        self.assertEqual(echo["body"]["limit"], 16)

    def test_nested_path_tool_is_addressable_both_ways(self):
        for spelling in ("server/version_history", "server-version_history"):
            echo = self.echo(spelling, "/proj/f")
            self.assertEqual(echo["path"], "/server/version_history")

    def test_dry_run_is_sent_in_query_and_body(self):
        # The plugin checks both; a body-only caller once got a silent real write.
        echo = self.echo("--dry-run", "rename_function", "FUN_1", "Foo")
        self.assertEqual(echo["query"]["dry_run"], ["true"])
        self.assertIs(echo["body"]["dry_run"], True)

    def test_bearer_token_is_sent(self):
        # Global options must precede the command, per the documented contract.
        proc = self.gmcp("-t", "sekrit", "decompile_function", "0x1")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        echo = json.loads(proc.stdout)["echo"]
        self.assertEqual(echo["auth"], "Bearer sekrit")

    def test_global_flag_after_the_tool_name_is_rejected(self):
        # ...and doing it the other way round must fail loudly, not be guessed at.
        proc = self.gmcp("decompile_function", "0x1", "-t", "sekrit")
        self.assertEqual(proc.returncode, 2)

    # -- output and exit codes --------------------------------------------

    def test_error_response_exits_1(self):
        proc = self.gmcp("raw", "GET", "/boom")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("no program loaded", proc.stdout)

    def test_http_error_status_exits_1_even_without_an_error_key(self):
        # An older plugin build answers an unknown route with a 404 HTML page.
        # Reporting that as success is how a missing endpoint looks like a
        # working one.
        proc = self.gmcp("raw", "GET", "/gone")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("HTTP 404", proc.stderr)
        self.assertIn("404 Not Found", proc.stdout)

    def test_http_error_status_exits_1_with_raw_out(self):
        proc = self.gmcp("--raw-out", "raw", "GET", "/gone")
        self.assertEqual(proc.returncode, 1)

    def test_usage_errors_do_not_need_a_server(self):
        # A malformed command line must not be reported as "no instance found":
        # that sends people hunting for a server problem they do not have.
        env = {k: v for k, v in os.environ.items() if not k.startswith("GHIDRA_MCP_")}
        env["GHIDRA_MCP_PORTS"] = "1 2"
        for args in (["help"], ["raw", "GET"], ["call"]):
            proc = subprocess.run(
                [sys.executable, "-S", "-E", GMCP, *args],
                capture_output=True, text=True, env=env,
            )
            self.assertEqual(proc.returncode, 2, f"{args}: {proc.stderr}")
            self.assertIn("usage:", proc.stderr)
            self.assertNotIn("no GhidraMCP instance", proc.stderr)

    def test_plain_text_passthrough_normalizes_crlf(self):
        proc = self.gmcp("raw", "GET", "/plain")
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn("\r", proc.stdout)
        self.assertIn("Program Name: x\nArchitecture: y", proc.stdout)

    def test_unknown_tool_exits_2_and_suggests(self):
        proc = self.gmcp("decompile_func")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("did you mean", proc.stderr)
        self.assertIn("decompile_function", proc.stderr)

    def test_unknown_param_exits_2_and_lists_real_ones(self):
        proc = self.gmcp("decompile_function", "0x1", "--nope", "1")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("has no parameter 'nope'", proc.stderr)
        self.assertIn("address", proc.stderr)

    def test_missing_required_param_exits_2_without_calling(self):
        proc = self.gmcp("rename_function", "only_one")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("requires: new_name", proc.stderr)

    def test_too_many_positionals_exits_2(self):
        proc = self.gmcp("decompile_function", "0x1", "true", "extra")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("too many positional", proc.stderr)

    def test_explicit_unreachable_url_exits_3_and_is_not_rescued(self):
        proc = self.gmcp("health", url="http://127.0.0.1:1")
        self.assertEqual(proc.returncode, 3)
        self.assertIn("cannot reach", proc.stderr)

    def test_discovery_failure_is_fast_and_actionable(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GHIDRA_MCP_")}
        env["GHIDRA_MCP_PORTS"] = "1 2 3"
        proc = subprocess.run(
            [sys.executable, "-S", "-E", GMCP, "health"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(proc.returncode, 3)
        self.assertIn("no GhidraMCP instance found", proc.stderr)
        self.assertIn("gmcp serve", proc.stderr)

    def test_discovery_finds_the_stub_server(self):
        port = self.server.server_address[1]
        env = {k: v for k, v in os.environ.items() if not k.startswith("GHIDRA_MCP_")}
        env["GHIDRA_MCP_PORTS"] = f"1 {port}"
        proc = subprocess.run(
            [sys.executable, "-S", "-E", GMCP, "raw", "GET", "/check_connection"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("GhidraMCP plugin running", proc.stdout)

    # -- serve -------------------------------------------------------------

    def test_serve_print_emits_a_java_command_without_launching(self):
        proc = self.gmcp("serve", "--print", "--ghidra", HERE, "--jar", GMCP)
        # HERE is not a Ghidra install, so this must fail loudly rather than
        # emit a command line that would die with ClassNotFoundException.
        self.assertEqual(proc.returncode, 2)
        self.assertIn("Ghidra install", proc.stderr)

    def test_serve_rejects_unknown_options(self):
        proc = self.gmcp("serve", "--nonsense")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("unknown option", proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
