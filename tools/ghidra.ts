/**
 * Single omp tool wrapping the `gmcp` CLI over the bethington/ghidra-mcp
 * Ghidra plugin's REST API.
 *
 * Why one tool and not the MCP server: that server publishes 253 tools. Mounted
 * as MCP, every one of their names + descriptions + JSON schemas lands in the
 * system prompt on every turn. This exposes one tool instead and lets the model
 * discover the surface on demand (`argv: ["tools", "rename"]`,
 * `argv: ["help", "rename_function"]`), so the context cost is flat.
 *
 * Env:
 *   GMCP_SCRIPT           override the gmcp.py path
 *   GMCP_PYTHON           python binary (default "python")
 *   GHIDRA_MCP_URL        skip port discovery and use this base URL
 *   GHIDRA_MCP_AUTH_TOKEN bearer token, when the plugin is configured with one
 */

import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { CustomToolFactory } from "@oh-my-pi/pi-coding-agent";

/**
 * There is exactly one copy of the CLI in this project: gmcp.py at the root,
 * one directory up from tools/. Resolving it from import.meta.url rather than a
 * fixed path is what makes a marketplace install self-contained -- the plugin is
 * cached to an opaque directory under ~/.omp/plugins/cache, so any absolute path
 * baked in here would be wrong there. No second vendored copy exists to drift.
 */
function resolveScript(): string {
  const override = process.env.GMCP_SCRIPT;
  if (override) return override;
  const here = dirname(fileURLToPath(import.meta.url));
  const sibling = join(here, "..", "gmcp.py");
  if (existsSync(sibling)) return sibling;
  throw new Error(
    `gmcp.py not found at ${sibling}. If you installed only tools/ghidra.ts, ` +
      "point GMCP_SCRIPT at gmcp.py from https://github.com/Raikaru/ghidra-mcp-cli " +
      "(or `pipx install git+https://github.com/Raikaru/ghidra-mcp-cli` and set " +
      "GMCP_SCRIPT to the installed gmcp.py).",
  );
}

const SCRIPT = resolveScript();
const PYTHON = process.env.GMCP_PYTHON ?? "python";
// gmcp.py imports nothing outside the stdlib, so skipping site-packages costs
// nothing and keeps a broken .pth in a user site-packages dir from prefixing
// every result with an ImportError traceback on stderr.
const PY_FLAGS = ["-S", "-E"];
const MAX_CHARS = 60_000;

const factory: CustomToolFactory = (pi) => ({
  name: "ghidra",
  label: "Ghidra",
  description: [
    "Drive a running Ghidra instance (bethington/ghidra-mcp plugin) — decompile,",
    "rename, retype, comment, xrefs, structs, scripts, emulation, debugger.",
    "`argv` is passed straight to the `gmcp` CLI.",
    "",
    "Discovery first, guessing never:",
    '  ["tools"]                        every tool name + description',
    '  ["tools", "struct"]              filter by substring',
    '  ["cats"]                         categories with counts',
    '  ["help", "rename_function"]      a tool\'s exact parameters',
    "",
    "Calling (a tool's real parameter names come from `help`, never from memory —",
    "e.g. rename_function takes old_name/new_name, not an address):",
    '  ["decompile_function", "0x401000"]           positionals fill required params',
    '  ["rename_function", "FUN_140001010", "Foo"]',
    '  ["--dry-run", "rename_function", "FUN_1", "Foo"]  write rolled back',
    '  ["-u", "http://127.0.0.1:8091", "get_metadata"]   target another instance',
    "",
    "Works identically against a GUI plugin and a headless server (same REST API).",
    "The live instance is found by probing loopback ports 8089-8094/8080/8081, so",
    "no -u is needed normally; pass -u only to force a specific one.",
    "PS2/R5900 note: list_functions prints `image::ADDR`, but that overlay space",
    "disassembles to nothing. Strip the prefix and use the bare address.",
    "To start a headless server:",
    '  ["serve", "--port", "8091", "--project", "C:/projects/myproj"] -- but that',
    "blocks, so run it as a managed process (hub start) instead of through here;",
    '["serve", "--print"] yields the exact java command line.',
    "",
    "Exit 1 means the server returned an error; 3 means nothing is listening",
    "(start the GUI plugin via Tools > GhidraMCP > Start MCP Server, or serve).",
  ].join("\n"),

  parameters: pi.zod.object({
    argv: pi.zod
      .array(pi.zod.string())
      .describe("gmcp arguments, e.g. [\"help\", \"decompile_function\"]"),
  }),

  async execute(_toolCallId, params, _onUpdate, _ctx, signal) {
    const argv = params.argv ?? [];
    if (argv.length === 0) {
      throw new Error('argv is empty; start with ["tools"] to see what exists');
    }

    const result = await pi.exec(PYTHON, [...PY_FLAGS, SCRIPT, ...argv], {
      signal,
      cwd: pi.cwd,
    });
    if (result.killed) {
      throw new Error("ghidra call was cancelled");
    }

    // gmcp writes the response to stdout and diagnostics to stderr; a nonzero
    // code with an empty stdout is always a stderr-only failure. "gmcp[info]:"
    // lines (e.g. which port discovery picked) are progress notes, not errors --
    // appending them to a real error message only obscures it.
    const stdout = (result.stdout ?? "").trim();
    const stderr = (result.stderr ?? "")
      .split("\n")
      .filter((line) => !line.startsWith("gmcp[info]:"))
      .join("\n")
      .trim();
    if (result.code !== 0 && !stdout) {
      throw new Error(stderr || `gmcp exited ${result.code}`);
    }

    let text = stdout;
    let truncated = false;
    if (text.length > MAX_CHARS) {
      text = `${text.slice(0, MAX_CHARS)}\n...[truncated; narrow the query or use offset/limit params]`;
      truncated = true;
    }
    if (result.code !== 0 && stderr) {
      text = `${text}\n\n[gmcp exit ${result.code}] ${stderr}`;
    }

    return {
      content: [{ type: "text", text }],
      details: {
        argv,
        exitCode: result.code,
        bytes: stdout.length,
        truncated,
        isError: result.code !== 0,
      },
    };
  },
});

export default factory;
