# gmcp — a CLI (and one omp tool) for Ghidra

Drive Ghidra from a shell or an AI agent: decompile, rename, retype, comment,
walk xrefs, build structs, run scripts, emulate, debug. Works against a Ghidra
GUI **or** a headless server it can start for you.

Backed by the REST API of [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp).
Zero dependencies — Python stdlib only, one file.

```console
$ gmcp tools struct
GET  get_struct_layout        Get a structure's field layout
POST create_struct           Create a new structure data type
...

$ gmcp help rename_function
POST /rename_function
usage: gmcp rename_function <old_name> <new_name> [--opt value ...]
  --old_name <string>   [body]
  --new_name <string>   [body]
  --program <string>    [optional, default=, query]

$ gmcp decompile_function 0x00193980
void main(void)
{
  FUN_005225a8(&gp0xffff93f8);
  FUN_001939b0(0);
  return;
}
```

## Why this exists

The upstream project ships an MCP server with **253 tools**. That is a lot of
capability and, mounted as MCP, a lot of context: every tool's name, description,
and JSON schema is in your model's system prompt on every single turn.

But the MCP server is not where the capability lives. The Ghidra Java plugin
serves each tool as a flat REST endpoint and publishes the whole API —
paths, methods, per-parameter types, sources, defaults, docs — at `/mcp/schema`.
The MCP layer is an adapter over that.

So `gmcp` reads `/mcp/schema` at runtime and builds its command surface from it.
Nothing is hardcoded: a plugin upgrade that adds endpoints needs no change here,
only `--refresh`. And the agent-facing side is **one** tool that discovers what
it needs on demand, so the context cost is flat.

## Install

You do not need omp, an AI agent, or anything beyond Python 3.9+ to use this.

```console
pipx install git+https://github.com/Raikaru/ghidra-mcp-cli     # gives you `gmcp`
```

Or from a clone, with no install step at all:

```console
git clone https://github.com/Raikaru/ghidra-mcp-cli
cd ghidra-mcp-cli
./gmcp tools              # POSIX shim
gmcp.cmd tools            # Windows shim
python gmcp.py tools      # or just run the file
```

For `gmcp serve` you also need a Ghidra install, JDK 21, and one jar:

```console
python scripts/fetch-headless-jar.py
```

The shims run `python -S -E`: nothing here imports outside the stdlib, so
skipping `site-packages` is free and immunises you against a broken `.pth` in a
user site-packages directory printing a traceback over every result.

On Windows, do **not** use `setx PATH "%PATH%;..."` — it merges the system PATH
into your user PATH and truncates at 1024 characters. Use:

```powershell
$p = [Environment]::GetEnvironmentVariable('Path','User')
[Environment]::SetEnvironmentVariable('Path', "$p;C:\path\to\ghidra-mcp-cli", 'User')
```

## Two ways to point it at Ghidra

**A running Ghidra GUI.** Enable the plugin (**File > Configure > Configure All
Plugins > GhidraMCP**), then **Tools > GhidraMCP > Start MCP Server**.

**A headless server, started by gmcp.** No GUI, no gradle build — just a Ghidra
install and JDK 21:

```console
gmcp serve --port 8089 --project /path/to/projects/myproj
gmcp serve --print          # show the java command line instead of running it
```

The headless server is the *same* REST API: it is a `GhidraLaunchable`
(`com.xebyte.headless.GhidraMCPHeadlessServer`) inside the ordinary GhidraMCP
extension jar. Every command below works identically against either.

**Importing with a chosen loader.** An install carrying loader extensions can
answer the same bytes several ways, and the choice is not always the one you
want: a GameCube RSO reader will claim a Game Boy Advance cartridge and yield
an empty PowerPC program. `gmcp import` names the loader and its options, and
prints the loader and language that were actually used:

```console
gmcp import --file game.elf --project /tmp/proj --loader ElfLoader \
            --loader-opt imagebase=0x900000
# imported game.elf: loader Executable and Linking Format (ELF), language MIPS:LE:32:default:default

gmcp serve --file game.elf --project /tmp/proj --loader ElfLoader   # import, then serve it
```

`--loader` takes a loader's Java class simple name (`ElfLoader`, `PeLoader`,
`GameCubeLoader`), which is what headless matches; a display name is refused
with that explanation. `--loader-opt key=value` is repeatable and becomes
headless' `-loader-<key> <value>`, so a loader that declares its options
(`Loader.getDefaultOptions`) never needs to ask. A loader that opens a dialog
instead still fails headlessly -- `GameCubeLoader` throws
`java.awt.HeadlessException` before defining a single block -- and the failure
now reports the loader and language it had chosen.

Either way you rarely need to say *where*: with no `-u` and no `GHIDRA_MCP_URL`,
gmcp probes loopback ports `8089-8094, 8080, 8081` concurrently and uses the
first that identifies itself. The GUI's port is a Ghidra Tool Option and drifts
as soon as you open a second window, so guessing 8089 is wrong more often than
it's right.

## Using it

```console
gmcp tools [substr]              # every tool, or filter by substring
gmcp tools --category function
gmcp cats                        # categories with counts
gmcp help <tool>                 # exact parameters, types, defaults, sources

gmcp decompile_function 0x401000
gmcp rename_function FUN_140001010 ProcessItem
gmcp decompile_function 0x401000 --include-line-numbers
gmcp --dry-run batch_set_comments '[{...}]'
gmcp raw GET /get_version        # bypass the schema entirely
```

Positional arguments fill a tool's required parameters in schema order;
`--name value`, `--name=value`, `--flag`, `--no-flag` cover the rest, and
kebab-case is accepted for snake_case parameters. `query`-source parameters go
in the URL and `body`-source parameters in the JSON body — decided per parameter
from the schema, so POST tools that mix both work. `integer` parameters accept
`0x` hex; `json` parameters are validated before being sent.

`--dry-run` sets `dry_run` in **both** the query string and the body, because the
plugin checks both and a body-only caller once got a silent real write.

### Options

Global options must precede the command; everything after the tool name is that
tool's arguments.

| Option | Meaning |
|---|---|
| `-u`, `--url` | base URL; skips discovery and is never second-guessed |
| `-t`, `--token` | bearer token |
| `--timeout` | request timeout, seconds (default 120) |
| `--refresh` | ignore the cached `/mcp/schema` |
| `--raw-out` | print the response body verbatim |
| `--dry-run` | roll back POST tools |
| `-v`, `--verbose` | log the request line to stderr |

| Variable | Default | Meaning |
|---|---|---|
| `GHIDRA_MCP_URL` | auto-probed | base URL; skips discovery |
| `GHIDRA_MCP_PORTS` | `8089-8094 8080 8081` | ports to probe |
| `GHIDRA_MCP_AUTH_TOKEN` | — | `Authorization: Bearer …` |
| `GHIDRA_MCP_TIMEOUT` | `120` | request timeout, seconds |
| `GHIDRA_INSTALL_DIR` | auto-detected | Ghidra install for `serve` |
| `GMCP_JAR` | newest in `dist/` | GhidraMCP jar for `serve` |

Schema cache: `%LOCALAPPDATA%\gmcp` or `~/.cache/gmcp`, keyed per URL, 24 h TTL.

**Exit codes:** `0` ok · `1` response carried a top-level `"error"` · `2` usage
error · `3` unreachable or unusable schema · `130` interrupted.

## The omp tool

Entirely optional, and packaged so it cannot rot: `tools/ghidra.ts` registers a
single [omp](https://github.com/oh-my-pi) tool named `ghidra` that forwards
`argv` to **the same `gmcp.py` at the repo root** — there is no second vendored
copy of the CLI to drift out of sync.

```jsonc
["tools", "struct"]                         // discover
["help", "rename_function"]                 // read the real signature
["decompile_function", "0x401000"]          // call
["--dry-run", "rename_function", "A", "B"]  // rehearse a write
```

Install from this repo as a marketplace:

```
/marketplace add Raikaru/ghidra-mcp-cli
/marketplace install ghidra@ghidra-mcp-cli
```

Or point omp at a clone: copy `tools/ghidra.ts` into `~/.omp/agent/tools/` and
set `GMCP_SCRIPT` to this repo's `gmcp.py`. The tool resolves the CLI from
`import.meta.url` rather than an absolute path, which is what lets a marketplace
install work from omp's opaque plugin cache. Custom tools are discovered at
startup, so restart omp after installing.

## Headless notes, all observed

- **Project locks.** A project a running Ghidra GUI has open cannot be opened
  headlessly; `open_project` returns `{"error": "Failed to open project: …"}`.
  Use a different `--project`, or close the GUI project first.
- `--project` does not create anything. A directory with no `.gpr` logs
  `No .gpr file found` and the server starts project-less. Use `create_project`
  (whose *parent* directory must already exist) or `--file`.
- `load_program` does not make the new program current. Use `switch_program`, or
  pass `--program <name>` per call.
- `language`/`compiler_spec` on `load_program` force a **raw binary** import, so
  they are for headerless firmware only. On an ELF/PE, leave them off.

### Custom processors (PS2 / R5900 and friends)

`gmcp serve` deliberately does **not** pass `-Dapplication.name`, and it puts
user-installed extension jars on the classpath. Both matter. Upstream's
`docker/entrypoint.sh` passes `-Dapplication.name=GhidraMCP`, which repoints
Ghidra's user settings directory at `%APPDATA%/ghidramcp/...`. Harmless in a
container; on a workstation it hides every GUI-installed extension — and with
them every language those extensions provide.

Concretely: `r5900:LE:32:default` does not exist in stock Ghidra. It comes from
`ghidra-emotionengine-reloaded`, installed under
`%APPDATA%/ghidra/<version>/Extensions`. With the settings directory redirected,
loading a PS2 ELF fails with `Failed to load program with language
'r5900:LE:32:default'`, or silently auto-detects as generic `MIPS:LE:64:64-32R6addr`
and decompiles to `halt_baddata()`. As shipped here, the same ELF imports
headlessly as `Architecture: MIPS-R5900`.

One more trap once it loads: a PS2 ELF's symbols land in an `image` **overlay**
space while the mapped executable memory is in the *default* space.
`disassemble_bytes image::0019d3f0` reports success with **zero** instructions;
the same address unqualified disassembles correctly. Strip the `image::` prefix
that `list_functions` prints, and `create_function 0x…` before decompiling.

## Tests

```console
python tests/test_gmcp.py
```

28 tests, no Ghidra and no network: a stub server serves a `/mcp/schema` in the
real shape and echoes requests back, so the tests pin the part that is easy to
get wrong — how a command line becomes an HTTP request.

## Licence

MIT (this repo). The GhidraMCP plugin and its jar are Apache-2.0, © Ben
Ethington; no upstream code is vendored here — `scripts/fetch-headless-jar.py`
downloads the published release artifact.
