#!/usr/bin/env python3
"""gmcp - schema-driven CLI for the bethington/ghidra-mcp Ghidra plugin.

The Ghidra plugin already exposes every one of its tools as a flat HTTP/REST
endpoint (default http://127.0.0.1:8089) and publishes a machine-readable
description of all of them at /mcp/schema. This CLI is a thin, fully generic
client over that schema: no tool list is hardcoded, so a plugin upgrade that
adds endpoints needs no change here.

Usage:
  gmcp [global opts] <command|tool> [args...]

Commands:
  tools [substr]        list tools (name, method, one-line description)
  cats                  list categories with tool counts
  help <tool>           show a tool's parameters
  raw <METHOD> <path>   call an arbitrary path (no schema lookup)
  health                GET /mcp/health
  import [opts]         import a binary with a named loader and its options
  serve [opts]          launch a HEADLESS Ghidra server exposing the same API
  <tool> [args...]      call a tool

serve options (no Ghidra GUI required; needs a Ghidra install + JDK 21):
  --port N              listen port                  (default 8089)
  --bind ADDR           bind address                 (default 127.0.0.1)
  --project PATH        Ghidra project dir to open/create
  --program NAME        program inside that project to open
  --file PATH           binary to import and open
  --ghidra DIR          Ghidra install (env GHIDRA_INSTALL_DIR / GHIDRA_HOME)
  --jar PATH            GhidraMCP jar carrying the headless server (env GMCP_JAR)
  --xmx SIZE            JVM heap                     (default 4g)
  --loader NAME         loader for --file, by class name (e.g. GameCubeLoader)
  --loader-opt k=value  loader option, repeatable (headless -loader-<k>)
  --analyze             analyze after loading    (default: import only)
  --print               print the java command line and exit, do not launch

import options (stock analyzeHeadless does the loading):
  --file PATH           binary to import                 (required)
  --project DIR         project directory to import into (required)
  --loader NAME         loader by class name, e.g. ElfLoader
  --loader-opt k=value  loader option, repeatable
  --analyze             analyze after loading
  --ghidra DIR          Ghidra install

  A headless server must not open a project that a running Ghidra GUI holds a
  lock on. Use a separate --project directory, or close the GUI project first.

Tool arguments:
  positional            fill the tool's required params, in schema order
  --name value          any param by name
  --name=value          same
  --flag                boolean param -> true
  --no-flag             boolean param -> false

Global options (must precede the command):
  -u/--url URL          base URL       (env GHIDRA_MCP_URL, default 127.0.0.1:8089)
  -t/--token TOKEN      bearer token   (env GHIDRA_MCP_AUTH_TOKEN)
  --timeout SECONDS     request timeout (env GHIDRA_MCP_TIMEOUT, default 120)
  --refresh             ignore the cached /mcp/schema
  --raw-out             print the response body verbatim (no re-formatting)
  --dry-run             send dry_run=true (POST tools roll their transaction back)
  -v/--verbose          log the request line to stderr

Exit status: 0 on success, 1 if the response carries a top-level "error",
2 on usage errors, 3 if the server is unreachable.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse

# urllib.request is imported lazily inside the two functions that issue HTTP.
# Measured on Windows/CPython 3.10: importing it costs ~55 ms, against a ~48 ms
# bare interpreter start -- more than half this program's startup, paid by every
# invocation including `--help`, `serve`, and every usage error. It is the single
# largest cost in a CLI that an agent may call dozens of times per task.

DEFAULT_URL = "http://127.0.0.1:8089"
SCHEMA_TTL = 24 * 3600
# Ports to probe when neither -u nor GHIDRA_MCP_URL says where to look. 8089 is
# the documented default, but the GUI plugin's port is a Tool Option and drifts
# the moment a second instance or a headless server is started -- observed live
# on 8090 (GUI) and 8091-8093 (headless).
PROBE_PORTS = (8089, 8090, 8091, 8092, 8093, 8094, 8080, 8081)


def discover_url() -> str:
    """First loopback port that answers as a GhidraMCP instance; Fail(3) if none.

    Connect probes run concurrently: on Windows a refused loopback connect still
    burns the full socket timeout, so probing eight ports serially cost 1.6 s on
    every miss. Threads bring that back to one timeout.
    """
    import socket
    import urllib.request
    from concurrent.futures import ThreadPoolExecutor

    ports = os.environ.get("GHIDRA_MCP_PORTS")
    candidates = (
        [int(p) for p in ports.replace(",", " ").split()] if ports else list(PROBE_PORTS)
    )

    def listening(port: int) -> bool:
        sock = socket.socket()
        sock.settimeout(0.25)
        try:
            return sock.connect_ex(("127.0.0.1", port)) == 0
        except OSError:
            return False
        finally:
            sock.close()

    with ThreadPoolExecutor(max_workers=len(candidates)) as pool:
        open_ports = [
            port for port, is_open in zip(candidates, pool.map(listening, candidates))
            if is_open
        ]

    for port in open_ports:
        # Something listens. Confirm it is actually GhidraMCP and not an
        # unrelated dev server that happens to squat the port.
        url = f"http://127.0.0.1:{port}"
        try:
            req = urllib.request.Request(url + "/check_connection")
            with urllib.request.urlopen(req, timeout=2) as resp:
                body = resp.read(200).decode("utf-8", "replace")
        except (urllib.error.URLError, OSError):
            continue
        if "GhidraMCP" in body or "Connect" in body:
            if port != candidates[0]:
                print(f"gmcp[info]: using GhidraMCP on port {port}", file=sys.stderr)
            return url
    # Nothing answered. Say so now: a doomed request to the default port costs
    # ~2 s on Windows before the OS reports the refusal.
    raise Fail(
        "no GhidraMCP instance found on 127.0.0.1 ports "
        + ", ".join(str(p) for p in candidates)
        + "\n  start one:  gmcp serve --port 8089 --project <dir>"
        + "\n  or in the GUI: Tools > GhidraMCP > Start MCP Server"
        + "\n  or point at it: gmcp -u http://host:port ...  /  set GHIDRA_MCP_URL",
        3,
    )


class Fail(Exception):
    def __init__(self, msg: str, code: int = 2) -> None:
        super().__init__(msg)
        self.code = code


# --------------------------------------------------------------------------
# transport
# --------------------------------------------------------------------------

class Client:
    def __init__(self, url: str, token: str | None, timeout: float, verbose: bool) -> None:
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.verbose = verbose

    def request(
        self, method: str, path: str, query: dict, body: dict | None
    ) -> tuple[int, str]:
        """Perform the call and return (http_status, body).

        The status is returned rather than swallowed because an error status with
        a non-JSON body is real: an older plugin build that lacks a route answers
        404 with an HTML page, which carries no `"error"` key and would otherwise
        be reported as success."""
        import urllib.request

        target = self.url + "/" + path.lstrip("/")
        if query:
            target += "?" + urllib.parse.urlencode(query)
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if self.verbose:
            print(f"-> {method} {target} {json.dumps(body) if body else ''}", file=sys.stderr)
        req = urllib.request.Request(target, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except urllib.error.URLError as e:
            raise Fail(
                f"cannot reach {self.url}: {e.reason}\n"
                "Is the Ghidra plugin's server started (Tools > GhidraMCP > Start MCP Server)?",
                3,
            ) from None


# --------------------------------------------------------------------------
# schema
# --------------------------------------------------------------------------

def cache_path(url: str) -> str:
    root = os.environ.get("LOCALAPPDATA") or os.path.join(
        os.path.expanduser("~"), ".cache"
    )
    key = urllib.parse.quote(url, safe="")
    return os.path.join(root, "gmcp", f"schema-{key}.json")


def load_schema(client: Client, refresh: bool) -> list[dict]:
    cf = cache_path(client.url)
    if not refresh:
        try:
            if time.time() - os.path.getmtime(cf) < SCHEMA_TTL:
                with open(cf, encoding="utf-8") as fh:
                    return json.load(fh)["tools"]
        except (OSError, ValueError, KeyError):
            pass
    status, body = client.request("GET", "/mcp/schema", {}, None)
    try:
        doc = json.loads(body)
        tools = doc["tools"]
    except (ValueError, KeyError):
        raise Fail(
            f"/mcp/schema returned HTTP {status} and unusable content: {body[:200]}",
            3,
        ) from None
    try:
        os.makedirs(os.path.dirname(cf), exist_ok=True)
        with open(cf, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
    except OSError:
        pass
    return tools


def tool_name(tool: dict) -> str:
    return tool["path"].lstrip("/")


def find_tool(tools: list[dict], name: str) -> dict:
    want = name.lstrip("/")
    variants = {want, want.replace("-", "/"), want.replace("/", "-")}
    for tool in tools:
        n = tool_name(tool)
        if n in variants or n.replace("/", "-") in variants:
            return tool
    hits = [tool_name(t) for t in tools if want in tool_name(t)]
    hint = "\n  did you mean: " + ", ".join(sorted(hits)[:10]) if hits else ""
    raise Fail(f"unknown tool {name!r} (try: gmcp tools {want}){hint}")


# --------------------------------------------------------------------------
# argument binding
# --------------------------------------------------------------------------

def coerce(param: dict, raw: str):
    kind = param.get("type", "string")
    if kind == "boolean":
        low = raw.lower()
        if low in ("1", "true", "yes", "on"):
            return True
        if low in ("0", "false", "no", "off"):
            return False
        raise Fail(f"--{param['name']}: expected a boolean, got {raw!r}")
    if kind == "integer":
        try:
            return int(raw, 0)
        except ValueError:
            raise Fail(f"--{param['name']}: expected an integer, got {raw!r}") from None
    if kind == "number":
        try:
            return float(raw)
        except ValueError:
            raise Fail(f"--{param['name']}: expected a number, got {raw!r}") from None
    if kind in ("object", "array", "json", "any"):
        try:
            return json.loads(raw)
        except ValueError:
            # 'json'/'any' params are declared as Java Strings holding JSON text;
            # a non-JSON value is still legal for 'any', so pass it through.
            if kind in ("json", "object", "array"):
                raise Fail(f"--{param['name']}: expected JSON, got {raw!r}") from None
            return raw
    return raw


def bind(tool: dict, argv: list[str], dry_run: bool) -> tuple[dict, dict]:
    params = {p["name"]: p for p in tool.get("params", [])}
    given: dict[str, object] = {}
    positional: list[str] = []

    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            positional.extend(argv[i + 1:])
            break
        if arg.startswith("--"):
            key, eq, inline = arg[2:].partition("=")
            negated = False
            # Params are snake_case server-side; accept the kebab-case spelling too.
            if key not in params and key.replace("-", "_") in params:
                key = key.replace("-", "_")
            for prefix in ("no-", "no_"):
                if key not in params and key.startswith(prefix):
                    cand = key[len(prefix):].replace("-", "_")
                    if cand in params:
                        key, negated = cand, True
                        break
            if key not in params:
                raise Fail(
                    f"{tool_name(tool)} has no parameter {key!r}\n"
                    f"  parameters: {', '.join(params) or '(none)'}"
                )
            param = params[key]
            if eq:
                value = coerce(param, inline)
            elif param.get("type") == "boolean":
                value = not negated
            elif i + 1 < len(argv):
                i += 1
                value = coerce(param, argv[i])
            else:
                raise Fail(f"--{key} needs a value")
            given[key] = value
        else:
            positional.append(arg)
        i += 1

    for value in positional:
        slot = next(
            (p for p in tool.get("params", [])
             if p.get("required") and p["name"] not in given),
            None,
        ) or next(
            (p for p in tool.get("params", []) if p["name"] not in given),
            None,
        )
        if slot is None:
            raise Fail(f"{tool_name(tool)}: too many positional arguments (at {value!r})")
        given[slot["name"]] = coerce(slot, value)

    missing = [
        p["name"] for p in tool.get("params", [])
        if p.get("required") and p["name"] not in given
    ]
    if missing:
        raise Fail(
            f"{tool_name(tool)} requires: {', '.join(missing)}\n"
            f"  see: gmcp help {tool_name(tool)}"
        )

    query: dict[str, object] = {}
    body: dict[str, object] = {}
    for name, value in given.items():
        sink = query if params[name].get("source") == "query" else body
        sink[name] = value if isinstance(value, (str, int, float, bool)) else json.dumps(value)
    if dry_run:
        # Both sinks: the plugin checks the query string and the JSON body.
        query["dry_run"] = "true"
        if tool.get("method", "GET").upper() != "GET":
            body["dry_run"] = True
    for key, value in list(query.items()):
        query[key] = "true" if value is True else "false" if value is False else value
    return query, body


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# headless server launch
#
# The headless server is the SAME REST API as the GUI plugin -- it is a
# GhidraLaunchable (com.xebyte.headless.GhidraMCPHeadlessServer) shipped inside
# the ordinary GhidraMCP extension jar. Every other command in this file works
# against it unchanged; the only thing missing was a way to start it. This
# reproduces the launch line the project's own docker/entrypoint.sh uses: plain
# java, with the Ghidra install's Framework/Features/Processors jars on the
# classpath. No Ghidra GUI, no gradle build.
# --------------------------------------------------------------------------

GHIDRA_JAR_GLOBS = (
    "Ghidra/Framework/*/lib/*.jar",
    "Ghidra/Features/*/lib/*.jar",
    "Ghidra/Processors/*/lib/*.jar",
    # Installation-scoped extensions. Not optional: a processor module such as
    # ghidra-emotionengine-reloaded (which is where r5900 / PS2 EE comes from --
    # stock Ghidra has no r5900 language) lives here or in the user extensions
    # dir. Omit these and the headless server silently has a smaller language
    # set than the GUI, so a PS2 ELF falls back to generic MIPS.
    "Ghidra/Extensions/*/lib/*.jar",
)


def user_extension_dirs(ghidra: str) -> list[str]:
    """Extensions installed per-user, i.e. everything the GUI's extension
    installer wrote. Layout: <appdata>/ghidra/<ghidra_dir_name>/Extensions/*."""
    import glob as _glob

    version_dir = os.path.basename(ghidra.rstrip("/"))
    roots = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        roots.append(os.path.join(appdata, "ghidra", version_dir, "Extensions"))
    roots.append(os.path.join(os.path.expanduser("~"), ".ghidra", f".{version_dir}", "Extensions"))
    out = []
    for root in roots:
        out.extend(sorted(_glob.glob(os.path.join(root, "*", "lib", "*.jar"))))
    return out


def find_ghidra(explicit: str | None) -> str:
    """Resolve the Ghidra install, auto-detecting only when nothing was named.

    An explicit --ghidra / GHIDRA_INSTALL_DIR that is wrong is an error, never a
    reason to quietly substitute some other install found on disk: `serve` would
    then run against a Ghidra the caller did not ask for, with a different
    language and extension set, and the mismatch would only surface much later as
    wrong disassembly."""
    import glob as _glob

    named = (
        ("--ghidra", explicit),
        ("GHIDRA_INSTALL_DIR", os.environ.get("GHIDRA_INSTALL_DIR")),
        ("GHIDRA_HOME", os.environ.get("GHIDRA_HOME")),
    )
    for source, cand in named:
        if not cand:
            continue
        if not os.path.isdir(os.path.join(cand, "Ghidra", "Framework")):
            raise Fail(
                f"{source}={cand} is not a Ghidra install "
                "(no Ghidra/Framework directory inside)"
            )
        return cand.replace("\\", "/")

    for root in ("C:/Tools", "C:/Program Files", os.path.expanduser("~"),
                 "/opt", "/usr/share", "/usr/local"):
        for cand in sorted(_glob.glob(os.path.join(root, "ghidra_*")), reverse=True):
            if os.path.isdir(os.path.join(cand, "Ghidra", "Framework")):
                return cand.replace("\\", "/")
    raise Fail(
        "cannot find a Ghidra install; pass --ghidra DIR or set GHIDRA_INSTALL_DIR"
    )


def find_jar(explicit: str | None) -> str:
    """Locate a GhidraMCP jar that carries the headless server.

    Searched in order so the same script works from a git clone, from a
    marketplace-installed plugin directory, and from a bare copy on PATH:
    explicit --jar, $GMCP_JAR, then dist/ in the script's directory and each of
    its first four ancestors (which reaches a repo root from plugins/x/bin/)."""
    import glob as _glob

    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (explicit, os.environ.get("GMCP_JAR")):
        if cand:
            if not os.path.isfile(cand):
                raise Fail(f"jar not found: {cand}")
            return cand.replace("\\", "/")
    # Walk up far enough to reach a repo root from plugins/<name>/bin/.
    roots, cursor = [], here
    for _ in range(4):
        roots.append(cursor)
        parent = os.path.dirname(cursor)
        if parent == cursor:
            break
        cursor = parent
    hits: list[str] = []
    for root in roots:
        hits.extend(_glob.glob(os.path.join(root, "dist", "GhidraMCP*.jar")))
    if not hits:
        raise Fail(
            "no GhidraMCP jar found. Fetch one:\n"
            "  python scripts/fetch-headless-jar.py\n"
            "or pass --jar PATH / set GMCP_JAR. Any release zip works:\n"
            "  GhidraMCP-<ver>.zip > GhidraMCP/lib/GhidraMCP-<ver>.jar"
        )
    return sorted(hits, reverse=True)[0].replace("\\", "/")


def find_java() -> str:
    home = os.environ.get("JAVA_HOME")
    if home:
        exe = os.path.join(home, "bin", "java.exe" if os.name == "nt" else "java")
        if os.path.isfile(exe):
            return exe.replace("\\", "/")
    return "java"


def loader_option_args(pairs: list[str]) -> list[str]:
    """`key=value` pairs as headless `-loader-<key> <value>` arguments.

    A loader declares its own options (Loader.getDefaultOptions) and headless
    sets them by name. Passing them is the difference between a loader that
    asks a question and a loader that answers it from argv: GameCubeLoader
    opens a Swing dialog during load, so with no options it throws
    HeadlessException before a single memory block exists.
    """
    args = []
    for pair in pairs:
        if "=" not in pair:
            raise Fail(f"--loader-opt wants key=value, got {pair!r}")
        key, value = pair.split("=", 1)
        key = key.strip()
        if not key:
            raise Fail(f"--loader-opt has an empty key: {pair!r}")
        args += [f"-loader-{key}", value]
    return args


def project_name_for(project_dir: str) -> str:
    """The project a directory already holds, or one named after it."""
    import glob as _glob

    existing = sorted(_glob.glob(os.path.join(project_dir, "*.gpr")))
    if existing:
        return os.path.splitext(os.path.basename(existing[0]))[0]
    return os.path.basename(os.path.abspath(project_dir)) or "gmcp"


def headless_import(ghidra: str, project_dir: str, binary: str, loader: str | None,
                    loader_opts: list[str], analyze: bool) -> tuple[str, str, str]:
    """Import `binary` with stock analyzeHeadless, reporting the choice it made.

    The loader and the language are echoed because they are a choice: an
    install carrying loader extensions can answer the same bytes several ways
    -- a GameCube RSO reader claims a Game Boy Advance cartridge and yields an
    empty PowerPC program -- and a result that does not say which loader ran
    cannot be reproduced.
    """
    import subprocess

    exe = os.path.join(ghidra, "support", "analyzeHeadless")
    if not os.path.isfile(exe):
        exe_bat = exe + ".bat"
        if not os.path.isfile(exe_bat):
            raise Fail(f"no analyzeHeadless in {ghidra}/support")
        exe = exe_bat
    os.makedirs(project_dir, exist_ok=True)
    name = project_name_for(project_dir)
    cmd = [exe, project_dir, name, "-import", binary]
    if loader:
        cmd += ["-loader", loader]
    cmd += loader_option_args(loader_opts)
    cmd += [] if analyze else ["-noanalysis"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    text = (result.stdout or "") + (result.stderr or "")
    used_loader = used_language = ""
    for line in text.splitlines():
        if "Using Loader:" in line:
            used_loader = line.split("Using Loader:", 1)[1].strip()
            used_loader = used_loader.removesuffix("(ProgramLoader)").strip()
        elif "Using Language/Compiler:" in line:
            used_language = line.split("Using Language/Compiler:", 1)[1].strip()
            used_language = used_language.removesuffix("(ProgramLoader)").strip()
    if "Invalid loader name specified" in text:
        raise Fail(
            f"no loader named {loader!r}: headless matches a loader's Java class "
            "simple name, not its display name -- e.g. ElfLoader, PeLoader, "
            "MachoLoader, GameCubeLoader, GBALoader")
    if result.returncode != 0 or "Import failed" in text:
        errors = [line.strip() for line in text.splitlines()
                  if "ERROR" in line or "Exception" in line][:4]
        raise Fail(
            "import failed"
            + (f" with loader {used_loader!r}" if used_loader else "")
            + (f" as {used_language}" if used_language else "")
            + (":\n  " + "\n  ".join(errors) if errors else ""))
    program = os.path.basename(binary)
    print(f"imported {program}: loader {used_loader or '?'}, "
          f"language {used_language or '?'}", file=sys.stderr)
    return name, program, used_loader


def local_import(rest: list[str]) -> int:
    """gmcp import --file PATH --project DIR [--loader NAME] [--loader-opt k=v]"""
    binary = project_dir = ghidra_dir = None
    loader = None
    loader_opts: list[str] = []
    analyze = False
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg == "--analyze":
            analyze = True
        elif arg in ("--file", "--project", "--ghidra", "--loader", "--loader-opt"):
            if i + 1 >= len(rest):
                raise Fail(f"{arg} needs a value")
            i += 1
            value = rest[i]
            if arg == "--file":
                binary = value
            elif arg == "--project":
                project_dir = value
            elif arg == "--ghidra":
                ghidra_dir = value
            elif arg == "--loader":
                loader = value
            else:
                loader_opts.append(value)
        else:
            raise Fail(f"import: unknown option {arg!r}")
        i += 1
    if not binary or not project_dir:
        raise Fail("usage: gmcp import --file PATH --project DIR "
                   "[--loader NAME] [--loader-opt key=value] [--analyze]")
    if not os.path.isfile(binary):
        raise Fail(f"no such file: {binary}")
    ghidra = find_ghidra(ghidra_dir)
    name, program, used = headless_import(ghidra, project_dir, binary, loader,
                                          loader_opts, analyze)
    print(json.dumps({"project": name, "program": program, "loader": used}))
    return 0


def serve(rest: list[str]) -> int:
    import glob as _glob

    opts = {"--port": "8089", "--bind": "127.0.0.1", "--xmx": "4g"}
    passthrough = {"--port", "--bind", "--project", "--program", "--file"}
    ghidra_dir = jar = None
    print_only = False
    loader = None
    loader_opts: list[str] = []
    analyze = False

    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg == "--print":
            print_only = True
        elif arg == "--analyze":
            analyze = True
        elif arg == "--loader":
            if i + 1 >= len(rest):
                raise Fail("--loader needs a loader name")
            i += 1
            loader = rest[i]
        elif arg == "--loader-opt":
            if i + 1 >= len(rest):
                raise Fail("--loader-opt needs key=value")
            i += 1
            loader_opts.append(rest[i])
        elif arg == "--ghidra":
            i += 1
            ghidra_dir = rest[i]
        elif arg == "--jar":
            i += 1
            jar = rest[i]
        elif arg in passthrough or arg == "--xmx":
            if i + 1 >= len(rest):
                raise Fail(f"{arg} needs a value")
            i += 1
            opts[arg] = rest[i]
        else:
            raise Fail(f"serve: unknown option {arg!r} (see gmcp --help)")
        i += 1

    if (loader or loader_opts) and not opts.get("--file"):
        raise Fail("--loader/--loader-opt only apply to an import: pass --file too")

    ghidra = find_ghidra(ghidra_dir)
    # A loader choice belongs to the import, and the server's own import path
    # takes no loader arguments: import here with stock headless, then serve
    # the program it wrote.
    if (loader or loader_opts) and not print_only:
        project_dir = opts.get("--project")
        if not project_dir:
            raise Fail("--loader/--loader-opt need --project DIR to import into")
        _, program, _ = headless_import(ghidra, project_dir, opts["--file"],
                                        loader, loader_opts, analyze)
        opts.pop("--file")
        opts.setdefault("--program", program)
    jar_path = find_jar(jar)

    classpath = [jar_path]
    for pattern in GHIDRA_JAR_GLOBS:
        classpath.extend(sorted(_glob.glob(os.path.join(ghidra, pattern))))
    # Skip other GhidraMCP copies the GUI may have installed: two versions of the
    # same classes on one classpath is a coin flip over which server you get.
    classpath.extend(
        p for p in user_extension_dirs(ghidra)
        if "ghidramcp" not in os.path.basename(p).lower()
    )
    if len(classpath) < 50:
        raise Fail(f"{ghidra} does not look like a Ghidra install (only {len(classpath)} jars)")

    cmd = [
        find_java(),
        f"-Xmx{opts['--xmx']}",
        "-XX:+UseG1GC",
        f"-Dghidra.home={ghidra}",
        # NO -Dapplication.name override. docker/entrypoint.sh passes
        # "-Dapplication.name=GhidraMCP", which repoints Ghidra's user settings
        # dir at %APPDATA%/ghidramcp/... -- harmless in a container, but on a
        # workstation it hides every GUI-installed extension, because those live
        # in %APPDATA%/ghidra/<version>/Extensions. Losing them means losing
        # their languages: a PS2 ELF then cannot be loaded as r5900 at all.
        "-Djava.awt.headless=true",
        "-classpath",
        os.pathsep.join(p.replace("\\", "/") for p in classpath),
        "com.xebyte.headless.GhidraMCPHeadlessServer",
    ]
    for flag in ("--port", "--bind", "--project", "--program", "--file"):
        if flag in opts:
            cmd += [flag, opts[flag]]

    if print_only:
        print(json.dumps(cmd, indent=2))
        return 0

    print(
        f"launching headless GhidraMCP: {ghidra} + {os.path.basename(jar_path)}\n"
        f"  -> http://{opts['--bind']}:{opts['--port']}/  (Ctrl+C to stop)",
        file=sys.stderr,
    )
    return launch_supervised(cmd)


def launch_supervised(cmd: list[str]) -> int:
    """Run the JVM so that it cannot outlive us.

    This matters more than it looks. A leaked headless JVM keeps its Ghidra
    project locked and its port bound, so the next `serve` fails and the GUI
    refuses to open the same project -- with no obvious culprit, since the
    launcher that started it is gone. Observed for real: a plain
    subprocess.call() child survived its parent being killed by a process
    supervisor and sat on port 8091 for eight minutes.

    POSIX: replace this process with the JVM, so there is only ever one process
    and it inherits our signals directly.

    Windows: put the JVM in a Job Object with KILL_ON_JOB_CLOSE. The handle dies
    with us however we die -- Ctrl+C, TerminateProcess, supervisor kill -- and
    the kernel then tears down the JVM. No ctypes failure is fatal: we fall back
    to a supervised subprocess.
    """
    import subprocess

    if os.name != "nt":
        try:
            os.execvp(cmd[0], cmd)
        except OSError as e:
            raise Fail(f"cannot exec {cmd[0]}: {e}", 3) from None

    job = None
    try:
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
        JobObjectExtendedLimitInformation = 9

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [(n, ctypes.c_ulonglong) for n in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        job = k32.CreateJobObjectW(None, None)
        if not job:
            raise OSError(ctypes.get_last_error(), "CreateJobObjectW")
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not k32.SetInformationJobObject(
            job, JobObjectExtendedLimitInformation,
            ctypes.byref(info), ctypes.sizeof(info),
        ):
            raise OSError(ctypes.get_last_error(), "SetInformationJobObject")
    except (ImportError, OSError, AttributeError) as e:
        print(f"gmcp[info]: no job-object supervision ({e}); "
              "kill the java process yourself if gmcp is killed abruptly",
              file=sys.stderr)
        job = None

    proc = subprocess.Popen(cmd)
    if job:
        import ctypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        if not k32.AssignProcessToJobObject(job, int(proc._handle)):
            print("gmcp[info]: could not assign the JVM to the job object",
                  file=sys.stderr)
    try:
        return proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        try:
            return proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            return proc.wait()


def emit(response: tuple[int, str], raw_out: bool) -> int:
    status, text = response
    failed = status >= 400
    if failed:
        print(f"gmcp: HTTP {status} from the server", file=sys.stderr)
    if raw_out:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
        return 1 if failed else 0
    try:
        doc = json.loads(text)
    except ValueError:
        # Several endpoints return plain text (get_metadata, disassemble_function,
        # the paginated listers) with CRLF line ends. Left alone, every line comes
        # out double-spaced on a terminal that already translates \n.
        plain = text.replace("\r\n", "\n")
        sys.stdout.write(plain if plain.endswith("\n") else plain + "\n")
        return 1 if failed else 0
    print(json.dumps(doc, indent=2, ensure_ascii=False))
    if failed or (isinstance(doc, dict) and "error" in doc):
        return 1
    return 0


def show_tools(tools: list[dict], needle: str | None, category: str | None) -> None:
    rows = []
    for tool in sorted(tools, key=tool_name):
        name = tool_name(tool)
        if needle and needle not in name and needle not in tool.get("description", ""):
            continue
        if category and tool.get("category") != category:
            continue
        desc = (tool.get("description") or "").split("\n")[0]
        rows.append((tool.get("method", "GET"), name, desc))
    width = max((len(r[1]) for r in rows), default=0)
    for method, name, desc in rows:
        print(f"{method:<4} {name:<{width}}  {desc[:96]}")
    print(f"\n{len(rows)} tool(s)", file=sys.stderr)


def show_help(tool: dict) -> None:
    print(f"{tool.get('method', 'GET')} /{tool_name(tool)}")
    if tool.get("category"):
        print(f"category: {tool['category']}")
    if tool.get("description"):
        print(f"\n{tool['description']}\n")
    params = tool.get("params", [])
    if not params:
        print("(no parameters)")
        return
    order = [p["name"] for p in params if p.get("required")]
    print("usage: gmcp " + tool_name(tool) + "".join(f" <{n}>" for n in order)
          + (" [--opt value ...]" if len(order) != len(params) else ""))
    print()
    for p in params:
        flag = f"--{p['name']} <{p.get('type', 'string')}>"
        tags = [] if p.get("required") else ["optional"]
        if p.get("default") is not None:
            tags.append(f"default={p['default']}")
        tags.append(p.get("source", "body"))
        print(f"  {flag:<34} [{', '.join(tags)}] {p.get('description', '')}")


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

def run(argv: list[str]) -> int:
    url = os.environ.get("GHIDRA_MCP_URL")
    token = os.environ.get("GHIDRA_MCP_AUTH_TOKEN")
    timeout = float(os.environ.get("GHIDRA_MCP_TIMEOUT", "120"))
    refresh = raw_out = dry_run = verbose = False

    while argv:
        arg = argv[0]
        if arg in ("-u", "--url"):
            url, argv = argv[1] if len(argv) > 1 else "", argv[1:]
        elif arg in ("-t", "--token"):
            token, argv = argv[1] if len(argv) > 1 else "", argv[1:]
        elif arg == "--timeout":
            timeout, argv = float(argv[1]), argv[1:]
        elif arg == "--refresh":
            refresh = True
        elif arg == "--raw-out":
            raw_out = True
        elif arg == "--dry-run":
            dry_run = True
        elif arg in ("-v", "--verbose"):
            verbose = True
        elif arg in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            break
        argv = argv[1:]

    if not argv:
        print(__doc__)
        return 2

    # Local-only work first: never probe for a server, or report one missing,
    # when the command line is malformed or does not need a server at all.
    # import is a local process launch too: stock headless does the loading, so
    # a loader and its options can be named on the command line.
    if argv[0] == "import":
        return local_import(argv[1:])

    if argv[0] == "serve":
        return serve(argv[1:])
    if argv[0] == "help" and len(argv) < 2:
        raise Fail("usage: gmcp help <tool>   (list tools with: gmcp tools)")
    if argv[0] == "raw" and len(argv) < 3:
        raise Fail("usage: gmcp raw <METHOD> <path> [json-body]")
    if argv[0] == "call" and len(argv) < 2:
        raise Fail("usage: gmcp call <tool> [args...]")

    client = Client(url or discover_url(), token, timeout, verbose)
    cmd, rest = argv[0], argv[1:]

    if cmd == "raw":
        if len(rest) < 2:
            raise Fail("usage: gmcp raw <METHOD> <path> [json-body]")
        method, path = rest[0].upper(), rest[1]
        body = json.loads(rest[2]) if len(rest) > 2 else (None if method == "GET" else {})
        return emit(client.request(method, path, {}, body), raw_out)

    if cmd == "health":
        return emit(client.request("GET", "/mcp/health", {}, None), raw_out)

    tools = load_schema(client, refresh)

    if cmd == "tools":
        needle = next((a for a in rest if not a.startswith("-")), None)
        category = None
        if "--category" in rest:
            category = rest[rest.index("--category") + 1]
            needle = None if needle == category else needle
        show_tools(tools, needle, category)
        return 0

    if cmd == "cats":
        counts: dict[str, int] = {}
        for tool in tools:
            counts[tool.get("category") or "(none)"] = counts.get(tool.get("category") or "(none)", 0) + 1
        for name, count in sorted(counts.items()):
            print(f"{count:>4}  {name}")
        return 0

    if cmd == "help":
        if not rest:
            raise Fail("usage: gmcp help <tool>")
        show_help(find_tool(tools, rest[0]))
        return 0

    if cmd == "call":
        if not rest:
            raise Fail("usage: gmcp call <tool> [args...]")
        cmd, rest = rest[0], rest[1:]

    tool = find_tool(tools, cmd)
    method = tool.get("method", "GET").upper()
    query, body = bind(tool, rest, dry_run)
    return emit(
        client.request(method, tool["path"], query, None if method == "GET" else body),
        raw_out,
    )


def main() -> int:
    try:
        return run(sys.argv[1:])
    except Fail as e:
        print(f"gmcp: {e}", file=sys.stderr)
        return e.code
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
