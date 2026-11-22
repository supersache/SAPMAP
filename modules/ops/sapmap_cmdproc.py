#!/usr/bin/env python3
"""
SAPMAP Command Processor — an interactive, plugin-style REPL over a .sapmap file.

The processor loads a ``.sapmap`` session file (plain JSON) as a mutable Python
``dict`` and loops over recurring prompts ("wiederkehrende Abfragen").  Each line
the operator types is dispatched to a :class:`Command`.

Design goals (see issue spec):

1. Input is a ``.sapmap`` file — loaded verbatim as a ``dict`` (we deliberately
   do NOT round-trip through :class:`SAPMAPState`, so unknown/forward-compatible
   keys survive edit-and-save).
2. The prompt *varies* with context — the currently selected node is appended as
   ``>SID``, and the outcome of the last command (success/failure) is reflected.
3. Commands are plugins with a **name**, **aliases**, **args** and **conditions**.
   A *condition* gates a command: it may only run when the condition holds (e.g.
   ``rfc-connect`` requires a selected ABAP node that has credentials).  A command
   may change the prompt on success or on failure.
4. The state is the ``.sapmap`` content as a ``dict``; it can be mutated and saved.

The three landscape commands required by the spec are implemented as plugins:

  * ``list_nodes`` / ``ln``     — print ``.nodes[].sid`` (screen-limited; ``a`` = all)
  * ``use_node_by_sid`` / ``un`` — select a node, appending ``>SID`` to the prompt
  * ``search_node`` / ``sn``    — substring search over sid/description/sapology

Built-in housekeeping commands (``help``, ``save``, ``quit``) round out the loop.

Run standalone::

    python3 -m modules.ops.sapmap_cmdproc states/my_session.sapmap
    # or, thanks to modules/__init__.py path registration:
    python3 modules/ops/sapmap_cmdproc.py states/my_session.sapmap
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import modules


# ---------------------------------------------------------------------------
# State helpers — operate on the raw .sapmap dict
# ---------------------------------------------------------------------------
#
# ``nodes`` in a .sapmap file is a dict keyed by SID (``{"KAI": {...}}``), but
# older/hand-edited files may carry a list.  ``iter_nodes`` normalises both into
# a list of ``(key, node)`` pairs so the rest of the code never has to care.

def iter_nodes(state: Dict[str, Any]) -> List[Tuple[Any, Dict[str, Any]]]:
    """Yield ``(key, node_dict)`` pairs regardless of the nodes container shape."""
    nodes = state.get("nodes")
    if isinstance(nodes, dict):
        return [(k, v) for k, v in nodes.items() if isinstance(v, dict)]
    if isinstance(nodes, list):
        return [(i, v) for i, v in enumerate(nodes) if isinstance(v, dict)]
    return []


def node_sid(key: Any, node: Dict[str, Any]) -> str:
    """Best-effort SID for a node — prefer the explicit field, fall back to key."""
    return str(node.get("sid") or key or "")


def find_node_by_sid(state: Dict[str, Any], sid: str) -> Optional[Dict[str, Any]]:
    """Case-insensitive lookup of a node by SID; ``None`` if absent."""
    want = (sid or "").strip().upper()
    for key, node in iter_nodes(state):
        if node_sid(key, node).upper() == want:
            return node
    return None


def node_has_verified_cred(node: Dict[str, Any]) -> bool:
    """True when the node carries at least one credential with ``verified: true``."""
    for cred in node.get("credentials") or []:
        if isinstance(cred, dict) and cred.get("verified") is True:
            return True
    return False


def node_search_haystack(node: Dict[str, Any]) -> str:
    """Concatenated, lower-cased text searched by ``search_node``."""
    sapology = node.get("sapology_data") or node.get("sapology") or {}
    if not isinstance(sapology, dict):
        sapology = {}
    parts = [
        node.get("sid", ""),
        node.get("description", ""),
        sapology.get("description", ""),
    ]
    return " ".join(str(p) for p in parts).lower()


# ---------------------------------------------------------------------------
# Command framework
# ---------------------------------------------------------------------------

@dataclass
class Arg:
    """Declarative description of a positional command argument."""
    name: str
    required: bool = False
    help: str = ""


@dataclass
class CommandResult:
    """Outcome of running a command.  ``ok`` drives the prompt's status marker."""
    ok: bool = True
    message: str = ""


# A condition is a predicate over the context plus the message shown when it
# fails.  Commands run only when every condition holds — this is how, e.g.,
# ``rfc-connect`` can be restricted to "a node is selected, it is ABAP, and it
# has credentials".  The reusable predicate factories below build these.
Condition = Tuple[Callable[["CommandContext"], bool], str]


@dataclass
class Command:
    """A plugin command: a name, aliases, args, gating conditions and a handler."""
    name: str
    handler: Callable[["CommandContext", List[str]], CommandResult]
    aliases: List[str] = field(default_factory=list)
    args: List[Arg] = field(default_factory=list)
    conditions: List[Condition] = field(default_factory=list)
    help: str = ""

    def usage(self) -> str:
        parts = [self.name]
        for a in self.args:
            parts.append(f"<{a.name}>" if a.required else f"[{a.name}]")
        return " ".join(parts)


class CommandContext:
    """Mutable session state shared across command invocations.

    Holds the loaded ``.sapmap`` dict, the backing file path, the selected node,
    an output sink (so the REPL is testable) and the outcome of the last command
    (used to vary the prompt).
    """

    def __init__(self, state: Dict[str, Any], path: Optional[str] = None,
                 out: Callable[[str], None] = print,
                 inp: Callable[[str], str] = input,
                 history_path: Optional[str] = ".cmdhistory"):
        self.state: Dict[str, Any] = state
        self.path: Optional[str] = path
        self.out = out
        self.inp = inp  # used by interactive commands (e.g. 'show' paging)
        # Local file every typed command is appended to; None disables history.
        self.history_path: Optional[str] = history_path
        # Re-entrant dispatch hook, wired by CommandProcessor; lets commands
        # such as 'redo' feed another line back through the parser/gating.
        self.dispatch: Optional[Callable[[str], Optional["CommandResult"]]] = None
        self.selected_sid: Optional[str] = None
        self.dirty: bool = False
        self.running: bool = True
        self.last_ok: Optional[bool] = None  # None until the first command runs

    # -- selection helpers ---------------------------------------------------
    def selected_node(self) -> Optional[Dict[str, Any]]:
        if not self.selected_sid:
            return None
        return find_node_by_sid(self.state, self.selected_sid)

    def echo(self, msg: str = "") -> None:
        self.out(msg)


# ---------------------------------------------------------------------------
# Reusable condition predicates (plugin building blocks)
# ---------------------------------------------------------------------------
#
# These let new commands declare their prerequisites declaratively, e.g.::
#
#     Command("rfc-connect", handler=_rfc_connect,
#             conditions=[require_selected_node(), require_abap(),
#                         require_credentials()])

def require_selected_node() -> Condition:
    return (lambda ctx: ctx.selected_node() is not None,
            "no node selected — use 'un <SID>' first")


def require_abap() -> Condition:
    def _pred(ctx: CommandContext) -> bool:
        node = ctx.selected_node() or {}
        return "ABAP" in str(node.get("system_type", "")).upper()
    return (_pred, "selected node is not an ABAP system")


def require_credentials() -> Condition:
    def _pred(ctx: CommandContext) -> bool:
        node = ctx.selected_node() or {}
        creds = node.get("credentials") or []
        return bool(creds)
    return (_pred, "selected node has no credentials")


# ---------------------------------------------------------------------------
# Built-in landscape commands
# ---------------------------------------------------------------------------

def _terminal_rows() -> int:
    return shutil.get_terminal_size(fallback=(80, 24)).lines


def cmd_list_nodes(ctx: CommandContext, args: List[str]) -> CommandResult:
    """Print node SIDs, limited to what fits on screen unless 'a' is given."""
    pairs = iter_nodes(ctx.state)
    if not pairs:
        ctx.echo("(no nodes in state)")
        return CommandResult(ok=False, message="no nodes")

    # (sid, node) sorted by SID; a trailing '*' flags a verified credential.
    entries = sorted(((node_sid(k, n), n) for k, n in pairs), key=lambda t: t[0])
    lines = [f"{sid}{'*' if node_has_verified_cred(node) else ''}" for sid, node in entries]

    # 'a' dumps every node at once (no pausing — handy for piping); plain 'ln'
    # pages the full list 'more'-style so nothing scrolls off screen.
    dump_all = bool(args) and args[0].lower() in ("a", "all", "-a", "--all")
    if dump_all:
        for line in lines:
            ctx.echo(line)
        return CommandResult(ok=True, message=f"{len(lines)} shown")

    fully = _page_lines(ctx, lines)
    return CommandResult(ok=fully, message=f"{len(lines)} node(s)")


def cmd_use_node(ctx: CommandContext, args: List[str]) -> CommandResult:
    """Select a node by SID; on success the prompt gains '>SID'."""
    sid = args[0]
    node = find_node_by_sid(ctx.state, sid)
    if node is None:
        ctx.echo(f"no such SID: {sid}")
        return CommandResult(ok=False, message=f"no such SID: {sid}")
    # Normalise to the node's canonical SID casing for the prompt.
    ctx.selected_sid = str(node.get("sid") or sid)
    ctx.echo(f"selected {ctx.selected_sid}")
    return CommandResult(ok=True, message=f"selected {ctx.selected_sid}")


def cmd_search_node(ctx: CommandContext, args: List[str]) -> CommandResult:
    """Substring search over sid / description / sapology description."""
    needle = args[0].lower()
    hits: List[Tuple[str, Dict[str, Any]]] = []
    for key, node in iter_nodes(ctx.state):
        if needle in node_search_haystack(node):
            hits.append((node_sid(key, node), node))

    if not hits:
        ctx.echo(f"no match for '{args[0]}'")
        return CommandResult(ok=False, message="no match")

    for sid, node in sorted(hits, key=lambda t: t[0]):
        sapology = node.get("sapology_data") or node.get("sapology") or {}
        desc = node.get("description") or (
            sapology.get("description") if isinstance(sapology, dict) else "") or ""
        stype = node.get("system_type", "")
        line = f"{sid:<10} {stype:<12} {desc}".rstrip()
        ctx.echo(line)
    return CommandResult(ok=True, message=f"{len(hits)} match(es)")


def _value_to_lines(value: Any) -> List[str]:
    """Render a node property value into a flat list of display lines.

    Lists become one line per element (dicts/lists compact-JSON'd with an index
    prefix); dicts are pretty-printed; scalars become a single line.
    """
    if isinstance(value, list):
        lines: List[str] = []
        for i, item in enumerate(value):
            if isinstance(item, (dict, list)):
                lines.append(f"[{i}] {json.dumps(item, default=str, ensure_ascii=False)}")
            else:
                lines.append(f"[{i}] {item}")
        return lines or ["(empty list)"]
    if isinstance(value, dict):
        return json.dumps(value, indent=2, default=str,
                          ensure_ascii=False).splitlines() or ["(empty dict)"]
    return [str(value)]


def _page_lines(ctx: CommandContext, lines: List[str],
                page_size: Optional[int] = None) -> bool:
    """Print lines a screenful at a time, 'more'-style.

    Pauses between pages with a ``--More--`` prompt; the operator presses Enter
    for the next page or ``q`` to stop.  Returns True if fully shown, False if
    the operator quit early.  Short output (fits one page) prints with no pause.
    """
    rows = page_size if page_size is not None else max(1, _terminal_rows() - 1)
    total = len(lines)
    i = 0
    while i < total:
        for line in lines[i:i + rows]:
            ctx.echo(line)
        i += rows
        if i >= total:
            break
        try:
            answer = ctx.inp(f"--More-- ({total - i} more, Enter = next, q = quit) ")
        except (EOFError, KeyboardInterrupt):
            ctx.echo("")
            return False
        if answer.strip().lower() == "q":
            ctx.echo(f"... ({total - i} more line(s) not shown)")
            return False
    return True


def cmd_show(ctx: CommandContext, args: List[str]) -> CommandResult:
    """Show one property of the selected node, paging long values like 'more'."""
    node = ctx.selected_node() or {}
    prop = args[0]
    if prop not in node:
        ctx.echo(f"no such property: {prop}")
        available = ", ".join(sorted(k for k in node if not str(k).startswith("_")))
        if available:
            ctx.echo(f"available: {available}")
        return CommandResult(ok=False, message="no such property")

    lines = _value_to_lines(node[prop])
    fully = _page_lines(ctx, lines)
    return CommandResult(ok=fully, message=f"{prop}: {len(lines)} line(s)")


# ---------------------------------------------------------------------------
# RFC_READ_TABLE command
# ---------------------------------------------------------------------------
#
# These helpers are deliberately plain module-level functions (no class): the
# command processor already owns all the session state we need, so there is no
# instance to carry.  They are adapted from a reference snippet that lived on a
# connection-wrapper object (``self.conn``); here the open connection is passed
# in explicitly instead.

def rfc_safe_call(conn: Any, func_name: str, **kwargs) -> Tuple[Any, Optional[str]]:
    """Call a function module and turn both error channels into one clear error.

    Returns ``(result, error)``.  On success ``error`` is ``None``; on failure
    ``error`` is a human-readable message (and ``result`` is ``None``).

    Python-level exceptions (``RFCError`` and its subclasses) are caught and
    rendered via :func:`format_rfc_exception`.  Note that ``RFC_READ_TABLE``
    reports problems (unknown table, buffer overflow, missing authorization)
    by *raising* an ABAP exception rather than returning a BAPIRET2 structure,
    so there is no BAPIRET2 post-check to run here.
    """
    # Lazy imports: the RFC backend (and its exception classes) pull in the
    # protocol layer, which we only want to touch when an RFC command actually
    # runs — keeping the plain .sapmap editing commands dependency-free.
    from sapmap_errors import format_rfc_exception
    from sap_rfc_ctypes import (
        ABAPApplicationError, ABAPRuntimeError,
        CommunicationError, LogonError, RFCError,
    )

    try:
        result = conn.call(func_name, **kwargs)
    except LogonError as e:
        return None, f"[{func_name}] logon failed: {format_rfc_exception(e)}"
    except CommunicationError as e:
        return None, f"[{func_name}] connection/gateway: {format_rfc_exception(e)}"
    except ABAPApplicationError as e:
        return None, f"[{func_name}] ABAP exception '{getattr(e, 'key', '')}': {format_rfc_exception(e)}"
    except ABAPRuntimeError as e:
        return None, f"[{func_name}] ABAP runtime error/dump: {format_rfc_exception(e)}"
    except RFCError as e:
        return None, f"[{func_name}] RFC error: {format_rfc_exception(e)}"

    return result, None


def rfc_read_table(conn: Any, tablename: str, attrs: str,
                   where: Optional[str] = None,
                   destination: Optional[str] = None,
                   rowcount: int = 1000) -> Tuple[Any, Optional[str]]:
    """Read ``attrs`` (comma-separated columns) from ``tablename`` via RFC_READ_TABLE.

    ``where`` is an optional WHERE clause (open-SQL syntax, e.g.
    ``MANDT = '000'``); ``destination`` an optional RFC destination to route the
    read through.  Returns ``(result, error)`` from :func:`rfc_safe_call`.
    """
    # Build the FIELDS table — one {FIELDNAME: COL} row per requested column.
    attrs_array = [x.strip() for x in attrs.split(",") if x.strip()]
    fields = [{"FIELDNAME": x.upper()} for x in attrs_array]

    params: Dict[str, Any] = {
        "QUERY_TABLE": tablename.upper(),
        "DELIMITER": "|",
        "FIELDS": fields,
        "ROWCOUNT": rowcount,
    }

    if where:
        # RFC_READ_TABLE truncates each OPTIONS line at 72 characters, so split
        # a long WHERE clause into 72-char chunks across multiple TEXT rows.
        params["OPTIONS"] = [{"TEXT": where[i:i + 72]}
                             for i in range(0, len(where), 72)]

    if destination:
        params["DESTINATION"] = destination

    return rfc_safe_call(conn, "RFC_READ_TABLE", **params)


def _render_read_table(result: Dict[str, Any]) -> List[str]:
    """Turn an RFC_READ_TABLE result into aligned, printable text lines.

    The FM returns FIELDS (column metadata) and DATA (``{"WA": "a|b|c"}`` rows,
    delimited by the "|" we requested).  We split each row back on "|" and pad
    every column to the width of the widest value so it reads like a table.
    """
    field_names = [f.get("FIELDNAME", "") for f in result.get("FIELDS", [])]
    rows = [r.get("WA", "").split("|") for r in result.get("DATA", [])]

    # Compute per-column width from the header and every cell.
    widths = [len(name) for name in field_names]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(cell))

    def fmt(cells: List[str]) -> str:
        return " | ".join(
            str(cells[i]).ljust(widths[i]) if i < len(cells) else "".ljust(widths[i])
            for i in range(len(widths))
        ).rstrip()

    lines = [fmt(field_names), "-+-".join("-" * w for w in widths)]
    lines.extend(fmt(row) for row in rows)
    lines.append(f"({len(rows)} row(s))")
    return lines


def cmd_read_table(ctx: CommandContext, args: List[str]) -> CommandResult:
    """RFC_READ_TABLE against the selected node: 'rt <table> <col,col> [where]'."""
    # Lazy imports so the RFC/model stack is only pulled in when used.
    from sapmap_models import SAPNode
    from sapmap_rfc import _get_connection, get_sdk_path

    # RFC_READ_TABLE only runs over the NW RFC SDK backend — refuse early with a
    # clear hint when the operator did not pass --sdk on the command line.
    if not get_sdk_path():
        ctx.echo("no NW RFC SDK path set — restart with '--sdk <PATH>'")
        return CommandResult(ok=False, message="no sdk path")

    tablename = args[0]
    attrs = args[1]
    # Everything after the first two tokens is the (space-containing) WHERE clause.
    where = " ".join(args[2:]) if len(args) > 2 else None

    # The processor edits the raw .sapmap dict; rebuild a SAPNode so we can reuse
    # _get_connection (credential selection, host/instance resolution, SNC, …).
    node_dict = ctx.selected_node() or {}
    try:
        node = SAPNode.from_dict(node_dict)
    except Exception as exc:  # defensive: hand-edited/partial node dicts
        ctx.echo(f"cannot build node from state: {exc}")
        return CommandResult(ok=False, message="bad node")

    try:
        with _get_connection(node) as conn:
            result, error = rfc_read_table(conn, tablename, attrs, where=where)
    except Exception as exc:  # connection setup errors (no creds, SDK missing, …)
        ctx.echo(f"connect failed: {exc}")
        return CommandResult(ok=False, message=f"connect failed: {exc}")

    if error:
        ctx.echo(error)
        return CommandResult(ok=False, message=error)

    fully = _page_lines(ctx, _render_read_table(result))
    return CommandResult(ok=fully, message=f"read {tablename}")


# ---------------------------------------------------------------------------
# Command history (persisted to a local .cmdhistory file)
# ---------------------------------------------------------------------------

def append_history(path: Optional[str], line: str) -> None:
    """Append a single typed command line to the history file.

    Best-effort: history is a convenience, so any I/O error is swallowed rather
    than interrupting the REPL.  A ``None`` path disables history entirely.
    """
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line.rstrip("\n") + "\n")
    except OSError:
        pass


def read_history(path: Optional[str]) -> List[str]:
    """Return all recorded command lines; empty if the file is absent/unreadable."""
    if not path:
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return [ln.rstrip("\n") for ln in fh]
    except OSError:
        return []


def cmd_history(ctx: CommandContext, args: List[str]) -> CommandResult:
    """Print the command history, paged by default or all at once with 'a'."""
    lines = read_history(ctx.history_path)
    if not lines:
        ctx.echo("(no history)")
        return CommandResult(ok=False, message="no history")

    # Number the entries so operators can reference them.
    width = len(str(len(lines)))
    numbered = [f"{i:>{width}}  {ln}" for i, ln in enumerate(lines, start=1)]

    # 'a' dumps everything without paging (handy for piping); plain 'history'
    # pages 'more'-style — mirrors list_nodes' behaviour.
    dump_all = bool(args) and args[0].lower() in ("a", "all", "-a", "--all")
    if dump_all:
        for line in numbered:
            ctx.echo(line)
        return CommandResult(ok=True, message=f"{len(numbered)} shown")

    fully = _page_lines(ctx, numbered)
    return CommandResult(ok=fully, message=f"{len(numbered)} entries")


def _normalize_bang(line: str) -> str:
    """Expand the compact redo form '!2' into '! 2' (shell-style).

    Only rewrites when a '!' is glued to its argument; a bare '!' or an already
    spaced '! 2' is returned unchanged.
    """
    if len(line) > 1 and line[0] == "!" and not line[1].isspace():
        return "! " + line[1:]
    return line


def cmd_redo(ctx: CommandContext, args: List[str]) -> CommandResult:
    """Re-run a command by its history number: 'redo <n>' (aliases '!', 'r').

    The number matches the index shown by 'history'.  Note the just-typed
    'redo <n>' line is itself recorded first, so later entries shift by one.
    """
    lines = read_history(ctx.history_path)
    if not lines:
        ctx.echo("(no history)")
        return CommandResult(ok=False, message="no history")

    try:
        n = int(args[0])
    except ValueError:
        ctx.echo(f"not a number: {args[0]}")
        return CommandResult(ok=False, message="bad index")

    if n < 1 or n > len(lines):
        ctx.echo(f"out of range: {n} (history has {len(lines)} entr"
                 f"{'y' if len(lines) == 1 else 'ies'})")
        return CommandResult(ok=False, message="out of range")

    target = lines[n - 1]

    # Guard against redo-of-redo (and thus accidental infinite loops): refuse
    # when the referenced entry is itself a 'redo' invocation.
    reg: Optional["CommandRegistry"] = ctx.state.get("__registry__")
    # Normalise so a compact '!1' entry is recognised as a redo, same as dispatch.
    guard_tokens = _normalize_bang(target).split()
    first_token = guard_tokens[0] if guard_tokens else ""
    resolved = reg.resolve(first_token) if reg else None
    if resolved is not None and resolved.name == "redo":
        ctx.echo(f"refusing to redo a 'redo' entry: {target}")
        return CommandResult(ok=False, message="redo loop")

    ctx.echo(f"> {target}")
    if ctx.dispatch is None:  # defensive: context built without a processor
        ctx.echo("redo unavailable (no dispatcher)")
        return CommandResult(ok=False, message="no dispatcher")

    result = ctx.dispatch(target)
    # An empty/comment target dispatches to None — treat that as a no-op success.
    return result if result is not None else CommandResult(ok=True, message="noop")


# ---------------------------------------------------------------------------
# OS command execution (SXPG_STEP_XPG_START) command
# ---------------------------------------------------------------------------

def cmd_exec_local(ctx: CommandContext, args: List[str]) -> CommandResult:
    """Run an OS command on the selected node: 'xpg <cmd> [params]'.

    Thin wrapper over :func:`sapmap_rfc.execute_local_command` — ``cmd`` is the
    executable, everything after it is forwarded as the ``params`` string.
    """
    # Lazy imports so the RFC/model stack is only pulled in when used.
    from sapmap_models import SAPNode
    from sapmap_rfc import execute_local_command, get_sdk_path

    # Like read_table, this goes through the NW RFC SDK backend — refuse early
    # with a clear hint when the operator did not pass --sdk.
    if not get_sdk_path():
        ctx.echo("no NW RFC SDK path set — restart with '--sdk <PATH>'")
        return CommandResult(ok=False, message="no sdk path")

    command = args[0]
    # Everything after the executable is the (space-containing) params string.
    params = " ".join(args[1:]) if len(args) > 1 else ""

    # The processor edits the raw .sapmap dict; rebuild a SAPNode so
    # execute_local_command can resolve credentials, host/instance and SNC.
    node_dict = ctx.selected_node() or {}
    try:
        node = SAPNode.from_dict(node_dict)
    except Exception as exc:  # defensive: hand-edited/partial node dicts
        ctx.echo(f"cannot build node from state: {exc}")
        return CommandResult(ok=False, message="bad node")

    try:
        result = execute_local_command(node, command, params)
    except Exception as exc:  # connection setup errors (SDK missing, etc.)
        ctx.echo(f"exec failed: {exc}")
        return CommandResult(ok=False, message=f"exec failed: {exc}")

    # execute_local_command returns {success, output: [lines], error}.
    for line in result.get("output") or []:
        ctx.echo(str(line))
    if not result.get("success"):
        err = result.get("error") or "command failed"
        ctx.echo(err)
        return CommandResult(ok=False, message=err)
    return CommandResult(ok=True, message="exec ok")


# ---------------------------------------------------------------------------
# Built-in housekeeping commands
# ---------------------------------------------------------------------------

def cmd_help(ctx: CommandContext, args: List[str]) -> CommandResult:
    reg: "CommandRegistry" = ctx.state.get("__registry__")  # set by processor
    if reg is None:
        ctx.echo("no registry")
        return CommandResult(ok=False)
    ctx.echo("commands:")
    for cmd in reg.unique_commands():
        aliases = f" ({', '.join(cmd.aliases)})" if cmd.aliases else ""
        ctx.echo(f"  {cmd.usage():<28}{aliases:<14} {cmd.help}")
    return CommandResult(ok=True)


def cmd_save(ctx: CommandContext, args: List[str]) -> CommandResult:
    path = args[0] if args else ctx.path
    if not path:
        ctx.echo("no path to save to (pass one: 'save <file>')")
        return CommandResult(ok=False, message="no path to save to")
    try:
        save_state_dict(ctx.state, path)
    except OSError as exc:
        ctx.echo(f"save failed: {exc}")
        return CommandResult(ok=False, message=f"save failed: {exc}")
    ctx.path = path
    ctx.dirty = False
    ctx.echo(f"saved -> {path}")
    return CommandResult(ok=True, message="saved")


def cmd_back(ctx: CommandContext, args: List[str]) -> CommandResult:
    """Unselect the current node; the prompt drops the '/SID' segment."""
    if not ctx.selected_sid:
        ctx.echo("no node selected")
        return CommandResult(ok=False, message="nothing to unselect")
    prev = ctx.selected_sid
    ctx.selected_sid = None
    ctx.echo(f"unselected {prev}")
    return CommandResult(ok=True, message=f"unselected {prev}")


def cmd_quit(ctx: CommandContext, args: List[str]) -> CommandResult:
    ctx.running = False
    if ctx.dirty:
        ctx.echo("note: unsaved changes (use 'save' before 'quit' to persist)")
    return CommandResult(ok=True, message="bye")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class CommandRegistry:
    """Name/alias → :class:`Command` lookup table."""

    def __init__(self) -> None:
        self._by_name: Dict[str, Command] = {}

    def register(self, cmd: Command) -> None:
        for token in [cmd.name, *cmd.aliases]:
            key = token.lower()
            if key in self._by_name:
                raise ValueError(f"duplicate command token: {token}")
            self._by_name[key] = cmd

    def resolve(self, token: str) -> Optional[Command]:
        return self._by_name.get((token or "").lower())

    def unique_commands(self) -> List[Command]:
        seen: List[Command] = []
        for cmd in self._by_name.values():
            if cmd not in seen:
                seen.append(cmd)
        return seen


def default_registry() -> CommandRegistry:
    reg = CommandRegistry()
    reg.register(Command(
        name="list_nodes", aliases=["ln", "ls"], handler=cmd_list_nodes,
        args=[Arg("a", required=False, help="'a' to dump all at once (no paging)")],
        help="print node SIDs (paged; 'a' = dump all without paging)"))
    reg.register(Command(
        name="use_node_by_sid", aliases=["un", "use"], handler=cmd_use_node,
        args=[Arg("sid", required=True, help="SID to select")],
        help="select a node by SID (prompt gains '>SID')"))
    reg.register(Command(
        name="search_node", aliases=["sn"], handler=cmd_search_node,
        args=[Arg("substring", required=True, help="text to search for")],
        help="search sid/description/sapology for a substring"))
    reg.register(Command(
        name="show", aliases=["s", "cat"], handler=cmd_show,
        args=[Arg("property", required=True, help="node property to display")],
        conditions=[require_selected_node()],
        help="show a property of the selected node (paged like 'more')"))
    reg.register(Command(
        name="read_table", aliases=["rt"], handler=cmd_read_table,
        args=[Arg("table", required=True, help="table name (e.g. USR02)"),
              Arg("columns", required=True, help="comma-separated columns (e.g. BNAME,CLASS)"),
              Arg("where", required=False, help="optional WHERE clause")],
        conditions=[require_selected_node(), require_abap(), require_credentials()],
        help="RFC_READ_TABLE on the selected node"))
    reg.register(Command(
        name="exec_local", aliases=["xpg", "elc"], handler=cmd_exec_local,
        args=[Arg("cmd", required=True, help="executable (e.g. /bin/sh, cmd.exe)"),
              Arg("params", required=False, help="command parameters")],
        conditions=[require_selected_node(), require_abap(), require_credentials()],
        help="run an OS command on the selected node (SXPG_STEP_XPG_START)"))
    reg.register(Command(
        name="history", aliases=["hist"], handler=cmd_history,
        args=[Arg("a", required=False, help="'a' to dump all at once (no paging)")],
        help="print command history (paged; 'a' = dump all without paging)"))
    reg.register(Command(
        name="redo", aliases=["!", "r"], handler=cmd_redo,
        args=[Arg("n", required=True, help="history number to re-run")],
        help="re-run a command by its 'history' number"))
    reg.register(Command(
        name="help", aliases=["?", "h"], handler=cmd_help,
        help="list available commands"))
    reg.register(Command(
        name="save", aliases=["w"], handler=cmd_save,
        args=[Arg("path", required=False, help="optional target path")],
        help="write the state back to the .sapmap file"))
    reg.register(Command(
        name="back", aliases=["b"], handler=cmd_back,
        help="unselect the current node"))
    reg.register(Command(
        name="quit", aliases=["q", "exit"], handler=cmd_quit,
        help="exit the processor"))
    return reg


# ---------------------------------------------------------------------------
# Persistence (raw dict <-> .sapmap JSON)
# ---------------------------------------------------------------------------

def load_state_dict(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object at top level")
    return data


def save_state_dict(state: Dict[str, Any], path: str) -> None:
    # Never persist the transient registry handle we stash on the dict.
    payload = {k: v for k, v in state.items() if not str(k).startswith("__")}
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Processor / REPL
# ---------------------------------------------------------------------------

class CommandProcessor:
    """Drives the recurring prompt loop over a loaded ``.sapmap`` dict."""

    def __init__(self, state: Dict[str, Any], path: Optional[str] = None,
                 registry: Optional[CommandRegistry] = None,
                 out: Callable[[str], None] = print,
                 inp: Callable[[str], str] = input,
                 history_path: Optional[str] = ".cmdhistory"):
        self.ctx = CommandContext(state, path, out=out, inp=inp,
                                  history_path=history_path)
        # Let commands (e.g. 'redo') re-run a line through full parsing/gating.
        self.ctx.dispatch = self.dispatch
        self.registry = registry or default_registry()
        # Expose the registry to the ``help`` command without a global.
        self.ctx.state["__registry__"] = self.registry
        self.inp = inp

    # -- prompt --------------------------------------------------------------
    def _base_label(self) -> str:
        """The leading prompt segment: the .sapmap file's name without its
        directory or extension (``states/foo.sapmap`` -> ``foo``)."""
        if self.ctx.path:
            stem = os.path.splitext(os.path.basename(self.ctx.path))[0]
            if stem:
                return stem
        return "sapmap"

    def prompt(self) -> str:
        """Build the varying prompt string.

        Base = part of the file name; ``/SID`` appended when a node is selected;
        a ``(!)`` marker after a failed command — so the prompt reflects both the
        current selection and the last outcome.  E.g. with file ``landscape.sapmap``
        and node ``CET`` selected: ``landscape/CET>``.
        """
        text = self._base_label()
        if self.ctx.selected_sid:
            text += f"/{self.ctx.selected_sid}"
        marker = " (!)" if self.ctx.last_ok is False else ""
        return f"{text}{marker}> "

    # -- dispatch ------------------------------------------------------------
    def dispatch(self, line: str) -> Optional[CommandResult]:
        """Parse and execute a single input line.  ``None`` = empty/comment."""
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        line = _normalize_bang(line)

        tokens = line.split()
        name, args = tokens[0], tokens[1:]
        cmd = self.registry.resolve(name)
        if cmd is None:
            self.ctx.echo(f"unknown command: {name} (try 'help')")
            return CommandResult(ok=False, message="unknown command")

        # Arg-count validation against the declared required args.
        required = sum(1 for a in cmd.args if a.required)
        if len(args) < required:
            self.ctx.echo(f"usage: {cmd.usage()}")
            return CommandResult(ok=False, message="bad usage")

        # Condition gating — every condition must hold or the command is refused.
        for predicate, message in cmd.conditions:
            if not predicate(self.ctx):
                self.ctx.echo(f"cannot run '{cmd.name}': {message}")
                return CommandResult(ok=False, message=message)

        result = cmd.handler(self.ctx, args)
        if result is None:
            result = CommandResult(ok=True)
        return result

    # -- loop ----------------------------------------------------------------
    def run(self) -> None:
        """Recurring-prompt loop until quit or EOF."""
        while self.ctx.running:
            try:
                line = self.inp(self.prompt())
            except EOFError:
                self.ctx.echo("")
                break
            except KeyboardInterrupt:
                self.ctx.echo("^C (use 'quit' to exit)")
                continue

            # Persist every non-empty, non-comment line before dispatching so the
            # history survives even a command that crashes the loop.
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                append_history(self.ctx.history_path, stripped)

            result = self.dispatch(line)
            if result is not None:
                self.ctx.last_ok = result.ok


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(
        prog="sapmap_cmdproc.py",
        description=__doc__.strip().splitlines()[0])
    parser.add_argument("file", help="the .sapmap session file to open")
    parser.add_argument("--sdk", metavar="PATH", default=None,
                        help="NW RFC SDK library path (required for RFC "
                             "commands such as 'read_table')")
    args = parser.parse_args(argv)

    path = args.file
    try:
        state = load_state_dict(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    # RFC commands require the NW RFC SDK — register the path up front so
    # _get_connection() picks the SDK (ctypes) backend.  Without --sdk the
    # RFC commands still refuse cleanly at run time (see cmd_read_table).
    if args.sdk:
        from sapmap_rfc import set_sdk_path
        set_sdk_path(args.sdk)
        print(f"[*] NW RFC SDK path: {args.sdk}")

    proc = CommandProcessor(state, path=path)
    proc.ctx.echo(f"loaded {path} — {len(iter_nodes(state))} node(s). Type 'help'.")
    proc.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
