#!/usr/bin/env python3
"""
SAP Credential Check driven by a SAPMAP scan file.

Reads a SAPMAP ``.sapmap`` / scan JSON file, extracts one ABAP dispatcher
target per node (via ``dispatcher_tuples``), and tries a user-supplied list
of ``user:password`` credentials against every enumerated client of each
system using the DIAG ``try_login`` from ``sap_default_creds``.

Because failed DIAG logins can lock SAP accounts, every executed attempt
is written to a JSON test-protocol log (system / user:pwd / client /
timestamp).  On the next run that log is read back and any attempt that
would re-test the same user on the same system+client is flagged as a
COLLISION — the effective run then REFUSES to start until the collisions
are resolved.  ``--simulate`` performs this collision check as a dry-run.

The per-attempt confirmation prompt is OFF by default; enable it with
``--confirm``.  ``-y/--yes`` runs unattended (overrides the prompt).

WARNING: Failed login attempts can lock SAP accounts. Use only with
explicit written authorization — see DISCLAIMER.md.

Usage:
    # one-time: seed the protocol file with the in-scope systems/clients
    python3 sap_easy_pwspray.py --init-protocol

    # dry-run collision check (short summary or long per-combo listing)
    python3 sap_easy_pwspray.py -i scan.sapmap -c creds.txt --simulate
    python3 sap_easy_pwspray.py -i scan.sapmap -c creds.txt --simulate long

    # effective run (refuses if collisions exist)
    python3 sap_easy_pwspray.py -i scan.sapmap -c creds.txt
    python3 sap_easy_pwspray.py -i scan.sapmap -c creds.txt --include ACX,TPE:010
    python3 sap_easy_pwspray.py -i scan.sapmap -c creds.txt --exclude BRP --confirm

Author: Kai Ullrich & Claude
"""

import sys
import json
import time
import fnmatch
import argparse

try:
    from sap_default_creds import (try_login, FINDING_RESULTS,
                                    RESULT_DESCRIPTIONS)
except ImportError:
    from files.sap_default_creds import (try_login, FINDING_RESULTS,
                                         RESULT_DESCRIPTIONS)


# ============================================================================
# Scan-file parsing
# ============================================================================

def dispatcher_tuples(data):
    """Yield (sid, "host:port", [clients]) for every ABAP node with a dispatcher.

    For each node under ``data["nodes"]`` whose ``system_type == "ABAP"``,
    pick the FIRST instance whose ``ports`` map contains a value of
    ``"dispatcher"``.  The host is taken from the instance's
    ``info.host`` (the resolvable FQDN the dispatcher reports) and falls
    back to the instance ``ip``.  ``clients`` is the list of every ``nr``
    under the node's ``clients`` array.

    Nodes without an ABAP type, without a dispatcher instance, or without
    enumerated clients are skipped.
    """
    for node in data.get("nodes", {}).values():
        if node.get("system_type") != "ABAP":
            continue

        inst = next(
            (i for i in node.get("instances", [])
             if "dispatcher" in (i.get("ports") or {}).values()),
            None,
        )
        if inst is None:
            continue

        port = next(p for p, svc in inst["ports"].items()
                    if svc == "dispatcher")
        host = (inst.get("info") or {}).get("host") or inst.get("ip")
        clients = [c["nr"] for c in node.get("clients", []) if c.get("nr")]

        if not host or not clients:
            continue

        yield (node.get("sid"), "%s:%s" % (host, port), clients)


def load_systems(path):
    """Load a scan file and return the list of dispatcher tuples."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return list(dispatcher_tuples(data))


# ============================================================================
# Credential-list parsing
# ============================================================================

def parse_creds(text):
    """Parse a multi-line ``user:password`` string into (user, password) pairs.

    Blank lines and lines starting with ``#`` are ignored.  Only the first
    ``:`` splits user from password, so passwords may contain colons.
    """
    creds = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            print("  [!] Ignoring malformed cred line (no ':'): %r" % line,
                  file=sys.stderr)
            continue
        user, password = line.split(":", 1)
        creds.append((user, password))
    return creds


def read_creds_arg(value):
    """Resolve the --creds argument to raw text.

    ``-`` reads from stdin; an existing file path is read; otherwise the
    value itself is treated as inline (possibly multi-line) credential text.
    """
    if value == "-":
        return sys.stdin.read()
    import os
    if os.path.isfile(value):
        with open(value, "r", encoding="utf-8") as f:
            return f.read()
    return value


# ============================================================================
# System scope (--include / --exclude)
# ============================================================================

def parse_scope(spec):
    """Parse an include/exclude spec into {SID_pattern: set(clients) | None}.

    Syntax: comma-separated tokens, each ``SID`` (all clients) or
    ``SID:client`` (one client).  Repeated SID tokens merge their
    clients; a bare ``SID`` token (all clients) wins over any
    ``SID:client`` for the same SID (value becomes ``None`` = all).

    The SID part may use shell-style wildcards (``*``, ``?``, ``[...]``)
    which are matched case-insensitively against each system's SID in
    :func:`apply_scope`.  So ``*:000`` targets client 000 on every
    system, and ``P*`` targets every SID starting with ``P``.

    Example: ``ABC,XYZ:010`` -> ``{"ABC": None, "XYZ": {"010"}}``
    Example: ``*:000``        -> ``{"*": {"000"}}``
    """
    scope = {}
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if ":" in token:
            sid, client = token.split(":", 1)
            sid = sid.strip().upper()
            client = client.strip().zfill(3)
            if sid in scope and scope[sid] is None:
                continue  # already "all clients"
            scope.setdefault(sid, set())
            if scope[sid] is not None:
                scope[sid].add(client)
        else:
            scope[token.strip().upper()] = None  # all clients
    return scope


def _scope_match(key, scope):
    """Return (matched, clients) for a SID against a parsed scope.

    ``scope`` maps SID patterns to ``None`` (all clients) or a set of
    clients.  Patterns are matched case-insensitively with shell-style
    wildcards.  ``matched`` is True if any pattern matched ``key``;
    ``clients`` is ``None`` when any matching pattern selects all
    clients, otherwise the union of the matching patterns' client sets.
    """
    matched = False
    selected = set()
    for pattern, clients in scope.items():
        if fnmatch.fnmatchcase(key, pattern):
            matched = True
            if clients is None:
                return True, None  # a pattern selecting all clients wins
            selected |= clients
    return matched, (selected if matched else None)


def apply_scope(systems, include=None, exclude=None):
    """Filter the systems list by an include and/or exclude scope.

    ``systems`` is a list of ``(sid, "host:port", [clients])``.  Both
    ``include`` and ``exclude`` may be given (either or both ``None`` =
    no filtering for that side).  SID patterns may contain wildcards (see
    :func:`parse_scope`).

    Order of evaluation: ``include`` is applied first to pick the
    candidate set, then ``exclude`` is subtracted from it — ``exclude``
    always wins, so a client matched by both is dropped.  Systems whose
    client list becomes empty are dropped.
    """
    filtered = []
    for sid, hostport, clients in systems:
        key = (sid or "").upper()

        # 1. include — narrow to the candidate clients (no include = all).
        if include is not None:
            matched, want = _scope_match(key, include)
            if not matched:
                continue
            kept = clients if want is None else [c for c in clients if c in want]
        else:
            kept = list(clients)

        # 2. exclude — always wins; subtract from whatever include kept.
        if exclude is not None:
            matched, drop = _scope_match(key, exclude)
            if matched:
                if drop is None:
                    continue  # whole system excluded
                kept = [c for c in kept if c not in drop]

        if kept:
            filtered.append((sid, hostport, kept))
    return filtered


# ============================================================================
# Test protocol / audit log (collision detection to avoid lockouts)
# ============================================================================

PROTOCOL_VERSION = "1.0"


def new_protocol(systems=None):
    """Return a fresh protocol dict, optionally seeded with a systems map."""
    from datetime import datetime, timezone
    return {
        "version": PROTOCOL_VERSION,
        "created": datetime.now(timezone.utc).isoformat(),
        "systems": {k: list(v) for k, v in (systems or {}).items()},
        "attempts": [],
    }


def load_protocol(path):
    """Load the protocol file, or return a fresh skeleton if it is absent."""
    import os
    if not os.path.isfile(path):
        return new_protocol()
    with open(path, "r", encoding="utf-8") as f:
        proto = json.load(f)
    proto.setdefault("attempts", [])
    proto.setdefault("systems", {})
    return proto


def save_protocol(path, proto):
    """Persist the protocol file (pretty-printed JSON)."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(proto, f, indent=2, ensure_ascii=False)
        f.write("\n")


def collision_keys(proto):
    """Set of (sid, client, user) already recorded — the lockout-risk key.

    A repeat test of the SAME user on the SAME system+client is what risks
    a lockout, regardless of which password was tried, so the password is
    deliberately not part of the key.
    """
    keys = set()
    for a in proto.get("attempts", []):
        keys.add(((a.get("sysid") or "").upper(),
                  a.get("client"), (a.get("user") or "").upper()))
    return keys


def record_attempt(proto, sysid, client, user, password, result):
    """Append one attempt record (sysid, user:pwd, client, timestamp)."""
    from datetime import datetime, timezone
    proto.setdefault("attempts", []).append({
        "sysid": sysid,
        "user": user,
        "password": password,
        "client": client,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "result": result,
    })


# ============================================================================
# Attempt planning & collision check
# ============================================================================

def plan_attempts(systems, creds):
    """Expand (systems x creds x clients) into a flat list of attempt dicts."""
    plan = []
    for sid, hostport, clients in systems:
        host, port_str = hostport.rsplit(":", 1)
        for user, password in creds:
            for client in clients:
                plan.append({
                    "sid": sid, "hostport": hostport,
                    "host": host, "port": int(port_str),
                    "client": client, "user": user, "password": password,
                })
    return plan


def split_collisions(plan, proto):
    """Partition a plan into (collisions, clean) against the protocol log."""
    keys = collision_keys(proto)
    collisions, clean = [], []
    for p in plan:
        key = ((p["sid"] or "").upper(), p["client"], (p["user"] or "").upper())
        (collisions if key in keys else clean).append(p)
    return collisions, clean


def simulate(plan, proto, long=False):
    """Dry-run: report which planned attempts collide with prior tests.

    Returns the number of colliding attempts.
    """
    collisions, clean = split_collisions(plan, proto)

    print("=" * 60)
    print("SIMULATION — no login is performed")
    print("=" * 60)

    if long:
        for p in plan:
            key = ((p["sid"] or "").upper(), p["client"],
                   (p["user"] or "").upper())
            hit = key in collision_keys(proto)
            tag = "COLLISION" if hit else "OK"
            print("  [%-9s] %s client %s  %s" %
                  (tag, p["sid"] or p["host"], p["client"], p["user"]))
        print("-" * 60)

    print("Planned attempts : %d" % len(plan))
    print("Collisions       : %d (already tested — would risk lockout)" %
          len(collisions))
    print("Clean            : %d (not yet tested)" % len(clean))

    if collisions and not long:
        print()
        print("Re-run with '--simulate long' to see each combination.")
    return len(collisions)


# ============================================================================
# Interactive confirmation
# ============================================================================

def confirm(prompt):
    """Ask the user to confirm on the CLI.

    Returns one of:
      "yes"   -- proceed with this attempt
      "skip"  -- skip this attempt, continue the loop
      "abort" -- abort the whole loop and quit

    A non-interactive stdin (EOF) is treated as "abort" so unattended
    runs without ``-y`` stop cleanly instead of silently skipping forever.
    """
    try:
        answer = input("%s [y]es / [n]o / [a]bort " % prompt).strip().lower()
    except EOFError:
        return "abort"
    if answer in ("y", "yes", "j", "ja"):
        return "yes"
    if answer in ("a", "abort", "q", "quit"):
        return "abort"
    return "skip"


# ============================================================================
# Main loop
# ============================================================================

def run(plan, proto, protocol_path, timeout=5, saprouter="",
        confirm_prompt=False, assume_yes=False, verbose=False, force=False):
    """Execute an attempt plan, logging each test.

    By default REFUSES to run if any planned attempt collides with a
    prior test (``split_collisions``): the user must resolve the
    collisions first (prune the protocol log, or narrow the scope /
    creds).  Pass ``force=True`` to run anyway despite collisions — the
    colliding attempts are flagged but still executed (accepts the
    lockout risk).

    The confirmation prompt is OFF by default; enable it with
    ``confirm_prompt=True``.  ``assume_yes=True`` overrides the prompt and
    runs unattended even when it is enabled.

    Each executed ``try_login`` is appended to ``proto`` and the protocol
    file is saved immediately so a crash mid-run never loses the audit
    trail (and never replays a test).

    Returns the list of finding dicts, or ``None`` if the run was refused.
    """
    collisions, _ = split_collisions(plan, proto)
    if collisions and not force:
        print("=" * 60)
        print("REFUSING TO RUN — %d collision(s) with prior tests" %
              len(collisions))
        print("=" * 60)
        for p in collisions:
            print("  [COLLISION] %s client %s  %s" %
                  (p["sid"] or p["host"], p["client"], p["user"]))
        print("-" * 60)
        print("These user/system/client combinations were already tested")
        print("(see %s). Re-testing risks account lockout." % protocol_path)
        print("Resolve the collisions first: prune the protocol log, or")
        print("narrow the run with --include/--exclude or a smaller cred list,")
        print("or override with --force (accepts the lockout risk).")
        return None

    if collisions and force:
        print("=" * 60)
        print("WARNING: --force set — running despite %d collision(s)." %
              len(collisions))
        print("Re-testing already-tried users risks account LOCKOUT.")
        print("=" * 60)

    # Keys that collide, so each attempt can be flagged in the loop.
    collision_set = collision_keys(proto)

    findings = []
    total = len(plan)
    ask = confirm_prompt and not assume_yes

    for index, p in enumerate(plan, start=1):
        sid, host, port = p["sid"], p["host"], p["port"]
        client, user, password = p["client"], p["user"], p["password"]
        is_collision = ((sid or "").upper(), client,
                        (user or "").upper()) in collision_set

        print()
        print("-" * 60)
        print("  [%d/%d]%s" % (index, total,
                               "  [COLLISION — forced]" if is_collision else ""))
        print("  System : %s (%s)" % (sid or "?", p["hostport"]))
        print("  Client : %s" % client)
        print("  User   : %s" % user)
        print("  Pass   : %s" % password)
        if saprouter:
            print("  Route  : %s" % saprouter)
        print("-" * 60)

        if ask:
            choice = confirm("  Attempt this login?")
            if choice == "abort":
                print("  [!] Aborted by user — stopping.")
                break
            if choice == "skip":
                print("  [-] Skipped.")
                continue

        result, detail = try_login(
            host, port, client, user, password,
            timeout=timeout, saprouter=saprouter)

        # Record every executed attempt immediately (audit + lockout guard).
        record_attempt(proto, sid, client, user, password, result)
        save_protocol(protocol_path, proto)

        if result in FINDING_RESULTS:
            print("  [+] VALID: %s / %s on %s client %s (%s)" %
                  (user, password, sid or p["hostport"], client, detail))
            findings.append({
                "sid": sid, "host": host, "port": port, "client": client,
                "username": user, "password": password,
                "result": result, "detail": detail,
            })
        elif verbose:
            print("  [-] %s / %s on client %s: %s" %
                  (user, password, client, detail))
        else:
            print("  [-] %s" % detail)

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="SAP credential check driven by a SAPMAP scan file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
WARNING: Failed login attempts can lock SAP accounts!
         Only use this tool with explicit authorization.

Examples:
  %(prog)s -i scan.sapmap -c creds.txt
  %(prog)s -i scan.sapmap -c creds.txt --saprouter /H/10.0.0.1/S/3299
  printf 'SAP*:06071992\\nDDIC:19920706\\n' | %(prog)s -i scan.sapmap -c - -y
        """)
    parser.add_argument("-i", "--input",
                        help="SAPMAP scan / .sapmap JSON file")
    parser.add_argument("-c", "--creds",
                        help="Credentials as 'user:password' per line — a file "
                             "path, inline text, or '-' for stdin")
    parser.add_argument("--protocol", default="pwspray_protocol.json",
                        help="Test-protocol JSON log (default: pwspray_protocol.json)")
    parser.add_argument("--init-protocol", action="store_true",
                        help="Create a fresh protocol file seeded with the "
                             "in-scope systems/clients, then exit")
    parser.add_argument("--saprouter", default="",
                        help="SAProuter route string prefix (e.g. /H/host/S/3299)")
    parser.add_argument("--timeout", type=int, default=5,
                        help="Per-connection timeout in seconds (default: 5)")
    parser.add_argument("--simulate", nargs="?", choices=["short", "long"],
                        const="short", default=None,
                        help="Dry-run collision check (no login). "
                             "'short' (default) = summary, 'long' = per-combo")
    parser.add_argument("--confirm", action="store_true",
                        help="Enable the per-attempt confirmation prompt "
                             "(off by default; overridden by -y)")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Run unattended — suppress the confirmation prompt")
    parser.add_argument("--force", action="store_true",
                        help="Run even if attempts collide with prior tests "
                             "(accepts the account-lockout risk)")
    parser.add_argument("--include",
                        help="Only these systems, e.g. ABC,XYZ:010 "
                             "(ABC all clients, XYZ client 010). The SID may "
                             "use wildcards, e.g. 'P*' or '*:000'")
    parser.add_argument("--exclude",
                        help="Drop these systems, same syntax as --include "
                             "(e.g. '*:000' excludes client 000 everywhere). "
                             "May be combined with --include; --exclude wins")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output (show misses with detail)")

    args = parser.parse_args()

    # --init-protocol: seed and exit.
    if args.init_protocol:
        import os
        if os.path.exists(args.protocol):
            print("Refusing to overwrite existing %s" % args.protocol,
                  file=sys.stderr)
            return 1
        save_protocol(args.protocol, new_protocol ())
        print("Created protocol %s." % (args.protocol))
        return 0

    if not args.input or not args.creds or not args.protocol:
        parser.error("-i/--input and -c/--creds and --protocol are required")

    systems = load_systems(args.input)
    creds = parse_creds(read_creds_arg(args.creds))

    if not systems:
        print("No ABAP dispatcher systems found in scan file.", file=sys.stderr)
        return 1
    if not creds:
        print("No valid credentials parsed.", file=sys.stderr)
        return 1

    # Apply include/exclude scope.
    include = parse_scope(args.include) if args.include else None
    exclude = parse_scope(args.exclude) if args.exclude else None
    systems = apply_scope(systems, include=include, exclude=exclude)
    if not systems:
        print("No systems left after include/exclude filtering.",
              file=sys.stderr)
        return 1

    proto = load_protocol(args.protocol)
    plan = plan_attempts(systems, creds)

    print("=" * 60)
    print("SAP Credential Check (scan-driven)")
    print("=" * 60)
    print("Systems     : %d" % len(systems))
    print("Credentials : %d" % len(creds))
    print("Attempts    : %d (max)" % len(plan))
    print("Protocol    : %s" % args.protocol)
    print()

    # Simulation mode: dry-run collision check, never logs in.
    if args.simulate:
        n = simulate(plan, proto, long=(args.simulate == "long"))
        return 2 if n else 0

    print("WARNING: Failed login attempts can lock SAP accounts!")

    t0 = time.time()
    findings = run(plan, proto, args.protocol,
                   timeout=args.timeout,
                   saprouter=args.saprouter,
                   confirm_prompt=args.confirm,
                   assume_yes=args.yes,
                   verbose=args.verbose,
                   force=args.force)
    elapsed = time.time() - t0

    if findings is None:
        return 1  # run refused due to collisions

    print()
    print("-" * 60)
    if findings:
        print("Found %d valid credential(s):" % len(findings))
        for f in findings:
            print("  %s / %s on %s client %s (%s)" %
                  (f["username"], f["password"], f["sid"] or f["host"],
                   f["client"], f["detail"]))
    else:
        print("No valid credentials found.")
    print("Time: %.1fs" % elapsed)
    print("-" * 60)

    return 0 if not findings else 2


if __name__ == "__main__":
    sys.exit(main())
