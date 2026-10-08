#!/usr/bin/env python3
"""
SAP Credential Check driven by a SAPMAP scan file.

Reads a SAPMAP ``.sapmap`` / scan JSON file, extracts one ABAP dispatcher
target per node (via ``dispatcher_tuples``), and tries a user-supplied list
of ``user:password`` credentials against every enumerated client of each
system using the DIAG ``try_login`` from ``sap_default_creds``.

Because failed DIAG logins can lock SAP accounts, each individual
``try_login`` is preceded by a summary and an interactive confirmation
prompt.  Decline and the attempt is skipped.  ``-y/--yes`` suppresses the
prompt and runs every attempt unattended.

WARNING: Failed login attempts can lock SAP accounts. Use only with
explicit written authorization — see DISCLAIMER.md.

Usage:
    python3 sap_creds_from_scan.py -i scan.sapmap -c creds.txt
    python3 sap_creds_from_scan.py -i scan.sapmap -c creds.txt --saprouter /H/1.2.3.4/S/3299
    printf 'SAP*:06071992\nDDIC:19920706\n' | \
        python3 sap_creds_from_scan.py -i scan.sapmap -c - -y

Author: Kai Ullrich & Claude
"""

import sys
import json
import time
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

def run(systems, creds, timeout=5, saprouter="", assume_yes=False,
        verbose=False):
    """Try every (cred x system x client) combination.

    Before each ``try_login`` a summary is printed; unless ``assume_yes``
    the user must confirm the attempt, otherwise it is skipped.

    Returns a list of finding dicts.
    """
    findings = []

    total = sum(len(clients) for _, _, clients in systems) * len(creds)
    index = 0

    for sid, hostport, clients in systems:
        host, port_str = hostport.rsplit(":", 1)
        port = int(port_str)

        for user, password in creds:
            for client in clients:
                index += 1
                print()
                print("-" * 60)
                print("  [%d/%d]" % (index, total))
                print("  System : %s (%s)" % (sid or "?", hostport))
                print("  Client : %s" % client)
                print("  User   : %s" % user)
                print("  Pass   : %s" % password)
                if saprouter:
                    print("  Route  : %s" % saprouter)
                print("-" * 60)

                if not assume_yes:
                    choice = confirm("  Attempt this login?")
                    if choice == "abort":
                        print("  [!] Aborted by user — stopping.")
                        return findings
                    if choice == "skip":
                        print("  [-] Skipped.")
                        continue

                result, detail = try_login(
                    host, port, client, user, password,
                    timeout=timeout, saprouter=saprouter)

                if result in FINDING_RESULTS:
                    print("  [+] VALID: %s / %s on %s client %s (%s)" %
                          (user, password, sid or hostport, client, detail))
                    findings.append({
                        "sid": sid,
                        "host": host,
                        "port": port,
                        "client": client,
                        "username": user,
                        "password": password,
                        "result": result,
                        "detail": detail,
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
    parser.add_argument("-i", "--input", required=True,
                        help="SAPMAP scan / .sapmap JSON file")
    parser.add_argument("-c", "--creds", required=True,
                        help="Credentials as 'user:password' per line — a file "
                             "path, inline text, or '-' for stdin")
    parser.add_argument("--saprouter", default="",
                        help="SAProuter route string prefix (e.g. /H/host/S/3299)")
    parser.add_argument("--timeout", type=int, default=5,
                        help="Per-connection timeout in seconds (default: 5)")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Suppress the per-attempt confirmation prompt")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output (show misses with detail)")

    args = parser.parse_args()

    systems = load_systems(args.input)
    creds = parse_creds(read_creds_arg(args.creds))

    if not systems:
        print("No ABAP dispatcher systems found in scan file.", file=sys.stderr)
        return 1
    if not creds:
        print("No valid credentials parsed.", file=sys.stderr)
        return 1

    total = sum(len(clients) for _, _, clients in systems) * len(creds)

    print("=" * 60)
    print("SAP Credential Check (scan-driven)")
    print("=" * 60)
    print("Systems     : %d" % len(systems))
    print("Credentials : %d" % len(creds))
    print("Attempts    : %d (max)" % total)
    if args.yes:
        print("Mode        : unattended (-y, confirmation suppressed)")
    print()
    print("WARNING: Failed login attempts can lock SAP accounts!")

    t0 = time.time()
    findings = run(systems, creds,
                   timeout=args.timeout,
                   saprouter=args.saprouter,
                   assume_yes=args.yes,
                   verbose=args.verbose)
    elapsed = time.time() - t0

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
