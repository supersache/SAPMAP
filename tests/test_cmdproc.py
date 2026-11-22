#!/usr/bin/env python3
"""Tests for sapmap_cmdproc.py — the plugin-style .sapmap command REPL."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sapmap_cmdproc import (
    Command,
    CommandContext,
    CommandProcessor,
    CommandResult,
    _page_lines,
    _value_to_lines,
    find_node_by_sid,
    iter_nodes,
    load_state_dict,
    node_has_verified_cred,
    require_abap,
    require_credentials,
    require_selected_node,
    save_state_dict,
)


def _state():
    return {
        "nodes": {
            "GFE": {
                "sid": "GFE",
                "system_type": "ABAP",
                "credentials": [{"username": "TECH", "password": "x", "verified": True}],
                "sapology_data": {"description": "Finance backbone"},
                "clients": [{"nr": str(n)} for n in range(10)],
            },
            "JV1": {
                "sid": "JV1",
                "system_type": "JAVA",
                "credentials": [],
                "description": "Portal node",
            },
        }
    }


def _proc(path=None):
    out = []
    proc = CommandProcessor(_state(), path=path, out=out.append)
    return proc, out


# -- helpers ----------------------------------------------------------------

def test_iter_nodes_handles_dict_and_list():
    assert len(iter_nodes(_state())) == 2
    listish = {"nodes": [{"sid": "AAA"}, {"sid": "BBB"}]}
    assert {sid for _, n in iter_nodes(listish) for sid in [n["sid"]]} == {"AAA", "BBB"}
    assert iter_nodes({}) == []


def test_find_node_by_sid_case_insensitive():
    st = _state()
    assert find_node_by_sid(st, "gfe")["sid"] == "GFE"
    assert find_node_by_sid(st, "nope") is None


# -- list_nodes -------------------------------------------------------------

def test_list_nodes_prints_sids():
    proc, out = _proc()
    r = proc.dispatch("ln a")
    assert r.ok
    assert any(l.startswith("GFE") for l in out)
    assert any(l.startswith("JV1") for l in out)


# -- use_node ---------------------------------------------------------------

def test_use_node_selects_and_changes_prompt():
    proc, out = _proc(path="states/landscape.sapmap")
    # Base label is the file name without directory/extension.
    assert proc.prompt() == "landscape> "
    r = proc.dispatch("un GFE")
    assert r.ok and proc.ctx.selected_sid == "GFE"
    assert proc.prompt() == "landscape/GFE> "


def test_prompt_falls_back_to_sapmap_without_path():
    proc, _ = _proc()
    assert proc.prompt() == "sapmap> "


def test_back_unselects_node():
    proc, out = _proc(path="states/landscape.sapmap")
    proc.dispatch("un GFE")
    assert proc.ctx.selected_sid == "GFE"
    out.clear()
    r = proc.dispatch("back")
    assert r.ok and proc.ctx.selected_sid is None
    assert proc.prompt() == "landscape> "
    assert any("unselected GFE" in l for l in out)


def test_back_without_selection_fails():
    proc, out = _proc()
    r = proc.dispatch("back")
    assert not r.ok
    assert any("no node selected" in l for l in out)


def test_use_node_unknown_sid_fails_and_marks_prompt():
    proc, out = _proc()
    r = proc.dispatch("un ZZZ")
    assert not r.ok
    assert any("no such SID" in line for line in out)
    proc.ctx.last_ok = r.ok
    assert "(!)" in proc.prompt()


def test_use_node_missing_arg_shows_usage():
    proc, out = _proc()
    r = proc.dispatch("un")
    assert not r.ok
    assert any("usage:" in line for line in out)


# -- search_node ------------------------------------------------------------

def test_search_node_matches_sid_and_description():
    proc, out = _proc()
    assert proc.dispatch("sn finance").ok        # sapology description
    assert any("GFE" in line for line in out)
    out.clear()
    assert proc.dispatch("sn portal").ok         # plain description
    assert any("JV1" in line for line in out)
    out.clear()
    assert not proc.dispatch("sn nomatch").ok


# -- conditions -------------------------------------------------------------

def test_conditions_gate_command():
    proc, out = _proc()
    proc.registry.register(Command(
        "rfc-connect", handler=lambda c, a: CommandResult(True, "ok"),
        conditions=[require_selected_node(), require_abap(), require_credentials()]))

    # No node selected -> refused.
    assert not proc.dispatch("rfc-connect").ok
    assert any("no node selected" in l for l in out)

    # Select the JAVA node (no creds, not ABAP) -> still refused.
    out.clear(); proc.dispatch("un JV1")
    out.clear()
    assert not proc.dispatch("rfc-connect").ok

    # Select the ABAP node with creds -> allowed.
    out.clear(); proc.dispatch("un GFE")
    out.clear()
    assert proc.dispatch("rfc-connect").ok


# -- unknown command --------------------------------------------------------

def test_unknown_command():
    proc, out = _proc()
    r = proc.dispatch("bogus")
    assert not r.ok
    assert any("unknown command" in l for l in out)


# -- persistence ------------------------------------------------------------

def test_save_roundtrip_drops_transient_keys(tmp_path):
    st = _state()
    st["__registry__"] = object()  # the kind of transient handle the REPL stashes
    path = tmp_path / "s.sapmap"
    save_state_dict(st, str(path))
    reloaded = load_state_dict(str(path))
    assert "__registry__" not in reloaded
    assert reloaded["nodes"]["GFE"]["sid"] == "GFE"


def test_empty_input_is_noop():
    proc, out = _proc()
    assert proc.dispatch("") is None
    assert proc.dispatch("   ") is None
    assert proc.dispatch("# comment") is None


# -- verified-credential marker ---------------------------------------------

def test_node_has_verified_cred_helper():
    assert node_has_verified_cred({"credentials": [{"verified": True}]})
    assert not node_has_verified_cred({"credentials": [{"verified": False}]})
    assert not node_has_verified_cred({"credentials": [{"username": "x"}]})
    assert not node_has_verified_cred({})


def test_list_nodes_marks_verified_with_star():
    proc, out = _proc()
    assert proc.dispatch("ln a").ok
    assert "GFE*" in out       # has a verified credential
    assert "JV1" in out and "JV1*" not in out


def test_list_nodes_pages_and_quits_on_q():
    # Many nodes + a small screen -> 'ln' pages; 'q' stops early.
    state = {"nodes": {f"S{n:02d}": {"sid": f"S{n:02d}"} for n in range(10)}}
    answers = iter(["q"])
    out = []
    proc = CommandProcessor(state, path=None, out=out.append,
                            inp=lambda prompt: next(answers))

    import sapmap_cmdproc as mod
    orig = mod._terminal_rows
    mod._terminal_rows = lambda: 4          # page size becomes 3
    try:
        r = proc.dispatch("ln")
    finally:
        mod._terminal_rows = orig
    assert not r.ok                          # quit early -> not fully shown
    assert out[:3] == ["S00", "S01", "S02"]
    assert any("not shown" in l for l in out)


def test_list_nodes_dump_all_does_not_page():
    # 'ln a' must never prompt, even with many nodes.
    state = {"nodes": {f"S{n:02d}": {"sid": f"S{n:02d}"} for n in range(50)}}

    def _boom(prompt):
        raise AssertionError("ln a must not page")
    out = []
    proc = CommandProcessor(state, path=None, out=out.append, inp=_boom)
    assert proc.dispatch("ln a").ok
    assert len([l for l in out if l.startswith("S")]) == 50


# -- show -------------------------------------------------------------------

def test_show_requires_selected_node():
    proc, out = _proc()
    r = proc.dispatch("show sid")
    assert not r.ok
    assert any("no node selected" in l for l in out)


def test_show_scalar_property():
    proc, out = _proc()
    proc.dispatch("un GFE")
    out.clear()
    r = proc.dispatch("show system_type")
    assert r.ok
    assert out == ["ABAP"]


def test_show_unknown_property_lists_available():
    proc, out = _proc()
    proc.dispatch("un GFE")
    out.clear()
    r = proc.dispatch("show nope")
    assert not r.ok
    assert any("no such property" in l for l in out)
    assert any("available:" in l for l in out)


def test_show_pages_long_array_and_quits_on_q():
    # Feed 'q' at the first --More-- prompt; only the first page should show.
    answers = iter(["q"])
    out = []
    ctx = CommandContext(
        {"nodes": {"GFE": {"sid": "GFE", "clients": [{"nr": str(n)} for n in range(10)]}}},
        out=out.append, inp=lambda prompt: next(answers))
    ctx.selected_sid = "GFE"
    lines = _value_to_lines(ctx.selected_node()["clients"])
    assert len(lines) == 10
    fully = _page_lines(ctx, lines, page_size=3)
    assert fully is False
    assert out[:3] == ['[0] {"nr": "0"}', '[1] {"nr": "1"}', '[2] {"nr": "2"}']
    assert any("not shown" in l for l in out)


def test_show_short_array_no_paging():
    # Fits in one page -> inp must never be called.
    def _boom(prompt):
        raise AssertionError("should not page")
    out = []
    ctx = CommandContext({}, out=out.append, inp=_boom)
    fully = _page_lines(ctx, ["a", "b"], page_size=5)
    assert fully is True
    assert out == ["a", "b"]


def test_value_to_lines_shapes():
    assert _value_to_lines("x") == ["x"]
    assert _value_to_lines([]) == ["(empty list)"]
    assert _value_to_lines([1, 2]) == ["[0] 1", "[1] 2"]
    assert _value_to_lines({"a": 1})[0].startswith("{")


# -- command history --------------------------------------------------------

def test_history_records_typed_commands(tmp_path):
    # run() appends every non-empty, non-comment line to the history file.
    hp = tmp_path / ".cmdhistory"
    state = {"nodes": {"GFE": {"sid": "GFE", "system_type": "ABAP"}}}
    feed = iter(["ln a", "# comment", "   ", "un GFE", "quit"])
    out = []
    proc = CommandProcessor(state, out=out.append,
                            inp=lambda prompt: next(feed),
                            history_path=str(hp))
    proc.run()
    assert hp.read_text(encoding="utf-8").splitlines() == ["ln a", "un GFE", "quit"]


def test_history_command_lists_entries(tmp_path):
    hp = tmp_path / ".cmdhistory"
    hp.write_text("ln a\nun GFE\n", encoding="utf-8")
    out = []
    proc = CommandProcessor({}, out=out.append, history_path=str(hp))
    r = proc.dispatch("history a")       # dump-all, never pages
    assert r.ok
    assert out == ["1  ln a", "2  un GFE"]


def test_history_command_empty(tmp_path):
    hp = tmp_path / ".cmdhistory"      # never created
    out = []
    proc = CommandProcessor({}, out=out.append, history_path=str(hp))
    r = proc.dispatch("history")
    assert not r.ok
    assert out == ["(no history)"]


# -- redo -------------------------------------------------------------------

def test_redo_reruns_history_entry(tmp_path):
    hp = tmp_path / ".cmdhistory"
    hp.write_text("un GFE\n", encoding="utf-8")
    state = {"nodes": {"GFE": {"sid": "GFE", "system_type": "ABAP"}}}
    out = []
    proc = CommandProcessor(state, out=out.append, history_path=str(hp))
    r = proc.dispatch("redo 1")           # re-runs 'un GFE'
    assert r.ok
    assert proc.ctx.selected_sid == "GFE"
    assert out[0] == "> un GFE"


def test_redo_aliases_bang_and_r(tmp_path):
    hp = tmp_path / ".cmdhistory"
    hp.write_text("ln a\n", encoding="utf-8")
    state = {"nodes": {"GFE": {"sid": "GFE"}}}
    for token in ("! 1", "r 1"):
        out = []
        proc = CommandProcessor(state, out=out.append, history_path=str(hp))
        assert proc.dispatch(token).ok
        assert out[0] == "> ln a"


def test_redo_out_of_range_and_nan(tmp_path):
    hp = tmp_path / ".cmdhistory"
    hp.write_text("ln a\n", encoding="utf-8")
    proc = CommandProcessor({}, out=[].append, history_path=str(hp))
    assert not proc.dispatch("redo 5").ok      # out of range
    assert not proc.dispatch("redo foo").ok    # not a number


def test_redo_refuses_redo_entry(tmp_path):
    hp = tmp_path / ".cmdhistory"
    hp.write_text("ln a\n! 1\n", encoding="utf-8")   # entry 2 is a redo
    out = []
    proc = CommandProcessor({"nodes": {}}, out=out.append, history_path=str(hp))
    r = proc.dispatch("redo 2")
    assert not r.ok
    assert any("refusing to redo" in l for l in out)


def test_redo_empty_history(tmp_path):
    hp = tmp_path / ".cmdhistory"      # never created
    out = []
    proc = CommandProcessor({}, out=out.append, history_path=str(hp))
    r = proc.dispatch("redo 1")
    assert not r.ok
    assert out == ["(no history)"]


def test_redo_compact_bang_form(tmp_path):
    hp = tmp_path / ".cmdhistory"
    hp.write_text("ln a\n", encoding="utf-8")
    state = {"nodes": {"GFE": {"sid": "GFE"}}}
    out = []
    proc = CommandProcessor(state, out=out.append, history_path=str(hp))
    assert proc.dispatch("!1").ok          # '!1' == '! 1'
    assert out[0] == "> ln a"


def test_redo_compact_form_refuses_redo_entry(tmp_path):
    hp = tmp_path / ".cmdhistory"
    hp.write_text("ln a\n!1\n", encoding="utf-8")   # entry 2 is a compact redo
    out = []
    proc = CommandProcessor({"nodes": {}}, out=out.append, history_path=str(hp))
    assert not proc.dispatch("redo 2").ok
    assert any("refusing to redo" in l for l in out)


# -- clear history ----------------------------------------------------------

def test_clear_history_empties_file(tmp_path):
    hp = tmp_path / ".cmdhistory"
    hp.write_text("ln a\nun GFE\n", encoding="utf-8")
    out = []
    proc = CommandProcessor({}, out=out.append, history_path=str(hp))
    r = proc.dispatch("clear_history")
    assert r.ok
    assert hp.read_text(encoding="utf-8") == ""
    assert out == ["history cleared"]


def test_clear_history_then_history_is_empty(tmp_path):
    hp = tmp_path / ".cmdhistory"
    hp.write_text("ln a\n", encoding="utf-8")
    out = []
    proc = CommandProcessor({}, out=out.append, history_path=str(hp))
    assert proc.dispatch("hc").ok          # alias
    out.clear()
    r = proc.dispatch("history")
    assert not r.ok
    assert out == ["(no history)"]
