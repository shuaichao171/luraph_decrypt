from __future__ import annotations

import json
import struct
from copy import deepcopy

import pytest

from tools.audit_readable import audit_cfg_report
from tools.luraph_devirtualize import (
    extract_opcode_handlers,
    extract_root_function_source,
    extract_vm_layout,
    instantiate_handler,
)
from tools.luraph_readable import (
    BasicBlock,
    FlowShape,
    HandlerCleanup,
    ReadableInstruction,
    _hybridize_context,
    _recover_table_literals,
    _render_context,
    _render_recovered_table,
    build_basic_blocks,
    derive_noise_statements,
    domain_string_score,
    instantiate_readable_handler,
    sanitize_handler,
    simplify_known_operation,
    specialize_opcode_handler,
)
from tools.luraph_recover import (
    RecoveryError,
    decode_lph_base85,
    dump_closure_graph,
    dump_root_bytecode,
    extract_payload,
    normalize_permissive_escapes,
    render_semantic_lua,
    suppress_payload_invocation,
    trace_payload,
    trace_vm_fetches,
)
from tools.probe_business import _select_programs
from tools.recover_script import compact_trace, expand_compact_trace


def test_probe_business_selects_requested_programs() -> None:
    report = {
        "program_summaries": [
            {"id": 160},
            {
                "id": 162,
                "visited_pcs": [{"pc": 1, "count": 1}],
                "instructions": [
                    {
                        "pc": 1,
                        "first_fetch_sequence": 10,
                        "operands": {
                            "large": {
                                "value": "x" * 161,
                                "type": "string",
                                "length": 161,
                            },
                            "small": {
                                "value": "SetSkin",
                                "type": "string",
                                "length": 7,
                            },
                        },
                    },
                    {"pc": 2},
                ],
            },
            {"id": 163},
        ],
        "context_summaries": [
            {"id": 151, "program": 160},
            {
                "id": 153,
                "program": 162,
                "path_pcs": [1],
                "instructions": [{"pc": 1}, {"pc": 2}],
            },
        ],
        "ok": True,
    }

    selected = _select_programs(report, [162])

    assert selected == {
        "program_summaries": [
            {
                "id": 162,
                "interesting_strings": ["SetSkin"],
                "visited_pcs": [{"pc": 1, "count": 1}],
                "instructions": [
                    {
                        "pc": 1,
                        "first_fetch_sequence": 10,
                        "operands": {
                            "large": {
                                "type": "string",
                                "length": 161,
                                "value_omitted": True,
                            },
                            "small": {
                                "value": "SetSkin",
                                "type": "string",
                                "length": 7,
                            },
                        },
                    }
                ],
            }
        ],
        "context_summaries": [
            {
                "id": 153,
                "program": 162,
                "path_pcs": [1],
                "instructions": [{"pc": 1}],
            }
        ],
        "ok": True,
    }
    assert len(report["program_summaries"]) == 3
    assert len(report["program_summaries"][1]["instructions"]) == 2


def encode_group(value: int) -> str:
    chars = ["!"] * 5
    for index in range(4, -1, -1):
        chars[index] = chr(value % 85 + 33)
        value //= 85
    return "".join(chars)


def test_decode_lph_base85_uses_little_endian_words() -> None:
    word = 0x1234ABCD
    assert decode_lph_base85("LPH?" + encode_group(word)) == struct.pack("<I", word)


def test_decode_lph_base85_expands_zero_run() -> None:
    assert decode_lph_base85("LPH?z") == b"\0\0\0\0"


def test_extract_payload_requires_one_lph_string() -> None:
    assert extract_payload("return [=[LPH?!!!!!]=]") == "LPH?!!!!!"
    with pytest.raises(RecoveryError):
        extract_payload("return [=[not-lph]=]")


def test_suppress_payload_invocation_only_changes_tail() -> None:
    source = "return({f=function() return function() end end}):f()(...);\n"
    assert suppress_payload_invocation(source).endswith(":f();\n")


def test_suppress_payload_invocation_rejects_unknown_wrapper() -> None:
    with pytest.raises(RecoveryError):
        suppress_payload_invocation("return function() end")


def test_normalize_permissive_escapes_only_changes_short_strings() -> None:
    source = r'''local a="\114s\104\ift"; local b='\__in\100e\x'; local c=[=[\i]=]'''
    assert normalize_permissive_escapes(source) == (
        r'''local a="\114s\104ift"; local b='__in\100ex'; local c=[=[\i]=]'''
    )


def test_dump_root_bytecode_does_not_invoke_returned_function() -> None:
    source = "return({f=function() return function() error('called') end end}):f()(...);"
    assert dump_root_bytecode(source).startswith(b"\x1bLJ")


def test_trace_payload_records_calls_and_recurses_into_callbacks() -> None:
    source = """
    return({f=function()
      return function()
        AddThing("sample", function(inst) inst.components.skin:Set(3) end)
      end
    end}):f()(...);
    """
    report = trace_payload(source, instruction_budget=50_000, callback_limit=5)
    calls = [event for event in report["events"] if event["op"] == "call"]
    assert report["root"]["ok"] is True
    assert report["callbacks_invoked"] == 1
    assert calls[0]["path"] == "AddThing"
    assert calls[0]["args"][0]["value"] == "sample"
    assert calls[0]["args"][1]["callback"] == 1
    assert any(call["path"].endswith("components.skin.Set") for call in calls)


def test_trace_payload_replaces_external_loaders() -> None:
    source = "return({f=function() return function() require('unsafe') end end}):f()(...);"
    report = trace_payload(source, instruction_budget=50_000, callback_limit=0)
    blocked = [event for event in report["events"] if event["op"] == "blocked_call"]
    assert blocked[0]["path"] == "require"


def test_trace_payload_only_compiles_luraph_forwarder_template() -> None:
    source = """
    return({f=function()
      return function()
        local target = function(value) AddThing(value) end
        local factory = loadstring([[return setfenv(function(...) return target(...) end,
          setmetatable({ ["target"] = ... }, { __index = getfenv((...)) }))]])
        factory(target)("sample")
        loadstring("return require('unsafe')")()
      end
    end}):f()(...);
    """
    report = trace_payload(source, instruction_budget=50_000, callback_limit=0)
    assert report["loaded_sources"][0]["compiled"] is True
    assert report["loaded_sources"][1]["compiled"] is False
    calls = [event for event in report["events"] if event["op"] == "call"]
    assert calls[0]["path"] == "AddThing"


def test_trace_payload_captures_budget_stack() -> None:
    source = (
        "return({f=function() return function() local n=0; "
        "while true do n=tonumber(tostring(n))+1 end end end}):f()(...);"
    )
    report = trace_payload(source, instruction_budget=10_000, callback_limit=0)
    assert report["root"]["ok"] is False
    assert report["budget_snapshots"][0]["scope"] == "root"
    assert report["budget_snapshots"][0]["frames"]


def test_dump_closure_graph_preserves_upvalue_references() -> None:
    source = """
    return({f=function()
      local values = { "one", 2 }
      return function() return values end
    end}):f()(...);
    """
    graph = dump_closure_graph(source)
    root = graph["nodes"][graph["root"]["ref"] - 1]
    assert root["type"] == "function"
    assert root["upvalues"][0]["name"] == "values"
    assert graph["stats"]["node_overflow"] is False


def test_trace_vm_fetches_forwards_opcodes_and_operands() -> None:
    source = """
    return({f=function()
      local u, h, O, W = { 7, 9 }, { 10, 20 }, { 30, 40 }, { 50, 60 }
      return function()
        local total = 0
        for pc = 1, 2 do total = total + u[pc] end
        return total, h[1], O[1], W[1]
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(source, fetch_budget=10)
    assert report["ok"] is True
    assert [item["opcode"] for item in report["fetches"]] == [7, 9]
    assert report["fetches"][1]["pc"] == 2
    assert report["fetches"][1]["h"] == 20
    assert report["fetches"][1]["O"] == 40
    assert report["fetches"][1]["W"] == 60
    assert report["fetch_count"] == 2
    assert report["contexts"] == 1
    assert report["fetches"][0]["context"] == 1
    assert report["context_summaries"][0]["path_pcs"] == [1, 2]
    assert report["context_summaries"][0]["path_overflow"] is False


def test_trace_vm_fetches_snapshots_operands_before_the_vm_mutates_them() -> None:
    source = """
    return({f=function()
      local u, h = { 7, 9 }, { 10, 20 }
      return function()
        local first = u[1]
        h[1] = 99
        local second = u[2]
        h[2] = 88
        return first + second
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(source, fetch_budget=10, include_programs=True)

    context_rows = report["context_summaries"][0]["instructions"]
    assert context_rows[0]["h"] == 10
    assert context_rows[0]["operands"]["h"] == 10
    assert context_rows[1]["h"] == 20
    assert context_rows[1]["operands"]["h"] == 20
    assert context_rows[0]["first_fetch_sequence"] == 1
    assert context_rows[1]["first_fetch_sequence"] == 2
    assert report["context_summaries"][0]["first_fetch_sequence"] == 1
    assert report["context_summaries"][0]["last_fetch_sequence"] == 2
    program_rows = report["program_summaries"][0]["instructions"]
    assert program_rows[0]["h"] == 99
    assert program_rows[1]["h"] == 88


def test_trace_vm_fetches_records_self_modified_operand_variants() -> None:
    source = """
    return({f=function()
      local u, h = { 7 }, { 10 }
      return function()
        local pc = 1
        local first = u[pc]
        h[pc] = 20
        local second = u[pc]
        return first + second
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        include_programs=True,
        runtime_fixture={"record_operand_variants": True},
    )

    context = report["context_summaries"][0]
    variants = context["instruction_variants"]
    assert context["operand_variant_count"] == 2
    assert [row["operands"]["h"] for row in variants] == [10, 20]
    assert [row["first_fetch_sequence"] for row in variants] == [1, 2]


def test_trace_vm_fetches_limits_operand_variants_to_requested_programs() -> None:
    source = """
    return({f=function()
      local u, h = { 7 }, { 10 }
      return function()
        local pc = 1
        local first = u[pc]
        h[pc] = 20
        local second = u[pc]
        return first + second
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        include_programs=True,
        runtime_fixture={
            "record_operand_variants": True,
            "operand_variant_programs": {999: True},
        },
    )

    context = report["context_summaries"][0]
    assert context["operand_variant_count"] == 0
    assert context["instruction_variants"] in ({}, [])


def test_trace_vm_fetches_supports_randomized_vm_upvalue_names() -> None:
    source = """
    return({f=function()
      local X, r = { 17 }, { 23 }
      return function() return X[1], r[1] end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        include_programs=True,
        instruction_upvalue_name="X",
        environment_upvalue_name="",
    )
    assert report["ok"] is True
    assert report["fetches"][0]["opcode"] == 17
    assert report["context_summaries"][0]["instructions"][0]["operands"]["r"] == 23


def test_trace_vm_fetches_can_bind_a_new_vm_closure_environment() -> None:
    source = """
    return({f=function()
      local u, h, o, W, j = { 105 }, { 1 }, { "rawget" }, { 1 }, {}
      return function()
        local z, B = {}, 1
        local opcode = u[B]
        if opcode == 105 then z[W[B]] = j[h[B]][o[B]] end
        return z[1]
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        bind_missing_environment=True,
    )
    assert report["ok"] is True
    assert report["environment_bindings"] == 1


def test_trace_vm_fetches_applies_data_only_environment_overrides() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function() return u[1], env.modname end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        environment_overrides={"env": {"modname": "workshop-test"}},
    )
    assert report["ok"] is True

    with pytest.raises(ValueError, match="unsafe environment overrides"):
        trace_vm_fetches(
            source,
            fetch_budget=10,
            environment_overrides={"require": "not allowed"},
        )


def test_trace_vm_fetches_loaded_mods_fixture_records_upvalue_patch() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        local mods = KnownModIndex:GetModsToLoad(true)
        if opcode == 7 and mods[1] == "workshop-test" then
          local method = ModManager.ApplyBridge
          local name = debug.getupvalue(method, 1)
          if name ~= nil then debug.setupvalue(method, 1, {}) end
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
        },
    )
    assert report["ok"] is True
    assert report["fixture_active"] is True
    assert report["fixture_environment_before_invoke"] == {
        "KnownModIndex": "table",
        "ModManager": "table",
        "debug": "table",
        "pairs": "function",
    }
    assert [event["op"] for event in report["fixture_events"]] == [
        "get_mods_to_load",
        "mod_manager_index",
        "debug_getupvalue",
        "debug_setupvalue",
    ]
    assert report["fixture_events"][1]["key"] == "ApplyBridge"
    assert report["fixture_events"][2]["index"] == 1
    assert report["fixture_events"][3]["value_type"] == "table"


def test_trace_vm_fetches_loaded_mods_fixture_probes_mod_value_methods() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        local mods = KnownModIndex:GetModsToLoad(true)
        if opcode == 7 and mods[1]:Matches("marker") then
          return ModManager.Unreachable
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_mod_values": True,
            "mod_probe_result": False,
        },
    )
    assert report["ok"] is True
    assert [event["op"] for event in report["fixture_events"]] == [
        "get_mods_to_load",
        "mod_value_index",
        "mod_value_call",
    ]
    assert report["fixture_events"][1] == {
        "op": "mod_value_index",
        "key": "Matches",
        "value": "workshop-test",
    }
    assert report["fixture_events"][2]["key"] == "Matches"
    assert report["fixture_events"][2]["argument_count"] == 2


def test_trace_vm_fetches_loaded_mods_fixture_probes_known_mod_methods() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        local mods = KnownModIndex:GetModsToLoad(true)
        local missing_key
        if opcode == 7 then
          return KnownModIndex[missing_key](KnownModIndex, mods[1])
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_known_mod_methods": True,
            "known_mod_method_result": "actual-name",
        },
    )
    assert report["ok"] is True
    assert [event["op"] for event in report["fixture_events"]] == [
        "get_mods_to_load",
        "known_mod_index",
        "known_mod_call",
    ]
    assert report["fixture_events"][1]["key"] == "nil"
    assert report["fixture_events"][2] == {
        "op": "known_mod_call",
        "key": "nil",
        "argument_count": 2,
        "mod_value": "workshop-test",
    }


def test_trace_vm_fetches_loaded_mods_fixture_probes_mod_environment() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        local mods = KnownModIndex:GetModsToLoad(true)
        if opcode == 7 then
          local mod = ModManager:GetMod(mods[1])
          return debug.getupvalue(mod.HiddenFunction, 1)
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_mod_manager_result_fields": True,
        },
    )
    assert report["ok"] is True
    assert [event["op"] for event in report["fixture_events"]] == [
        "get_mods_to_load",
        "mod_manager_index",
        "mod_manager_call",
        "mod_manager_result_index",
        "debug_getupvalue",
    ]
    assert report["fixture_events"][1]["key"] == "GetMod"
    assert report["fixture_events"][2]["mod_value"] == "workshop-test"
    assert report["fixture_events"][3]["field"] == "HiddenFunction"


def test_loaded_mod_fixture_can_leave_unknown_mod_fields_nil() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        local mods = KnownModIndex:GetModsToLoad(true)
        if opcode == 7 then
          local mod = ModManager:GetMod(mods[1])
          if mod.Missing ~= nil then error("expected nil") end
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_mod_manager_result_fields": True,
            "mod_environment_missing_fields_are_nil": True,
        },
    )

    assert report["ok"] is True
    assert report["fixture_events"][-1] == {
        "op": "mod_manager_result_index",
        "field": "Missing",
    }


def test_loaded_mod_fixture_can_seed_known_mod_result_fields() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        local mods = KnownModIndex:GetModsToLoad(true)
        local info = KnownModIndex:GetModInfo(mods[1])
        if opcode == 7 and info.name ~= "Target Name" then
          error("wrong name")
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_known_mod_methods": True,
            "probe_known_mod_result_fields": True,
            "known_mod_result_fields": {"name": "Target Name"},
        },
    )

    assert report["ok"] is True
    assert report["fixture_events"][-1] == {
        "op": "known_mod_result_index",
        "field": "name",
    }


def test_trace_vm_fetches_loaded_mods_fixture_seeds_raw_fields() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        local mods = KnownModIndex:GetModsToLoad(true)
        if opcode == 7 then
          local mod = ModManager:GetMod(mods[1])
          return type(rawget(mod, "Configured"))
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_mod_manager_result_fields": True,
            "mod_environment_fields": {"Configured": {"entry": 1}},
        },
    )
    assert report["ok"] is True
    assert report["fixture_events"][3] == {
        "op": "mod_environment_seed",
        "fields": [{"field": "Configured", "value_type": "table"}],
    }


def test_trace_vm_fetches_loaded_mods_fixture_probes_seed_tables() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        local mods = KnownModIndex:GetModsToLoad(true)
        if opcode == 7 then
          local mod = ModManager:GetMod(mods[1])
          local configured = rawget(mod, "Configured")
          local missing = configured.Expected
          for _ in pairs(configured) do break end
          return missing
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_mod_manager_result_fields": True,
            "mod_environment_fields": {"Configured": {"entry": 1}},
            "probe_mod_seed_tables": True,
        },
    )
    operations = [event["op"] for event in report["fixture_events"]]
    assert "fixture_probe_table_index" in operations
    assert "fixture_probe_table_pairs" in operations
    index_event = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_probe_table_index"
    )
    assert index_event == {
        "op": "fixture_probe_table_index",
        "path": "Configured",
        "key": "Expected",
    }


def test_trace_vm_fetches_can_trace_raw_access_to_seed_tables() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        local mods = KnownModIndex:GetModsToLoad(true)
        if opcode == 7 then
          local mod = ModManager:GetMod(mods[1])
          local configured = rawget(mod, "Configured")
          rawset(configured, "Patched", "yes")
          return rawget(configured, "Patched")
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_mod_manager_result_fields": True,
            "mod_environment_fields": {"Configured": {}},
            "probe_mod_seed_tables": True,
            "probe_fixture_raw_access": True,
            "record_fixture_probe_final_state": True,
        },
    )

    accesses = [
        event
        for event in report["fixture_events"]
        if event["op"].startswith("fixture_probe_table_raw")
    ]
    assert accesses == [
        {
            "byte_length": 3,
            "key": "Patched",
            "op": "fixture_probe_table_rawset",
            "path": "Configured",
            "value": "yes",
            "value_type": "string",
        },
        {
            "byte_length": 3,
            "key": "Patched",
            "op": "fixture_probe_table_rawget",
            "path": "Configured",
            "value": "yes",
            "value_type": "string",
        },
    ]
    final_state = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_probe_table_final_state"
        and event["path"] == "Configured"
    )
    assert final_state["entries"] == [
        {
            "byte_length": 3,
            "key": "Patched",
            "key_type": "string",
            "value": "yes",
            "value_type": "string",
        }
    ]


def test_loaded_mod_fixture_can_probe_global_raw_access() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then
          AddSimPostInit(function()
            local before = rawget(_G, "Before")
            rawset(_G, "After", before)
          end)
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        environment_overrides={"Before": "seed"},
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": [],
            "probe_global_raw_access": True,
            "defer_raw_access_probe_until_callbacks": True,
        },
        alias_global_environment=True,
        proxy_unknown_globals=True,
        callback_limit=1,
    )

    assert report["ok"] is True
    assert report["fixture_events"] == [
        {
            "byte_length": 4,
            "key": "Before",
            "op": "global_rawget",
            "value": "seed",
            "value_type": "string",
        },
        {
            "byte_length": 4,
            "key": "After",
            "op": "global_rawset",
            "value": "seed",
            "value_type": "string",
        },
    ]


def test_loaded_mod_fixture_can_probe_seeded_global_tables() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then
          AddSimPostInit(function()
            local configured = rawget(_G, "Configured")
            local seed = rawget(configured, "Seed")
            rawset(configured, "After", seed)
          end)
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        environment_overrides={"Configured": {"Seed": "value"}},
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": [],
            "probe_global_tables": ["Configured"],
            "probe_fixture_raw_access": True,
            "probe_global_raw_access": True,
            "defer_raw_access_probe_until_callbacks": True,
        },
        alias_global_environment=True,
        proxy_unknown_globals=True,
        callback_limit=1,
    )

    raw_events = [
        event
        for event in report["fixture_events"]
        if "raw" in event["op"]
    ]
    assert raw_events == [
        {
            "key": "Configured",
            "op": "global_rawget",
            "value_type": "table",
        },
        {
            "byte_length": 5,
            "key": "Seed",
            "op": "fixture_probe_table_rawget",
            "path": "GLOBAL.Configured",
            "value": "value",
            "value_type": "string",
        },
        {
            "byte_length": 5,
            "key": "After",
            "op": "fixture_probe_table_rawset",
            "path": "GLOBAL.Configured",
            "value": "value",
            "value_type": "string",
        },
    ]


def test_loaded_mod_fixture_can_defer_mod_environment_raw_access() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then
          AddSimPostInit(function()
            local environment = ModManager:GetMod("workshop-probe")
            local before = rawget(environment, "Before")
            rawset(environment, "After", before)
          end)
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": [],
            "probe_mod_manager_result_fields": True,
            "mod_environment_fields": {"Before": "seed"},
            "probe_mod_environment_raw_access": True,
            "defer_raw_access_probe_until_callbacks": True,
        },
        alias_global_environment=True,
        proxy_unknown_globals=True,
        callback_limit=1,
    )

    assert report["ok"] is True
    raw_events = [
        event
        for event in report["fixture_events"]
        if event["op"] in {"mod_environment_rawget", "mod_environment_rawset"}
    ]
    assert raw_events == [
        {
            "key": "Before",
            "op": "mod_environment_rawget",
            "value_type": "string",
        },
        {
            "key": "After",
            "op": "mod_environment_rawset",
            "value_type": "string",
        },
    ]


def test_loaded_mod_fixture_tracks_seeded_global_function_identity() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then
          AddSimPostInit(function()
            local configured = rawget(_G, "Configured")
            configured.Replaced = function(callback)
              callback("inner")
              return true
            end
          end)
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        environment_overrides={"Configured": {}},
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": [],
            "global_table_function_fields": {
                "Configured": ["Unchanged", "Replaced"],
            },
            "probe_global_tables": ["Configured"],
            "invoke_fixture_functions": [
                {
                    "path": "GLOBAL.Configured",
                    "field": "Replaced",
                    "arguments": [{"fixture_callback": True}],
                },
            ],
            "record_fixture_probe_final_state": True,
        },
        alias_global_environment=True,
        proxy_unknown_globals=True,
        callback_limit=1,
    )

    final_state = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_probe_table_final_state"
    )
    function_call = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_function_call"
    )
    assert function_call == {
        "field": "Replaced",
        "ok": True,
        "op": "fixture_function_call",
        "path": "GLOBAL.Configured",
        "result": True,
        "result_type": "boolean",
    }
    callback_call = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_callback_call"
    )
    assert callback_call == {
        "argument_count": 1,
        "argument_index": 1,
        "arguments": [
            {"length": 5, "type": "string", "value": "inner"},
        ],
        "field": "Replaced",
        "op": "fixture_callback_call",
        "path": "GLOBAL.Configured",
    }
    assert final_state["entries"] == [
        {
            "key": "Replaced",
            "key_type": "string",
            "value_type": "function",
        },
        {
            "function_role": "GLOBAL.Configured.Unchanged.seed",
            "key": "Unchanged",
            "key_type": "string",
            "value_type": "function",
        },
    ]


def test_loaded_mod_fixture_seeds_global_table_index_functions() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then
          AddSimPostInit(function()
            local methods = getmetatable(Configured).__index
            methods.Replaced = function() return true end
          end)
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        environment_overrides={"Configured": {}},
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": [],
            "global_table_index_function_fields": {
                "Configured": ["Unchanged", "Replaced"],
            },
            "invoke_fixture_functions": [
                {
                    "path": "GLOBAL.Configured.__index",
                    "field": "Replaced",
                },
            ],
            "record_fixture_probe_final_state": True,
        },
        alias_global_environment=True,
        proxy_unknown_globals=True,
        callback_limit=1,
    )

    function_call = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_function_call"
    )
    assert function_call == {
        "field": "Replaced",
        "ok": True,
        "op": "fixture_function_call",
        "path": "GLOBAL.Configured.__index",
        "result": True,
        "result_type": "boolean",
    }
    final_state = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_probe_table_final_state"
    )
    assert final_state["path"] == "GLOBAL.Configured.__index"
    assert final_state["entries"] == [
        {
            "key": "Replaced",
            "key_type": "string",
            "value_type": "function",
        },
        {
            "function_role": "GLOBAL.Configured.__index.Unchanged.seed",
            "key": "Unchanged",
            "key_type": "string",
            "value_type": "function",
        },
    ]


def test_loaded_mod_fixture_configures_global_function_returns() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then
          AddSimPostInit(function()
            local original = ConfiguredFunction
            ConfiguredFunction = function(...)
              return original(...)
            end
          end)
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        environment_overrides={
            "FirstResult": "first",
            "SecondResult": "second",
            "ThirdResult": "third",
        },
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": [],
            "global_function_names": ["ConfiguredFunction"],
            "global_function_return_globals": {
                "ConfiguredFunction": [
                    "FirstResult",
                    "SecondResult",
                    "ThirdResult",
                ],
            },
            "record_fixture_seed_function_calls": True,
            "record_fixture_function_all_results": True,
            "invoke_fixture_functions": [
                {
                    "path": "GLOBAL",
                    "field": "ConfiguredFunction",
                    "arguments": ["argument"],
                },
            ],
        },
        alias_global_environment=True,
        proxy_unknown_globals=True,
        callback_limit=1,
    )

    seed_call = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_table_seed_function_call"
    )
    assert seed_call["function_role"] == "GLOBAL.ConfiguredFunction.seed"
    function_call = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_function_call"
    )
    assert function_call["result_count"] == 3
    assert [result["value"] for result in function_call["results"]] == [
        "first",
        "second",
        "third",
    ]


def test_loaded_mod_fixture_configures_seeded_table_function_returns() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then
          AddSimPostInit(function()
            local first, second = Configured.Run("argument")
            ResultState.first = first
            ResultState.second = second
          end)
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        environment_overrides={
            "Configured": {},
            "FirstResult": {"name": "first"},
            "SecondResult": "second",
            "ResultState": {},
        },
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": [],
            "global_table_function_fields": {"Configured": ["Run"]},
            "global_table_function_return_globals": {
                "Configured": {
                    "Run": ["FirstResult", "SecondResult"],
                },
            },
            "record_fixture_table_seed_function_calls": True,
            "probe_global_tables": ["ResultState"],
            "record_fixture_probe_final_state": True,
        },
        alias_global_environment=True,
        proxy_unknown_globals=True,
        callback_limit=1,
    )

    seed_call = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_table_seed_function_call"
    )
    assert seed_call == {
        "argument_count": 1,
        "arguments": [
                {
                    "byte_length": 8,
                    "type": "string",
                    "value": "argument",
            }
        ],
        "function_role": "GLOBAL.Configured.Run.seed",
        "op": "fixture_table_seed_function_call",
    }
    final_state = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_probe_table_final_state"
    )
    assert final_state["entries"] == [
        {
            "key": "first",
            "key_type": "string",
            "value_type": "table",
        },
        {
            "byte_length": 6,
            "key": "second",
            "key_type": "string",
            "value": "second",
            "value_type": "string",
        },
    ]


def test_loaded_mod_fixture_seeds_configured_function_upvalues() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then
          AddSimPostInit(function()
            local _, direct = debug.getupvalue(DirectProbe, 2)
            local _, method = debug.getupvalue(Configured.MethodProbe, 2)
            direct.direct_seen = true
            method.method_seen = true
          end)
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        environment_overrides={
            "Configured": {},
            "DirectState": {},
            "MethodState": {},
        },
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": [],
            "global_function_names": ["DirectProbe"],
            "global_function_first_upvalues": {
                "DirectProbe": "DirectState",
            },
            "global_table_function_fields": {
                "Configured": ["MethodProbe"],
            },
            "global_table_function_first_upvalues": {
                "Configured": {"MethodProbe": "MethodState"},
            },
            "probe_global_tables": ["DirectState", "MethodState"],
            "record_fixture_probe_final_state": True,
        },
        alias_global_environment=True,
        proxy_unknown_globals=True,
        callback_limit=1,
    )

    states = {
        event["path"]: event["entries"]
        for event in report["fixture_events"]
        if event["op"] == "fixture_probe_table_final_state"
    }
    assert states["GLOBAL.DirectState"] == [
        {
            "key": "direct_seen",
            "key_type": "string",
            "value": True,
            "value_type": "boolean",
        }
    ]
    assert states["GLOBAL.MethodState"] == [
        {
            "key": "method_seen",
            "key_type": "string",
            "value": True,
            "value_type": "boolean",
        }
    ]


def test_loaded_mod_fixture_invokes_mod_environment_functions() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then
          local mod = ModManager:GetMod("workshop-test")
          mod.Replaced = function() return true end
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_mod_manager_result_fields": True,
            "mod_environment_function_fields": ["Seed", "Replaced"],
            "invoke_fixture_functions": [
                {"path": "MOD", "index": 1, "field": "Replaced"},
            ],
            "record_fixture_mod_environment_final_state": True,
        },
    )

    function_call = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_function_call"
    )
    assert function_call == {
        "field": "Replaced",
        "index": 1,
        "ok": True,
        "op": "fixture_function_call",
        "path": "MOD",
        "result": True,
        "result_type": "boolean",
    }
    final_state = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "mod_environment_final_state"
    )
    assert final_state["entries"] == [
        {"key": "Replaced", "value_type": "function"},
        {
            "function_role": "MOD.1.Seed.seed",
            "key": "Seed",
            "value_type": "function",
        },
    ]


def test_loaded_mod_fixture_logs_mod_function_calls_and_returns_globals() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then
          local mod = ModManager:GetMod("workshop-test")
          local returned = mod.Seed("from-root")
          returned.called = true
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        environment_overrides={"ReturnValue": {}},
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_mod_manager_result_fields": True,
            "mod_environment_function_fields": ["Seed"],
            "record_fixture_mod_function_calls": True,
            "mod_environment_function_return_globals": {
                "Seed": ["ReturnValue"],
            },
            "probe_global_tables": ["ReturnValue"],
            "record_fixture_probe_final_state": True,
        },
    )

    function_call = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_table_seed_function_call"
    )
    assert function_call == {
        "argument_count": 1,
        "arguments": [
            {
                "byte_length": 9,
                "type": "string",
                "value": "from-root",
            }
        ],
        "function_role": "MOD.1.Seed.seed",
        "op": "fixture_table_seed_function_call",
    }
    final_state = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_probe_table_final_state"
    )
    assert final_state["entries"] == [
        {
            "key": "called",
            "key_type": "string",
            "value": True,
            "value_type": "boolean",
        }
    ]


def test_loaded_mod_fixture_mod_function_returns_globals_without_logging() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then
          local mod = ModManager:GetMod("workshop-test")
          local returned = mod.Seed()
          returned.called = true
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        environment_overrides={"ReturnValue": {}},
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_mod_manager_result_fields": True,
            "mod_environment_function_fields": ["Seed"],
            "mod_environment_function_return_globals": {
                "Seed": ["ReturnValue"],
            },
            "probe_global_tables": ["ReturnValue"],
            "record_fixture_probe_final_state": True,
        },
    )

    assert not any(
        event["op"] == "fixture_table_seed_function_call"
        for event in report["fixture_events"]
    )
    final_state = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_probe_table_final_state"
    )
    assert final_state["entries"] == [
        {
            "key": "called",
            "key_type": "string",
            "value": True,
            "value_type": "boolean",
        }
    ]


def test_loaded_mod_fixture_seeds_nested_mod_environment_functions() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then
          local mod = ModManager:GetMod("workshop-test")
          mod.Root.Replaced = function() return true end
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_mod_manager_result_fields": True,
            "mod_environment_fields": {"Root": {}},
            "probe_mod_seed_tables": True,
            "mod_environment_table_function_fields": {
                "Root": ["Seed", "Replaced"],
            },
            "record_fixture_probe_final_state": True,
        },
    )

    root_state = next(
        event
        for event in report["fixture_events"]
        if event.get("op") == "fixture_probe_table_final_state"
        and event.get("path") == "Root"
    )
    assert root_state["entries"] == [
        {
            "key": "Replaced",
            "key_type": "string",
            "value_type": "function",
        },
        {
            "function_role": "MOD.1.Root.Seed.seed",
            "key": "Seed",
            "key_type": "string",
            "value_type": "function",
        },
    ]


def test_loaded_mod_fixture_preserves_nil_arguments_and_nested_results() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
      end
    end}):f()(...);
    """
    controller_path = "GLOBAL.Player.components.controller"
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        environment_overrides={
            "Player": {"components": {"controller": {}}},
            "FirstResult": "first",
            "TailResult": "tail",
        },
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": [],
            "probe_global_tables": ["Player"],
            "fixture_probe_table_function_fields": {
                controller_path: ["HasSkin"],
            },
            "fixture_probe_table_function_return_globals": {
                controller_path: {
                    "HasSkin": ["FirstResult", "MissingResult", "TailResult"],
                },
            },
            "record_fixture_table_seed_function_calls": True,
            "record_fixture_function_all_results": True,
            "invoke_fixture_functions": [
                {
                    "path": controller_path,
                    "field": "HasSkin",
                    "arguments": ["first", {"fixture_nil": True}, "tail"],
                },
            ],
        },
    )

    seed_call = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_table_seed_function_call"
    )
    assert seed_call["arguments"] == [
        {"byte_length": 5, "type": "string", "value": "first"},
        {"type": "nil"},
        {"byte_length": 4, "type": "string", "value": "tail"},
    ]
    function_call = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_function_call"
    )
    assert function_call["result_count"] == 3
    assert function_call["results"] == [
        {"byte_length": 5, "type": "string", "value": "first"},
        {"type": "nil"},
        {"byte_length": 4, "type": "string", "value": "tail"},
    ]


def test_loaded_mod_fixture_records_function_environment_calls() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then
          local mod = ModManager:GetMod("workshop-test")
          getfenv(mod.Probe)
          setfenv(mod.Probe, _G)
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_mod_manager_result_fields": True,
            "mod_environment_function_fields": ["Probe"],
            "record_fixture_function_environment_calls": True,
        },
        alias_global_environment=True,
    )

    environment_events = [
        event
        for event in report["fixture_events"]
        if event["op"] in {"fixture_getfenv", "fixture_setfenv"}
    ]
    assert environment_events == [
        {
            "function_environment_role": "fixture_mod_environment",
            "function_role": "MOD.1.Probe.seed",
            "op": "fixture_getfenv",
        },
        {
            "environment_role": "target_environment",
            "function_role": "MOD.1.Probe.seed",
            "op": "fixture_setfenv",
        },
    ]


def test_loaded_mod_fixture_seeds_named_mod_function_upvalues() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then
          local mod = ModManager:GetMod("workshop-test")
          local n1 = debug.getupvalue(mod.Probe, 1)
          local n2, characters = debug.getupvalue(mod.Probe, 2)
          local n3 = debug.getupvalue(mod.Probe, 3)
          if n1 == "namemaps" and n2 == "characterskins"
              and n3 == "itemskins" then
            characters.seen = true
          end
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        environment_overrides={
            "Names": {},
            "Characters": {},
            "Items": {},
            "OldOwnership": {},
        },
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_mod_manager_result_fields": True,
            "mod_environment_function_fields": ["Probe"],
            "mod_environment_function_upvalue_tables": {
                "Probe": [
                    "Names",
                    "Characters",
                    "Items",
                    "OldOwnership",
                ],
            },
            "mod_environment_function_upvalue_shapes": {
                "Probe": "fengling_skinapi_v1",
            },
            "record_fixture_table_paths_final_state": [
                {"global": "Characters"},
            ],
        },
        alias_global_environment=True,
    )

    final_state = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_table_path_final_state"
    )
    assert final_state["entries"] == [
        {
            "key": "seen",
            "key_type": "string",
            "value": True,
            "value_type": "boolean",
        }
    ]


def test_loaded_mod_fixture_records_seeded_global_function_calls() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then DirectProbe("root") end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": [],
            "global_function_names": ["DirectProbe"],
            "record_fixture_seed_function_calls": True,
            "record_fixture_global_fields": ["DirectProbe"],
        },
    )

    seed_call = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_seed_function_call"
    )
    assert seed_call == {
        "argument_count": 1,
        "function_role": "GLOBAL.DirectProbe.seed",
        "op": "fixture_seed_function_call",
    }
    final_state = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_global_field_final_state"
    )
    assert final_state == {
        "field": "DirectProbe",
        "function_role": "GLOBAL.DirectProbe.seed",
        "op": "fixture_global_field_final_state",
        "value_type": "function",
    }


def test_loaded_mod_fixture_records_seeded_global_table_function_calls() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        DirectAPI.Run("probe", 7)
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        environment_overrides={"DirectAPI": {}},
        runtime_fixture={
            "kind": "loaded_mods",
            "global_table_function_fields": {"DirectAPI": ["Run"]},
            "record_fixture_table_seed_function_calls": True,
        },
        alias_global_environment=True,
        proxy_unknown_globals=True,
    )

    seed_call = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_table_seed_function_call"
    )
    assert seed_call == {
        "argument_count": 2,
        "arguments": [
            {
                "byte_length": 5,
                "type": "string",
                "value": "probe",
            },
            {"type": "number", "value": 7},
        ],
        "function_role": "GLOBAL.DirectAPI.Run.seed",
        "op": "fixture_table_seed_function_call",
    }


def test_loaded_mod_fixture_records_and_captures_global_function_arguments() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then
          DirectProbe("rpc-name", function(value) Captured(value) end)
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": [],
            "global_function_names": ["DirectProbe"],
            "record_fixture_seed_function_calls": True,
            "record_fixture_seed_function_arguments": True,
            "capture_fixture_seed_function_callbacks": True,
            "fixture_seed_callback_arguments": {
                "GLOBAL.DirectProbe.seed": {
                    "arguments": ["actual"],
                    "argument_count": 1,
                }
            },
            "minimal_vm_trace": True,
        },
        proxy_unknown_globals=True,
        callback_limit=1,
    )

    seed_call = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_seed_function_call"
    )
    assert seed_call["arguments"] == [
        {
            "byte_length": 8,
            "type": "string",
            "value": "rpc-name",
        },
        {"type": "function"},
    ]
    assert report["callback_results"] == [
        {
            "argument": 2,
            "id": 1,
            "ok": True,
            "origin": "GLOBAL.DirectProbe.seed",
        }
    ]
    assert any(
        event.get("path") == "Captured"
        for event in report["global_events"]
    )


def test_loaded_mod_fixture_records_callback_vm_program() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then
          local u = { 8 }
          DirectProbe(function()
            local callback_opcode = u[1]
            if callback_opcode == 8 then CallbackRan() end
          end)
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=20,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": [],
            "global_function_names": ["DirectProbe"],
            "record_fixture_seed_function_calls": True,
            "capture_fixture_seed_function_callbacks": True,
            "record_fixture_callback_programs": True,
            "minimal_vm_trace": True,
        },
        proxy_unknown_globals=True,
        callback_limit=1,
    )

    assert report["callback_results"][0]["ok"] is True
    assert report["callback_results"][0]["program"] > 0
    assert any(
        event.get("path") == "CallbackRan"
        for event in report["global_events"]
    )


def test_loaded_mod_fixture_seeds_table_functions_before_callbacks() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then
          DirectProbe(function()
            if Timer.DoTaskInTime("inst", 0.25) then Confirmed() end
          end)
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=20,
        environment_overrides={"Timer": {}},
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": [],
            "global_function_names": ["DirectProbe"],
            "record_fixture_seed_function_calls": True,
            "capture_fixture_seed_function_callbacks": True,
            "callback_global_table_function_fields": {
                "Timer": ["DoTaskInTime"],
            },
            "callback_global_table_function_results": {
                "Timer": {"DoTaskInTime": True},
            },
        },
        proxy_unknown_globals=True,
        callback_limit=1,
    )

    event = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_callback_table_function_call"
    )
    assert event["function_role"] == (
        "GLOBAL.Timer.DoTaskInTime.callback_seed"
    )
    assert event["argument_count"] == 2
    assert event["arguments"] == [
        {"length": 4, "type": "string", "value": "inst"},
        0.25,
    ]
    assert any(
        item.get("path") == "Confirmed"
        for item in report["global_events"]
    )


def test_loaded_mod_fixture_snapshots_callback_upvalues_before_and_after() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then
          local state = { count = 1 }
          DirectProbe(function() state.count = state.count + 1 end)
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=20,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": [],
            "global_function_names": ["DirectProbe"],
            "record_fixture_seed_function_calls": True,
            "capture_fixture_seed_function_callbacks": True,
            "record_fixture_callback_upvalues": True,
        },
        callback_limit=1,
    )

    events = [
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_callback_upvalues"
    ]
    assert [event["phase"] for event in events] == ["before", "after"]

    def state_count(event):
        state = next(
            item for item in event["upvalues"] if item["name"] == "state"
        )
        count = next(
            item
            for item in state["value"]["entries"]
            if item["key"] == "count"
        )
        return count["value"]["value"]

    assert state_count(events[0]) == 1
    assert state_count(events[1]) == 2


def test_invoke_fixture_function_can_reuse_a_fixture_global() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then
          UseGlobal = function(value)
            value.seen = value.name
            return value
          end
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        environment_overrides={"Shared": {"name": "fixture"}},
        runtime_fixture={
            "kind": "loaded_mods",
            "invoke_fixture_functions": [
                {
                    "path": "GLOBAL",
                    "field": "UseGlobal",
                    "arguments": [{"fixture_global": "Shared"}],
                }
            ],
            "record_fixture_table_paths_final_state": [
                {"global": "Shared"},
            ],
        },
        alias_global_environment=True,
    )

    final_state = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_table_path_final_state"
    )
    assert final_state["entries"] == [
        {
            "byte_length": 7,
            "key": "name",
            "key_type": "string",
            "value": "fixture",
            "value_type": "string",
        },
        {
            "byte_length": 7,
            "key": "seen",
            "key_type": "string",
            "value": "fixture",
            "value_type": "string",
        },
    ]


def test_loaded_mod_fixture_records_uninstrumented_table_paths() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then Configured.Nested.seen = true end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        environment_overrides={"Configured": {"Nested": {}}},
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": [],
            "record_fixture_table_paths_final_state": [
                {"global": "Configured", "keys": ["Nested"]},
            ],
        },
        alias_global_environment=True,
    )

    final_state = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_table_path_final_state"
    )
    assert final_state == {
        "entries": [
            {
                "key": "seen",
                "key_type": "string",
                "value": True,
                "value_type": "boolean",
            }
        ],
        "op": "fixture_table_path_final_state",
        "path": "GLOBAL.Configured.Nested",
        "value_type": "table",
    }


def test_loaded_mod_fixture_seeds_four_explicit_table_upvalues() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then
          local _, value = debug.getupvalue(Configured.Probe, 4)
          value.seen = true
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        environment_overrides={
            "Configured": {},
            "First": {},
            "Second": {},
            "Third": {},
            "Fourth": {},
        },
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": [],
            "global_table_function_fields": {"Configured": ["Probe"]},
            "global_table_function_upvalue_tables": {
                "Configured": {
                    "Probe": ["First", "Second", "Third", "Fourth"],
                }
            },
            "record_fixture_table_paths_final_state": [
                {"global": "Fourth"},
            ],
        },
        alias_global_environment=True,
    )

    final_state = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_table_path_final_state"
    )
    assert final_state["entries"] == [
        {
            "key": "seen",
            "key_type": "string",
            "value": True,
            "value_type": "boolean",
        }
    ]


def test_loaded_mod_fixture_seeds_fengling_skinapi_upvalue_names() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        if opcode == 7 then
          local n1 = debug.getupvalue(Configured.Probe, 1)
          local n2 = debug.getupvalue(Configured.Probe, 2)
          local n3, value = debug.getupvalue(Configured.Probe, 3)
          if n1 == "namemaps" and n2 == "characterskins"
              and n3 == "itemskins" then
            value.seen = true
          end
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        environment_overrides={
            "Configured": {},
            "NameMaps": {},
            "CharacterSkins": {},
            "ItemSkins": {},
            "OriginalOwnership": {},
        },
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": [],
            "global_table_function_fields": {"Configured": ["Probe"]},
            "global_table_function_upvalue_tables": {
                "Configured": {
                    "Probe": [
                        "NameMaps",
                        "CharacterSkins",
                        "ItemSkins",
                        "OriginalOwnership",
                    ],
                }
            },
            "global_table_function_upvalue_shapes": {
                "Configured": {"Probe": "fengling_skinapi_v1"},
            },
            "record_fixture_table_paths_final_state": [
                {"global": "ItemSkins"},
            ],
        },
        alias_global_environment=True,
    )

    final_state = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_table_path_final_state"
    )
    assert final_state["entries"] == [
        {
            "key": "seen",
            "key_type": "string",
            "value": True,
            "value_type": "boolean",
        }
    ]


def test_loaded_mod_fixture_seeds_nested_probe_table_functions() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        Configured.Nested.Run("probe")
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        environment_overrides={"Configured": {"Nested": {}}},
        runtime_fixture={
            "kind": "loaded_mods",
            "probe_global_tables": ["Configured"],
            "fixture_probe_table_function_fields": {
                "GLOBAL.Configured.Nested": ["Run"],
            },
            "record_fixture_table_seed_function_calls": True,
            "record_fixture_probe_final_state": True,
        },
        alias_global_environment=True,
        proxy_unknown_globals=True,
    )

    seed_call = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_table_seed_function_call"
    )
    assert seed_call == {
        "argument_count": 1,
        "arguments": [
            {
                "byte_length": 5,
                "type": "string",
                "value": "probe",
            }
        ],
        "function_role": "GLOBAL.Configured.Nested.Run.seed",
        "op": "fixture_table_seed_function_call",
    }
    final_state = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_probe_table_final_state"
        and event["path"] == "GLOBAL.Configured.Nested"
    )
    assert final_state["entries"] == [
        {
            "function_role": "GLOBAL.Configured.Nested.Run.seed",
            "key": "Run",
            "key_type": "string",
            "value_type": "function",
        }
    ]


def test_loaded_mod_fixture_records_shallow_table_argument_entries() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        DirectAPI.Run({ probe = true, count = 2 })
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        environment_overrides={"DirectAPI": {}},
        runtime_fixture={
            "kind": "loaded_mods",
            "global_table_function_fields": {"DirectAPI": ["Run"]},
            "record_fixture_table_seed_function_calls": True,
            "record_fixture_table_argument_entries": True,
        },
        alias_global_environment=True,
        proxy_unknown_globals=True,
    )

    seed_call = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_table_seed_function_call"
    )
    assert seed_call["arguments"] == [
        {
            "entries": [
                {
                    "key": "count",
                    "key_type": "string",
                    "value": 2,
                    "value_type": "number",
                },
                {
                    "key": "probe",
                    "key_type": "string",
                    "value": True,
                    "value_type": "boolean",
                },
            ],
            "type": "table",
        }
    ]


def test_trace_vm_fetches_loaded_mods_fixture_seeds_postinit_functions() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        local mods = KnownModIndex:GetModsToLoad(true)
        if opcode == 7 then
          local mod = ModManager:GetMod(mods[1])
          local postinitfns = rawget(mod, "postinitfns")
          return debug.getupvalue(postinitfns.ProbeFlat[1], 2)
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_mod_manager_result_fields": True,
            "mod_environment_fields": {
                "ls_skineddata": {},
                "postinitfns": {},
            },
            "seed_postinit_probe_functions": True,
        },
    )
    operations = [event["op"] for event in report["fixture_events"]]
    assert "postinit_probe_seed" in operations
    getupvalue_event = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "debug_getupvalue"
    )
    assert getupvalue_event["index"] == 2
    assert getupvalue_event["value_type"] == "table"


def test_trace_vm_fetches_seeds_legion_signature_upvalue_names() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        local mods = KnownModIndex:GetModsToLoad(true)
        if opcode == 7 then
          local mod = ModManager:GetMod(mods[1])
          local fn = mod.postinitfns.LegionSignatureProbe[1]
          for index = 1, 8 do
            if debug.getupvalue(fn, index) == nil then break end
          end
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_mod_manager_result_fields": True,
            "mod_environment_fields": {"postinitfns": {}},
            "seed_legion_signature_probe_function": True,
        },
    )

    names = {
        event["name"]
        for event in report["fixture_events"]
        if event["op"] == "debug_getupvalue" and "name" in event
    }
    assert {"CU", "qU", "oU", "cU"}.issubset(names)


def test_trace_vm_fetches_can_seed_legion_qU_identity_upvalue() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        local mods = KnownModIndex:GetModsToLoad(true)
        if opcode == 7 then
          local mod = ModManager:GetMod(mods[1])
          local fn = mod.postinitfns.LegionSignatureProbe[1]
          local _, qU = debug.getupvalue(fn, 3)
          return debug.getupvalue(qU, 1)
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_mod_manager_result_fields": True,
            "mod_environment_fields": {
                "postinitfns": {},
                "ls_skineddata": {},
            },
            "probe_mod_seed_tables": True,
            "seed_legion_signature_probe_function": True,
            "legion_qU_first_upvalue": "ls_skineddata",
        },
    )

    getupvalue_events = [
        event
        for event in report["fixture_events"]
        if event["op"] == "debug_getupvalue"
    ]
    assert getupvalue_events[-1]["name"] == "captured"
    assert getupvalue_events[-1]["value_role"] == (
        "fixture_probe_table:ls_skineddata"
    )


def test_trace_vm_fetches_can_seed_legion_exports() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        local mods = KnownModIndex:GetModsToLoad(true)
        if opcode == 7 then
          local mod = ModManager:GetMod(mods[1])
          return mod.LS_C_Init("probe")
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_mod_manager_result_fields": True,
            "seed_legion_export_functions": True,
            "record_fixture_mod_environment_final_state": True,
        },
    )

    call = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "legion_export_call"
    )
    assert call == {
        "argument_count": 1,
        "name": "LS_C_Init",
        "op": "legion_export_call",
    }
    final_state = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "mod_environment_final_state"
    )
    assert final_state["entries"] == [
        {"key": "LS_C_Init", "value_type": "function"},
        {"key": "LS_C_Reskin", "value_type": "function"},
        {"key": "LS_C_Set", "value_type": "function"},
    ]


def test_trace_vm_fetches_can_invoke_legion_signature_upvalues() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        local mods = KnownModIndex:GetModsToLoad(true)
        if opcode == 7 then ModManager:GetMod(mods[1]) end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_mod_manager_result_fields": True,
            "mod_environment_fields": {"postinitfns": {}},
            "seed_legion_signature_probe_function": True,
            "invoke_legion_patched_upvalues": True,
        },
    )

    calls = [
        event
        for event in report["fixture_events"]
        if event["op"] == "legion_patched_upvalue_call"
    ]
    assert len(calls) == 21
    assert {event["upvalue"] for event in calls} == {"CU", "oU", "cU"}
    assert all(event["ok"] for event in calls)


def test_trace_vm_fetches_loaded_mods_fixture_scans_mod_environment() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        local mods = KnownModIndex:GetModsToLoad(true)
        if opcode == 7 then
          local mod = ModManager:GetMod(mods[1])
          for _, fn in pairs(mod) do
            if type(fn) == "function" then
              debug.getupvalue(fn, 1)
            end
          end
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_mod_manager_result_fields": True,
            "probe_mod_environment_functions": True,
            "probe_mod_environment_pairs": True,
        },
    )
    assert report["ok"] is True
    assert [event["op"] for event in report["fixture_events"]] == [
        "get_mods_to_load",
        "mod_manager_index",
        "mod_manager_call",
        "mod_environment_pairs",
        "debug_getupvalue",
    ]
    assert report["fixture_events"][4]["index"] == 1


def test_trace_vm_fetches_records_mod_environment_raw_access() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        local mods = KnownModIndex:GetModsToLoad(true)
        if opcode == 7 then
          local mod = ModManager:GetMod(mods[1])
          local value = rawget(mod, "Configured")
          rawset(mod, "Changed", value)
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_mod_manager_result_fields": True,
            "mod_environment_fields": {"Configured": 7},
            "probe_mod_environment_raw_access": True,
        },
    )

    accesses = [
        event
        for event in report["fixture_events"]
        if event["op"].startswith("mod_environment_raw")
    ]
    assert accesses == [
        {
            "op": "mod_environment_rawget",
            "key": "Configured",
            "value_type": "number",
        },
        {
            "op": "mod_environment_rawset",
            "key": "Changed",
            "value_type": "number",
        },
    ]


def test_trace_vm_fetches_seeds_mod_function_chunk_source() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        local mods = KnownModIndex:GetModsToLoad(true)
        if opcode == 7 then ModManager:GetMod(mods[1]) end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "probe_mod_manager_result_fields": True,
            "mod_environment_function_fields": ["RegisterSkin"],
            "mod_environment_function_sources": {
                "RegisterSkin": "@../mods/workshop-test/modmain.lua"
            },
        },
    )

    event = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "mod_environment_source_function_seed"
    )
    assert event == {
        "op": "mod_environment_source_function_seed",
        "field": "RegisterSkin",
        "source": "@../mods/workshop-test/modmain.lua",
    }


def test_minimal_vm_trace_keeps_budget_and_fixture_events() -> None:
    source = """
    return({f=function()
      local u = { 7, 9 }
      return function()
        local first = u[1]
        local mods = KnownModIndex:GetModsToLoad(true)
        return first + u[2], mods[1]
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "loaded_mods": ["workshop-test"],
            "minimal_vm_trace": True,
        },
    )

    assert report["ok"] is True
    assert report["fetch_count"] == 2
    assert report["fetches"] == {}
    assert report["fixture_events"] == [
        {"op": "get_mods_to_load", "all": True},
    ]


def test_trace_vm_fetches_can_probe_vm_registers_at_one_pc() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local z = {
          [1] = "receiver",
          [9] = true,
          [10] = string.char(0x90, 0x00),
        }
        local opcode = u[1]
        return z[1], opcode
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "vm_probe_program": 1,
            "vm_probe_pc": 1,
        },
    )
    assert report["ok"] is True
    probe = report["fixture_events"][0]
    assert probe["op"] == "vm_probe"
    assert probe["program"] == 1
    assert probe["pc"] == 1
    registers = next(
        item["slots"] for item in probe["locals"] if item["name"] == "z"
    )
    assert registers == [
        {
            "byte_length": 8,
            "index": 1,
            "type": "string",
            "value": "receiver",
        },
        {"index": 9, "type": "boolean", "value": True},
        {
            "byte_length": 2,
            "encoding": "hex",
            "index": 10,
            "type": "string",
            "value": "9000",
        },
    ]


def test_trace_vm_fetches_can_probe_vm_registers_at_multiple_pcs() -> None:
    source = """
    return({f=function()
      local u = { 7, 9 }
      return function()
        local z = { [1] = "receiver" }
        return u[1], u[2], z[1]
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "vm_probe_program": 1,
            "vm_probe_pcs": {1: True, 2: True},
        },
    )
    assert report["ok"] is True
    probes = [
        event for event in report["fixture_events"] if event["op"] == "vm_probe"
    ]
    assert [probe["pc"] for probe in probes] == [1, 2]


def test_trace_vm_fetches_can_alias_the_isolated_global_environment() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function() return u[1], GLOBAL.rawget(GLOBAL, "io") end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        alias_global_environment=True,
    )
    assert report["ok"] is True


def test_loaded_mod_fixture_instruments_invoked_table_arguments() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        DirectProbe = function(value)
          value.seen = value.name
          return value
        end
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={
            "kind": "loaded_mods",
            "invoke_fixture_functions": [
                {
                    "path": "GLOBAL",
                    "field": "DirectProbe",
                    "arguments": [
                        {
                            "fixture_probe": True,
                            "path": "call.argument",
                            "value": {"name": "probe"},
                        }
                    ],
                }
            ],
            "record_fixture_probe_final_state": True,
        },
    )

    final_state = next(
        event
        for event in report["fixture_events"]
        if event["op"] == "fixture_probe_table_final_state"
    )
    assert final_state == {
        "op": "fixture_probe_table_final_state",
        "path": "call.argument",
        "entries": [
            {
                "key": "name",
                "key_type": "string",
                "value": "probe",
                "byte_length": 5,
                "value_type": "string",
            },
            {
                "key": "seen",
                "key_type": "string",
                "value": "probe",
                "byte_length": 5,
                "value_type": "string",
            },
        ],
    }


def test_trace_vm_fetches_proxies_globals_and_invokes_callbacks() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        RegisterThing(opcode, function() UnknownAction("inside") end)
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        proxy_unknown_globals=True,
        callback_limit=2,
    )
    assert report["ok"] is True
    assert report["callbacks_captured"] == 1
    assert report["callbacks_invoked"] == 1
    calls = [event["path"] for event in report["global_events"] if event["op"] == "call"]
    assert calls == ["RegisterThing", "UnknownAction"]


def test_trace_vm_fetches_records_callback_nil_containing_results() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        RegisterThing(function() return "first", nil, "tail" end)
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        runtime_fixture={"record_fixture_callback_all_results": True},
        proxy_unknown_globals=True,
        callback_limit=1,
    )

    assert report["callback_results"] == [
        {
            "id": 1,
            "origin": "RegisterThing",
            "argument": 1,
            "ok": True,
            "result_count": 3,
            "results": [
                {"type": "string", "value": "first", "length": 5},
                {"type": "nil"},
                {"type": "string", "value": "tail", "length": 4},
            ],
        }
    ]


def test_trace_vm_fetches_treats_do_task_in_time_as_a_function() -> None:
    source = """
    return({f=function()
      local u = { 7 }
      return function()
        local opcode = u[1]
        RegisterThing(opcode, function(inst)
          if type(inst.DoTaskInTime) == "function" then
            inst:DoTaskInTime(0, function() UnknownAction("later") end)
          end
        end)
      end
    end}):f()(...);
    """
    report = trace_vm_fetches(
        source,
        fetch_budget=10,
        proxy_unknown_globals=True,
        callback_limit=3,
    )

    assert report["ok"] is True
    assert report["callbacks_captured"] == 2
    assert report["callbacks_invoked"] == 2
    calls = [event["path"] for event in report["global_events"] if event["op"] == "call"]
    assert calls == [
        "RegisterThing",
        "callback.1.arg1.DoTaskInTime",
        "UnknownAction",
    ]


def test_extracts_and_instantiates_opcode_handlers() -> None:
    vm_function = """
    function(...)
      local B = 1
      while true do
        local g = u[B]
        if g < 2 then
          if g == 1 then z[h[B]] = e[B] else B = O[B] end
        else
          return z[W[B]]
        end
        B = B + 1
      end
    end
    """
    loader = f"return({{f=function() return {vm_function} end}}):f()(...);"
    assert extract_root_function_source(loader).startswith("function(...)")
    handlers = extract_opcode_handlers(vm_function, [0, 1, 2])
    assert "B = O[B]" in handlers[0]
    assert "z[h[B]] = e[B]" in handlers[1]
    assert "return z[W[B]]" in handlers[2]
    assert (
        instantiate_handler(handlers[1], {"h": 3, "e": {"type": "string", "value": "x"}})
        == 'r3 = "x"'
    )


def test_handler_ranking_rejects_shared_integrity_leaf() -> None:
    vm_function = """
    function(...)
      local B = 1
      while true do
        local g = u[B]
        if C[1] then
          x, C[2] = -4, 215
          return
        elseif g < 1 then
          if g == 0 then k = U else m = U end
        else
          if g == 1 then l = U else z[h[B]] = e[B] end
        end
        B = B + 1
      end
    end
    """
    handlers = extract_opcode_handlers(vm_function, [0, 1])
    assert handlers[0].strip() == "k = U"
    assert handlers[1].strip() == "l = U"


def test_layout_and_instantiation_support_random_vm_names() -> None:
    vm_function = """
    function(...)
      local pc = 1
      repeat
        local opcode = X[pc]
        if opcode < 2 then
          if opcode == 0 then R[a[pc]] = e[pc] else pc = j[pc] end
        else
          if opcode == 2 then return R[w[pc]] else R[a[pc]] = R[w[pc]] end
        end
        pc = pc + 1
      until false
    end
    """
    layout = extract_vm_layout(vm_function)
    assert layout.pc_variable == "pc"
    assert layout.register_variable == "R"
    handlers = extract_opcode_handlers(vm_function, [0, 1, 2, 3])
    instruction = {
        "operands": {
            "a": 3,
            "e": {"type": "string", "value": "sample"},
        }
    }
    assert (
        instantiate_handler(
            handlers[0],
            instruction,
            pc_variable=layout.pc_variable,
            register_variable=layout.register_variable,
        )
        == 'r3 = "sample"'
    )


def test_handler_extraction_skips_integrity_guard_before_dispatch() -> None:
    vm_function = """
    function(...)
      local B = 1
      while true do
        local opcode = u[B]
        if C[1] then return end
        if opcode < 2 then
          if opcode == 0 then z[h[B]] = e[B] else B = O[B] end
        else
          if opcode == 2 then return z[W[B]] else z[h[B]] = z[W[B]] end
        end
        B = B + 1
      end
    end
    """
    handlers = extract_opcode_handlers(vm_function, [0, 1, 2, 3])
    assert "C[1]" not in handlers[0]
    assert "z[h[B]] = e[B]" in handlers[0]
    assert "B = O[B]" in handlers[1]


def test_readable_cleanup_removes_shared_integrity_prefix() -> None:
    prefix = "if C[1] then C[2] = 4 end"
    handlers = {
        0: f"{prefix}\nz[h[B]] = e[B]",
        1: f"{prefix}\nk = U",
        2: f"{prefix}\nl = U",
    }
    noise = derive_noise_statements(handlers)
    assert len(noise) == 1
    cleaned = sanitize_handler(handlers[0], noise)
    assert "C[1]" not in cleaned.source
    assert "z[h[B]] = e[B]" in cleaned.source


def test_readable_cleanup_unwraps_integrity_guard() -> None:
    cleaned = sanitize_handler(
        "if C[1] then return else z[h[B]] = e[B] end",
        set(),
    )
    assert cleaned.unwrapped_integrity_guards == 1
    assert cleaned.source.strip() == "z[h[B]] = e[B]"


def test_readable_cleanup_removes_pure_integrity_branch() -> None:
    cleaned = sanitize_handler(
        "if C[1] then return C[2] end\nz[h[B]] = e[B]",
        set(),
    )
    assert "C[" not in cleaned.source
    assert cleaned.source.strip() == "z[h[B]] = e[B]"


def test_readable_cleanup_removes_pure_integrity_elseif() -> None:
    cleaned = sanitize_handler(
        "if z[h[B]] then z[O[B]] = 1 elseif C[1] then return C[2] end",
        set(),
    )
    assert "C[" not in cleaned.source
    assert "elseif" not in cleaned.source
    assert "z[O[B]] = 1" in cleaned.source


def test_readable_cleanup_keeps_normal_integrity_else_state() -> None:
    cleaned = sanitize_handler(
        "if C[1] then return C[2] else state = 2 end\nz[h[B]] = state",
        set(),
    )
    assert "C[" not in cleaned.source
    assert "state = 2" in cleaned.source
    assert "z[h[B]] = 2" in cleaned.source


def test_readable_cleanup_avoids_integrity_return_in_else() -> None:
    cleaned = sanitize_handler(
        "if C[1] then else return end\nz[h[B]] = 2",
        set(),
    )
    assert "return" not in cleaned.source
    assert cleaned.source.strip() == "z[h[B]] = 2"


def test_opcode_specialization_preserves_instruction_table_writes() -> None:
    specialized = specialize_opcode_handler(
        "if g == u[B] then x = u[B] end\nu[B] = x",
        70,
        opcode_variable="g",
        instruction_upvalue="u",
        pc_variable="B",
    )
    assert specialized == "if 70 == 70 then x = 70 end\nu[B] = x"


def test_readable_cleanup_unfolds_constant_state_loop() -> None:
    cleaned = sanitize_handler(
        """
        state = 1
        while true do
            if state == 1 then
                value = 10
                state = 2
            elseif state == 2 then
                z[h[B]] = value
                break
            end
        end
        """,
        set(),
    )
    assert cleaned.unfolded_state_loops == 1
    assert "while" not in cleaned.source
    assert "z[h[B]] = 10" in cleaned.source


def test_readable_handler_rewrites_vm_jump_target() -> None:
    cleanup = HandlerCleanup(
        "B = O[B]",
        0,
        0,
        FlowShape(True, True, False, False),
    )
    source, targets = instantiate_readable_handler(cleanup, {"O": 4})
    assert source == "goto L0005"
    assert targets == [5]


def test_readable_hybrid_uses_runtime_operands_for_jump_targets() -> None:
    context = {
        "id": 1,
        "program": 1,
        "fetch_count": 1,
        "visited_pcs": [{"pc": 1, "count": 1}],
        "path_pcs": [1, 4],
        "instructions": [
            {"pc": 1, "opcode": 1, "O": 3, "operands": {"O": 3}},
            {"pc": 2, "opcode": 2},
            {"pc": 3, "opcode": 2},
            {"pc": 4, "opcode": 2},
        ],
    }
    program = {
        "id": 1,
        "instructions": [
            {"pc": 1, "opcode": 1, "O": 8, "operands": {"O": 8}},
            {"pc": 2, "opcode": 2},
            {"pc": 3, "opcode": 2},
            {"pc": 4, "opcode": 2},
        ],
    }
    hybrid = _hybridize_context(context, program)
    handlers = {
        1: HandlerCleanup(
            "B = O[B]",
            0,
            0,
            FlowShape(True, True, False, False),
        ),
        2: HandlerCleanup(
            "-- no operation",
            0,
            0,
            FlowShape(False, False, False, False),
        ),
    }

    source, _ = _render_context(
        "fixture",
        hybrid,
        handlers,
        pc_variable="B",
        register_variable="z",
    )

    assert "goto L0004" in source
    assert "goto L0009" not in source
    assert hybrid["instructions"][0]["operands"]["O"] == 8


def test_readable_handler_collapses_vm_closure_builder() -> None:
    source = """
    U = opaque_table
    k = C[48](U, V)
    C[27](k, t)
    for y = 1, 2 do V[y] = z[y] end
    r3 = k
    """
    assert simplify_known_operation(source) == "r3 = vm_closure(opaque_table)"


def test_domain_string_scoring_prioritizes_mod_semantics() -> None:
    assert domain_string_score("rawget") == 0
    assert domain_string_score("modf") == 0
    assert domain_string_score(r"\x01\x02modname") == 0
    assert domain_string_score("AddPrefabPostInit") >= 5
    assert domain_string_score("workshop-3043439883") >= 10
    assert domain_string_score("PRISM_TERRA_SKIN_BRIDGE_ACTIVE") >= 9


def test_readable_context_rewrites_out_of_range_jump_as_integrity_trap() -> None:
    handlers = {
        1: HandlerCleanup(
            "B = O[B]",
            0,
            0,
            FlowShape(True, True, False, False),
        )
    }
    source, report = _render_context(
        "sample.lua",
        {
            "id": 1,
            "program": 1,
            "fetch_count": 1,
            "visited_pcs": [{"pc": 1, "count": 1}],
            "instructions": [{"pc": 1, "opcode": 1, "O": 216}],
        },
        handlers,
        pc_variable="B",
        register_variable="z",
    )
    assert 'vm_integrity_trap("L0217")' in source
    assert "goto L0217" not in source
    assert report["unresolved_jump_targets"] == [217]


def test_readable_observed_context_marks_omitted_valid_target() -> None:
    handlers = {
        1: HandlerCleanup(
            "B = O[B]",
            0,
            0,
            FlowShape(True, True, False, False),
        )
    }
    source, report = _render_context(
        "sample.lua",
        {
            "id": 1,
            "program": 1,
            "fetch_count": 1,
            "visited_pcs": [{"pc": 1, "count": 1}],
            "instructions": [
                {"pc": 1, "opcode": 1, "O": 1},
                {"pc": 2, "opcode": 1, "O": 1},
            ],
        },
        handlers,
        pc_variable="B",
        register_variable="z",
        observed_only=True,
    )
    assert 'vm_unobserved_path("L0002")' in source
    assert "goto L0002" not in source
    assert report["instructions"] == 1


def test_readable_audit_detects_undefined_goto(tmp_path) -> None:
    readable_path = tmp_path / "sample.readable.lua"
    readable_path.write_text(
        """local function closure_context_0001(...)
    -- block L0001: predecessors [entry/unresolved], successors []
    ::L0001::
    goto L0002
end
""",
        encoding="utf-8",
    )
    cfg_path = tmp_path / "sample.cfg.json"
    cfg_path.write_text(
        json.dumps(
            {
                "outputs": {"readable": str(readable_path)},
                "handlers": 1,
                "unparsed_handler_templates": 0,
                "unresolved_handlers": 0,
                "context_reports": [
                    {
                        "id": 1,
                        "instructions": 1,
                        "unresolved_jump_targets": [],
                        "blocks": [
                            {
                                "label": "L0001",
                                "instruction_indexes": [0],
                                "successors": [],
                                "predecessors": [],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    report = audit_cfg_report(cfg_path)
    assert report["undefined_goto_labels"] == ["context 1 -> L0002"]


def test_readable_cfg_connects_jump_and_fallthrough() -> None:
    instructions = [
        ReadableInstruction(1, 1, "goto L0004", "BRANCH", [4], False, False, 1),
        ReadableInstruction(2, 2, 'r1 = "x"', "LOAD_VALUE", [], False, False, 1),
        ReadableInstruction(3, 3, "return r1", "RETURN", [], False, True, 1),
        ReadableInstruction(4, 4, "return nil", "RETURN", [], False, True, 1),
    ]
    blocks = build_basic_blocks(instructions)
    assert all(isinstance(block, BasicBlock) for block in blocks)
    assert [block.label for block in blocks] == ["L0001", "L0002", "L0004"]
    assert blocks[0].successors == ["L0004", "L0002"]
    assert blocks[2].predecessors == ["L0001"]


def test_readable_cfg_does_not_add_fallthrough_across_pc_gap() -> None:
    instructions = [
        ReadableInstruction(1, 1, "r1 = 1", "LOAD_VALUE", [], False, False, 1),
        ReadableInstruction(4, 2, "return r1", "RETURN", [], False, True, 1),
    ]
    blocks = build_basic_blocks(instructions)
    assert [block.label for block in blocks] == ["L0001", "L0004"]
    assert blocks[0].successors == []
    assert blocks[1].predecessors == []


def test_readable_reassembles_nested_table_literals() -> None:
    instructions = [
        ReadableInstruction(1, 1, "r7 = {}", "NEW_TABLE", [], False, False, 1),
        ReadableInstruction(2, 1, "r8 = {}", "NEW_TABLE", [], False, False, 1),
        ReadableInstruction(
            3, 1, 'r8["id"] = "100"', "SET_TABLE", [], False, False, 1
        ),
        ReadableInstruction(
            4, 1, 'r8["enabled"] = true', "SET_TABLE", [], False, False, 1
        ),
        ReadableInstruction(
            5, 1, 'r7["first"] = r8', "SET_TABLE", [], False, False, 1
        ),
        ReadableInstruction(6, 1, "r8 = {}", "NEW_TABLE", [], False, False, 1),
        ReadableInstruction(
            7, 1, 'r8["id"] = "200"', "SET_TABLE", [], False, False, 1
        ),
        ReadableInstruction(
            8, 1, 'r8["version"] = "2"', "SET_TABLE", [], False, False, 1
        ),
        ReadableInstruction(
            9, 1, 'r7["second"] = r8', "SET_TABLE", [], False, False, 1
        ),
    ]
    recovered = _recover_table_literals(instructions)
    assert recovered == [
        (
            "r7",
            {
                "first": {"id": '"100"', "enabled": "true"},
                "second": {"id": '"200"', "version": '"2"'},
            },
        )
    ]
    rendered = "\n".join(_render_recovered_table("mods", recovered[0][1]))
    assert "local mods = {" in rendered
    assert 'id = "100"' in rendered
    assert "enabled = true" in rendered


def test_compact_trace_round_trips_program_instructions() -> None:
    trace = {
        "program_summaries": [
            {
                "id": 1,
                "instructions": [
                    {"pc": 1, "opcode": 7, "e": {"type": "string", "value": "x"}}
                ],
            }
        ],
        "context_summaries": [
            {
                "id": 1,
                "instructions": [
                    {"pc": 1, "opcode": 7, "e": {"type": "string", "value": "x"}}
                ],
            }
        ],
    }
    expected = deepcopy(trace)
    compacted = compact_trace(trace)
    assert len(compacted["constant_pool"]) == 1
    assert len(compacted["instruction_rows"]) == 1
    assert expand_compact_trace(compacted) == expected


def test_render_semantic_lua_groups_callback_events() -> None:
    source = """
    return({f=function()
      return function()
        AddThing("sample", function(inst) inst.components.skin:Set(3) end)
      end
    end}):f()(...);
    """
    rendered = render_semantic_lua(
        "sample.lua",
        trace_payload(source, instruction_budget=50_000, callback_limit=5),
    )
    assert "callback_1 = function" in rendered
    assert 'AddThing("sample", callback_1)' in rendered
    assert "arg1.components.skin:Set(3)" in rendered
