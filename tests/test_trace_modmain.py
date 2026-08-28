from tools.trace_modmain import trace_modmain


def test_trace_modmain_captures_exports_and_callbacks() -> None:
    report = trace_modmain(
        """
        GLOBAL.setmetatable(env, {
            __index = function(_, key)
                return GLOBAL.rawget(GLOBAL, key)
            end,
        })
        assert(MissingCanary == nil)
        Exported = { nested = { enabled = true } }
        AddPrefabPostInit("probe", function() return true end)
        """,
        instruction_budget=100_000,
        snapshot_depth=3,
    )

    assert report["ok"] is True
    assert report["callbacks"] == [
        {
            "id": 1,
            "api": "AddPrefabPostInit",
            "argument": 2,
            "source": "@target_modmain.lua",
            "linedefined": 10,
            "lastlinedefined": 10,
            "nups": 0,
        }
    ]
    exported = next(
        entry for entry in report["environment"] if entry["key"] == "Exported"
    )
    nested = next(
        entry
        for entry in exported["value"]["entries"]
        if entry["key"] == "nested"
    )
    enabled = next(
        entry
        for entry in nested["value"]["entries"]
        if entry["key"] == "enabled"
    )
    assert enabled["value"] == {"type": "boolean", "value": True}
    assert {"op": "global_read", "path": "MissingCanary"} in report["events"]


def test_trace_modmain_blocks_ffi_and_jit_require() -> None:
    report = trace_modmain(
        """
        local ffi = require("ffi")
        local jit = require("jit")
        Exported = {
            pointer = ffi.cast("void *", 12),
            version = jit.version_num,
        }
        """,
        instruction_budget=100_000,
    )

    assert report["ok"] is True
    assert [
        event
        for event in report["events"]
        if event["op"] == "blocked_require"
    ] == [
        {"op": "blocked_require", "path": "ffi"},
        {"op": "blocked_require", "path": "jit"},
    ]
