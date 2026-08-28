from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from lupa.lua51 import lua_type

from tools.luraph_recover import (
    lua_table_to_python,
    make_lua51_runtime,
    normalize_permissive_escapes,
)

DEFAULT_INSTRUCTION_BUDGET = 10_000_000
DEFAULT_EVENT_LIMIT = 20_000


def trace_modmain(
    source: str,
    *,
    instruction_budget: int = DEFAULT_INSTRUCTION_BUDGET,
    event_limit: int = DEFAULT_EVENT_LIMIT,
    snapshot_depth: int = 3,
) -> dict[str, Any]:
    """Execute a non-LPH DST modmain in an isolated Lua 5.1 environment."""
    if instruction_budget <= 0:
        raise ValueError("instruction_budget must be positive")
    if event_limit <= 0:
        raise ValueError("event_limit must be positive")
    if snapshot_depth < 0:
        raise ValueError("snapshot_depth cannot be negative")

    runtime = make_lua51_runtime()
    build_runner = runtime.eval(
        r'''
        function(source, instruction_budget, event_limit, snapshot_depth)
          local raw_type = type
          local raw_tostring = tostring
          local raw_pairs = pairs
          local raw_rawget = rawget
          local raw_rawset = rawset
          local raw_setmetatable = setmetatable
          local raw_select = select
          local raw_loadstring = loadstring
          local raw_setfenv = setfenv
          local raw_xpcall = xpcall
          local raw_error = error
          local raw_math_min = math.min
          local raw_debug = debug
          local debug_getinfo = debug.getinfo
          local debug_getupvalue = debug.getupvalue
          local debug_sethook = debug.sethook
          local debug_traceback = debug.traceback

          local events = {}
          local callbacks = {}
          local callback_ids = {}
          local proxy_mt = {}

          local function append(event)
            if #events < event_limit then
              events[#events + 1] = event
            end
          end

          local function proxy_path(value)
            return raw_rawget(value, "__trace_proxy_path")
          end

          local function is_proxy(value)
            return raw_type(value) == "table"
              and proxy_path(value) ~= nil
          end

          local function register_callback(fn, api_name, argument_index)
            local callback_id = callback_ids[fn]
            if callback_id == nil then
              callback_id = #callbacks + 1
              callback_ids[fn] = callback_id
              local info = debug_getinfo(fn, "Snu")
              callbacks[callback_id] = {
                id = callback_id,
                api = api_name,
                argument = argument_index,
                source = info and info.source or nil,
                linedefined = info and info.linedefined or nil,
                lastlinedefined = info and info.lastlinedefined or nil,
                nups = info and info.nups or nil,
              }
            end
            return callback_id
          end

          local function describe(value, api_name, argument_index)
            local kind = raw_type(value)
            local output = { type = kind }
            if kind == "string" then
              output.value = #value <= 300 and value or nil
              output.length = #value
            elseif kind == "number" or kind == "boolean" then
              output.value = value
            elseif kind == "function" then
              output.callback = register_callback(
                value, api_name, argument_index
              )
            elseif is_proxy(value) then
              output.path = proxy_path(value)
            end
            return output
          end

          local function new_proxy(path)
            return raw_setmetatable({ __trace_proxy_path = path }, proxy_mt)
          end

          proxy_mt.__index = function(self, key)
            local path = proxy_path(self) .. "." .. raw_tostring(key)
            append({ op = "proxy_index", path = path })
            return new_proxy(path)
          end
          proxy_mt.__newindex = function(self, key, value)
            append({
              op = "proxy_set",
              path = proxy_path(self) .. "." .. raw_tostring(key),
              value = describe(value, proxy_path(self), 0),
            })
          end
          proxy_mt.__call = function(self, ...)
            local arguments = {}
            for index = 1, raw_select("#", ...) do
              arguments[index] = describe(
                raw_select(index, ...), proxy_path(self), index
              )
            end
            append({
              op = "proxy_call",
              path = proxy_path(self),
              arguments = arguments,
            })
            return new_proxy(proxy_path(self) .. "()")
          end
          proxy_mt.__tostring = function(self) return proxy_path(self) end
          proxy_mt.__len = function() return 0 end
          proxy_mt.__unm = function(self)
            return new_proxy("-(" .. proxy_path(self) .. ")")
          end
          proxy_mt.__add = function(left, right)
            return new_proxy(
              "(" .. raw_tostring(left) .. "+" .. raw_tostring(right) .. ")"
            )
          end
          proxy_mt.__sub = function(left, right)
            return new_proxy(
              "(" .. raw_tostring(left) .. "-" .. raw_tostring(right) .. ")"
            )
          end
          proxy_mt.__mul = function(left, right)
            return new_proxy(
              "(" .. raw_tostring(left) .. "*" .. raw_tostring(right) .. ")"
            )
          end
          proxy_mt.__div = function(left, right)
            return new_proxy(
              "(" .. raw_tostring(left) .. "/" .. raw_tostring(right) .. ")"
            )
          end
          proxy_mt.__mod = function(left, right)
            return new_proxy(
              "(" .. raw_tostring(left) .. "%" .. raw_tostring(right) .. ")"
            )
          end
          proxy_mt.__pow = function(left, right)
            return new_proxy(
              "(" .. raw_tostring(left) .. "^" .. raw_tostring(right) .. ")"
            )
          end
          proxy_mt.__concat = function(left, right)
            return new_proxy(
              "(" .. raw_tostring(left) .. ".." .. raw_tostring(right) .. ")"
            )
          end
          proxy_mt.__eq = function() return false end
          proxy_mt.__lt = function() return false end
          proxy_mt.__le = function() return false end

          local function make_api(name, result)
            return function(...)
              local arguments = {}
              for index = 1, raw_select("#", ...) do
                arguments[index] = describe(
                  raw_select(index, ...), name, index
                )
              end
              append({ op = "api_call", path = name, arguments = arguments })
              return result
            end
          end

          local safe_global = {}
          for key, value in raw_pairs(_G) do
            safe_global[key] = value
          end
          safe_global.io = nil
          safe_global.os = nil
          safe_global.package = nil
          safe_global.require = nil
          safe_global.dofile = nil
          safe_global.loadfile = nil
          safe_global.module = nil
          safe_global.ffi = nil
          safe_global.jit = nil
          safe_global.python = nil
          safe_global.GLOBAL = safe_global

          local raw_global_rawget = raw_rawget
          safe_global.rawget = function(owner, key)
            local value = raw_global_rawget(owner, key)
            if owner == safe_global and value == nil then
              local path = raw_tostring(key)
              append({ op = "global_read", path = path })
            end
            return value
          end

          local ffi_calls = raw_setmetatable({}, {
            __index = function(owner, key)
              local fn = function(...)
                append({
                  op = "blocked_ffi_call",
                  path = "ffi.C." .. raw_tostring(key),
                })
                return 0
              end
              raw_rawset(owner, key, fn)
              return fn
            end,
          })
          local ffi_stub = {
            C = ffi_calls,
            abi = function() return false end,
            cdef = function() return nil end,
            cast = function() return 0 end,
            copy = function() return nil end,
            errno = function() return 0 end,
            fill = function() return nil end,
            gc = function(value) return value end,
            istype = function() return false end,
            load = function() return ffi_calls end,
            metatype = function(_, value) return value end,
            new = function() return 0 end,
            sizeof = function() return 0 end,
            string = function() return "" end,
            typeof = function()
              return function() return 0 end
            end,
          }
          local jit_stub = {
            arch = "x64",
            os = "Windows",
            version = "LuaJIT 2.1.0",
            version_num = 20100,
            attach = function() return nil end,
            flush = function() return nil end,
            off = function() return nil end,
            on = function() return nil end,
            status = function() return false end,
          }
          safe_global.ffi = ffi_stub
          safe_global.jit = jit_stub
          safe_global.require = function(name)
            append({ op = "blocked_require", path = raw_tostring(name) })
            if name == "ffi" then return ffi_stub end
            if name == "jit" then return jit_stub end
            if name == "jit.util" then return new_proxy("jit.util") end
            return nil
          end

          local nil_apis = {
            "AddClassPostConstruct",
            "AddComponentPostInit",
            "AddGamePostInit",
            "AddGlobalClassPostConstruct",
            "AddModRPCHandler",
            "AddClientModRPCHandler",
            "AddPlayerPostInit",
            "AddPrefabPostInit",
            "AddPrefabPostInitAny",
            "AddReplicableComponent",
            "AddSimPostInit",
            "AddStategraphActionHandler",
            "AddStategraphEvent",
            "AddStategraphPostInit",
            "AddStategraphState",
            "AddUserCommand",
            "modimport",
          }
          for _, name in raw_pairs(nil_apis) do
            safe_global[name] = make_api(name, nil)
          end
          safe_global.GetModConfigData = make_api("GetModConfigData", nil)
          safe_global.Asset = make_api("Asset", new_proxy("Asset.result"))
          safe_global.TUNING = new_proxy("TUNING")
          safe_global.STRINGS = new_proxy("STRINGS")
          safe_global.ACTIONS = new_proxy("ACTIONS")
          safe_global.bit = safe_global.bit32
          safe_global.json = {
            decode = function() return {} end,
            encode = function() return "{}" end,
          }
          safe_global.MODROOT = "modroot/"
          safe_global.PrefabFiles = {}
          safe_global.Assets = {}

          local environment = { GLOBAL = safe_global }
          environment.env = environment
          raw_setmetatable(environment, {
            __index = function(_, key)
              return safe_global.rawget(safe_global, key)
            end,
          })

          local wrapped = "return function(...)\n" .. source .. "\nend"
          local compiled, compile_error = raw_loadstring(
            wrapped, "@target_modmain.lua"
          )
          if compiled == nil then
            return {
              ok = false,
              error = raw_tostring(compile_error),
              events = events,
              callbacks = callbacks,
              environment = {},
            }
          end
          raw_setfenv(compiled, environment)
          local target = compiled()
          raw_setfenv(target, environment)

          local executed = 0
          local quantum = raw_math_min(1000, instruction_budget)
          local function hook()
            executed = executed + quantum
            if executed >= instruction_budget then
              raw_error("instruction budget exceeded", 0)
            end
          end
          local function on_error(message)
            return debug_traceback(raw_tostring(message), 2)
          end
          debug_sethook(hook, "", quantum)
          local ok, error_message = raw_xpcall(target, on_error)
          debug_sethook(nil, "", 0)

          local function snapshot(value, depth, seen)
            local kind = raw_type(value)
            local output = { type = kind }
            if kind == "string" then
              output.value = #value <= 500 and value or nil
              output.length = #value
            elseif kind == "number" or kind == "boolean" then
              output.value = value
            elseif kind == "function" then
              local info = debug_getinfo(value, "Snu")
              output.source = info and info.source or nil
              output.linedefined = info and info.linedefined or nil
              output.nups = info and info.nups or nil
              local upvalues = {}
              for index = 1, (info and info.nups or 0) do
                local name, upvalue = debug_getupvalue(value, index)
                upvalues[#upvalues + 1] = {
                  index = index,
                  name = name,
                  type = raw_type(upvalue),
                }
              end
              output.upvalues = upvalues
            elseif is_proxy(value) then
              output.path = proxy_path(value)
            elseif kind == "table" and depth > 0 and not seen[value] then
              seen[value] = true
              local entries = {}
              for key, child in raw_pairs(value) do
                entries[#entries + 1] = {
                  key = raw_tostring(key),
                  key_type = raw_type(key),
                  value = snapshot(child, depth - 1, seen),
                }
              end
              output.entries = entries
              output.entry_count = #entries
            end
            return output
          end

          local environment_entries = {}
          for key, value in raw_pairs(environment) do
            if key ~= "GLOBAL" and key ~= "env" and key ~= "newproxy" then
              environment_entries[#environment_entries + 1] = {
                key = raw_tostring(key),
                key_type = raw_type(key),
                value = snapshot(value, snapshot_depth, {}),
              }
            end
          end

          raw_rawset(_G, "debug", raw_debug)
          return {
            ok = ok,
            error = ok and nil or raw_tostring(error_message),
            instructions = executed,
            event_overflow = #events >= event_limit,
            events = events,
            callbacks = callbacks,
            environment = environment_entries,
          }
        end
        ''',
    )
    report = build_runner(
        normalize_permissive_escapes(source),
        instruction_budget,
        event_limit,
        snapshot_depth,
    )
    return lua_table_to_python(report, type_checker=lua_type)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Trace a non-LPH DST modmain in an isolated Lua 5.1 runtime."
    )
    parser.add_argument("source", type=Path)
    parser.add_argument(
        "--instruction-budget", type=int, default=DEFAULT_INSTRUCTION_BUDGET
    )
    parser.add_argument("--event-limit", type=int, default=DEFAULT_EVENT_LIMIT)
    parser.add_argument("--snapshot-depth", type=int, default=3)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    report = trace_modmain(
        args.source.read_text(encoding="utf-8"),
        instruction_budget=args.instruction_budget,
        event_limit=args.event_limit,
        snapshot_depth=args.snapshot_depth,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
