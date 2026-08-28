from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from lupa.lua51 import LuaRuntime as Lua51Runtime
from lupa.lua51 import lua_type as lua51_type
from lupa.luajit21 import LuaRuntime, lua_type

LONG_STRING_RE = re.compile(r"\[=\[(.*?)\]=\]", re.DOTALL)
TAIL_CALL_RE = re.compile(r"\(\.\.\.\);(?P<suffix>\s*)$")
LUA_51_ESCAPES = frozenset("abfnrtv\\\"'")
DEFAULT_INSTRUCTION_BUDGET = 2_000_000
DEFAULT_VM_FETCH_BUDGET = 100_000
DEFAULT_CALLBACK_LIMIT = 200
DEFAULT_EVENT_LIMIT = 50_000
BLOCKED_ENVIRONMENT_OVERRIDES = frozenset(
    {
        "dofile",
        "ffi",
        "io",
        "jit",
        "load",
        "loadfile",
        "loadstring",
        "module",
        "os",
        "package",
        "python",
        "require",
    }
)


class RecoveryError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class PayloadInfo:
    source: str
    marker: str
    encoded_size: int
    decoded_size: int
    sha256: str


def extract_payload(source: str) -> str:
    matches = LONG_STRING_RE.findall(source)
    payloads = [value for value in matches if value.startswith("LPH")]
    if len(payloads) != 1:
        raise RecoveryError(f"expected one LPH payload, found {len(payloads)}")
    return payloads[0]


def decode_lph_base85(payload: str) -> bytes:
    if len(payload) < 4 or not payload.startswith("LPH"):
        raise RecoveryError("payload does not have an LPH header")

    encoded = payload[4:].replace("z", "!!!!!")
    if len(encoded) % 5:
        raise RecoveryError("expanded ASCII85 payload is not aligned to 5 bytes")

    decoded = bytearray(len(encoded) // 5 * 4)
    offset = 0
    for index in range(0, len(encoded), 5):
        value = 0
        for char in encoded[index : index + 5]:
            digit = ord(char) - 33
            if not 0 <= digit < 85:
                raise RecoveryError(f"invalid ASCII85 character {char!r}")
            value = value * 85 + digit
        struct.pack_into("<I", decoded, offset, value & 0xFFFF_FFFF)
        offset += 4
    return bytes(decoded)


def suppress_payload_invocation(source: str) -> str:
    patched, count = TAIL_CALL_RE.subn(r";\g<suffix>", source, count=1)
    if count != 1:
        raise RecoveryError("could not locate the final Luraph payload invocation")
    return patched


def normalize_permissive_escapes(source: str) -> str:
    """Match the permissive unknown-escape behaviour expected by the loader."""
    output: list[str] = []
    index = 0
    while index < len(source):
        if source.startswith("[=[", index):
            end = source.find("]=]", index + 3)
            if end < 0:
                raise RecoveryError("unterminated Lua long string")
            output.append(source[index : end + 3])
            index = end + 3
            continue

        quote = source[index]
        if quote not in "\"'":
            output.append(quote)
            index += 1
            continue

        output.append(quote)
        index += 1
        while index < len(source):
            char = source[index]
            if char == quote:
                output.append(char)
                index += 1
                break
            if char != "\\":
                output.append(char)
                index += 1
                continue

            if index + 1 >= len(source):
                raise RecoveryError("unterminated escape sequence")
            escaped = source[index + 1]
            if escaped.isdigit():
                end = index + 2
                while end < len(source) and end < index + 4 and source[end].isdigit():
                    end += 1
                output.append(source[index:end])
                index = end
            elif escaped in LUA_51_ESCAPES or escaped in "\r\n":
                output.append(source[index : index + 2])
                index += 2
            else:
                output.append(escaped)
                index += 2
        else:
            raise RecoveryError("unterminated Lua short string")

    return "".join(output)


def make_lua_runtime() -> LuaRuntime:
    runtime = LuaRuntime(
        encoding="utf-8",
        unpack_returned_tuples=True,
        register_eval=False,
        register_builtins=False,
        max_memory=512 * 1024 * 1024,
    )
    runtime.execute(
        """
        io = nil
        os = nil
        package = nil
        require = nil
        dofile = nil
        loadfile = nil
        module = nil
        ffi = nil
        jit = nil
        python = nil
        """
    )
    return runtime


def make_lua51_runtime() -> Lua51Runtime:
    runtime = Lua51Runtime(
        encoding="utf-8",
        unpack_returned_tuples=True,
        register_eval=False,
        register_builtins=False,
        max_memory=512 * 1024 * 1024,
    )
    runtime.execute(
        r"""
        do
          local UINT32 = 4294967296
          local UINT31 = 2147483648
          local floor = math.floor
          local function norm(value) return value % UINT32 end
          local function binary(left, right, mode)
            left, right = norm(left), norm(right)
            local output, place = 0, 1
            for _ = 1, 32 do
              local a, b = left % 2, right % 2
              local include = (mode == "and" and a == 1 and b == 1)
                or (mode == "or" and (a == 1 or b == 1))
                or (mode == "xor" and a ~= b)
              if include then output = output + place end
              left, right, place = floor(left / 2), floor(right / 2), place * 2
            end
            return output
          end
          bit32 = {}
          function bit32.band(...)
            local output = UINT32 - 1
            for index = 1, select("#", ...) do
              output = binary(output, (select(index, ...)), "and")
            end
            return output
          end
          function bit32.bor(...)
            local output = 0
            for index = 1, select("#", ...) do
              output = binary(output, (select(index, ...)), "or")
            end
            return output
          end
          function bit32.bxor(...)
            local output = 0
            for index = 1, select("#", ...) do
              output = binary(output, (select(index, ...)), "xor")
            end
            return output
          end
          function bit32.bnot(value) return UINT32 - 1 - norm(value) end
          function bit32.lshift(value, displacement)
            if displacement < 0 then return bit32.rshift(value, -displacement) end
            if displacement >= 32 then return 0 end
            return norm(norm(value) * 2 ^ displacement)
          end
          function bit32.rshift(value, displacement)
            if displacement < 0 then return bit32.lshift(value, -displacement) end
            if displacement >= 32 then return 0 end
            return floor(norm(value) / 2 ^ displacement)
          end
          function bit32.arshift(value, displacement)
            if displacement < 0 then return bit32.lshift(value, -displacement) end
            value = norm(value)
            if displacement >= 32 then return value >= UINT31 and UINT32 - 1 or 0 end
            if value >= UINT31 then value = value - UINT32 end
            return norm(floor(value / 2 ^ displacement))
          end
          function bit32.lrotate(value, displacement)
            displacement = displacement % 32
            return norm(bit32.lshift(value, displacement)
              + bit32.rshift(value, 32 - displacement))
          end
          function bit32.rrotate(value, displacement)
            return bit32.lrotate(value, -displacement)
          end
          function bit32.extract(value, field, width)
            width = width or 1
            return bit32.band(bit32.rshift(value, field), 2 ^ width - 1)
          end
          function bit32.replace(value, replacement, field, width)
            width = width or 1
            local mask = bit32.lshift(2 ^ width - 1, field)
            return bit32.bor(
              bit32.band(value, bit32.bnot(mask)),
              bit32.band(bit32.lshift(replacement, field), mask)
            )
          end
          function bit32.btest(...) return bit32.band(...) ~= 0 end
        end
        io = nil
        os = nil
        package = nil
        require = nil
        dofile = nil
        loadfile = nil
        module = nil
        python = nil
        """
    )
    return runtime


def capture_root_closure(
    source: str, *, chunk_name: str = "@luraph.lua", use_lua51: bool = False
) -> tuple[Any, Any]:
    runtime = make_lua51_runtime() if use_lua51 else make_lua_runtime()
    type_checker = lua51_type if use_lua51 else lua_type
    patched = normalize_permissive_escapes(suppress_payload_invocation(source))
    closure = runtime.execute(patched, name=chunk_name)
    if type_checker(closure) != "function":
        raise RecoveryError(f"loader returned {type_checker(closure)!r}, not a function")
    return runtime, closure


def dump_root_bytecode(source: str) -> bytes:
    runtime = LuaRuntime(
        encoding=None,
        unpack_returned_tuples=True,
        register_eval=False,
        register_builtins=False,
        max_memory=512 * 1024 * 1024,
    )
    runtime.execute(
        b"io=nil;os=nil;package=nil;require=nil;dofile=nil;loadfile=nil;module=nil;ffi=nil;jit=nil"
    )
    patched = normalize_permissive_escapes(suppress_payload_invocation(source))
    closure = runtime.execute(patched.encode("utf-8"), name=b"@luraph.lua")
    if lua_type(closure) != "function":
        raise RecoveryError("loader did not return a root closure for bytecode export")
    dumped = runtime.eval(b"string.dump")(closure)
    if not isinstance(dumped, bytes):
        raise RecoveryError("LuaJIT string.dump did not return bytes")
    return dumped


def trace_payload(
    source: str,
    *,
    instruction_budget: int = DEFAULT_INSTRUCTION_BUDGET,
    callback_limit: int = DEFAULT_CALLBACK_LIMIT,
    event_limit: int = DEFAULT_EVENT_LIMIT,
    proxy_unknown_globals: bool = True,
) -> dict[str, Any]:
    """Run the protected closure against inert proxies and record observable behaviour."""
    if instruction_budget < 0:
        raise ValueError("instruction_budget cannot be negative")
    if callback_limit < 0:
        raise ValueError("callback_limit cannot be negative")
    if event_limit <= 0:
        raise ValueError("event_limit must be positive")

    runtime, closure = capture_root_closure(source, use_lua51=True)
    install_tracer = runtime.eval(
        r'''
        function(target, instruction_budget, callback_limit, event_limit, proxy_unknown_globals)
          local raw_type = type
          local raw_tostring = tostring
          local raw_pairs = pairs
          local raw_setmetatable = setmetatable
          local raw_getmetatable = getmetatable
          local raw_rawget = rawget
          local raw_rawset = rawset
          local raw_unpack = unpack
          local raw_xpcall = xpcall
          local raw_error = error
          local raw_loadstring = loadstring
          local raw_math_min = math.min
          local raw_string_byte = string.byte
          local raw_string_char = string.char
          local raw_string_find = string.find
          local raw_string_format = string.format
          local raw_table_concat = table.concat
          local raw_debug = debug
          local debug_sethook = debug.sethook
          local debug_getinfo = debug.getinfo
          local debug_getlocal = debug.getlocal
          local debug_getupvalue = debug.getupvalue
          local debug_setupvalue = debug.setupvalue
          local debug_traceback = debug.traceback

          local events = {}
          local callbacks = {}
          local callback_ids = {}
          local callback_functions = {}
          local loaded_sources = {}
          local budget_snapshots = {}
          local event_overflow = false
          local current_scope = "root"
          local proxy_mt = {}

          local function escape_string(value, maximum)
            local output = {}
            local limit = raw_math_min(#value, maximum)
            for index = 1, limit do
              local byte = raw_string_byte(value, index)
              if byte >= 32 and byte <= 126 and byte ~= 34 and byte ~= 92 then
                output[#output + 1] = raw_string_char(byte)
              elseif byte == 34 then
                output[#output + 1] = '\\"'
              elseif byte == 92 then
                output[#output + 1] = '\\\\'
              else
                output[#output + 1] = raw_string_format("\\x%02x", byte)
              end
            end
            if #value > maximum then
              output[#output + 1] = raw_string_format("...<%d bytes>", #value)
            end
            return raw_table_concat(output)
          end

          local function append(event)
            if #events < event_limit then
              event.sequence = #events + 1
              event.scope = current_scope
              events[#events + 1] = event
            else
              event_overflow = true
            end
          end

          local function is_proxy(value)
            return raw_type(value) == "table" and raw_rawget(value, "__trace_proxy") == true
          end

          local function proxy_path(value)
            return raw_rawget(value, "__trace_path")
          end

          local function register_callback(fn, path, argument)
            local callback_id = callback_ids[fn]
            if callback_id ~= nil then return callback_id end
            callback_id = #callbacks + 1
            callback_ids[fn] = callback_id
            callback_functions[callback_id] = fn
            local info = debug_getinfo(fn, "Snu")
            callbacks[callback_id] = {
              id = callback_id,
              origin_scope = current_scope,
              origin_path = path,
              argument = argument,
              what = info.what,
              source = info.source,
              linedefined = info.linedefined,
              lastlinedefined = info.lastlinedefined,
              nups = info.nups,
              status = "captured",
            }
            return callback_id
          end

          local function describe(value, path, argument)
            local kind = raw_type(value)
            if kind == "nil" then return { type = "nil" } end
            if kind == "string" then
              return { type = "string", value = escape_string(value, 1000), length = #value }
            end
            if kind == "number" or kind == "boolean" then
              return { type = kind, value = value }
            end
            if kind == "function" then
              return {
                type = "function",
                callback = register_callback(value, path, argument),
              }
            end
            if is_proxy(value) then
              return { type = "proxy", path = proxy_path(value) }
            end
            return { type = kind, value = escape_string(raw_tostring(value), 240) }
          end

          local function new_proxy(path)
            return raw_setmetatable(
              { __trace_proxy = true, __trace_path = path },
              proxy_mt
            )
          end

          proxy_mt.__index = function(self, key)
            local key_text = raw_type(key) == "string" and key or raw_tostring(key)
            local path = proxy_path(self) .. "." .. key_text
            append({ op = "index", path = path, key = describe(key, path, 0) })
            return new_proxy(path)
          end
          proxy_mt.__newindex = function(self, key, value)
            local key_text = raw_type(key) == "string" and key or raw_tostring(key)
            local path = proxy_path(self) .. "." .. key_text
            append({ op = "set", path = path, value = describe(value, path, 0) })
          end
          proxy_mt.__call = function(self, ...)
            local path = proxy_path(self)
            local arguments = { ... }
            local rendered = {}
            for index = 1, #arguments do
              rendered[index] = describe(arguments[index], path, index)
            end
            append({ op = "call", path = path, args = rendered })
            return new_proxy(path .. "()")
          end
          proxy_mt.__tostring = function(self) return proxy_path(self) end
          proxy_mt.__len = function() return 0 end
          proxy_mt.__unm = function(self) return new_proxy("-(" .. proxy_path(self) .. ")") end
          proxy_mt.__add = function(left, right)
            return new_proxy("(" .. raw_tostring(left) .. "+" .. raw_tostring(right) .. ")")
          end
          proxy_mt.__sub = function(left, right)
            return new_proxy("(" .. raw_tostring(left) .. "-" .. raw_tostring(right) .. ")")
          end
          proxy_mt.__mul = function(left, right)
            return new_proxy("(" .. raw_tostring(left) .. "*" .. raw_tostring(right) .. ")")
          end
          proxy_mt.__div = function(left, right)
            return new_proxy("(" .. raw_tostring(left) .. "/" .. raw_tostring(right) .. ")")
          end
          proxy_mt.__mod = function(left, right)
            return new_proxy("(" .. raw_tostring(left) .. "%" .. raw_tostring(right) .. ")")
          end
          proxy_mt.__pow = function(left, right)
            return new_proxy("(" .. raw_tostring(left) .. "^" .. raw_tostring(right) .. ")")
          end
          proxy_mt.__concat = function(left, right)
            return new_proxy("(" .. raw_tostring(left) .. ".." .. raw_tostring(right) .. ")")
          end
          proxy_mt.__eq = function() return false end
          proxy_mt.__lt = function() return false end
          proxy_mt.__le = function() return false end
          proxy_mt.__metatable = "isolated trace proxy"

          local function blocked_function(name)
            return function(...)
              local arguments = { ... }
              local rendered = {}
              for index = 1, #arguments do
                rendered[index] = describe(arguments[index], name, index)
              end
              append({ op = "blocked_call", path = name, args = rendered })
              return new_proxy(name .. "()")
            end
          end

          local function sandbox_loadstring(code, chunk_name)
            local code_type = raw_type(code)
            local record = {
              length = code_type == "string" and #code or nil,
              source = code_type == "string" and escape_string(code, 200000) or nil,
              chunk_name = raw_type(chunk_name) == "string"
                and escape_string(chunk_name, 500) or nil,
              compiled = false,
            }
            loaded_sources[#loaded_sources + 1] = record
            local source_id = #loaded_sources
            if code_type == "string"
                and #code <= 4096
                and raw_string_find(code, "return setfenv(function", 1, true)
                and raw_string_find(code, "getfenv((...))", 1, true)
                and raw_string_byte(code, 1) ~= 27 then
              local compiled, message = raw_loadstring(code, chunk_name)
              if compiled ~= nil then
                record.compiled = true
                append({ op = "sandbox_loadstring", path = "loadstring", source = source_id })
                return compiled
              end
              record.error = escape_string(raw_tostring(message), 500)
            end
            append({ op = "captured_loadstring", path = "loadstring", source = source_id })
            return function(...)
              append({ op = "captured_chunk_call", path = "loadstring", source = source_id })
              return new_proxy("loadstring[" .. source_id .. "]()")
            end
          end

          local globals_mt = {
            __index = function(_, key)
              local path = raw_type(key) == "string" and key or raw_tostring(key)
              append({ op = "global", path = path })
              return new_proxy(path)
            end,
            __newindex = function(table_value, key, value)
              local path = raw_type(key) == "string" and key or raw_tostring(key)
              append({ op = "global_set", path = path, value = describe(value, path, 0) })
              raw_rawset(table_value, key, value)
            end,
            __metatable = "isolated trace globals",
          }

          GLOBAL = new_proxy("GLOBAL")
          env = new_proxy("env")
          load = blocked_function("load")
          loadstring = sandbox_loadstring
          require = blocked_function("require")
          dofile = blocked_function("dofile")
          loadfile = blocked_function("loadfile")
          module = blocked_function("module")
          collectgarbage = blocked_function("collectgarbage")
          io = nil
          os = nil
          package = nil
          ffi = nil
          jit = nil
          python = nil
          debug = {
            getinfo = function(target, options)
              return debug_getinfo(target, options)
            end,
            traceback = function(message, level)
              return debug_traceback(message, level)
            end,
            getupvalue = function(target, index)
              local info = debug_getinfo(target, "S")
              if info ~= nil and info.source == "@luraph.lua" then
                return debug_getupvalue(target, index)
              end
              return nil
            end,
            setupvalue = function(target, index, value)
              local info = debug_getinfo(target, "S")
              if info ~= nil and info.source == "@luraph.lua" then
                return debug_setupvalue(target, index, value)
              end
              return nil
            end,
          }
          if proxy_unknown_globals then raw_setmetatable(_G, globals_mt) end

          local function run_with_budget(fn, scope, ...)
            local arguments = { ... }
            local executed = 0
            local budget_enabled = instruction_budget > 0
            local quantum = budget_enabled and raw_math_min(1000, instruction_budget) or 0
            local previous_scope = current_scope
            current_scope = scope
            local function snapshot_value(value)
              local kind = raw_type(value)
              local result = { type = kind }
              if kind == "number" or kind == "boolean" then
                result.value = value
              elseif kind == "string" then
                result.value = escape_string(value, 240)
                result.length = #value
              elseif is_proxy(value) then
                result.path = proxy_path(value)
              elseif kind == "table" then
                local samples = {}
                for index = 1, 12 do
                  local item = raw_rawget(value, index)
                  local item_type = raw_type(item)
                  if item_type == "number" or item_type == "boolean" then
                    samples[#samples + 1] = { key = index, value = item }
                  elseif item_type == "string" then
                    samples[#samples + 1] = {
                      key = index,
                      value = escape_string(item, 80),
                    }
                  end
                end
                result.samples = samples
              end
              return result
            end
            local function capture_budget_snapshot()
              local snapshot = { scope = scope, frames = {} }
              for level = 2, 14 do
                local info = debug_getinfo(level, "Slnu")
                if info == nil then break end
                local frame = {
                  level = level,
                  source = info.source,
                  currentline = info.currentline,
                  linedefined = info.linedefined,
                  lastlinedefined = info.lastlinedefined,
                  name = info.name,
                  what = info.what,
                  nups = info.nups,
                  locals = {},
                }
                for index = 1, 40 do
                  local name, value = debug_getlocal(level, index)
                  if name == nil then break end
                  frame.locals[#frame.locals + 1] = {
                    index = index,
                    name = name,
                    value = snapshot_value(value),
                  }
                end
                snapshot.frames[#snapshot.frames + 1] = frame
              end
              budget_snapshots[#budget_snapshots + 1] = snapshot
            end
            local function hook()
              executed = executed + quantum
              if executed >= instruction_budget then
                raw_error("instruction budget exceeded", 0)
              end
            end
            local function invoke() return fn(raw_unpack(arguments)) end
            local function on_error(message)
              if raw_tostring(message) == "instruction budget exceeded" then
                capture_budget_snapshot()
              end
              return raw_tostring(message)
            end
            if budget_enabled then debug_sethook(hook, "", quantum) end
            local ok, result = raw_xpcall(invoke, on_error)
            if budget_enabled then debug_sethook(nil, "", 0) end
            append({
              op = "scope_result",
              path = scope,
              ok = ok,
              result = describe(result, scope, 0),
              instructions = executed,
            })
            current_scope = previous_scope
            return ok, result, executed
          end

          local root_ok, root_result, root_instructions = run_with_budget(target, "root")
          local next_callback = 1
          local invoked_callbacks = 0
          while next_callback <= #callbacks and invoked_callbacks < callback_limit do
            local callback = callbacks[next_callback]
            callback.status = "running"
            local callback_scope = "callback:" .. callback.id
            local ok, result, executed = run_with_budget(
              callback_functions[callback.id],
              callback_scope,
              new_proxy(callback_scope .. ".arg1"),
              new_proxy(callback_scope .. ".arg2"),
              new_proxy(callback_scope .. ".arg3"),
              new_proxy(callback_scope .. ".arg4")
            )
            callback.status = ok and "completed" or "errored"
            callback.error = ok and nil or escape_string(raw_tostring(result), 500)
            callback.instructions = executed
            invoked_callbacks = invoked_callbacks + 1
            next_callback = next_callback + 1
          end

          debug_sethook(nil, "", 0)
          raw_rawset(_G, "debug", raw_debug)
          return {
            root = {
              ok = root_ok,
              error = root_ok and nil or escape_string(raw_tostring(root_result), 500),
              instructions = root_instructions,
            },
            callbacks = callbacks,
            events = events,
            loaded_sources = loaded_sources,
            budget_snapshots = budget_snapshots,
            event_overflow = event_overflow,
            callback_limit_reached = next_callback <= #callbacks,
            callbacks_invoked = invoked_callbacks,
          }
        end
        '''
    )
    report = install_tracer(
        closure,
        instruction_budget,
        callback_limit,
        event_limit,
        proxy_unknown_globals,
    )
    runtime.execute("debug.sethook(nil, '', 0)")
    return lua_table_to_python(report, type_checker=lua51_type)


def dump_closure_graph(
    source: str,
    *,
    max_depth: int = 8,
    max_nodes: int = 20_000,
    max_entries: int = 200_000,
    max_string: int = 16_384,
) -> dict[str, Any]:
    """Serialize the root VM closure's reachable Lua tables and functions."""
    if min(max_depth, max_nodes, max_entries, max_string) <= 0:
        raise ValueError("closure graph limits must be positive")

    runtime, closure = capture_root_closure(source)
    serialize = runtime.eval(
        r'''
        function(root, max_depth, max_nodes, max_entries, max_string)
          local nodes = {}
          local seen = {}
          local entry_count = 0
          local node_overflow = false
          local entry_overflow = false

          local function escape_string(value)
            local output = {}
            local limit = math.min(#value, max_string)
            for index = 1, limit do
              local byte = string.byte(value, index)
              if byte >= 32 and byte <= 126 and byte ~= 34 and byte ~= 92 then
                output[#output + 1] = string.char(byte)
              elseif byte == 34 then
                output[#output + 1] = '\\"'
              elseif byte == 92 then
                output[#output + 1] = '\\\\'
              else
                output[#output + 1] = string.format("\\x%02x", byte)
              end
            end
            return table.concat(output), #value > max_string
          end

          local encode
          encode = function(value, depth)
            local kind = type(value)
            if kind == "nil" then return { type = "nil" } end
            if kind == "number" or kind == "boolean" then
              return { type = kind, value = value }
            end
            if kind == "string" then
              local escaped, truncated = escape_string(value)
              return {
                type = "string",
                value = escaped,
                length = #value,
                truncated = truncated or nil,
              }
            end
            if kind ~= "table" and kind ~= "function" then
              return { type = kind, value = tostring(value) }
            end

            local existing = seen[value]
            if existing ~= nil then return { ref = existing } end
            if #nodes >= max_nodes then
              node_overflow = true
              return { type = kind, truncated = "node_limit" }
            end

            local identifier = #nodes + 1
            seen[value] = identifier
            local node = { id = identifier, type = kind }
            nodes[identifier] = node
            if depth >= max_depth then
              node.truncated = "depth_limit"
              return { ref = identifier }
            end

            if kind == "table" then
              node.entries = {}
              for key, item in pairs(value) do
                if entry_count >= max_entries then
                  entry_overflow = true
                  node.truncated = "entry_limit"
                  break
                end
                entry_count = entry_count + 1
                node.entries[#node.entries + 1] = {
                  key = encode(key, depth + 1),
                  value = encode(item, depth + 1),
                }
              end
            else
              local info = debug.getinfo(value, "Snu")
              node.what = info.what
              node.source = info.source
              node.linedefined = info.linedefined
              node.lastlinedefined = info.lastlinedefined
              node.nups = info.nups
              node.upvalues = {}
              local index = 1
              while true do
                local name, item = debug.getupvalue(value, index)
                if name == nil then break end
                node.upvalues[#node.upvalues + 1] = {
                  index = index,
                  name = name,
                  value = encode(item, depth + 1),
                }
                index = index + 1
              end
            end
            return { ref = identifier }
          end

          return {
            root = encode(root, 0),
            nodes = nodes,
            stats = {
              nodes = #nodes,
              entries = entry_count,
              node_overflow = node_overflow,
              entry_overflow = entry_overflow,
              max_depth = max_depth,
            },
          }
        end
        '''
    )
    return lua_table_to_python(
        serialize(closure, max_depth, max_nodes, max_entries, max_string)
    )


def trace_vm_fetches(
    source: str,
    *,
    fetch_budget: int = DEFAULT_VM_FETCH_BUDGET,
    event_limit: int = DEFAULT_EVENT_LIMIT,
    include_programs: bool = False,
    pass_environment: bool = False,
    use_lua51: bool = True,
    bind_missing_environment: bool = False,
    environment_overrides: dict[str, Any] | None = None,
    runtime_fixture: dict[str, Any] | None = None,
    alias_global_environment: bool = False,
    proxy_unknown_globals: bool = False,
    callback_limit: int = 0,
    instruction_upvalue_name: str = "u",
    environment_upvalue_name: str = "j",
) -> dict[str, Any]:
    """Trace virtual instruction fetches without changing the VM operands.

    Luraph's generated interpreter reads the current opcode through its ``u``
    upvalue. Replacing only that table with a forwarding proxy exposes the
    virtual PC stream while leaving the instruction and operand values intact.
    """
    if fetch_budget <= 0:
        raise ValueError("fetch_budget must be positive")
    if event_limit <= 0:
        raise ValueError("event_limit must be positive")
    if callback_limit < 0:
        raise ValueError("callback_limit cannot be negative")
    environment_overrides = environment_overrides or {}
    runtime_fixture = runtime_fixture or {}
    blocked_overrides = BLOCKED_ENVIRONMENT_OVERRIDES.intersection(
        environment_overrides
    )
    if blocked_overrides:
        names = ", ".join(sorted(blocked_overrides))
        raise ValueError(f"unsafe environment overrides are blocked: {names}")

    runtime, closure = capture_root_closure(source, use_lua51=use_lua51)
    type_checker = lua51_type if use_lua51 else lua_type
    lua_environment_overrides = runtime.table_from(
        environment_overrides,
        recursive=True,
    )
    lua_runtime_fixture = runtime.table_from(runtime_fixture, recursive=True)
    install_tracer = runtime.eval(
        r'''
        function(target, fetch_budget, event_limit, include_programs,
          pass_environment, bind_missing_environment, environment_overrides,
          runtime_fixture,
          alias_global_environment, proxy_unknown_globals, callback_limit,
          instruction_upvalue_name, environment_upvalue_name)
          local raw_debug = debug
          local raw_error = error
          local raw_getmetatable = getmetatable
          local raw_getfenv = getfenv
          local raw_loadstring = loadstring
          local raw_pairs = pairs
          local raw_rawget = rawget
          local raw_rawset = rawset
          local raw_setmetatable = setmetatable
          local raw_setfenv = setfenv
          local raw_select = select
          local raw_unpack = unpack
          local raw_string_byte = string.byte
          local raw_string_format = string.format
          local raw_table_concat = table.concat
          local raw_table_sort = table.sort
          local raw_tostring = tostring
          local raw_xpcall = xpcall

          local function describe_probe_string(value)
            local byte_count = #value
            for byte_index = 1, byte_count do
              local byte_value = raw_string_byte(value, byte_index)
              if byte_value < 32 or byte_value > 126 then
                local encoded = {}
                local encoded_count = byte_count < 64 and byte_count or 64
                for encoded_index = 1, encoded_count do
                  encoded[#encoded + 1] = raw_string_format(
                    "%02X", raw_string_byte(value, encoded_index)
                  )
                end
                if encoded_count < byte_count then
                  encoded[#encoded + 1] = "..."
                end
                return raw_table_concat(encoded), "hex", byte_count
              end
            end
            return value, nil, byte_count
          end

          local target_environment = raw_getfenv(target)
          local original_environment_values = {}
          if alias_global_environment then
            original_environment_values[#original_environment_values + 1] = {
              key = "GLOBAL",
              present = raw_rawget(target_environment, "GLOBAL") ~= nil,
              value = raw_rawget(target_environment, "GLOBAL"),
            }
            raw_rawset(target_environment, "GLOBAL", target_environment)
          end
          for key, value in pairs(environment_overrides) do
            original_environment_values[#original_environment_values + 1] = {
              key = key,
              present = raw_rawget(target_environment, key) ~= nil,
              value = raw_rawget(target_environment, key),
            }
            raw_rawset(target_environment, key, value)
          end

          local fixture_events = {}
          local fixture_active = runtime_fixture.kind == "loaded_mods"
          local fixture_probe_table_paths = {}
          local fixture_probe_tables_by_path = {}
          local fixture_function_roles = {}
          local fixture_mod_environments = {}
          local fixture_legion_signature_functions = {}
          local pending_callbacks = {}
          local fixture_vm_program
          local fixture_vm_context
          local fixture_vm_pc
          local install_fixture_raw_access_probe
          local instrument_fixture_probe_table
          local function install_environment_value(key, value)
            original_environment_values[#original_environment_values + 1] = {
              key = key,
              present = raw_rawget(target_environment, key) ~= nil,
              value = raw_rawget(target_environment, key),
            }
            raw_rawset(target_environment, key, value)
          end
          local function known_table_role(value)
            if value == target_environment then return "target_environment" end
            if type(value) == "table"
                and raw_rawget(value, "__fixture_mod_environment") then
              return "fixture_mod_environment"
            end
            if type(value) == "table"
                and fixture_probe_table_paths[value] ~= nil then
              return "fixture_probe_table:" .. fixture_probe_table_paths[value]
            end
            local known_globals = {
              "string",
              "table",
              "math",
              "coroutine",
              "debug",
              "KnownModIndex",
              "ModManager",
            }
            for role_index = 1, #known_globals do
              local global_name = known_globals[role_index]
              if value == raw_rawget(target_environment, global_name) then
                return "global:" .. global_name
              end
            end
            return nil
          end
          if fixture_active then
            local loaded_mods = runtime_fixture.loaded_mods or {}
            if runtime_fixture.probe_mod_values then
              local probed_mods = {}
              for mod_key, mod_value in pairs(loaded_mods) do
                local probe
                probe = raw_setmetatable({ trace_value = mod_value }, {
                  __index = function(_, key)
                    fixture_events[#fixture_events + 1] = {
                      op = "mod_value_index",
                      key = raw_tostring(key),
                      value = raw_tostring(mod_value),
                    }
                    return function(...)
                      fixture_events[#fixture_events + 1] = {
                        op = "mod_value_call",
                        key = raw_tostring(key),
                        argument_count = raw_select("#", ...),
                      }
                      if runtime_fixture.mod_probe_result == nil then
                        return true
                      end
                      return runtime_fixture.mod_probe_result
                    end
                  end,
                  __tostring = function() return raw_tostring(mod_value) end,
                })
                probed_mods[mod_key] = probe
              end
              loaded_mods = probed_mods
            end
            local function make_fixture_method(first_upvalue)
              local u1, u2, u3, u4 = first_upvalue or {}, {}, {}, {}
              local u5, u6, u7, u8 = {}, {}, {}, {}
              local u9, u10, u11, u12 = {}, {}, {}, {}
              local u13, u14, u15, u16 = {}, {}, {}, {}
              return function(...)
                if raw_select("#", ...) < 0 then
                  return u1, u2, u3, u4, u5, u6, u7, u8,
                    u9, u10, u11, u12, u13, u14, u15, u16
                end
              end
            end
            local function make_fixture_method_with_upvalues(values)
              local u1, u2, u3, u4 =
                values[1], values[2], values[3], values[4]
              return function()
                return u1, u2, u3, u4
              end
            end
            local function make_fengling_skinapi_v1_method(values)
              local namemaps = values[1]
              local characterskins = values[2]
              local itemskins = values[3]
              local oldTheInventoryCheckOwnership = values[4]
              return function()
                return namemaps, characterskins, itemskins,
                  oldTheInventoryCheckOwnership
              end
            end
            local function encode_fixture_argument(value)
              local value_type = type(value)
              local encoded = { type = value_type }
              if value_type == "string" then
                encoded.value, encoded.encoding, encoded.byte_length =
                  describe_probe_string(value)
              elseif value_type == "number" or value_type == "boolean"
                  or value_type == "nil" then
                encoded.value = value
              elseif value_type == "table" then
                encoded.role = known_table_role(value)
                if runtime_fixture.record_fixture_table_argument_entries then
                  local entries = {}
                  for key, item in raw_pairs(value) do
                    local item_type = type(item)
                    local entry = {
                      key = raw_tostring(key),
                      key_type = type(key),
                      value_type = item_type,
                    }
                    if item_type == "string" then
                      entry.value, entry.encoding, entry.byte_length =
                        describe_probe_string(item)
                    elseif item_type == "number" or item_type == "boolean"
                        or item_type == "nil" then
                      entry.value = item
                    end
                    entries[#entries + 1] = entry
                  end
                  raw_table_sort(entries, function(left, right)
                    return left.key < right.key
                  end)
                  encoded.entries = entries
                end
              end
              return encoded
            end
            local function make_logged_fixture_method(first_upvalue, role)
              local base_method = make_fixture_method(first_upvalue)
              return function(...)
                local event = {
                  op = "fixture_seed_function_call",
                  function_role = role,
                  argument_count = raw_select("#", ...),
                }
                if runtime_fixture.record_fixture_seed_function_arguments then
                  local arguments = {}
                  for argument_index = 1, raw_select("#", ...) do
                    arguments[argument_index] = encode_fixture_argument(
                      raw_select(argument_index, ...)
                    )
                  end
                  event.arguments = arguments
                end
                fixture_events[#fixture_events + 1] = event
                if runtime_fixture.capture_fixture_seed_function_callbacks then
                  for argument_index = 1, raw_select("#", ...) do
                    local argument = raw_select(argument_index, ...)
                    if type(argument) == "function" then
                      pending_callbacks[#pending_callbacks + 1] = {
                        origin = role,
                        argument = argument_index,
                        fn = argument,
                      }
                    end
                  end
                end
                return base_method(...)
              end
            end
            local function make_logged_table_fixture_method(
                role, return_values)
              return function(...)
                local arguments = {}
                for argument_index = 1, raw_select("#", ...) do
                  arguments[argument_index] =
                    encode_fixture_argument(raw_select(argument_index, ...))
                end
                fixture_events[#fixture_events + 1] = {
                  op = "fixture_table_seed_function_call",
                  function_role = role,
                  argument_count = raw_select("#", ...),
                  arguments = arguments,
                }
                if return_values ~= nil then
                  return raw_unpack(
                    return_values, 1, return_values.n or #return_values
                  )
                end
              end
            end
            local function make_returning_fixture_method(return_values)
              return function()
                return raw_unpack(
                  return_values, 1, return_values.n or #return_values
                )
              end
            end
            for global_name, field_names in pairs(
                runtime_fixture.global_table_function_fields or {}) do
              local global_table = raw_rawget(target_environment, global_name)
              if type(global_table) == "table" then
                for _, field_name in pairs(field_names) do
                  local first_upvalue_names = raw_rawget(
                    runtime_fixture.global_table_function_first_upvalues or {},
                    global_name
                  )
                  local first_upvalue_name = type(first_upvalue_names) == "table"
                    and raw_rawget(first_upvalue_names, field_name) or nil
                  local first_upvalue = type(first_upvalue_name) == "string"
                    and raw_rawget(target_environment, first_upvalue_name) or nil
                  local upvalue_names_by_global = raw_rawget(
                    runtime_fixture.global_table_function_upvalue_tables or {},
                    global_name
                  )
                  local upvalue_names = type(upvalue_names_by_global) == "table"
                    and raw_rawget(upvalue_names_by_global, field_name) or nil
                  local upvalue_values
                  if type(upvalue_names) == "table" then
                    upvalue_values = {}
                    for upvalue_index = 1, 4 do
                      local upvalue_name = raw_rawget(
                        upvalue_names, upvalue_index
                      )
                      upvalue_values[upvalue_index] =
                        type(upvalue_name) == "string"
                        and raw_rawget(target_environment, upvalue_name) or nil
                    end
                  end
                  local shapes_by_global = raw_rawget(
                    runtime_fixture.global_table_function_upvalue_shapes or {},
                    global_name
                  )
                  local upvalue_shape = type(shapes_by_global) == "table"
                    and raw_rawget(shapes_by_global, field_name) or nil
                  local role = "GLOBAL." .. raw_tostring(global_name) .. "."
                    .. raw_tostring(field_name) .. ".seed"
                  local return_names_by_global = raw_rawget(
                    runtime_fixture.global_table_function_return_globals
                      or {},
                    global_name
                  )
                  local return_names = type(return_names_by_global) == "table"
                    and raw_rawget(return_names_by_global, field_name) or nil
                  local return_values
                  if type(return_names) == "table" then
                    return_values = { n = #return_names }
                    for return_index = 1, #return_names do
                      return_values[return_index] = raw_rawget(
                        target_environment, return_names[return_index]
                      )
                    end
                  end
                  local method
                  if runtime_fixture.record_fixture_table_seed_function_calls then
                    method = make_logged_table_fixture_method(
                      role, return_values
                    )
                  elseif upvalue_shape == "fengling_skinapi_v1" then
                    method = make_fengling_skinapi_v1_method(upvalue_values or {})
                  elseif upvalue_values ~= nil then
                    method = make_fixture_method_with_upvalues(upvalue_values)
                  else
                    method = make_fixture_method(first_upvalue)
                  end
                  raw_setfenv(method, target_environment)
                  raw_rawset(global_table, field_name, method)
                  fixture_function_roles[method] = role
                end
              end
            end
            for _, global_name in pairs(
                runtime_fixture.global_function_names or {}) do
              local first_upvalue_name = raw_rawget(
                runtime_fixture.global_function_first_upvalues or {},
                global_name
              )
              local first_upvalue = type(first_upvalue_name) == "string"
                and raw_rawget(target_environment, first_upvalue_name) or nil
              local role =
                "GLOBAL." .. raw_tostring(global_name) .. ".seed"
              local return_names = raw_rawget(
                runtime_fixture.global_function_return_globals or {},
                global_name
              )
              local return_values
              if type(return_names) == "table" then
                return_values = { n = #return_names }
                for return_index = 1, #return_names do
                  return_values[return_index] = raw_rawget(
                    target_environment, return_names[return_index]
                  )
                end
              end
              local method
              if runtime_fixture.record_fixture_seed_function_calls
                  and return_values ~= nil then
                method = make_logged_table_fixture_method(role, return_values)
              elseif runtime_fixture.record_fixture_seed_function_calls then
                method = make_logged_fixture_method(first_upvalue, role)
              elseif return_values ~= nil then
                method = make_returning_fixture_method(return_values)
              else
                method = make_fixture_method(first_upvalue)
              end
              raw_setfenv(method, target_environment)
              install_environment_value(global_name, method)
              fixture_function_roles[method] = role
            end
            local function make_legion_signature_method(
                buildgate_probe, kick_probe, qU_first_upvalue)
              local CU = function() end
              local qU
              if qU_first_upvalue ~= nil then
                local captured = qU_first_upvalue
                qU = function() return captured end
              else
                qU = function() end
              end
              local oU = function() end
              local cU = function() end
              return function(...)
                if raw_select("#", ...) < 0 then
                  return CU, qU, oU, cU, buildgate_probe, kick_probe
                end
              end
            end
            instrument_fixture_probe_table = function(value, path, seen)
              if type(value) ~= "table" then return value end
              seen = seen or {}
              if seen[value] then return value end
              seen[value] = true
              fixture_probe_table_paths[value] = path
              fixture_probe_tables_by_path[path] = value
              for key, item in raw_pairs(value) do
                instrument_fixture_probe_table(
                  item, path .. "." .. raw_tostring(key), seen
                )
              end
              raw_setmetatable(value, {
                __index = function(_, key)
                  fixture_events[#fixture_events + 1] = {
                    op = "fixture_probe_table_index",
                    path = path,
                    key = raw_tostring(key),
                  }
                  return nil
                end,
              })
              return value
            end
            for _, global_name in pairs(
                runtime_fixture.probe_global_tables or {}) do
              local global_value = raw_rawget(target_environment, global_name)
              instrument_fixture_probe_table(
                global_value, "GLOBAL." .. raw_tostring(global_name)
              )
            end
            for global_name, field_names in pairs(
                runtime_fixture.global_table_index_function_fields or {}) do
              local global_table = raw_rawget(target_environment, global_name)
              if type(global_table) == "table" then
                local index_table = {}
                local index_path = "GLOBAL." .. raw_tostring(global_name)
                  .. ".__index"
                for _, field_name in pairs(field_names) do
                  local role = index_path .. "."
                    .. raw_tostring(field_name) .. ".seed"
                  local method = runtime_fixture
                      .record_fixture_table_seed_function_calls
                    and make_logged_table_fixture_method(role)
                    or make_fixture_method()
                  raw_setfenv(method, target_environment)
                  raw_rawset(index_table, field_name, method)
                  fixture_function_roles[method] = role
                end
                instrument_fixture_probe_table(index_table, index_path)
                raw_setmetatable(global_table, { __index = index_table })
              end
            end
            for probe_path, field_names in pairs(
                runtime_fixture.fixture_probe_table_function_fields or {}) do
              local owner = fixture_probe_tables_by_path[probe_path]
              if type(owner) == "table" then
                for _, field_name in pairs(field_names) do
                  local role = raw_tostring(probe_path) .. "."
                    .. raw_tostring(field_name) .. ".seed"
                  local return_names_by_path = raw_rawget(
                    runtime_fixture
                      .fixture_probe_table_function_return_globals or {},
                    probe_path
                  )
                  local return_names = type(return_names_by_path) == "table"
                    and raw_rawget(return_names_by_path, field_name) or nil
                  local return_values
                  if type(return_names) == "table" then
                    return_values = { n = #return_names }
                    for return_index = 1, #return_names do
                      return_values[return_index] = raw_rawget(
                        target_environment, return_names[return_index]
                      )
                    end
                  end
                  local method
                  if runtime_fixture.record_fixture_table_seed_function_calls
                  then
                    method = make_logged_table_fixture_method(
                      role, return_values
                    )
                  elseif return_values ~= nil then
                    method = make_returning_fixture_method(return_values)
                  else
                    method = make_fixture_method()
                  end
                  raw_setfenv(method, target_environment)
                  raw_rawset(owner, field_name, method)
                  fixture_function_roles[method] = role
                end
              end
            end
            local mod_manager = raw_setmetatable({}, {
              __index = function(self, key)
                fixture_events[#fixture_events + 1] = {
                  op = "mod_manager_index",
                  key = raw_tostring(key),
                }
                if key == "GetMod"
                    and runtime_fixture.probe_mod_manager_result_fields then
                  local method = function(...)
                    fixture_events[#fixture_events + 1] = {
                      op = "mod_manager_call",
                      key = raw_tostring(key),
                      argument_count = raw_select("#", ...),
                      mod_value = raw_tostring(raw_select(2, ...)),
                    }
                    local mod_environment = {}
                    mod_environment.__fixture_mod_environment = true
                    fixture_mod_environments[#fixture_mod_environments + 1] =
                      mod_environment
                    local configured_fields =
                      runtime_fixture.mod_environment_fields
                    if type(configured_fields) == "table" then
                      local seeded_fields = {}
                      for field, value in raw_pairs(configured_fields) do
                        if runtime_fixture.probe_mod_seed_tables then
                          value = instrument_fixture_probe_table(
                            value, raw_tostring(field)
                          )
                        end
                        raw_rawset(mod_environment, field, value)
                        seeded_fields[#seeded_fields + 1] = {
                          field = raw_tostring(field),
                          value_type = type(value),
                        }
                      end
                      fixture_events[#fixture_events + 1] = {
                        op = "mod_environment_seed",
                        fields = seeded_fields,
                      }
                    end
                    for table_field, function_fields in pairs(
                        runtime_fixture
                          .mod_environment_table_function_fields or {}) do
                      local owner = raw_rawget(mod_environment, table_field)
                      if type(owner) == "table" then
                        for _, field_name in pairs(function_fields) do
                          local method = make_fixture_method()
                          raw_setfenv(method, mod_environment)
                          raw_rawset(owner, field_name, method)
                          fixture_function_roles[method] =
                            "MOD." .. raw_tostring(#fixture_mod_environments)
                            .. "." .. raw_tostring(table_field) .. "."
                            .. raw_tostring(field_name) .. ".seed"
                        end
                      end
                    end
                    for _, field_name in pairs(
                        runtime_fixture.mod_environment_function_fields or {}) do
                      local role =
                        "MOD." .. raw_tostring(#fixture_mod_environments)
                        .. "." .. raw_tostring(field_name) .. ".seed"
                      local configured_upvalue_names = raw_rawget(
                        runtime_fixture.mod_environment_function_upvalue_tables
                          or {},
                        field_name
                      )
                      local configured_upvalues = {}
                      if type(configured_upvalue_names) == "table" then
                        for upvalue_index, upvalue_name in pairs(
                            configured_upvalue_names) do
                          configured_upvalues[upvalue_index] = raw_rawget(
                            target_environment, upvalue_name
                          )
                        end
                      end
                      local first_upvalue_name = raw_rawget(
                        runtime_fixture.mod_environment_function_first_upvalues
                          or {},
                        field_name
                      )
                      local first_upvalue = type(first_upvalue_name) == "string"
                        and raw_rawget(target_environment, first_upvalue_name)
                        or nil
                      if configured_upvalues[1] == nil then
                        configured_upvalues[1] = first_upvalue
                      end
                      local upvalue_shape = raw_rawget(
                        runtime_fixture.mod_environment_function_upvalue_shapes
                          or {},
                        field_name
                      )
                      local configured_source = raw_rawget(
                        runtime_fixture.mod_environment_function_sources or {},
                        field_name
                      )
                      local configured_return_names = raw_rawget(
                        runtime_fixture
                          .mod_environment_function_return_globals or {},
                        field_name
                      )
                      local configured_return_values
                      if type(configured_return_names) == "table" then
                        configured_return_values = {
                          n = #configured_return_names,
                        }
                        for return_index = 1, #configured_return_names do
                          configured_return_values[return_index] = raw_rawget(
                            target_environment,
                            configured_return_names[return_index]
                          )
                        end
                      end
                      local method
                      if runtime_fixture.record_fixture_mod_function_calls then
                        method = make_logged_table_fixture_method(
                          role, configured_return_values
                        )
                      elseif type(configured_source) == "string" then
                        local factory = assert(raw_loadstring(
                          "return function(...) "
                            .. "local u1,u2,u3,u4,u5,u6,u7,u8,"
                            .. "u9,u10,u11,u12,u13,u14,u15,u16=... "
                            .. "return function(...) "
                            .. "if select('#',...)<0 then return "
                            .. "u1,u2,u3,u4,u5,u6,u7,u8,"
                            .. "u9,u10,u11,u12,u13,u14,u15,u16 "
                            .. "end end end",
                          configured_source
                        ))
                        raw_setfenv(factory, mod_environment)
                        local build_method = factory()
                        method = build_method(
                          configured_upvalues[1] or {},
                          configured_upvalues[2] or {},
                          configured_upvalues[3] or {},
                          configured_upvalues[4] or {},
                          {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}
                        )
                        fixture_events[#fixture_events + 1] = {
                          op = "mod_environment_source_function_seed",
                          field = field_name,
                          source = raw_debug.getinfo(method, "S").source,
                        }
                      elseif upvalue_shape == "four_explicit" then
                        method = make_fixture_method_with_upvalues(
                          configured_upvalues
                        )
                      elseif upvalue_shape == "fengling_skinapi_v1" then
                        method = make_fengling_skinapi_v1_method(
                          configured_upvalues
                        )
                      elseif configured_return_values ~= nil then
                        method = make_returning_fixture_method(
                          configured_return_values
                        )
                      else
                        method = make_fixture_method(configured_upvalues[1])
                      end
                      raw_setfenv(method, mod_environment)
                      raw_rawset(mod_environment, field_name, method)
                      fixture_function_roles[method] = role
                    end
                    if runtime_fixture.seed_legion_export_functions then
                      local export_names = {
                        "LS_C_Set",
                        "LS_C_Init",
                        "LS_C_Reskin",
                      }
                      for export_index = 1, #export_names do
                        local export_name = export_names[export_index]
                        local export_function = function(...)
                          fixture_events[#fixture_events + 1] = {
                            op = "legion_export_call",
                            name = export_name,
                            argument_count = raw_select("#", ...),
                          }
                          return runtime_fixture.legion_export_result
                        end
                        raw_setfenv(export_function, mod_environment)
                        raw_rawset(mod_environment, export_name, export_function)
                      end
                      fixture_events[#fixture_events + 1] = {
                        op = "legion_export_seed",
                        function_count = #export_names,
                      }
                    end
                    if runtime_fixture.seed_legion_signature_probe_function then
                      local postinitfns =
                        raw_rawget(mod_environment, "postinitfns")
                      if type(postinitfns) == "table" then
                        local buildgate_probe = {
                          dataname = runtime_fixture.legion_buildgate_dataname
                            or "AnimState",
                          fnname = runtime_fixture.legion_buildgate_fnname,
                        }
                        local kick_probe = { wfi7hy0ff_L = "Kick" }
                        if runtime_fixture.probe_mod_seed_tables then
                          instrument_fixture_probe_table(
                            buildgate_probe,
                            "postinitfns.LegionSignature.buildgate"
                          )
                          instrument_fixture_probe_table(
                            kick_probe,
                            "postinitfns.LegionSignature.kick"
                          )
                        end
                        local qU_first_upvalue
                        if runtime_fixture.legion_qU_first_upvalue
                            == "ls_skineddata" then
                          qU_first_upvalue =
                            raw_rawget(mod_environment, "ls_skineddata")
                        elseif runtime_fixture.legion_qU_first_upvalue
                            == "function" then
                          qU_first_upvalue = function() end
                        elseif runtime_fixture.legion_qU_first_upvalue
                            == "function_with_ls_skineddata" then
                          local identity =
                            raw_rawget(mod_environment, "ls_skineddata")
                          qU_first_upvalue = function() return identity end
                        end
                        local signature_function =
                          make_legion_signature_method(
                            buildgate_probe,
                            kick_probe,
                            qU_first_upvalue
                          )
                        raw_setfenv(signature_function, mod_environment)
                        fixture_legion_signature_functions[
                          #fixture_legion_signature_functions + 1
                        ] = signature_function
                        raw_rawset(
                          postinitfns,
                          "LegionSignatureProbe",
                          { signature_function }
                        )
                        fixture_events[#fixture_events + 1] = {
                          op = "legion_signature_probe_seed",
                          function_count = 1,
                        }
                      end
                    end
                    if runtime_fixture.seed_postinit_probe_functions then
                      local postinitfns =
                        raw_rawget(mod_environment, "postinitfns")
                      local skin_identity =
                        raw_rawget(mod_environment, "ls_skineddata")
                      if type(postinitfns) == "table" then
                        local flat_function =
                          make_fixture_method(skin_identity)
                        local nested_function =
                          make_fixture_method(skin_identity)
                        raw_setfenv(flat_function, mod_environment)
                        raw_setfenv(nested_function, mod_environment)
                        local flat = { flat_function }
                        local nested = { probe = { nested_function } }
                        raw_rawset(postinitfns, "ProbeFlat", flat)
                        raw_rawset(postinitfns, "ProbeNested", nested)
                        if runtime_fixture.probe_mod_seed_tables then
                          instrument_fixture_probe_table(
                            flat, "postinitfns.ProbeFlat"
                          )
                          instrument_fixture_probe_table(
                            nested, "postinitfns.ProbeNested"
                          )
                        end
                        fixture_events[#fixture_events + 1] = {
                          op = "postinit_probe_seed",
                          function_count = 2,
                        }
                      end
                    end
                    if runtime_fixture.probe_mod_environment_functions then
                      local probe_function = make_fixture_method()
                      raw_setfenv(probe_function, mod_environment)
                      mod_environment.ProbeFunction = probe_function
                    end
                    return raw_setmetatable(mod_environment, {
                      __index = function(_, field)
                        fixture_events[#fixture_events + 1] = {
                          op = "mod_manager_result_index",
                          field = raw_tostring(field),
                        }
                        if runtime_fixture.mod_environment_missing_fields_are_nil
                        then
                          return nil
                        end
                        return make_fixture_method()
                      end,
                    })
                  end
                  raw_rawset(self, key, method)
                  return method
                end
                local method = make_fixture_method()
                raw_rawset(self, key, method)
                return method
              end,
            })
            local known_mod_index
            known_mod_index = raw_setmetatable({
              GetModsToLoad = function(_, all)
                fixture_events[#fixture_events + 1] = {
                  op = "get_mods_to_load",
                  all = all,
                }
                return loaded_mods
              end,
            }, {
              __index = function(_, key)
                if not runtime_fixture.probe_known_mod_methods then
                  return nil
                end
                fixture_events[#fixture_events + 1] = {
                  op = "known_mod_index",
                  key = raw_tostring(key),
                }
                return function(...)
                  fixture_events[#fixture_events + 1] = {
                    op = "known_mod_call",
                    key = raw_tostring(key),
                    argument_count = raw_select("#", ...),
                    mod_value = raw_tostring(raw_select(2, ...)),
                  }
                  if runtime_fixture.probe_known_mod_result_fields then
                    return raw_setmetatable({}, {
                      __index = function(_, field)
                        fixture_events[#fixture_events + 1] = {
                          op = "known_mod_result_index",
                          field = raw_tostring(field),
                        }
                        local configured_result_fields =
                          runtime_fixture.known_mod_result_fields
                        if type(configured_result_fields) == "table" then
                          return raw_rawget(configured_result_fields, field)
                        end
                        return runtime_fixture.known_mod_field_result
                      end,
                    })
                  end
                  return runtime_fixture.known_mod_method_result
                end
              end,
            })
            local debug_shim = raw_setmetatable({
              getupvalue = function(fn, upvalue_index)
                local name, value = raw_debug.getupvalue(fn, upvalue_index)
                fixture_events[#fixture_events + 1] = {
                  op = "debug_getupvalue",
                  index = upvalue_index,
                  name = name,
                  value_type = type(value),
                  value_role = known_table_role(value),
                  function_environment_role = type(fn) == "function"
                    and known_table_role(raw_getfenv(fn)) or nil,
                  program = fixture_vm_program,
                  context = fixture_vm_context,
                  pc = fixture_vm_pc,
                }
                return name, value
              end,
              setupvalue = function(fn, upvalue_index, value)
                local name = raw_debug.setupvalue(fn, upvalue_index, value)
                fixture_events[#fixture_events + 1] = {
                  op = "debug_setupvalue",
                  index = upvalue_index,
                  name = name,
                  value_type = type(value),
                  value_role = known_table_role(value),
                  function_environment_role = type(fn) == "function"
                    and known_table_role(raw_getfenv(fn)) or nil,
                  program = fixture_vm_program,
                  context = fixture_vm_context,
                  pc = fixture_vm_pc,
                }
                return name
              end,
            }, { __index = raw_debug })
            install_environment_value("KnownModIndex", known_mod_index)
            install_environment_value("ModManager", mod_manager)
            install_environment_value("debug", debug_shim)
            if runtime_fixture.record_fixture_function_environment_calls
                or runtime_fixture.record_fixture_getfenv_calls then
              install_environment_value("getfenv", function(fn)
                local function_environment = raw_getfenv(fn)
                fixture_events[#fixture_events + 1] = {
                  op = "fixture_getfenv",
                  function_role = fixture_function_roles[fn],
                  function_environment_role =
                    known_table_role(function_environment),
                }
                return function_environment
              end)
            end
            if runtime_fixture.record_fixture_function_environment_calls
                or runtime_fixture.record_fixture_setfenv_calls then
              install_environment_value("setfenv", function(fn, environment)
                fixture_events[#fixture_events + 1] = {
                  op = "fixture_setfenv",
                  function_role = fixture_function_roles[fn],
                  environment_role = known_table_role(environment),
                }
                return raw_setfenv(fn, environment)
              end)
            end
            if runtime_fixture.probe_mod_environment_pairs
                or runtime_fixture.probe_mod_seed_tables then
              install_environment_value("pairs", function(table_value)
                local is_mod_environment = type(table_value) == "table"
                  and raw_rawget(
                    table_value, "__fixture_mod_environment"
                  ) ~= nil
                local probe_path = type(table_value) == "table"
                  and fixture_probe_table_paths[table_value] or nil
                if is_mod_environment or probe_path ~= nil then
                  local entries = {}
                  for key, value in raw_pairs(table_value) do
                    entries[#entries + 1] = {
                      key = raw_tostring(key),
                      value_type = type(value),
                    }
                  end
                  fixture_events[#fixture_events + 1] = {
                    op = is_mod_environment
                      and "mod_environment_pairs"
                      or "fixture_probe_table_pairs",
                    path = probe_path,
                    entries = entries,
                  }
                end
                return raw_pairs(table_value)
              end)
            end
            install_fixture_raw_access_probe = function()
              install_environment_value("rawget", function(table_value, key)
                local result = raw_rawget(table_value, key)
                local probe_path = type(table_value) == "table"
                  and fixture_probe_table_paths[table_value] or nil
                local is_mod_environment = type(table_value) == "table"
                  and raw_rawget(
                    table_value, "__fixture_mod_environment"
                  ) ~= nil
                if probe_path ~= nil then
                  local event = {
                    op = "fixture_probe_table_rawget",
                    path = probe_path,
                    key = raw_tostring(key),
                    value_type = type(result),
                  }
                  if type(result) == "string" then
                    event.value, event.encoding, event.byte_length =
                      describe_probe_string(result)
                  end
                  fixture_events[#fixture_events + 1] = event
                elseif runtime_fixture.probe_mod_environment_raw_access
                    and is_mod_environment then
                  fixture_events[#fixture_events + 1] = {
                    op = "mod_environment_rawget",
                    key = raw_tostring(key),
                    value_type = type(result),
                  }
                elseif runtime_fixture.probe_global_raw_access
                    and table_value == target_environment then
                  local event = {
                    op = "global_rawget",
                    key = raw_tostring(key),
                    value_type = type(result),
                  }
                  if type(result) == "string" then
                    event.value, event.encoding, event.byte_length =
                      describe_probe_string(result)
                  end
                  fixture_events[#fixture_events + 1] = event
                end
                return result
              end)
              install_environment_value("rawset", function(table_value, key, value)
                local probe_path = type(table_value) == "table"
                  and fixture_probe_table_paths[table_value] or nil
                local is_mod_environment = type(table_value) == "table"
                  and raw_rawget(
                    table_value, "__fixture_mod_environment"
                  ) ~= nil
                if probe_path ~= nil then
                  local event = {
                    op = "fixture_probe_table_rawset",
                    path = probe_path,
                    key = raw_tostring(key),
                    value_type = type(value),
                  }
                  if type(value) == "string" then
                    event.value, event.encoding, event.byte_length =
                      describe_probe_string(value)
                  end
                  fixture_events[#fixture_events + 1] = event
                elseif runtime_fixture.probe_mod_environment_raw_access
                    and is_mod_environment then
                  fixture_events[#fixture_events + 1] = {
                    op = "mod_environment_rawset",
                    key = raw_tostring(key),
                    value_type = type(value),
                  }
                elseif runtime_fixture.probe_global_raw_access
                    and table_value == target_environment then
                  local event = {
                    op = "global_rawset",
                    key = raw_tostring(key),
                    value_type = type(value),
                  }
                  if type(value) == "string" then
                    event.value, event.encoding, event.byte_length =
                      describe_probe_string(value)
                  end
                  fixture_events[#fixture_events + 1] = event
                end
                return raw_rawset(table_value, key, value)
              end)
            end
            if (runtime_fixture.probe_fixture_raw_access
                or runtime_fixture.probe_mod_environment_raw_access
                or runtime_fixture.probe_global_raw_access)
                and not runtime_fixture.defer_raw_access_probe_until_callbacks
            then
              install_fixture_raw_access_probe()
            end
          end

          local upvalues = {}
          local upvalue_indexes = {}
          local index = 1
          while true do
            local name, value = raw_debug.getupvalue(target, index)
            if name == nil then break end
            upvalues[name] = value
            upvalue_indexes[name] = index
            index = index + 1
          end

          local instructions = upvalues[instruction_upvalue_name]
          if type(instructions) ~= "table"
              or upvalue_indexes[instruction_upvalue_name] == nil then
            return {
              ok = false,
              error = "root closure does not expose the inferred instruction table",
              fetches = {},
            }
          end
          if environment_upvalue_name == "" then
            local best_name, best_score
            for name, value in pairs(upvalues) do
              if name ~= instruction_upvalue_name and type(value) == "table" then
                local entries, tables, numbers = 0, 0, 0
                for _, item in pairs(value) do
                  entries = entries + 1
                  if type(item) == "table" then tables = tables + 1 end
                  if type(item) == "number" then numbers = numbers + 1 end
                end
                local score = tables * 4 + numbers * 2 - math.abs(entries - 10)
                if entries >= 5 and entries <= 20
                    and (best_score == nil or score > best_score) then
                  best_name, best_score = name, score
                end
              end
            end
            environment_upvalue_name = best_name or ""
          end

          local patch_sites = {}
          local programs = {}
          local program_by_instructions = {}
          local scanned = {}
          local function discover(value)
            local kind = type(value)
            if (kind ~= "function" and kind ~= "table") or scanned[value] then
              return
            end
            scanned[value] = true

            if kind == "table" then
              for key, item in pairs(value) do
                discover(key)
                discover(item)
              end
              return
            end

            local function_upvalues = {}
            local function_indexes = {}
            local item_index = 1
            while true do
              local name, item = raw_debug.getupvalue(value, item_index)
              if name == nil then break end
              function_upvalues[name] = item
              function_indexes[name] = item_index
              item_index = item_index + 1
            end

            local function_instructions =
              function_upvalues[instruction_upvalue_name]
            if type(function_instructions) == "table" then
              local program = program_by_instructions[function_instructions]
              if program == nil then
                program = {
                  id = #programs + 1,
                  instructions = function_instructions,
                  operands = function_upvalues,
                }
                programs[#programs + 1] = program
                program_by_instructions[function_instructions] = program
              end
              patch_sites[#patch_sites + 1] = {
                fn = value,
                index = function_indexes[instruction_upvalue_name],
                program = program,
                operands = function_upvalues,
              }
            end

            for _, item in pairs(function_upvalues) do discover(item) end
          end
          discover(target)

          local fetches = {}
          local tail_fetches = {}
          local fetch_count = 0
          local error_frames = {}
          local proxy_set = {}
          local program_by_proxy = {}
          local function_program = {}
          local function_operands = {}
          local function_context = {}
          local contexts = {}
          local current_vm_depth = 0
          local environment_bindings = 0
          local function register_function(fn, program, operands)
            function_program[fn] = program
            function_operands[fn] = operands
            local context = function_context[fn]
            if context == nil then
              context = {
                id = #contexts + 1,
                fn = fn,
                program = program,
                operands = operands,
              }
              contexts[#contexts + 1] = context
              function_context[fn] = context
            else
              context.program = program
              context.operands = operands
            end
            return context
          end
          local function encode_operand(value)
            local kind = type(value)
            if kind == "nil" or kind == "number" or kind == "boolean" then
              return value
            end
            if kind ~= "string" then return { type = kind } end

            local output = {}
            for byte_index = 1, #value do
              local byte = string.byte(value, byte_index)
              if byte >= 32 and byte <= 126 and byte ~= 34 and byte ~= 92 then
                output[#output + 1] = string.char(byte)
              elseif byte == 34 then
                output[#output + 1] = '\\"'
              elseif byte == 92 then
                output[#output + 1] = '\\\\'
              else
                output[#output + 1] = string.format("\\x%02x", byte)
              end
            end
            return {
              type = "string",
              value = table.concat(output),
              length = #value,
            }
          end

          local function operand(operands, table_name, pc)
            local values = operands[table_name]
            if type(values) == "table" then
              return encode_operand(raw_rawget(values, pc))
            end
            return nil
          end

          local function operands_at(operands, pc)
            local values = {}
            for name, table_value in pairs(operands) do
              if name ~= instruction_upvalue_name and type(table_value) == "table" then
                local value = raw_rawget(table_value, pc)
                if value ~= nil then values[name] = encode_operand(value) end
              end
            end
            return values
          end

          local function instruction_signature(program, operands, pc)
            local parts = {}
            local opcode = raw_rawget(program.instructions, pc)
            parts[1] = "opcode:" .. type(opcode) .. ":" .. raw_tostring(opcode)
            for name, values in raw_pairs(operands) do
              if type(values) == "table" then
                local value = raw_rawget(values, pc)
                if value ~= nil then
                  parts[#parts + 1] = raw_tostring(name) .. ":"
                    .. type(value) .. ":" .. raw_tostring(value)
                end
              end
            end
            raw_table_sort(parts)
            return raw_table_concat(parts, "\31")
          end

          local function instruction_at(program, operands, pc)
            local h_value = type(operands.h) == "table"
              and raw_rawget(operands.h, pc) or nil
            local o_value = type(operands.o) == "table"
              and raw_rawget(operands.o, pc) or nil
            local j_value = type(operands.j) == "table"
              and raw_rawget(operands.j, h_value) or nil
            local j_nested = type(j_value) == "table"
              and raw_rawget(j_value, o_value) or nil
            return {
              pc = pc,
              opcode = encode_operand(raw_rawget(program.instructions, pc)),
              h = encode_operand(h_value),
              O = type(operands.O) == "table"
                and encode_operand(raw_rawget(operands.O, pc)) or nil,
              W = type(operands.W) == "table"
                and encode_operand(raw_rawget(operands.W, pc)) or nil,
              N = type(operands.N) == "table"
                and encode_operand(raw_rawget(operands.N, pc)) or nil,
              o = encode_operand(o_value),
              e = type(operands.e) == "table"
                and encode_operand(raw_rawget(operands.e, pc)) or nil,
              j_h = encode_operand(j_value),
              j_h_o = encode_operand(j_nested),
              operands = operands_at(operands, pc),
            }
          end

          local function resolve_vm_context()
            for level = 2, 32 do
              local info = raw_debug.getinfo(level, "f")
              if info == nil then break end
              local values = {}
              local matches = false
              local item_index = 1
              while true do
                local name, value = raw_debug.getupvalue(info.func, item_index)
                if name == nil then break end
                values[name] = value
                if name == instruction_upvalue_name and proxy_set[value] then
                  matches = value
                end
                item_index = item_index + 1
              end
              if matches then
                return info.func, values, program_by_proxy[matches]
              end
            end
            return nil, nil, nil
          end

          local function make_proxy(program)
            local program_instructions = program.instructions
            local proxy
            proxy = raw_setmetatable({}, {
              __index = function(_, pc)
                fetch_count = fetch_count + 1
                local sequence = fetch_count
                if sequence > fetch_budget then
                  raw_error("__LURAPH_VM_FETCH_BUDGET__", 0)
                end
                local caller_fn, resolved_operands, resolved_program
                local direct_info = raw_debug.getinfo(2, "f")
                local direct_context = direct_info ~= nil
                  and function_context[direct_info.func] or nil
                if direct_context ~= nil then
                  caller_fn = direct_info.func
                  resolved_operands = direct_context.operands
                  resolved_program = direct_context.program
                else
                  caller_fn, resolved_operands, resolved_program =
                    resolve_vm_context()
                end
                local active_context = caller_fn ~= nil
                  and function_context[caller_fn] or nil
                local active_program = resolved_program
                  or (active_context and active_context.program)
                  or function_program[caller_fn]
                  or program
                local active_operands = resolved_operands
                  or (active_context and active_context.operands)
                  or function_operands[caller_fn]
                  or program.operands
                fixture_vm_program = active_program.id
                fixture_vm_context = active_context and active_context.id or nil
                fixture_vm_pc = pc
                if active_context ~= nil then
                  active_context.first_fetch_sequence =
                    active_context.first_fetch_sequence or sequence
                  active_context.last_fetch_sequence = sequence
                  active_context.fetch_count =
                    (active_context.fetch_count or 0) + 1
                  active_context.visited_pcs = active_context.visited_pcs or {}
                  active_context.visited_pcs[pc] =
                    (active_context.visited_pcs[pc] or 0) + 1
                  active_context.path_pcs = active_context.path_pcs or {}
                  if #active_context.path_pcs < event_limit then
                    active_context.path_pcs[#active_context.path_pcs + 1] = pc
                  else
                    active_context.path_overflow = true
                  end
                  active_context.instruction_snapshots =
                    active_context.instruction_snapshots or {}
                  if active_context.instruction_snapshots[pc] == nil then
                    active_context.instruction_snapshots[pc] =
                      instruction_at(active_program, active_operands, pc)
                    active_context.instruction_snapshots[pc]
                      .first_fetch_sequence = sequence
                    active_context.instruction_snapshot_count =
                      (active_context.instruction_snapshot_count or 0) + 1
                  end
                  local requested_variant_programs =
                    runtime_fixture.operand_variant_programs
                  local has_requested_variant_programs =
                    type(requested_variant_programs) == "table"
                  local should_record_variants =
                    runtime_fixture.record_operand_variants
                    and (
                      (
                        runtime_fixture.operand_variant_program == nil
                        and not has_requested_variant_programs
                      )
                      or runtime_fixture.operand_variant_program
                        == active_program.id
                      or (
                        has_requested_variant_programs
                        and raw_rawget(
                          requested_variant_programs, active_program.id
                        )
                      )
                    )
                  if should_record_variants then
                    active_context.instruction_variant_signatures =
                      active_context.instruction_variant_signatures or {}
                    active_context.instruction_variants =
                      active_context.instruction_variants or {}
                    local signature = instruction_signature(
                      active_program, active_operands, pc
                    )
                    if active_context.instruction_variant_signatures[pc]
                        ~= signature then
                      active_context.instruction_variant_signatures[pc] = signature
                      local variant = instruction_at(
                        active_program, active_operands, pc
                      )
                      variant.first_fetch_sequence = sequence
                      active_context.instruction_variants[
                        #active_context.instruction_variants + 1
                      ] = variant
                    end
                  end
                end
                active_program.last_operands = active_operands
                active_program.fetch_count = (active_program.fetch_count or 0) + 1
                active_program.visited_pcs = active_program.visited_pcs or {}
                active_program.visited_pcs[pc] =
                  (active_program.visited_pcs[pc] or 0) + 1
                local opcode = program_instructions[pc]
                if runtime_fixture.minimal_vm_trace then
                  return opcode
                end
                local event = {
                  sequence = sequence,
                  program = active_program.id,
                  context = active_context and active_context.id or nil,
                  pc = pc,
                  opcode = opcode,
                  h = operand(active_operands, "h", pc),
                  O = operand(active_operands, "O", pc),
                  W = operand(active_operands, "W", pc),
                  N = operand(active_operands, "N", pc),
                  o = operand(active_operands, "o", pc),
                  e = operand(active_operands, "e", pc),
                  depth = current_vm_depth,
                }
                if sequence <= event_limit then fetches[sequence] = event end
                tail_fetches[(sequence - 1) % 100 + 1] = event
                local requested_probe_pcs = runtime_fixture.vm_probe_pcs
                local should_probe_pc = runtime_fixture.vm_probe_pc == pc
                  or (
                    type(requested_probe_pcs) == "table"
                    and raw_rawget(requested_probe_pcs, pc)
                  )
                if should_probe_pc
                    and (
                      runtime_fixture.vm_probe_program == nil
                      or runtime_fixture.vm_probe_program == active_program.id
                    ) then
                  local probe_locals = {}
                  local local_index = 1
                  while local_index <= 40 do
                    local local_name, local_value =
                      raw_debug.getlocal(2, local_index)
                    if local_name == nil then break end
                    local value_kind = type(local_value)
                    local local_description = {
                      index = local_index,
                      name = local_name,
                      type = value_kind,
                    }
                    if value_kind == "string" then
                      local_description.value,
                        local_description.encoding,
                        local_description.byte_length =
                          describe_probe_string(local_value)
                    elseif value_kind == "nil" or value_kind == "number"
                        or value_kind == "boolean" then
                      local_description.value = local_value
                    else
                      local_description.display = raw_tostring(local_value)
                    end
                    if value_kind == "table" then
                      local_description.role = known_table_role(local_value)
                      local traced_value = raw_rawget(local_value, "trace_value")
                      if traced_value ~= nil then
                        local_description.trace_value =
                          raw_tostring(traced_value)
                      end
                      local slots = {}
                      local probe_slot_limit =
                        runtime_fixture.vm_probe_slot_limit or 40
                      for slot_index = 0, probe_slot_limit do
                        local slot_value = raw_rawget(local_value, slot_index)
                        if slot_value ~= nil then
                          local slot_kind = type(slot_value)
                          local slot = {
                            index = slot_index,
                            type = slot_kind,
                          }
                          if slot_kind == "string" then
                            slot.value, slot.encoding, slot.byte_length =
                              describe_probe_string(slot_value)
                          elseif slot_kind == "number"
                              or slot_kind == "boolean" then
                            slot.value = slot_value
                          else
                            slot.display = raw_tostring(slot_value)
                            if slot_kind == "table" then
                              slot.role = known_table_role(slot_value)
                              local slot_traced_value =
                                raw_rawget(slot_value, "trace_value")
                              if slot_traced_value ~= nil then
                                slot.trace_value =
                                  raw_tostring(slot_traced_value)
                              end
                            end
                          end
                          slots[#slots + 1] = slot
                        end
                      end
                      local_description.slots = slots
                    end
                    probe_locals[#probe_locals + 1] = local_description
                    local_index = local_index + 1
                  end
                  fixture_events[#fixture_events + 1] = {
                    op = "vm_probe",
                    program = active_program.id,
                    context = active_context and active_context.id or nil,
                    pc = pc,
                    locals = probe_locals,
                  }
                end
                return opcode
              end,
              __newindex = function(_, key, value)
                program_instructions[key] = value
              end,
              __metatable = "read-only VM instruction trace proxy",
            })
            proxy_set[proxy] = true
            program_by_proxy[proxy] = program
            return proxy
          end

          local function bind_environment_if_needed(fn, program, operands)
            local environment_values = operands[environment_upvalue_name]
            if not bind_missing_environment
                or type(environment_values) ~= "table"
                or raw_rawget(environment_values, 1) ~= nil then
              return
            end

            -- A newly-created VM closure can begin executing before replacing
            -- its u upvalue takes effect. Bind its environment from the call
            -- hook, where the actual closure and its private operands are known.
            raw_rawset(environment_values, 1, raw_getfenv(fn))
            environment_bindings = environment_bindings + 1
          end

          for _, program in ipairs(programs) do
            program.proxy = make_proxy(program)
          end

          local function instrument_created(created)
            if type(created) ~= "function" then return created end

            local created_upvalues = {}
            local created_indexes = {}
            local created_index = 1
            while true do
              local name, item = raw_debug.getupvalue(created, created_index)
              if name == nil then break end
              created_upvalues[name] = item
              created_indexes[name] = created_index
              created_index = created_index + 1
            end

            local created_instructions =
              created_upvalues[instruction_upvalue_name]
            if proxy_set[created_instructions] then
              register_function(
                created,
                program_by_proxy[created_instructions],
                created_upvalues
              )
            end
            if type(created_instructions) == "table"
                and not proxy_set[created_instructions] then
              local program = program_by_instructions[created_instructions]
              if program == nil then
                program = {
                  id = #programs + 1,
                  instructions = created_instructions,
                  operands = created_upvalues,
                }
                program.proxy = make_proxy(program)
                programs[#programs + 1] = program
                program_by_instructions[created_instructions] = program
              end
              patch_sites[#patch_sites + 1] = {
                fn = created,
                index = created_indexes[instruction_upvalue_name],
                program = program,
                operands = created_upvalues,
              }
              raw_debug.setupvalue(
                created,
                created_indexes[instruction_upvalue_name],
                program.proxy
              )
              register_function(created, program, created_upvalues)
            end

            local created_program = function_program[created]
            if created_program ~= nil then
              bind_environment_if_needed(
                created, created_program, created_upvalues
              )
            end

            return created
          end

          for _, site in ipairs(patch_sites) do
            raw_debug.setupvalue(site.fn, site.index, site.program.proxy)
            register_function(site.fn, site.program, site.operands)
          end

          local global_events = {}
          local global_event_overflow = false
          local callback_seen = {}
          local callback_results = {}
          local proxy_paths = {}
          local global_proxy_mt = {}
          local original_target_metatable = raw_getmetatable(target_environment)
          local function append_global_event(event)
            if #global_events < event_limit then
              event.sequence = #global_events + 1
              global_events[#global_events + 1] = event
            else
              global_event_overflow = true
            end
          end
          local function new_global_proxy(path)
            local proxy = raw_setmetatable({}, global_proxy_mt)
            proxy_paths[proxy] = path
            return proxy
          end
          local function call_global_proxy(path, ...)
            local arguments = {}
            for argument_index = 1, raw_select("#", ...) do
              local value = raw_select(argument_index, ...)
              arguments[argument_index] = encode_operand(value)
              if type(value) == "function" and not callback_seen[value] then
                instrument_created(value)
                callback_seen[value] = true
                pending_callbacks[#pending_callbacks + 1] = {
                  fn = value,
                  origin = path,
                  argument = argument_index,
                }
              end
            end
            append_global_event({ op = "call", path = path, args = arguments })
            return new_global_proxy(path .. "()")
          end
          global_proxy_mt.__index = function(self, key)
            local path = proxy_paths[self] .. "." .. raw_tostring(key)
            append_global_event({ op = "index", path = path })
            if key == "DoTaskInTime" then
              return function(...) return call_global_proxy(path, ...) end
            end
            return new_global_proxy(path)
          end
          global_proxy_mt.__newindex = function(self, key, value)
            append_global_event({
              op = "set",
              path = proxy_paths[self] .. "." .. raw_tostring(key),
              value = encode_operand(value),
            })
          end
          global_proxy_mt.__call = function(self, ...)
            return call_global_proxy(proxy_paths[self], ...)
          end
          global_proxy_mt.__tostring = function(self) return proxy_paths[self] end
          global_proxy_mt.__len = function() return 0 end
          global_proxy_mt.__unm = function(self)
            return new_global_proxy("-(" .. proxy_paths[self] .. ")")
          end
          global_proxy_mt.__add = function(left, right)
            return new_global_proxy(
              "(" .. raw_tostring(left) .. "+" .. raw_tostring(right) .. ")"
            )
          end
          global_proxy_mt.__sub = function(left, right)
            return new_global_proxy(
              "(" .. raw_tostring(left) .. "-" .. raw_tostring(right) .. ")"
            )
          end
          global_proxy_mt.__mul = function(left, right)
            return new_global_proxy(
              "(" .. raw_tostring(left) .. "*" .. raw_tostring(right) .. ")"
            )
          end
          global_proxy_mt.__div = function(left, right)
            return new_global_proxy(
              "(" .. raw_tostring(left) .. "/" .. raw_tostring(right) .. ")"
            )
          end
          global_proxy_mt.__concat = function(left, right)
            return new_global_proxy(
              "(" .. raw_tostring(left) .. ".." .. raw_tostring(right) .. ")"
            )
          end
          global_proxy_mt.__eq = function() return false end
          global_proxy_mt.__lt = function() return false end
          global_proxy_mt.__le = function() return false end
          if proxy_unknown_globals then
            raw_setmetatable(target_environment, {
              __index = function(_, key)
                local existing
                if type(original_target_metatable) == "table" then
                  local original_index = original_target_metatable.__index
                  if type(original_index) == "function" then
                    existing = original_index(target_environment, key)
                  elseif type(original_index) == "table" then
                    existing = original_index[key]
                  end
                end
                if existing ~= nil then return existing end
                local path = raw_tostring(key)
                append_global_event({ op = "global", path = path })
                return new_global_proxy(path)
              end,
              __newindex = function(table_value, key, value)
                append_global_event({
                  op = "global_set",
                  path = raw_tostring(key),
                  value = encode_operand(value),
                })
                raw_rawset(table_value, key, value)
              end,
            })
          end
          local previous_hook, previous_mask, previous_count = raw_debug.gethook()
          local fixture_environment_before_invoke = {
            KnownModIndex = type(raw_rawget(target_environment, "KnownModIndex")),
            ModManager = type(raw_rawget(target_environment, "ModManager")),
            debug = type(raw_rawget(target_environment, "debug")),
            pairs = type(raw_rawget(target_environment, "pairs")),
          }
          raw_debug.sethook(function(event)
            local info = raw_debug.getinfo(2, "f")
            if info == nil then return end
            local fn = info.func
            if event == "call" then
              instrument_created(fn)
              if function_program[fn] ~= nil then
                current_vm_depth = current_vm_depth + 1
              end
            elseif function_program[fn] ~= nil then
              current_vm_depth = math.max(0, current_vm_depth - 1)
            end
          end, "cr")
          local function invoke_target()
            if pass_environment then return target(raw_getfenv(target)) end
            return target()
          end
          local ok, result = raw_xpcall(invoke_target, function(message)
            local level = 2
            while true do
              local info = raw_debug.getinfo(level, "Sfn")
              if info == nil then break end
              local frame = {
                level = level,
                source = info.source,
                linedefined = info.linedefined,
                lastlinedefined = info.lastlinedefined,
                locals = {},
              }
              if function_program[info.func] ~= nil then
                frame.program = function_program[info.func].id
              end
              local local_index = 1
              while local_index <= 40 do
                local name, value = raw_debug.getlocal(level, local_index)
                if name == nil then break end
                frame.locals[#frame.locals + 1] = {
                  index = local_index,
                  name = name,
                  value = encode_operand(value),
                }
                local_index = local_index + 1
              end
              error_frames[#error_frames + 1] = frame
              level = level + 1
            end
            return raw_tostring(message)
          end)
          for global_name, field_names in pairs(
              runtime_fixture.callback_global_table_function_fields or {}) do
            local global_table = raw_rawget(target_environment, global_name)
            if type(global_table) == "table" then
              for _, field_name in pairs(field_names) do
                local role = "GLOBAL." .. raw_tostring(global_name) .. "."
                  .. raw_tostring(field_name) .. ".callback_seed"
                local configured_results = raw_rawget(
                  runtime_fixture.callback_global_table_function_results or {},
                  global_name
                )
                local configured_result = type(configured_results) == "table"
                  and raw_rawget(configured_results, field_name) or nil
                local method = function(...)
                  local arguments = {}
                  for argument_index = 1, raw_select("#", ...) do
                    arguments[argument_index] = encode_operand(
                      raw_select(argument_index, ...)
                    )
                  end
                  fixture_events[#fixture_events + 1] = {
                    op = "fixture_callback_table_function_call",
                    function_role = role,
                    argument_count = raw_select("#", ...),
                    arguments = arguments,
                  }
                  return configured_result
                end
                raw_rawset(global_table, field_name, method)
                fixture_function_roles[method] = role
              end
            end
          end
          if runtime_fixture.defer_raw_access_probe_until_callbacks
              and install_fixture_raw_access_probe ~= nil
              and (runtime_fixture.probe_fixture_raw_access
                or runtime_fixture.probe_mod_environment_raw_access
                or runtime_fixture.probe_global_raw_access) then
            install_fixture_raw_access_probe()
          end
          local function snapshot_callback_upvalues(callback, phase)
            if not runtime_fixture.record_fixture_callback_upvalues then
              return
            end
            local entry_limit =
              runtime_fixture.fixture_callback_upvalue_entry_limit or 40
            local function summarize(value, depth, seen)
              local value_type = type(value)
              local summary = { type = value_type }
              if value_type == "number" or value_type == "boolean"
                  or value_type == "nil" then
                summary.value = value
              elseif value_type == "string" then
                summary.byte_length = #value
                if #value <= 120 then summary.value = value end
              elseif value_type == "table" and depth < 2 then
                seen = seen or {}
                if seen[value] then
                  summary.cycle = true
                  return summary
                end
                seen[value] = true
                local entries = {}
                local total = 0
                for key, item in raw_pairs(value) do
                  total = total + 1
                  if #entries < entry_limit then
                    entries[#entries + 1] = {
                      key = raw_tostring(key),
                      key_type = type(key),
                      value = summarize(item, depth + 1, seen),
                    }
                  end
                end
                raw_table_sort(entries, function(left, right)
                  return left.key < right.key
                end)
                summary.entry_count = total
                summary.entries = entries
              end
              return summary
            end
            local upvalues = {}
            for upvalue_index = 1, 16 do
              local name, value = raw_debug.getupvalue(
                callback.fn, upvalue_index
              )
              if name == nil then break end
              local upvalue = {
                index = upvalue_index,
                name = name,
                value_type = type(value),
              }
              if name == instruction_upvalue_name and type(value) == "table" then
                upvalue.entry_count = #value
              else
                upvalue.value = summarize(value, 0, {})
              end
              upvalues[#upvalues + 1] = upvalue
            end
            fixture_events[#fixture_events + 1] = {
              op = "fixture_callback_upvalues",
              phase = phase,
              origin = callback.origin,
              upvalues = upvalues,
            }
          end
          local callbacks_invoked = 0
          local callback_index = 1
          while callback_index <= #pending_callbacks
              and callbacks_invoked < callback_limit do
            local callback = pending_callbacks[callback_index]
            snapshot_callback_upvalues(callback, "before")
            local callback_request = raw_rawget(
              runtime_fixture.fixture_seed_callback_arguments or {},
              callback.origin
            )
            local callback_arguments = {}
            local callback_argument_count = 4
            if type(callback_request) == "table" then
              callback_argument_count = callback_request.argument_count
                or #(callback_request.arguments or {})
              for argument_index = 1, callback_argument_count do
                local argument = raw_rawget(
                  callback_request.arguments or {}, argument_index
                )
                if type(argument) == "table" and argument.fixture_global then
                  callback_arguments[argument_index] = raw_rawget(
                    target_environment, argument.fixture_global
                  )
                else
                  callback_arguments[argument_index] = argument
                end
              end
            else
              for argument_index = 1, callback_argument_count do
                callback_arguments[argument_index] = new_global_proxy(
                  "callback." .. callback_index .. ".arg"
                    .. argument_index
                )
              end
            end
            local callback_ok, callback_result, callback_call_results
            if runtime_fixture.record_fixture_callback_all_results then
              local function capture_callback_results(...)
                callback_call_results = { n = raw_select("#", ...), ... }
              end
              capture_callback_results(raw_xpcall(
                function()
                  return callback.fn(raw_unpack(
                    callback_arguments, 1, callback_argument_count
                  ))
                end,
                function(message) return raw_tostring(message) end
              ))
              callback_ok = callback_call_results[1]
              callback_result = callback_call_results[2]
            else
              callback_ok, callback_result = raw_xpcall(
                function()
                  return callback.fn(raw_unpack(
                    callback_arguments, 1, callback_argument_count
                  ))
                end,
                function(message) return raw_tostring(message) end
              )
            end
            snapshot_callback_upvalues(callback, "after")
            local callback_event = {
              id = callback_index,
              origin = callback.origin,
              argument = callback.argument,
              ok = callback_ok,
            }
            if not callback_ok then callback_event.error = callback_result end
            if callback_ok and callback_call_results ~= nil then
              callback_event.result_count = callback_call_results.n - 1
              callback_event.results = {}
              for result_index = 2, callback_call_results.n do
                local result_value = callback_call_results[result_index]
                local encoded_result = encode_operand(result_value)
                if encoded_result == nil then
                  encoded_result = { type = "nil" }
                elseif type(encoded_result) ~= "table" then
                  encoded_result = {
                    type = type(result_value),
                    value = encoded_result,
                  }
                end
                callback_event.results[result_index - 1] = encoded_result
              end
            end
            if runtime_fixture.record_fixture_callback_programs then
              local callback_program = function_program[callback.fn]
              if callback_program ~= nil then
                callback_event.program = callback_program.id
              end
            end
            callback_results[#callback_results + 1] = callback_event
            callbacks_invoked = callbacks_invoked + 1
            callback_index = callback_index + 1
          end
          for _, request in pairs(
              runtime_fixture.invoke_fixture_functions or {}) do
            local owner
            if request.path == "GLOBAL" then
              owner = target_environment
            elseif request.path == "MOD" then
              owner = fixture_mod_environments[request.index or 1]
            else
              owner = fixture_probe_tables_by_path[request.path]
            end
            local fn = type(owner) == "table"
              and raw_rawget(owner, request.field) or nil
            local requested_arguments = request.arguments or {}
            local argument_count = #requested_arguments
            local arguments = {}
            for argument_index = 1, argument_count do
              local argument = requested_arguments[argument_index]
              if type(argument) == "table" and argument.fixture_nil then
                arguments[argument_index] = nil
              elseif type(argument) == "table" and argument.fixture_callback then
                local callback_index = argument_index
                arguments[argument_index] = function(...)
                  local callback_arguments = {}
                  for callback_argument_index = 1, raw_select("#", ...) do
                    callback_arguments[callback_argument_index] =
                      encode_operand(raw_select(callback_argument_index, ...))
                  end
                  fixture_events[#fixture_events + 1] = {
                    op = "fixture_callback_call",
                    path = request.path,
                    field = raw_tostring(request.field),
                    argument_index = callback_index,
                    argument_count = raw_select("#", ...),
                    arguments = callback_arguments,
                  }
                  return argument.return_value
                end
              elseif type(argument) == "table" and argument.fixture_probe then
                local probe_value = argument.value or {}
                local probe_path = argument.path
                  or ("invoke." .. raw_tostring(request.path) .. "."
                    .. raw_tostring(request.field) .. ".arg"
                    .. raw_tostring(argument_index))
                arguments[argument_index] = instrument_fixture_probe_table(
                  probe_value, probe_path
                )
              elseif type(argument) == "table" and argument.fixture_global then
                arguments[argument_index] = raw_rawget(
                  target_environment, argument.fixture_global
                )
              else
                arguments[argument_index] = argument
              end
            end
            local call_ok, call_result, call_results
            if type(fn) == "function" then
              if runtime_fixture.record_fixture_function_all_results then
                local function capture_results(...)
                  call_results = { n = raw_select("#", ...), ... }
                end
                capture_results(raw_xpcall(
                  function()
                    return fn(raw_unpack(arguments, 1, argument_count))
                  end,
                  function(message) return raw_tostring(message) end
                ))
                call_ok, call_result = call_results[1], call_results[2]
              else
                call_ok, call_result = raw_xpcall(
                  function()
                    return fn(raw_unpack(arguments, 1, argument_count))
                  end,
                  function(message) return raw_tostring(message) end
                )
              end
            else
              call_ok = false
              call_result = "target is not a function"
            end
            local event = {
              op = "fixture_function_call",
              path = request.path,
              index = request.path == "MOD" and (request.index or 1) or nil,
              field = raw_tostring(request.field),
              ok = call_ok,
              result_type = type(call_result),
            }
            if call_ok and call_results ~= nil then
              event.result_count = call_results.n - 1
              event.results = {}
              for result_index = 2, call_results.n do
                local result_value = call_results[result_index]
                local encoded_result = { type = type(result_value) }
                if type(result_value) == "string" then
                  encoded_result.value, encoded_result.encoding,
                    encoded_result.byte_length =
                    describe_probe_string(result_value)
                elseif type(result_value) == "number"
                    or type(result_value) == "boolean" then
                  encoded_result.value = result_value
                end
                event.results[#event.results + 1] = encoded_result
              end
            end
            if call_ok and (type(call_result) == "nil"
                or type(call_result) == "number"
                or type(call_result) == "boolean") then
              event.result = call_result
            elseif call_ok and type(call_result) == "string" then
              event.result, event.encoding, event.byte_length =
                describe_probe_string(call_result)
            elseif not call_ok then
              event.error = call_result
            end
            fixture_events[#fixture_events + 1] = event
          end
          if runtime_fixture.record_fixture_probe_final_state then
            for table_value, probe_path in raw_pairs(fixture_probe_table_paths) do
              local entries = {}
              for key, value in raw_pairs(table_value) do
                local entry = {
                  key = raw_tostring(key),
                  key_type = type(key),
                  value_type = type(value),
                }
                if type(value) == "string" then
                  entry.value, entry.encoding, entry.byte_length =
                    describe_probe_string(value)
                elseif type(value) == "number" or type(value) == "boolean" then
                  entry.value = value
                elseif type(value) == "function"
                    and fixture_function_roles[value] ~= nil then
                  entry.function_role = fixture_function_roles[value]
                end
                entries[#entries + 1] = entry
              end
              raw_table_sort(entries, function(left, right)
                return left.key < right.key
              end)
              fixture_events[#fixture_events + 1] = {
                op = "fixture_probe_table_final_state",
                path = probe_path,
                entries = entries,
              }
            end
          end
          for _, request in pairs(
              runtime_fixture.record_fixture_table_paths_final_state or {}) do
            local path = "GLOBAL." .. raw_tostring(request.global)
            local table_value = raw_rawget(
              target_environment, request.global
            )
            for _, key in pairs(request.keys or {}) do
              table_value = type(table_value) == "table"
                and raw_rawget(table_value, key) or nil
              path = path .. "." .. raw_tostring(key)
            end
            local entries = {}
            if type(table_value) == "table" then
              for key, value in raw_pairs(table_value) do
                local entry = {
                  key = raw_tostring(key),
                  key_type = type(key),
                  value_type = type(value),
                }
                if type(value) == "string" then
                  entry.value, entry.encoding, entry.byte_length =
                    describe_probe_string(value)
                elseif type(value) == "number" or type(value) == "boolean" then
                  entry.value = value
                elseif type(value) == "function"
                    and fixture_function_roles[value] ~= nil then
                  entry.function_role = fixture_function_roles[value]
                end
                entries[#entries + 1] = entry
              end
              raw_table_sort(entries, function(left, right)
                return left.key < right.key
              end)
            end
            fixture_events[#fixture_events + 1] = {
              op = "fixture_table_path_final_state",
              path = path,
              value_type = type(table_value),
              entries = entries,
            }
          end
          for _, field_name in pairs(
              runtime_fixture.record_fixture_global_fields or {}) do
            local value = raw_rawget(target_environment, field_name)
            local event = {
              op = "fixture_global_field_final_state",
              field = raw_tostring(field_name),
              value_type = type(value),
            }
            if type(value) == "function"
                and fixture_function_roles[value] ~= nil then
              event.function_role = fixture_function_roles[value]
            end
            fixture_events[#fixture_events + 1] = event
          end
          if runtime_fixture.record_fixture_mod_environment_final_state then
            for environment_index = 1, #fixture_mod_environments do
              local entries = {}
              for key, value in raw_pairs(
                  fixture_mod_environments[environment_index]) do
                if key ~= "__fixture_mod_environment" then
                  local entry = {
                    key = raw_tostring(key),
                    value_type = type(value),
                  }
                  if type(value) == "function"
                      and fixture_function_roles[value] ~= nil then
                    entry.function_role = fixture_function_roles[value]
                  end
                  entries[#entries + 1] = entry
                end
              end
              raw_table_sort(entries, function(left, right)
                return left.key < right.key
              end)
              fixture_events[#fixture_events + 1] = {
                op = "mod_environment_final_state",
                index = environment_index,
                entries = entries,
              }
            end
          end
          if runtime_fixture.invoke_legion_patched_upvalues then
            local requested_names = { CU = true, oU = true, cU = true }
            for signature_index = 1,
                #fixture_legion_signature_functions do
              local signature_function =
                fixture_legion_signature_functions[signature_index]
              local signature_upvalues = {}
              local signature_upvalue_index = 1
              while true do
                local name, value = raw_debug.getupvalue(
                  signature_function, signature_upvalue_index
                )
                if name == nil then break end
                signature_upvalues[name] = value
                signature_upvalue_index = signature_upvalue_index + 1
              end
              local probe_cases = {
                { name = "zero", argument_count = 0 },
                { name = "nil", argument_count = 1, value = nil },
                { name = "false", argument_count = 1, value = false },
                { name = "string", argument_count = 1, value = "probe" },
                { name = "empty_table", argument_count = 1, value = {} },
                {
                  name = "buildgate",
                  argument_count = 1,
                  value = signature_upvalues.buildgate_probe,
                },
                {
                  name = "kick",
                  argument_count = 1,
                  value = signature_upvalues.kick_probe,
                },
              }
              for upvalue_name in raw_pairs(requested_names) do
                local patched_function = signature_upvalues[upvalue_name]
                if type(patched_function) == "function" then
                  for probe_index = 1, #probe_cases do
                    local probe_case = probe_cases[probe_index]
                    local call_ok, call_result = raw_xpcall(
                      function()
                        if probe_case.argument_count == 0 then
                          return patched_function()
                        end
                        return patched_function(probe_case.value)
                      end,
                      function(message) return raw_tostring(message) end
                    )
                    local event = {
                      op = "legion_patched_upvalue_call",
                      signature_index = signature_index,
                      upvalue = upvalue_name,
                      probe = probe_case.name,
                      ok = call_ok,
                      result_type = call_ok and type(call_result) or nil,
                      result_role = call_ok
                        and known_table_role(call_result) or nil,
                    }
                    if call_ok and type(call_result) == "string" then
                      event.result, event.encoding, event.byte_length =
                        describe_probe_string(call_result)
                    elseif call_ok and (
                        type(call_result) == "number"
                        or type(call_result) == "boolean") then
                      event.result = call_result
                    elseif not call_ok then
                      event.error = call_result
                    end
                    fixture_events[#fixture_events + 1] = event
                  end
                end
              end
            end
          end
          raw_debug.sethook(previous_hook, previous_mask, previous_count)
          if proxy_unknown_globals then
            raw_setmetatable(target_environment, original_target_metatable)
          end
          for _, original in ipairs(original_environment_values) do
            if original.present then
              raw_rawset(target_environment, original.key, original.value)
            else
              raw_rawset(target_environment, original.key, nil)
            end
          end
          for _, site in ipairs(patch_sites) do
            raw_debug.setupvalue(site.fn, site.index, site.program.instructions)
          end

          local stopped_by_budget = not ok
            and result == "__LURAPH_VM_FETCH_BUDGET__"
          local program_summaries = {}
          for _, program in ipairs(programs) do
            local visited = {}
            for pc, count in pairs(program.visited_pcs or {}) do
              visited[#visited + 1] = { pc = pc, count = count }
            end
            table.sort(visited, function(left, right) return left.pc < right.pc end)
            program_summaries[#program_summaries + 1] = {
              id = program.id,
              instruction_count = #program.instructions,
              fetch_count = program.fetch_count or 0,
              visited_pcs = visited,
            }
            if include_programs then
              local rows = {}
              local operands = program.last_operands or program.operands
              for pc = 1, #program.instructions do
                local h_value = type(operands.h) == "table"
                  and raw_rawget(operands.h, pc) or nil
                local o_value = type(operands.o) == "table"
                  and raw_rawget(operands.o, pc) or nil
                local j_value = type(operands.j) == "table"
                  and raw_rawget(operands.j, h_value) or nil
                local j_nested = type(j_value) == "table"
                  and raw_rawget(j_value, o_value) or nil
                rows[pc] = {
                  pc = pc,
                  opcode = encode_operand(raw_rawget(program.instructions, pc)),
                  h = encode_operand(h_value),
                  O = type(operands.O) == "table"
                    and encode_operand(raw_rawget(operands.O, pc)) or nil,
                  W = type(operands.W) == "table"
                    and encode_operand(raw_rawget(operands.W, pc)) or nil,
                  N = type(operands.N) == "table"
                    and encode_operand(raw_rawget(operands.N, pc)) or nil,
                  o = encode_operand(o_value),
                  e = type(operands.e) == "table"
                    and encode_operand(raw_rawget(operands.e, pc)) or nil,
                  j_h = encode_operand(j_value),
                  j_h_o = encode_operand(j_nested),
                  operands = operands_at(operands, pc),
                }
              end
              program_summaries[#program_summaries].instructions = rows
            end
          end
          local context_summaries = {}
          for _, context in ipairs(contexts) do
            local visited = {}
            for pc, count in pairs(context.visited_pcs or {}) do
              visited[#visited + 1] = { pc = pc, count = count }
            end
            table.sort(visited, function(left, right) return left.pc < right.pc end)
            local summary = {
              id = context.id,
              program = context.program.id,
              instruction_count = #context.program.instructions,
              fetch_count = context.fetch_count or 0,
              first_fetch_sequence = context.first_fetch_sequence,
              last_fetch_sequence = context.last_fetch_sequence,
              visited_pcs = visited,
              path_pcs = context.path_pcs or {},
              path_overflow = context.path_overflow or false,
              operand_snapshot_mode = "first_fetch_for_observed_pc",
              operand_snapshot_count =
                context.instruction_snapshot_count or 0,
              operand_variant_mode = runtime_fixture.record_operand_variants
                and "first_fetch_and_changes_for_observed_pc" or nil,
              operand_variant_count = context.instruction_variants
                and #context.instruction_variants or 0,
            }
            if include_programs then
              local rows = {}
              local operands = context.operands
              for pc = 1, #context.program.instructions do
                rows[pc] = context.instruction_snapshots
                  and context.instruction_snapshots[pc]
                  or instruction_at(context.program, operands, pc)
              end
              summary.instructions = rows
              if runtime_fixture.record_operand_variants then
                summary.instruction_variants =
                  context.instruction_variants or {}
              end
            end
            context_summaries[#context_summaries + 1] = summary
          end
          return {
            ok = ok,
            error = ok and nil or result,
            stopped_by_budget = stopped_by_budget,
            fetch_budget = fetch_budget,
            patched_upvalues = #patch_sites,
            programs = #programs,
            program_summaries = program_summaries,
            contexts = #contexts,
            context_summaries = context_summaries,
            fetch_count = math.min(fetch_count, fetch_budget),
            event_limit = event_limit,
            event_overflow = fetch_count > event_limit,
            environment_bindings = environment_bindings,
            instruction_upvalue_name = instruction_upvalue_name,
            environment_upvalue_name = environment_upvalue_name,
            operand_snapshot_format = "first-fetch-v1",
            global_events = global_events,
            global_event_overflow = global_event_overflow,
            callbacks_captured = #pending_callbacks,
            callbacks_invoked = callbacks_invoked,
            callback_limit_reached = callback_index <= #pending_callbacks,
            callback_results = callback_results,
            fetches = fetches,
            tail_fetches = tail_fetches,
            error_frames = error_frames,
            fixture_events = fixture_events,
            fixture_active = fixture_active,
            fixture_environment_before_invoke = fixture_environment_before_invoke,
          }
        end
        '''
    )
    report = lua_table_to_python(
        install_tracer(
            closure,
            fetch_budget,
            event_limit,
            include_programs,
            pass_environment,
            bind_missing_environment,
            lua_environment_overrides,
            lua_runtime_fixture,
            alias_global_environment,
            proxy_unknown_globals,
            callback_limit,
            instruction_upvalue_name,
            environment_upvalue_name,
        ),
        type_checker=type_checker,
    )
    report["tail_fetches"] = sorted(
        report.get("tail_fetches", []), key=lambda event: event["sequence"]
    )
    return report


def _decode_escaped_bytes(value: str) -> bytes:
    output = bytearray()
    index = 0
    while index < len(value):
        if value[index] != "\\":
            output.extend(value[index].encode("utf-8"))
            index += 1
            continue
        if value.startswith(r"\\", index):
            output.append(92)
            index += 2
        elif value.startswith(r'\"', index):
            output.append(34)
            index += 2
        elif (
            value.startswith(r"\x", index)
            and index + 3 < len(value)
            and all(char in "0123456789abcdefABCDEF" for char in value[index + 2 : index + 4])
        ):
            output.append(int(value[index + 2 : index + 4], 16))
            index += 4
        else:
            output.append(92)
            index += 1
    return bytes(output)


def _lua_bytes_literal(value: str) -> str:
    output = ['"']
    for byte in _decode_escaped_bytes(value):
        if 32 <= byte <= 126 and byte not in (34, 92):
            output.append(chr(byte))
        elif byte == 34:
            output.append(r'\"')
        elif byte == 92:
            output.append(r"\\")
        elif byte == 10:
            output.append(r"\n")
        elif byte == 13:
            output.append(r"\r")
        elif byte == 9:
            output.append(r"\t")
        else:
            output.append(f"\\{byte:03d}")
    output.append('"')
    return "".join(output)


def _trace_value_to_lua(value: dict[str, Any], scope: str) -> str:
    kind = value.get("type")
    if kind == "nil":
        return "nil"
    if kind == "boolean":
        return "true" if value["value"] else "false"
    if kind == "number":
        return repr(value["value"])
    if kind == "string":
        return _lua_bytes_literal(value["value"])
    if kind == "function":
        return f"callback_{value['callback']}"
    if kind == "proxy":
        return _trace_path_to_lua(value["path"], scope)
    return f"TRACE_VALUE[{json.dumps(kind or 'unknown')}]"


def _trace_path_to_lua(path: str, scope: str) -> str:
    callback_prefix = f"{scope}." if scope.startswith("callback:") else ""
    if callback_prefix and path.startswith(callback_prefix):
        path = path[len(callback_prefix) :]
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:[.:][A-Za-z_][A-Za-z0-9_]*|\(\))*", path):
        return path
    return f"TRACE_PROXY[{json.dumps(path, ensure_ascii=False)}]"


def _render_trace_event(event: dict[str, Any]) -> str | None:
    operation = event["op"]
    scope = event["scope"]
    if operation in {"global", "index", "scope_result"}:
        return None
    path = _trace_path_to_lua(event["path"], scope)
    if operation in {"set", "global_set"}:
        return f"{path} = {_trace_value_to_lua(event['value'], scope)}"
    if operation in {"call", "blocked_call"}:
        arguments = list(event.get("args", []))
        rendered_path = path
        if "." in path and arguments and arguments[0].get("type") == "proxy":
            receiver, method = path.rsplit(".", 1)
            first = _trace_path_to_lua(arguments[0]["path"], scope)
            if first == receiver and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", method):
                rendered_path = f"{receiver}:{method}"
                arguments = arguments[1:]
        rendered_arguments = ", ".join(
            _trace_value_to_lua(argument, scope) for argument in arguments
        )
        statement = f"{rendered_path}({rendered_arguments})"
        if operation == "blocked_call":
            return f"-- BLOCKED EXTERNAL CALL: {statement}"
        return statement
    return f"-- unrendered trace event: {json.dumps(event, ensure_ascii=False)}"


def render_semantic_lua(source_name: str, trace: dict[str, Any]) -> str:
    """Render an inert, readable account of calls observed during sandbox tracing."""
    events_by_scope: dict[str, list[dict[str, Any]]] = {}
    for event in trace["events"]:
        events_by_scope.setdefault(event["scope"], []).append(event)

    callbacks = trace.get("callbacks", [])
    lines = [
        f"-- Semantic recovery of {source_name}",
        "-- Generated from one isolated execution path; this is not the original text.",
        "-- TRACE_PROXY/TRACE_VALUE mark environment-dependent values.",
        "",
        "local TRACE_PROXY = setmetatable({}, { __index = function() return nil end })",
        "local TRACE_VALUE = TRACE_PROXY",
    ]
    if callbacks:
        lines.append("local " + ", ".join(f"callback_{item['id']}" for item in callbacks))
    lines.append("")

    for callback in callbacks:
        callback_id = callback["id"]
        lines.extend(
            [
                f"-- Captured at {callback['origin_scope']} -> {callback['origin_path']} argument {callback['argument']}",
                f"callback_{callback_id} = function(arg1, arg2, arg3, arg4)",
            ]
        )
        body = [
            rendered
            for event in events_by_scope.get(f"callback:{callback_id}", [])
            if (rendered := _render_trace_event(event)) is not None
        ]
        lines.extend(f"    {line}" for line in body or ["-- no observable proxy interaction"])
        if callback.get("status") == "errored":
            lines.append(f"    -- trace stopped: {callback.get('error', 'unknown error')}")
        lines.extend(["end", ""])

    lines.append("-- Root chunk")
    root_body = [
        rendered
        for event in events_by_scope.get("root", [])
        if (rendered := _render_trace_event(event)) is not None
    ]
    lines.extend(root_body or ["-- no observable proxy interaction"])
    if not trace["root"]["ok"]:
        lines.append(f"-- root trace stopped: {trace['root'].get('error', 'unknown error')}")
    lines.append("")
    return "\n".join(lines)


def describe_closure(
    runtime: LuaRuntime, closure: Any, *, depth: int = 0
) -> dict[str, Any]:
    describe = runtime.eval(
        """
        function(fn, max_depth)
          local seen = {}

          local function safe_string(value)
            local output = {}
            for index = 1, math.min(#value, 120) do
              local byte = string.byte(value, index)
              if byte >= 32 and byte <= 126 and byte ~= 92 then
                output[#output + 1] = string.char(byte)
              else
                output[#output + 1] = string.format("\\\\x%02x", byte)
              end
            end
            return table.concat(output)
          end

          local function summarize(fn_value, remaining)
            if seen[fn_value] then
              return { recursive = true }
            end
            seen[fn_value] = true
            local info = debug.getinfo(fn_value, "Snu")
            local result = {
                what = info.what,
                source = info.source,
                linedefined = info.linedefined,
                lastlinedefined = info.lastlinedefined,
                nups = info.nups,
                upvalues = {},
            }
            local index = 1
            while true do
                local name, value = debug.getupvalue(fn_value, index)
                if name == nil then break end
                local kind = type(value)
                local item = { index = index, name = name, type = kind }
                if kind == "table" then
                    local count = 0
                    local array_count = 0
                    local key_types = {}
                    local value_types = {}
                    for key in pairs(value) do
                        count = count + 1
                        if type(key) == "number" and key >= 1 and key % 1 == 0 then
                            array_count = array_count + 1
                        end
                        key_types[type(key)] = true
                        value_types[type(value[key])] = true
                    end
                    item.count = count
                    item.array_count = array_count
                    item.key_types = key_types
                    item.value_types = value_types
                    item.samples = {}
                    for sample_index = 1, math.min(array_count, 12) do
                        local sample = value[sample_index]
                        local sample_type = type(sample)
                        if sample_type == "number" or sample_type == "boolean" then
                            item.samples[#item.samples + 1] = sample
                        elseif sample_type == "string" then
                            item.samples[#item.samples + 1] = safe_string(sample)
                        else
                            item.samples[#item.samples + 1] = "<" .. sample_type .. ">"
                        end
                    end
                elseif kind == "string" then
                    item.length = #value
                    item.preview = safe_string(value)
                elseif kind == "number" or kind == "boolean" then
                    item.value = value
                elseif kind == "function" then
                    local child = debug.getinfo(value, "Snu")
                    item.nups = child.nups
                    item.what = child.what
                    if remaining > 0 then
                        item.closure = summarize(value, remaining - 1)
                    end
                end
                result.upvalues[#result.upvalues + 1] = item
                index = index + 1
            end
            return result
          end

          return summarize(fn, max_depth)
        end
        """
    )
    return lua_table_to_python(describe(closure, depth))


def lua_table_to_python(
    value: Any, *, type_checker: Callable[[Any], str | None] = lua_type
) -> Any:
    if type_checker(value) != "table":
        return value

    keys = list(value.keys())
    if keys and all(isinstance(key, int) for key in keys):
        largest = max(keys)
        if set(keys) == set(range(1, largest + 1)):
            return [
                lua_table_to_python(value[index], type_checker=type_checker)
                for index in range(1, largest + 1)
            ]
    return {
        str(key): lua_table_to_python(value[key], type_checker=type_checker)
        for key in keys
    }


def inspect_file(path: Path, capture: bool, depth: int = 0) -> dict[str, Any]:
    source = path.read_text(encoding="utf-8")
    payload = extract_payload(source)
    decoded = decode_lph_base85(payload)
    info = PayloadInfo(
        source=str(path),
        marker=payload[:4],
        encoded_size=len(payload),
        decoded_size=len(decoded),
        sha256=hashlib.sha256(decoded).hexdigest(),
    )
    result: dict[str, Any] = {"payload": asdict(info)}
    if capture:
        runtime, closure = capture_root_closure(source)
        result["closure"] = describe_closure(runtime, closure, depth=depth)
    return result


def summarize_trace(trace: dict[str, Any]) -> dict[str, Any]:
    event_counts: dict[str, int] = {}
    for event in trace["events"]:
        event_counts[event["op"]] = event_counts.get(event["op"], 0) + 1
    return {
        "root": trace["root"],
        "callbacks_captured": len(trace.get("callbacks", [])),
        "callbacks_invoked": trace["callbacks_invoked"],
        "callback_limit_reached": trace["callback_limit_reached"],
        "events": len(trace["events"]),
        "event_counts": event_counts,
        "event_overflow": trace["event_overflow"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Statically unpack and safely probe this Luraph loader family."
    )
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument(
        "--capture",
        action="store_true",
        help="construct the root VM closure without invoking the protected payload",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=0,
        help="recursively describe function upvalues to this depth",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="write decoded LPH byte streams to this directory",
    )
    parser.add_argument(
        "--bytecode-dir",
        type=Path,
        help="write the non-executed root VM closures as LuaJIT bytecode",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="include the isolated dynamic trace in standard output",
    )
    parser.add_argument(
        "--trace-dir",
        type=Path,
        help="write isolated dynamic trace reports as JSON",
    )
    parser.add_argument(
        "--recovered-dir",
        type=Path,
        help="write readable semantic Lua reconstructed from isolated traces",
    )
    parser.add_argument(
        "--graph-dir",
        type=Path,
        help="write the root VM closure object graphs as JSON",
    )
    parser.add_argument(
        "--instruction-budget",
        type=int,
        default=DEFAULT_INSTRUCTION_BUDGET,
        help="maximum traced Lua VM instructions per scope; 0 disables the hook",
    )
    parser.add_argument(
        "--callback-limit",
        type=int,
        default=DEFAULT_CALLBACK_LIMIT,
        help="maximum captured callbacks to invoke per input",
    )
    parser.add_argument(
        "--event-limit",
        type=int,
        default=DEFAULT_EVENT_LIMIT,
        help="maximum trace events retained per input",
    )
    parser.add_argument(
        "--no-global-proxy",
        action="store_true",
        help="leave unknown globals nil instead of installing the trace metatable",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    reports = []
    for path in args.inputs:
        report = inspect_file(path, capture=args.capture, depth=args.depth)
        reports.append(report)
        source = path.read_text(encoding="utf-8")
        if args.output_dir is not None:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            decoded = decode_lph_base85(extract_payload(source))
            (args.output_dir / f"{path.stem}.lph.bin").write_bytes(decoded)
        if args.bytecode_dir is not None:
            args.bytecode_dir.mkdir(parents=True, exist_ok=True)
            (args.bytecode_dir / f"{path.stem}.root.ljbc").write_bytes(
                dump_root_bytecode(source)
            )
        should_trace = (
            args.trace or args.trace_dir is not None or args.recovered_dir is not None
        )
        if should_trace:
            trace = trace_payload(
                source,
                instruction_budget=args.instruction_budget,
                callback_limit=args.callback_limit,
                event_limit=args.event_limit,
                proxy_unknown_globals=not args.no_global_proxy,
            )
            report["trace"] = trace if args.trace else summarize_trace(trace)
            if args.trace_dir is not None:
                args.trace_dir.mkdir(parents=True, exist_ok=True)
                (args.trace_dir / f"{path.stem}.trace.json").write_text(
                    json.dumps(trace, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
            if args.recovered_dir is not None:
                args.recovered_dir.mkdir(parents=True, exist_ok=True)
                (args.recovered_dir / f"{path.stem}.recovered.lua").write_text(
                    render_semantic_lua(path.name, trace),
                    encoding="utf-8",
                )
        if args.graph_dir is not None:
            args.graph_dir.mkdir(parents=True, exist_ok=True)
            graph = dump_closure_graph(source)
            report["graph"] = graph["stats"]
            (args.graph_dir / f"{path.stem}.graph.json").write_text(
                json.dumps(graph, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
    print(json.dumps(reports, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
