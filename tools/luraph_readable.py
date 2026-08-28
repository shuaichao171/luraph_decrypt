from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from tools.luraph_devirtualize import extract_vm_layout, instantiate_handler

DIRECT_REGISTER_ASSIGNMENT_RE = re.compile(r"^(r\d+)\s*=\s*(.+)$")
TABLE_ASSIGNMENT_RE = re.compile(r"^(r\d+\s*\[[^\n]+\])\s*=\s*(.+)$")
NEW_TABLE_RE = re.compile(r"^(r\d+)\s*=\s*\{\s*\}$")
TABLE_FIELD_RE = re.compile(
    r'^(r\d+)\s*\[("(?:[^"\\]|\\.)*")\]\s*=\s*(.+)$'
)
REGISTER_RE = re.compile(r"\br\d+\b")
OPAQUE_RE = re.compile(r"<([A-Za-z_]\w*)>")
SIMPLE_VALUE_RE = re.compile(
    r"(?:nil|true|false|-?\d+(?:\.\d+)?|\"(?:[^\"\\]|\\.)*\"|"
    r"[A-Za-z_]\w*(?:(?:\.[A-Za-z_]\w*)|(?:\[[^\]]+\]))*)"
)
DOMAIN_TERM_RE = re.compile(
    r"skin|prefab|modname|modinfo|modindex|\bmod\b|component|postinit|asset|build|bank|"
    r"anim|character|config|workshop|recipe|inventory|equippable|locomotor",
    re.IGNORECASE,
)
COMMON_RUNTIME_STRINGS = frozenset(
    {
        "__call",
        "__index",
        "__metatable",
        "assert",
        "byte",
        "char",
        "format",
        "getfenv",
        "getmetatable",
        "gsub",
        "ipairs",
        "len",
        "linedefined",
        "namewhat",
        "next",
        "nparams",
        "pairs",
        "pcall",
        "rawget",
        "rawset",
        "select",
        "setfenv",
        "setmetatable",
        "short_src",
        "source",
        "sub",
        "tonumber",
        "tostring",
        "type",
        "unpack",
        "what",
        "xpcall",
    }
)


def _semantic_anchor_pattern(pc_variable: str, register_variable: str) -> re.Pattern[str]:
    pc_name = re.escape(pc_variable)
    register_name = re.escape(register_variable)
    return re.compile(
        rf"\b{register_name}\s*\[|\({register_name}\)\s*\[|"
        rf"\b{pc_name}\b|\b[A-Za-z_]\w*\s*\[\s*{pc_name}\s*\]"
    )


def _integrity_reference_pattern(integrity_variable: str) -> re.Pattern[str]:
    integrity_name = re.escape(integrity_variable)
    return re.compile(rf"\b{integrity_name}\s*\[|\({integrity_name}\)\s*\[")


def _jump_assignment_pattern(pc_variable: str) -> re.Pattern[str]:
    return re.compile(rf"\b{re.escape(pc_variable)}\s*=\s*\(?\s*(-?\d+)\s*\)?")


@dataclass(frozen=True, slots=True)
class FlowShape:
    has_jump: bool
    unconditional_jump: bool
    has_return: bool
    terminal_return: bool


@dataclass(frozen=True, slots=True)
class HandlerCleanup:
    source: str
    removed_common_statements: int
    unwrapped_integrity_guards: int
    flow: FlowShape
    unfolded_state_loops: int = 0
    parse_fallback: bool = False


@dataclass(slots=True)
class ReadableInstruction:
    pc: int
    opcode: int
    source: str
    kind: str
    jump_targets: list[int]
    unconditional_jump: bool
    terminal_return: bool
    observed: int


@dataclass(slots=True)
class BasicBlock:
    label: str
    start_pc: int
    end_pc: int
    instruction_indexes: list[int]
    successors: list[str]
    predecessors: list[str]


def _lua_ast() -> Any:
    try:
        from luaparser import ast
    except ImportError as error:  # pragma: no cover - exercised by CLI environment
        raise RuntimeError(
            "readable decompilation requires luaparser; run with "
            "`uv run --with lupa --with luaparser`"
        ) from error
    return ast


def _parse_handler(source: str) -> tuple[Any, Any]:
    ast = _lua_ast()
    tree = ast.parse(f"return function()\n{source}\nend")
    return ast, tree.body.body[0].values[0]


def _try_parse_handler(source: str) -> tuple[Any, Any] | None:
    ast = _lua_ast()
    try:
        tree = ast.parse(f"return function()\n{source}\nend")
    except ast.SyntaxException:
        repaired = re.sub(r"(?m)^elseif\b", "if", source)
        if repaired == source:
            return None
        try:
            tree = ast.parse(f"return function()\n{repaired}\nend")
        except ast.SyntaxException:
            return None
    return ast, tree.body.body[0].values[0]


def _render_statement(ast: Any, statement: Any) -> str:
    return ast.to_lua_source(statement).strip()


def _has_semantic_anchor(
    ast: Any,
    node: Any,
    pc_variable: str,
    register_variable: str,
) -> bool:
    if node is None:
        return False
    return bool(
        _semantic_anchor_pattern(pc_variable, register_variable).search(
            ast.to_lua_source(node)
        )
    )


def _is_integrity_test(ast: Any, node: Any, integrity_variable: str) -> bool:
    return bool(
        _integrity_reference_pattern(integrity_variable).search(
            ast.to_lua_source(node)
        )
    )


def _branch_quality(ast: Any, node: Any, integrity_variable: str) -> tuple[int, int, int]:
    if node is None:
        return 1, 0, 0
    nodes = list(ast.walk(node))
    has_trap_flow = any(type(item).__name__ == "Return" for item in nodes)
    if not has_trap_flow:
        has_trap_flow = any(
            type(item).__name__ == "While"
            and _constant_value(item.test, {}) is True
            for item in nodes
        )
    integrity_references = len(
        _integrity_reference_pattern(integrity_variable).findall(
            ast.to_lua_source(node)
        )
    )
    meaningful_nodes = sum(
        type(item).__name__ not in {"Block", "SemiColon"} for item in nodes
    )
    return int(not has_trap_flow), -integrity_references, int(meaningful_nodes > 0)


def specialize_opcode_handler(
    source: str,
    opcode: int,
    *,
    opcode_variable: str,
    instruction_upvalue: str,
    pc_variable: str,
) -> str:
    """Substitute constants that remain fixed throughout one dispatch leaf."""
    instruction_read = re.compile(
        rf"\b{re.escape(instruction_upvalue)}\s*\[\s*"
        rf"{re.escape(pc_variable)}\s*\](?!\s*=)"
    )
    source = instruction_read.sub(str(opcode), source)
    return re.sub(
        rf"\b{re.escape(opcode_variable)}\b",
        str(opcode),
        source,
    )


def derive_noise_statements(
    handlers: dict[int, str],
    *,
    pc_variable: str = "B",
    register_variable: str = "z",
    integrity_variable: str = "C",
) -> set[str]:
    """Find repeated top-level integrity statements without VM semantics."""
    statement_counts: Counter[str] = Counter()
    for source in handlers.values():
        parsed = _try_parse_handler(source)
        if parsed is None:
            continue
        ast, function = parsed
        statements = {
            _render_statement(ast, statement) for statement in function.body.body
        }
        statement_counts.update(statements)
    semantic_anchor = _semantic_anchor_pattern(pc_variable, register_variable)
    integrity_reference = _integrity_reference_pattern(integrity_variable)
    return {
        statement
        for statement, count in statement_counts.items()
        if count >= 3
        and integrity_reference.search(statement)
        and not semantic_anchor.search(statement)
    }


def _prune_nested_blocks(
    ast: Any,
    statement: Any,
    noise_statements: set[str],
    pc_variable: str,
    register_variable: str,
    integrity_variable: str,
) -> tuple[list[Any], int, int]:
    rendered = _render_statement(ast, statement)
    if rendered in noise_statements:
        return [], 1, 0

    removed = 0
    unwrapped = 0
    body = getattr(statement, "body", None)
    if type(body).__name__ == "Block":
        body.body, child_removed, child_unwrapped = _prune_block(
            ast,
            body.body,
            noise_statements,
            pc_variable,
            register_variable,
            integrity_variable,
        )
        removed += child_removed
        unwrapped += child_unwrapped

    orelse = getattr(statement, "orelse", None)
    if type(orelse).__name__ == "Block":
        orelse.body, child_removed, child_unwrapped = _prune_block(
            ast,
            orelse.body,
            noise_statements,
            pc_variable,
            register_variable,
            integrity_variable,
        )
        removed += child_removed
        unwrapped += child_unwrapped
    elif type(orelse).__name__ == "ElseIf":
        replacement, child_removed, child_unwrapped = _prune_nested_blocks(
            ast,
            orelse,
            noise_statements,
            pc_variable,
            register_variable,
            integrity_variable,
        )
        removed += child_removed
        unwrapped += child_unwrapped
        if not replacement:
            statement.orelse = None
        elif len(replacement) == 1:
            statement.orelse = replacement[0]
        else:
            statement.orelse = type(statement.body)(body=replacement)

    if type(statement).__name__ not in {"If", "ElseIf"} or not _is_integrity_test(
        ast, statement.test, integrity_variable
    ):
        return [statement], removed, unwrapped
    if _has_semantic_anchor(ast, statement.test, pc_variable, register_variable):
        return [statement], removed, unwrapped

    body_has_semantics = _has_semantic_anchor(
        ast, statement.body, pc_variable, register_variable
    )
    else_has_semantics = _has_semantic_anchor(
        ast, statement.orelse, pc_variable, register_variable
    )
    if not body_has_semantics and not else_has_semantics:
        if statement.orelse is None:
            return [], removed + 1, unwrapped
        body_quality = _branch_quality(ast, statement.body, integrity_variable)
        else_quality = _branch_quality(ast, statement.orelse, integrity_variable)
        if body_quality == else_quality:
            return [statement], removed, unwrapped
        if body_quality > else_quality:
            return list(statement.body.body), removed, unwrapped + 1
        if type(statement.orelse).__name__ == "Block":
            return list(statement.orelse.body), removed, unwrapped + 1
        return [statement.orelse], removed, unwrapped + 1
    if body_has_semantics == else_has_semantics:
        return [statement], removed, unwrapped
    if body_has_semantics:
        return list(statement.body.body), removed, unwrapped + 1
    if type(statement.orelse).__name__ == "Block":
        return list(statement.orelse.body), removed, unwrapped + 1
    return [statement], removed, unwrapped


def _prune_block(
    ast: Any,
    statements: list[Any],
    noise_statements: set[str],
    pc_variable: str,
    register_variable: str,
    integrity_variable: str,
) -> tuple[list[Any], int, int]:
    output: list[Any] = []
    removed = 0
    unwrapped = 0
    for statement in statements:
        replacement, item_removed, item_unwrapped = _prune_nested_blocks(
            ast,
            statement,
            noise_statements,
            pc_variable,
            register_variable,
            integrity_variable,
        )
        output.extend(replacement)
        removed += item_removed
        unwrapped += item_unwrapped
    return output, removed, unwrapped


def _assigns_pc(statement: Any, pc_variable: str) -> bool:
    if type(statement).__name__ != "Assign":
        return False
    return any(
        type(target).__name__ == "Name" and target.id == pc_variable
        for target in statement.targets
    )


def _flow_shape(ast: Any, function: Any, pc_variable: str) -> FlowShape:
    top_level = function.body.body
    all_nodes = list(ast.walk(function.body))
    return FlowShape(
        has_jump=any(_assigns_pc(node, pc_variable) for node in all_nodes),
        unconditional_jump=any(
            _assigns_pc(node, pc_variable) for node in top_level
        ),
        has_return=any(type(node).__name__ == "Return" for node in all_nodes),
        terminal_return=any(type(node).__name__ == "Return" for node in top_level),
    )


_UNKNOWN = object()
_LUA_NIL = object()


def _lua_truthy(value: object) -> bool:
    return value is not False and value is not _LUA_NIL


def _constant_value(node: Any, values: dict[str, object]) -> object:
    if node is None:
        return _UNKNOWN
    name = getattr(node, "_name", type(node).__name__)
    if name == "Name":
        return values.get(node.id, _UNKNOWN)
    if name == "Number":
        return node.n
    if name == "String":
        return node.s
    if name == "True":
        return True
    if name == "False":
        return False
    if name == "Nil":
        return _LUA_NIL
    if name == "ULNotOp":
        operand = _constant_value(node.operand, values)
        return _UNKNOWN if operand is _UNKNOWN else not _lua_truthy(operand)
    if name == "UMinusOp":
        operand = _constant_value(node.operand, values)
        if operand is _UNKNOWN:
            return _UNKNOWN
        try:
            return -operand
        except TypeError:
            return _UNKNOWN
    if name in {"LAndOp", "LOrOp"}:
        left = _constant_value(node.left, values)
        if left is _UNKNOWN:
            return _UNKNOWN
        if name == "LAndOp":
            return _constant_value(node.right, values) if _lua_truthy(left) else left
        return left if _lua_truthy(left) else _constant_value(node.right, values)

    left = _constant_value(getattr(node, "left", None), values)
    right = _constant_value(getattr(node, "right", None), values)
    if left is _UNKNOWN or right is _UNKNOWN:
        return _UNKNOWN
    operations = {
        "AddOp": lambda: left + right,
        "SubOp": lambda: left - right,
        "MultOp": lambda: left * right,
        "FloatDivOp": lambda: left / right,
        "FloorDivOp": lambda: left // right,
        "ModOp": lambda: left % right,
        "ExpoOp": lambda: left**right,
        "Concat": lambda: str(left) + str(right),
        "REqOp": lambda: left == right,
        "RNotEqOp": lambda: left != right,
        "RLtOp": lambda: left < right,
        "RLtEqOp": lambda: left <= right,
        "RGtOp": lambda: left > right,
        "RGtEqOp": lambda: left >= right,
    }
    operation = operations.get(name)
    if operation is None:
        return _UNKNOWN
    try:
        return operation()
    except (ArithmeticError, TypeError, ValueError):
        return _UNKNOWN


def _assigned_simple_names(ast: Any, node: Any) -> set[str]:
    return {
        target.id
        for item in ast.walk(node)
        if type(item).__name__ in {"Assign", "LocalAssign"}
        for target in item.targets
        if type(target).__name__ == "Name"
    }


def _constant_node(value: object) -> Any | None:
    from luaparser.astnodes import FalseExpr, Nil, Number, TrueExpr

    if value is _LUA_NIL:
        return Nil()
    if value is True:
        return TrueExpr()
    if value is False:
        return FalseExpr()
    if isinstance(value, (int, float)):
        return Number(n=value)
    return None


class _StaticControlSimplifier:
    def __init__(self, ast: Any) -> None:
        self.ast = ast
        self.unfolded_loops = 0
        self.resolved_branches = 0

    def _update_assignment(self, statement: Any, values: dict[str, object]) -> None:
        evaluated = [_constant_value(value, values) for value in statement.values]
        for index, value in enumerate(evaluated):
            replacement = _constant_node(value)
            if replacement is not None:
                statement.values[index] = replacement
        for index, target in enumerate(statement.targets):
            if type(target).__name__ != "Name":
                continue
            value = evaluated[index] if index < len(evaluated) else _LUA_NIL
            if value is _UNKNOWN:
                values.pop(target.id, None)
            else:
                values[target.id] = value

    def _branch_statements(self, branch: Any) -> list[Any]:
        if branch is None:
            return []
        if type(branch).__name__ == "Block":
            return list(branch.body)
        return [branch]

    def _execute_loop(
        self,
        statement: Any,
        values: dict[str, object],
    ) -> tuple[list[Any], str | None] | None:
        trial_values = dict(values)
        output: list[Any] = []
        trial = _StaticControlSimplifier(self.ast)
        is_repeat = type(statement).__name__ == "Repeat"
        for _ in range(256):
            if not is_repeat:
                verdict = _constant_value(statement.test, trial_values)
                if verdict is _UNKNOWN:
                    return None
                if not _lua_truthy(verdict):
                    values.clear()
                    values.update(trial_values)
                    self.unfolded_loops += 1 + trial.unfolded_loops
                    self.resolved_branches += trial.resolved_branches
                    return output, None

            body, signal, deterministic = trial.execute_block(
                list(statement.body.body),
                trial_values,
                deterministic=True,
            )
            if not deterministic:
                return None
            output.extend(body)
            if signal == "break":
                values.clear()
                values.update(trial_values)
                self.unfolded_loops += 1 + trial.unfolded_loops
                self.resolved_branches += trial.resolved_branches
                return output, None
            if signal == "return":
                values.clear()
                values.update(trial_values)
                self.unfolded_loops += 1 + trial.unfolded_loops
                self.resolved_branches += trial.resolved_branches
                return output, signal

            if is_repeat:
                verdict = _constant_value(statement.test, trial_values)
                if verdict is _UNKNOWN:
                    return None
                if _lua_truthy(verdict):
                    values.clear()
                    values.update(trial_values)
                    self.unfolded_loops += 1 + trial.unfolded_loops
                    self.resolved_branches += trial.resolved_branches
                    return output, None
        return None

    def execute_block(
        self,
        statements: list[Any],
        values: dict[str, object] | None = None,
        *,
        deterministic: bool = False,
    ) -> tuple[list[Any], str | None, bool]:
        if values is None:
            values = {}
        output: list[Any] = []
        for statement in statements:
            kind = type(statement).__name__
            if kind == "SemiColon":
                continue
            if kind in {"Assign", "LocalAssign"}:
                self._update_assignment(statement, values)
                output.append(statement)
                continue
            if kind in {"If", "ElseIf"}:
                verdict = _constant_value(statement.test, values)
                if verdict is _UNKNOWN:
                    if deterministic:
                        return output, None, False
                    for name in _assigned_simple_names(self.ast, statement):
                        values.pop(name, None)
                    output.append(statement)
                    continue
                self.resolved_branches += 1
                branch = statement.body if _lua_truthy(verdict) else statement.orelse
                selected, signal, complete = self.execute_block(
                    self._branch_statements(branch),
                    values,
                    deterministic=deterministic,
                )
                if not complete:
                    return output, signal, False
                output.extend(selected)
                if signal:
                    return output, signal, True
                continue
            if kind in {"While", "Repeat"}:
                unfolded = self._execute_loop(statement, values)
                if unfolded is None:
                    if deterministic:
                        return output, None, False
                    for name in _assigned_simple_names(self.ast, statement):
                        values.pop(name, None)
                    output.append(statement)
                    continue
                selected, signal = unfolded
                output.extend(selected)
                if signal:
                    return output, signal, True
                continue
            if kind == "Break":
                return output, "break", True
            if kind == "Return":
                output.append(statement)
                return output, "return", True
            for name in _assigned_simple_names(self.ast, statement):
                values.pop(name, None)
            output.append(statement)
        return output, None, True


def simplify_static_control_flow(ast: Any, statements: list[Any]) -> tuple[list[Any], int]:
    simplifier = _StaticControlSimplifier(ast)
    output, _, _ = simplifier.execute_block(statements)
    return output, simplifier.unfolded_loops


def sanitize_handler(
    source: str,
    noise_statements: set[str],
    *,
    pc_variable: str = "B",
    register_variable: str = "z",
    integrity_variable: str = "C",
) -> HandlerCleanup:
    if source.strip().startswith("-- no operation"):
        return HandlerCleanup(
            source.strip(),
            0,
            0,
            FlowShape(False, False, False, False),
        )
    parsed = _try_parse_handler(source)
    if parsed is None:
        flow = FlowShape(
            has_jump=bool(
                re.search(rf"\b{re.escape(pc_variable)}\s*=", source)
            ),
            unconditional_jump=False,
            has_return=bool(re.search(r"\breturn\b", source)),
            terminal_return=source.lstrip().startswith("return"),
        )
        return HandlerCleanup(source.strip(), 0, 0, flow, parse_fallback=True)
    ast, function = parsed

    statements, removed, unwrapped = _prune_block(
        ast,
        function.body.body,
        noise_statements,
        pc_variable,
        register_variable,
        integrity_variable,
    )
    statements, unfolded_loops = simplify_static_control_flow(ast, statements)
    function.body.body = statements
    rendered = "\n".join(_render_statement(ast, statement) for statement in statements)
    return HandlerCleanup(
        rendered.strip() or "-- no operation after integrity-noise removal",
        removed,
        unwrapped,
        _flow_shape(ast, function, pc_variable),
        unfolded_loops,
    )


def _cleanup_lua(source: str) -> str:
    source = OPAQUE_RE.sub(lambda match: f"opaque_{match.group(1)}", source)
    simple_parentheses = re.compile(
        r"\((r\d+|nil|true|false|-?\d+(?:\.\d+)?)\)"
    )
    previous = None
    while previous != source:
        previous = source
        source = simple_parentheses.sub(r"\1", source)

    lines: list[str] = []
    blank = False
    for raw_line in source.splitlines():
        line = raw_line.rstrip()
        if line.strip() == ";":
            continue
        line = re.sub(r";\s*$", "", line)
        if not line.strip():
            if lines and not blank:
                lines.append("")
            blank = True
            continue
        lines.append(line)
        blank = False
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


def instantiate_readable_handler(
    cleanup: HandlerCleanup,
    instruction: dict[str, Any],
    *,
    pc_variable: str = "B",
    register_variable: str = "z",
) -> tuple[str, list[int]]:
    instantiated = instantiate_handler(
        cleanup.source,
        instruction,
        pc_variable=pc_variable,
        register_variable=register_variable,
    )
    jump_assignment = _jump_assignment_pattern(pc_variable)
    targets = [int(value) + 1 for value in jump_assignment.findall(instantiated)]

    def jump_to_label(match: re.Match[str]) -> str:
        target = int(match.group(1)) + 1
        if target < 0:
            return match.group(0)
        return f"goto L{target:04d}"

    instantiated = jump_assignment.sub(jump_to_label, instantiated)
    return _cleanup_lua(instantiated), targets


def simplify_known_operation(source: str) -> str:
    """Collapse verbose VM machinery when the high-level operation is explicit."""
    closure_target = re.search(r"(?m)^\s*(r\d+)\s*=\s*\(?k\)?\s*$", source)
    if (
        closure_target
        and "opaque_table" in source
        and re.search(r"\bfor\b", source)
        and re.search(r"\bC\s*\[\s*\d+\s*\]\s*\(\s*U\s*,\s*V\s*\)", source)
    ):
        return f"{closure_target.group(1)} = vm_closure(opaque_table)"
    return source


def classify_operation(source: str, flow: FlowShape, targets: list[int]) -> str:
    stripped = source.strip()
    if stripped.startswith("-- no operation"):
        return "NO_OP"
    if flow.terminal_return:
        return "RETURN"
    if targets:
        return "JUMP" if flow.unconditional_jump else "BRANCH"
    if "vm_closure(" in stripped:
        return "CLOSURE"
    if "function" in stripped:
        return "CLOSURE"
    if "\n" not in stripped:
        assignment = DIRECT_REGISTER_ASSIGNMENT_RE.fullmatch(stripped)
        if assignment:
            right = assignment.group(2).strip()
            if right == "{}":
                return "NEW_TABLE"
            if re.fullmatch(r"r\d+", right):
                return "MOVE"
            if SIMPLE_VALUE_RE.fullmatch(right):
                return "LOAD_VALUE"
            if re.search(r"\[[^\]]+\]$", right):
                return "GET_TABLE"
            if "(" in right:
                return "CALL"
            return "ASSIGN"
        if TABLE_ASSIGNMENT_RE.fullmatch(stripped):
            return "SET_TABLE"
        if re.search(r"[A-Za-z_][\w.\[\]\"]*\s*\(", stripped):
            return "CALL"
    if re.search(r"\bfor\b", stripped):
        return "FOR"
    if re.search(r"\bif\b", stripped):
        return "TEST"
    if flow.has_return:
        return "CONDITIONAL_RETURN"
    return "OPERATION"


def _substitute_registers(expression: str, bindings: dict[str, str]) -> str:
    def replacement(match: re.Match[str]) -> str:
        return bindings.get(match.group(0), match.group(0))

    return REGISTER_RE.sub(replacement, expression)


def _propagate_block(
    instructions: list[ReadableInstruction],
    indexes: list[int],
) -> None:
    bindings: dict[str, str] = {}
    for index in indexes:
        instruction = instructions[index]
        source = instruction.source.strip()
        if "\n" in source:
            bindings.clear()
            continue

        direct = DIRECT_REGISTER_ASSIGNMENT_RE.fullmatch(source)
        table = TABLE_ASSIGNMENT_RE.fullmatch(source)
        if direct:
            target, right = direct.groups()
            right = _substitute_registers(right.strip(), bindings)
            instruction.source = f"{target} = {right}"
            bindings.pop(target, None)
            if SIMPLE_VALUE_RE.fullmatch(right):
                bindings[target] = right
        elif table:
            left, right = table.groups()
            instruction.source = f"{left} = {_substitute_registers(right, bindings)}"
        else:
            instruction.source = _substitute_registers(source, bindings)

        if instruction.kind in {"BRANCH", "JUMP", "RETURN"}:
            bindings.clear()


def _clone_recovered_table(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _clone_recovered_table(item) for key, item in value.items()}
    return value


def _recover_table_literals(
    instructions: list[ReadableInstruction],
) -> list[tuple[str, dict[str, Any]]]:
    tables: dict[str, dict[str, Any]] = {}
    attached_registers: set[str] = set()
    for instruction in instructions:
        normalized = re.sub(r"\s+", " ", instruction.source).strip()
        new_table = NEW_TABLE_RE.fullmatch(normalized)
        if new_table:
            tables[new_table.group(1)] = {}
            continue
        field = TABLE_FIELD_RE.fullmatch(normalized)
        if field is None:
            continue
        register, raw_key, raw_value = field.groups()
        if register not in tables:
            continue
        try:
            key = json.loads(raw_key)
        except json.JSONDecodeError:
            continue
        child = raw_value.strip()
        if re.fullmatch(r"r\d+", child) and child in tables:
            tables[register][key] = _clone_recovered_table(tables[child])
            attached_registers.add(child)
        elif SIMPLE_VALUE_RE.fullmatch(child):
            tables[register][key] = child

    def is_interesting(table: dict[str, Any]) -> bool:
        nested = sum(isinstance(value, dict) for value in table.values())
        keys = {key.lower() for key in table if isinstance(key, str)}
        return nested >= 2 or len(keys.intersection({"id", "version", "enabled"})) >= 2

    return [
        (register, table)
        for register, table in tables.items()
        if register not in attached_registers and table and is_interesting(table)
    ]


def _render_recovered_table(
    name: str,
    table: dict[str, Any],
    *,
    indent: int = 0,
) -> list[str]:
    prefix = " " * indent
    lines = [f"{prefix}local {name} = {{" if indent == 0 else f"{prefix}{{"]
    for key, value in table.items():
        key_source = (
            key
            if isinstance(key, str) and re.fullmatch(r"[A-Za-z_]\w*", key)
            else f"[{json.dumps(key, ensure_ascii=False)}]"
        )
        if isinstance(value, dict):
            nested = _render_recovered_table("", value, indent=indent + 4)
            lines.append(f"{' ' * (indent + 4)}{key_source} = {nested[0].lstrip()}")
            lines.extend(nested[1:-1])
            lines.append(f"{' ' * (indent + 4)}}},")
        else:
            lines.append(f"{' ' * (indent + 4)}{key_source} = {value},")
    lines.append(f"{prefix}}}")
    return lines


def build_basic_blocks(
    instructions: list[ReadableInstruction],
) -> list[BasicBlock]:
    if not instructions:
        return []
    pc_to_index = {instruction.pc: index for index, instruction in enumerate(instructions)}
    boundaries = {instructions[0].pc}
    for index, instruction in enumerate(instructions):
        boundaries.update(
            target for target in instruction.jump_targets if target in pc_to_index
        )
        if (
            instruction.jump_targets or instruction.terminal_return
        ) and index + 1 < len(instructions):
            boundaries.add(instructions[index + 1].pc)
        if (
            index + 1 < len(instructions)
            and instructions[index + 1].pc != instruction.pc + 1
        ):
            boundaries.add(instructions[index + 1].pc)

    blocks: list[BasicBlock] = []
    current: list[int] = []
    for index, instruction in enumerate(instructions):
        if current and instruction.pc in boundaries:
            first = instructions[current[0]].pc
            last = instructions[current[-1]].pc
            blocks.append(
                BasicBlock(f"L{first:04d}", first, last, current, [], [])
            )
            current = []
        current.append(index)
    if current:
        first = instructions[current[0]].pc
        last = instructions[current[-1]].pc
        blocks.append(BasicBlock(f"L{first:04d}", first, last, current, [], []))

    pc_to_block = {
        instructions[index].pc: block.label
        for block in blocks
        for index in block.instruction_indexes
    }
    for block_index, block in enumerate(blocks):
        tail = instructions[block.instruction_indexes[-1]]
        successors: list[str] = []
        if not tail.terminal_return:
            successors.extend(
                pc_to_block[target]
                for target in tail.jump_targets
                if target in pc_to_block
            )
            if not tail.unconditional_jump and block_index + 1 < len(blocks):
                next_block = blocks[block_index + 1]
                if next_block.start_pc == tail.pc + 1:
                    successors.append(next_block.label)
        block.successors = list(dict.fromkeys(successors))

    by_label = {block.label: block for block in blocks}
    for block in blocks:
        for successor in block.successors:
            by_label[successor].predecessors.append(block.label)
    for block in blocks:
        _propagate_block(instructions, block.instruction_indexes)
    return blocks


def _expand_constant_references(value: Any, constants: list[Any]) -> Any:
    if isinstance(value, list):
        return [_expand_constant_references(item, constants) for item in value]
    if not isinstance(value, dict):
        return value
    if set(value) == {"constant_ref"}:
        return constants[value["constant_ref"] - 1]
    return {
        key: _expand_constant_references(item, constants)
        for key, item in value.items()
    }


def _collect_strings(value: Any, output: set[str]) -> None:
    if isinstance(value, list):
        for item in value:
            _collect_strings(item, output)
        return
    if not isinstance(value, dict):
        return
    if value.get("type") == "string" and isinstance(value.get("value"), str):
        output.add(value["value"])
        return
    for item in value.values():
        _collect_strings(item, output)


def domain_string_score(value: str) -> int:
    stripped = value.strip()
    if (
        len(stripped) < 4
        or len(stripped) > 512
        or stripped.count("\\x") >= 2
        or stripped in COMMON_RUNTIME_STRINGS
    ):
        return 0
    score = 0
    if re.search(r"\d{8,}", stripped):
        score += 8
    if DOMAIN_TERM_RE.search(stripped):
        score += 5
    if re.search(r"\bAdd[A-Z][A-Za-z]+", stripped):
        score += 5
    if re.fullmatch(r"[A-Z][A-Z0-9_]{5,}", stripped) and "_" in stripped:
        score += 4
    if "_" in stripped or "/" in stripped or "\\" in stripped:
        score += 2
    if stripped.endswith(".lua"):
        score += 2
    return score


def load_context_trace(path: Path) -> dict[str, Any]:
    trace = json.loads(path.read_text(encoding="utf-8"))
    if trace.get("format") != "luraph-context-ir-v2":
        return trace
    constants = trace.get("constant_pool", [])
    rows = [
        _expand_constant_references(row, constants)
        for row in trace.get("instruction_rows", [])
    ]
    output = {
        key: value
        for key, value in trace.items()
        if key not in {"format", "constant_pool", "instruction_rows"}
    }
    for collection_name in ("program_summaries", "context_summaries"):
        output[collection_name] = []
        for summary in trace.get(collection_name, []):
            expanded = {
                key: value for key, value in summary.items() if key != "instruction_refs"
            }
            expanded["instructions"] = [
                rows[reference - 1] for reference in summary.get("instruction_refs", [])
            ]
            output[collection_name].append(expanded)
    return output


def _hybridize_context(
    context: dict[str, Any],
    program: dict[str, Any] | None,
) -> dict[str, Any]:
    """Use normalized operands for semantics and first-fetch rows for runtime flow."""
    if program is None:
        return context
    final_rows = {row["pc"]: row for row in program.get("instructions", [])}
    visited = {item["pc"] for item in context.get("visited_pcs", [])}
    merged_rows: list[dict[str, Any]] = []
    for runtime_row in context.get("instructions", []):
        final_row = final_rows.get(runtime_row["pc"], runtime_row)
        merged = dict(final_row)
        if runtime_row["pc"] in visited:
            merged["_runtime_instruction"] = runtime_row
        merged_rows.append(merged)
    return {**context, "instructions": merged_rows}


def _render_context(
    source_name: str,
    context: dict[str, Any],
    handlers: dict[int, HandlerCleanup],
    *,
    pc_variable: str,
    register_variable: str,
    observed_only: bool = False,
) -> tuple[str, dict[str, Any]]:
    visited = {
        item["pc"]: item["count"] for item in context.get("visited_pcs", [])
    }
    strings: set[str] = set()
    _collect_strings(context.get("instructions", []), strings)
    scored_strings = sorted(
        (
            (domain_string_score(value), value)
            for value in strings
            if domain_string_score(value) > 0
        ),
        key=lambda item: (-item[0], item[1]),
    )
    rows = list(context.get("instructions", []))
    all_pcs = {row["pc"] for row in rows}
    if observed_only:
        rows_by_pc = {row["pc"]: row for row in rows}
        path_order = list(
            dict.fromkeys(
                pc
                for pc in context.get("path_pcs", [])
                if pc in rows_by_pc and visited.get(pc, 0) > 0
            )
        )
        path_seen = set(path_order)
        path_order.extend(
            row["pc"]
            for row in rows
            if visited.get(row["pc"], 0) > 0 and row["pc"] not in path_seen
        )
        rows = [rows_by_pc[pc] for pc in path_order]
    instructions: list[ReadableInstruction] = []
    unresolved_handlers = 0
    for row in rows:
        opcode = row.get("opcode")
        if not isinstance(opcode, int) or opcode not in handlers:
            unresolved_handlers += 1
            source = "-- unresolved opcode"
            targets: list[int] = []
            flow = FlowShape(False, False, False, False)
            numeric_opcode = -1
        else:
            cleanup = handlers[opcode]
            source, targets = instantiate_readable_handler(
                cleanup,
                row,
                pc_variable=pc_variable,
                register_variable=register_variable,
            )
            runtime_row = row.get("_runtime_instruction")
            if isinstance(runtime_row, dict):
                _, runtime_targets = instantiate_readable_handler(
                    cleanup,
                    runtime_row,
                    pc_variable=pc_variable,
                    register_variable=register_variable,
                )
                if runtime_targets and len(runtime_targets) == len(targets):
                    for static_target, runtime_target in zip(
                        targets, runtime_targets, strict=True
                    ):
                        source = source.replace(
                            f"L{static_target:04d}",
                            f"L{runtime_target:04d}",
                        )
                    targets = runtime_targets
            source = simplify_known_operation(source)
            flow = cleanup.flow
            numeric_opcode = opcode
        instructions.append(
            ReadableInstruction(
                pc=row["pc"],
                opcode=numeric_opcode,
                source=source,
                kind=classify_operation(source, flow, targets),
                jump_targets=targets,
                unconditional_jump=flow.unconditional_jump,
                terminal_return=flow.terminal_return,
                observed=visited.get(row["pc"], 0),
            )
        )

    valid_pcs = {instruction.pc for instruction in instructions}
    for instruction in instructions:
        for target in instruction.jump_targets:
            if target not in all_pcs:
                replacement = f'vm_integrity_trap("L{target:04d}")'
            elif target not in valid_pcs and observed_only:
                replacement = f'vm_unobserved_path("L{target:04d}")'
            else:
                continue
            instruction.source = instruction.source.replace(
                f"goto L{target:04d}",
                replacement,
            )
            if target not in all_pcs:
                instruction.source = instruction.source.replace(
                    f"goto L{target:04d}", replacement
                )
            instruction.source = _jump_assignment_pattern(pc_variable).sub(
                lambda match, expected=target, substitute=replacement: (
                    substitute
                    if int(match.group(1)) + 1 == expected
                    else match.group(0)
                ),
                instruction.source,
            )
    blocks = build_basic_blocks(instructions)
    recovered_tables = _recover_table_literals(instructions) if observed_only else []
    lines = [
        (
            f"-- {source_name} observed closure context {context['id']}"
            if observed_only
            else f"-- {source_name} closure context {context['id']}"
        ),
        (
            f"-- code program {context['program']}; "
            f"observed fetches {context.get('fetch_count', 0)}"
        ),
    ]
    if recovered_tables:
        lines.append("-- Reassembled from observed table assignments; verify below.")
        for register, table in recovered_tables:
            lines.extend(
                _render_recovered_table(
                    f"recovered_context_{context['id']:04d}_{register}",
                    table,
                )
            )
        lines.append("")
    lines.append(
        f"local function observed_context_{context['id']:04d}(...)"
        if observed_only
        else f"local function closure_context_{context['id']:04d}(...)"
    )
    for block in blocks:
        predecessors = ", ".join(block.predecessors) or "entry/unresolved"
        successors = ", ".join(block.successors) or "return/exit"
        lines.extend(
            [
                "",
                (
                    f"    -- block {block.label}: predecessors [{predecessors}], "
                    f"successors [{successors}]"
                ),
                f"    ::{block.label}::",
            ]
        )
        for index in block.instruction_indexes:
            instruction = instructions[index]
            observed_text = (
                f"observed {instruction.observed}x"
                if instruction.observed
                else "not observed"
            )
            target_text = (
                " -> "
                + ", ".join(f"L{target:04d}" for target in instruction.jump_targets)
                if instruction.jump_targets
                else ""
            )
            lines.append(
                f"    -- L{instruction.pc:04d} | opcode {instruction.opcode} | "
                f"{instruction.kind}{target_text} | {observed_text}"
            )
            lines.extend(
                f"    {line}" if line else ""
                for line in instruction.source.splitlines()
            )
    lines.extend(["end", ""])

    kind_counts = Counter(instruction.kind for instruction in instructions)
    unresolved_targets = sorted(
        {
            target
            for instruction in instructions
            for target in instruction.jump_targets
            if target not in valid_pcs
        }
    )
    report = {
        "id": context["id"],
        "program": context["program"],
        "instructions": len(instructions),
        "observed_pcs": len(visited),
        "path_fetches": len(context.get("path_pcs", [])),
        "path_overflow": bool(context.get("path_overflow", False)),
        "recovered_table_literals": len(recovered_tables),
        "blocks": [asdict(block) for block in blocks],
        "operation_kinds": dict(sorted(kind_counts.items())),
        "unresolved_handlers": unresolved_handlers,
        "unresolved_jump_targets": unresolved_targets,
        "domain_score": sum(score for score, _ in scored_strings),
        "max_domain_score": max(
            (score for score, _ in scored_strings),
            default=0,
        ),
        "interesting_strings": [value for _, value in scored_strings[:50]],
    }
    return "\n".join(lines), report


def decompile_summary(summary_path: Path, output_root: Path) -> dict[str, Any]:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    outputs = {name: Path(path) for name, path in summary["outputs"].items()}
    trace = load_context_trace(outputs["programs"])
    layout = extract_vm_layout(outputs["root_source"].read_text(encoding="utf-8"))
    handler_report = json.loads(outputs["handlers"].read_text(encoding="utf-8"))
    selected_handlers = {
        int(opcode): value["selected"]
        for opcode, value in handler_report["handlers"].items()
    }
    specialized_handlers = {
        opcode: specialize_opcode_handler(
            source,
            opcode,
            opcode_variable=layout.opcode_variable,
            instruction_upvalue=layout.instruction_upvalue,
            pc_variable=layout.pc_variable,
        )
        for opcode, source in selected_handlers.items()
    }
    noise_statements = derive_noise_statements(
        specialized_handlers,
        pc_variable=layout.pc_variable,
        register_variable=layout.register_variable,
        integrity_variable=layout.integrity_variable,
    )
    handlers = {
        opcode: sanitize_handler(
            source,
            noise_statements,
            pc_variable=layout.pc_variable,
            register_variable=layout.register_variable,
            integrity_variable=layout.integrity_variable,
        )
        for opcode, source in specialized_handlers.items()
    }

    name = summary_path.stem
    readable_path = output_root / "readable" / f"{name}.readable.lua"
    focus_path = output_root / "readable" / f"{name}.focus.lua"
    observed_path = output_root / "readable" / f"{name}.observed.lua"
    cfg_path = output_root / "artifacts" / "readable" / f"{name}.cfg.json"
    readable_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.parent.mkdir(parents=True, exist_ok=True)

    context_sources: list[str] = []
    observed_sources: list[tuple[str, dict[str, Any]]] = []
    context_reports: list[dict[str, Any]] = []
    programs_by_id = {
        program["id"]: program for program in trace.get("program_summaries", [])
    }
    for raw_context in trace.get("context_summaries", []):
        context = _hybridize_context(
            raw_context,
            programs_by_id.get(raw_context.get("program")),
        )
        source, report = _render_context(
            name,
            context,
            handlers,
            pc_variable=layout.pc_variable,
            register_variable=layout.register_variable,
        )
        context_sources.append(source)
        context_reports.append(report)
        if report["max_domain_score"] >= 4:
            observed_source, observed_report = _render_context(
                name,
                context,
                handlers,
                pc_variable=layout.pc_variable,
                register_variable=layout.register_variable,
                observed_only=True,
            )
            observed_sources.append((observed_source, observed_report))

    removed = sum(item.removed_common_statements for item in handlers.values())
    unwrapped = sum(item.unwrapped_integrity_guards for item in handlers.values())
    parse_fallbacks = sum(item.parse_fallback for item in handlers.values())
    unfolded_loops = sum(item.unfolded_state_loops for item in handlers.values())
    header = [
        f"-- Readable control-flow recovery for {name}",
        "-- This is conservative pseudo-Lua reconstructed from Luraph context IR.",
        "-- Original names and unobserved environment-specific closures remain unavailable.",
        f"-- handlers={len(handlers)} common_noise_patterns={len(noise_statements)}",
        f"-- removed_handler_statements={removed} unwrapped_integrity_guards={unwrapped}",
        f"-- unfolded_handler_state_loops={unfolded_loops} unparsed_handler_templates={parse_fallbacks}",
        "",
    ]
    readable_path.write_text(
        "\n".join(header + context_sources),
        encoding="utf-8",
    )
    focused_contexts = [
        (source, report)
        for source, report in zip(context_sources, context_reports, strict=True)
        if report["max_domain_score"] >= 4
    ]
    focus_header = [
        f"-- Domain-focused readable recovery for {name}",
        "-- Selected by constants such as DST APIs, workshop IDs, skin/prefab/mod keys.",
        "-- This is an indexable subset; use the full .readable.lua for complete evidence.",
        f"-- selected_contexts={len(focused_contexts)} total_contexts={len(context_reports)}",
        "",
    ]
    focus_sections = [
        "\n".join(
            [
                "-- Domain hints: "
                + ", ".join(
                    json.dumps(value, ensure_ascii=False)
                    for value in report["interesting_strings"][:12]
                ),
                source,
            ]
        )
        for source, report in focused_contexts
    ]
    focus_path.write_text(
        "\n".join(focus_header + focus_sections),
        encoding="utf-8",
    )
    observed_instruction_count = sum(
        report["instructions"] for _, report in observed_sources
    )
    observed_header = [
        f"-- Observed-path readable recovery for {name}",
        "-- Only PCs fetched by the isolated trace are included.",
        "-- vm_unobserved_path marks a valid branch omitted from this coverage view.",
        "-- Use .focus.lua and .readable.lua for unobserved static evidence.",
        (
            f"-- selected_contexts={len(observed_sources)} "
            f"observed_instructions={observed_instruction_count}"
        ),
        "",
    ]
    observed_path.write_text(
        "\n".join(observed_header + [source for source, _ in observed_sources]),
        encoding="utf-8",
    )

    block_count = sum(len(context["blocks"]) for context in context_reports)
    unresolved_handlers = sum(
        context["unresolved_handlers"] for context in context_reports
    )
    unresolved_targets = sum(
        len(context["unresolved_jump_targets"]) for context in context_reports
    )
    report = {
        "source": summary["source"],
        "contexts": len(context_reports),
        "handlers": len(handlers),
        "vm_layout": asdict(layout),
        "common_noise_patterns": len(noise_statements),
        "removed_handler_statements": removed,
        "unwrapped_integrity_guards": unwrapped,
        "unfolded_handler_state_loops": unfolded_loops,
        "unparsed_handler_templates": parse_fallbacks,
        "blocks": block_count,
        "unresolved_handlers": unresolved_handlers,
        "unresolved_jump_targets": unresolved_targets,
        "focused_contexts": len(focused_contexts),
        "observed_focus_instructions": observed_instruction_count,
        "outputs": {
            "readable": str(readable_path),
            "focus": str(focus_path),
            "observed": str(observed_path),
            "cfg": str(cfg_path),
        },
        "context_reports": context_reports,
    }
    cfg_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return {
        key: value for key, value in report.items() if key != "context_reports"
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert recovered Luraph context IR into readable CFG pseudo-Lua."
    )
    parser.add_argument("summaries", nargs="+", type=Path)
    parser.add_argument("--output-root", type=Path, default=Path("recovered"))
    return parser


def main() -> int:
    args = build_parser().parse_args()
    reports = [
        decompile_summary(summary_path, args.output_root)
        for summary_path in args.summaries
    ]
    print(json.dumps(reports, ensure_ascii=False, indent=2))
    return 1 if any(report["unresolved_handlers"] for report in reports) else 0


if __name__ == "__main__":
    raise SystemExit(main())
