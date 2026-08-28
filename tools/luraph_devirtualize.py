from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from tools.luraph_recover import (
    normalize_permissive_escapes,
    suppress_payload_invocation,
)


def _lua_ast() -> Any:
    try:
        from luaparser import ast
    except ImportError as error:  # pragma: no cover - exercised by the CLI environment
        raise RuntimeError(
            "handler extraction requires luaparser; run with `uv run --with luaparser`"
        ) from error
    return ast


@dataclass(frozen=True, slots=True)
class VMLayout:
    opcode_variable: str
    instruction_upvalue: str
    pc_variable: str
    register_variable: str
    integrity_variable: str


def _vm_loop_layout(node: Any) -> VMLayout | None:
    if type(node).__name__ not in {"While", "Repeat"}:
        return None
    statements = [
        item for item in node.body.body if type(item).__name__ != "SemiColon"
    ]
    if not statements or type(statements[0]).__name__ != "LocalAssign":
        return None
    assignment = statements[0]
    if len(assignment.targets) != len(assignment.values):
        return None
    indexed_pairs = [
        (target, value)
        for target, value in zip(assignment.targets, assignment.values, strict=True)
        if type(target).__name__ == "Name"
        and type(value).__name__ == "Index"
        and type(value.value).__name__ == "Name"
        and type(value.idx).__name__ == "Name"
    ]
    if len(indexed_pairs) != 1:
        return None
    target, value = indexed_pairs[0]
    opcode_variable = target.id
    instruction_upvalue = value.value.id
    pc_variable = value.idx.id
    has_large_dispatch = any(
        type(item).__name__ in {"If", "ElseIf"}
        and sum(1 for child in _lua_ast().walk(item) if type(child).__name__ == "If")
        >= 2
        for item in statements[1:]
    )
    increments_pc = any(
        type(item).__name__ == "Assign"
        and len(item.targets) == 1
        and type(item.targets[0]).__name__ == "Name"
        and item.targets[0].id == pc_variable
        and len(item.values) == 1
        and getattr(item.values[0], "_name", "") == "AddOp"
        for item in statements[1:]
    )
    if not has_large_dispatch or not increments_pc:
        return None

    register_counts: Counter[str] = Counter()
    for item in _lua_ast().walk(node):
        if type(item).__name__ != "Index" or type(item.value).__name__ != "Name":
            continue
        if any(
            type(child).__name__ == "Index"
            and type(child.idx).__name__ == "Name"
            and child.idx.id == pc_variable
            for child in _lua_ast().walk(item.idx)
        ):
            register_counts[item.value.id] += 1
    if not register_counts:
        return None
    register_variable = register_counts.most_common(1)[0][0]

    integrity_counts: Counter[str] = Counter()
    for item in _lua_ast().walk(node):
        if (
            type(item).__name__ == "Index"
            and type(item.value).__name__ == "Name"
            and type(item.idx).__name__ == "Number"
            and item.value.id not in {instruction_upvalue, register_variable}
        ):
            integrity_counts[item.value.id] += 1
    integrity_variable = (
        integrity_counts.most_common(1)[0][0] if integrity_counts else "C"
    )
    return VMLayout(
        opcode_variable,
        instruction_upvalue,
        pc_variable,
        register_variable,
        integrity_variable,
    )


def _direct_vm_loop(function: Any) -> Any | None:
    return next(
        (item for item in function.body.body if _vm_loop_layout(item) is not None),
        None,
    )


def extract_root_function_source(loader_source: str) -> str:
    """Extract the smallest generated function containing the VM dispatch loop."""
    ast = _lua_ast()
    patched = normalize_permissive_escapes(suppress_payload_invocation(loader_source))
    tree = ast.parse(patched)
    candidates = [
        node
        for node in ast.walk(tree)
        if type(node).__name__ == "AnonymousFunction"
        and _direct_vm_loop(node) is not None
    ]
    if not candidates:
        raise ValueError("no Luraph VM dispatch function was found")
    rendered = [ast.to_lua_source(candidate) for candidate in candidates]
    return min(rendered, key=len).strip() + "\n"


def extract_vm_layout(root_function_source: str) -> VMLayout:
    ast = _lua_ast()
    tree = ast.parse("return " + root_function_source)
    function = tree.body.body[0].values[0]
    loop = _direct_vm_loop(function)
    if loop is None:
        raise ValueError("root function does not contain a VM dispatch loop")
    layout = _vm_loop_layout(loop)
    if layout is None:
        raise ValueError("could not infer the VM dispatch layout")
    return layout


def _eval_for_opcode(
    node: Any,
    opcode: int,
    opcode_variable: str,
) -> bool | int | float | None:
    name = getattr(node, "_name", type(node).__name__)
    if name == "Name":
        return opcode if node.id == opcode_variable else None
    if name == "Number":
        return node.n
    if name == "TrueExpr":
        return True
    if name == "FalseExpr":
        return False
    if name == "ULNotOp":
        value = _eval_for_opcode(node.operand, opcode, opcode_variable)
        return None if value is None else not bool(value)

    if name in {"AndLoOp", "OrLoOp"}:
        left = _eval_for_opcode(node.left, opcode, opcode_variable)
        right = _eval_for_opcode(node.right, opcode, opcode_variable)
        if name == "AndLoOp":
            if left is False or right is False:
                return False
            if left is True:
                return right
            if right is True:
                return left
            return None
        if left is True or right is True:
            return True
        if left is False:
            return right
        if right is False:
            return left
        return None

    comparisons = {
        "REqOp": lambda left, right: left == right,
        "RNotEqOp": lambda left, right: left != right,
        "RLtOp": lambda left, right: left < right,
        "RLtEqOp": lambda left, right: left <= right,
        "RGtOp": lambda left, right: left > right,
        "RGtEqOp": lambda left, right: left >= right,
    }
    if name in comparisons:
        left = _eval_for_opcode(node.left, opcode, opcode_variable)
        right = _eval_for_opcode(node.right, opcode, opcode_variable)
        if left is None or right is None:
            return None
        return comparisons[name](left, right)
    return None


def _contains_opcode_test(node: Any, opcode_variable: str) -> bool:
    ast = _lua_ast()
    for child in ast.walk(node):
        if type(child).__name__ not in {"If", "ElseIf"}:
            continue
        if any(
            type(item).__name__ == "Name" and item.id == opcode_variable
            for item in ast.walk(child.test)
        ):
            return True
    return False


def _opcode_test_count(node: Any, opcode_variable: str) -> int:
    ast = _lua_ast()
    return sum(
        1
        for child in ast.walk(node)
        if type(child).__name__ in {"If", "ElseIf"}
        and any(
            type(item).__name__ == "Name" and item.id == opcode_variable
            for item in ast.walk(child.test)
        )
    )


def _expand_dispatch_block(
    block: Any,
    opcode: int,
    opcode_variable: str,
) -> list[list[Any]]:
    if block is None:
        return [[]]
    if type(block).__name__ in {"If", "ElseIf"}:
        statements = [block]
    else:
        statements = block.body
    paths: list[list[Any]] = [[]]
    for statement in statements:
        if type(statement).__name__ == "SemiColon":
            continue
        if type(statement).__name__ not in {"If", "ElseIf"}:
            for path in paths:
                path.append(statement)
            continue

        verdict = _eval_for_opcode(statement.test, opcode, opcode_variable)
        branches: list[Any]
        if verdict is True:
            branches = [statement.body]
        elif verdict is False:
            branches = [statement.orelse]
        elif _contains_opcode_test(statement, opcode_variable):
            branches = [statement.body, statement.orelse]
        else:
            for path in paths:
                path.append(statement)
            continue

        expanded = [
            child_path
            for branch in branches
            for child_path in _expand_dispatch_block(
                branch,
                opcode,
                opcode_variable,
            )
        ]
        paths = [path + child_path for path in paths for child_path in expanded]
    return paths


def _handler_score(
    source: str,
    duplicate_count: int = 1,
    *,
    pc_variable: str = "B",
    register_variable: str = "z",
    integrity_variable: str = "C",
) -> tuple[int, int]:
    register_name = re.escape(register_variable)
    pc_name = re.escape(pc_variable)
    register_operations = len(
        re.findall(rf"\b{register_name}\s*\[|\({register_name}\)\s*\[", source)
    )
    operand_uses = len(
        re.findall(rf"\b[A-Za-z_]\w*\s*\[\s*{pc_name}\s*\]", source)
    )
    control_operations = len(
        re.findall(rf"\b{pc_name}\s*=|\breturn\b", source)
    )
    state_assignments = len(
        re.findall(r"(?m)^\s*(?:local\s+)?[A-Za-z_]\w*\s*=", source)
    )
    integrity_name = re.escape(integrity_variable)
    integrity_references = len(
        re.findall(
            rf"\b{integrity_name}\s*\[|\({integrity_name}\)\s*\[",
            source,
        )
    )
    constant_return = bool(re.fullmatch(r"return\s+[-+]?\d+\s*;?", source.strip()))
    semantic_anchor = register_operations or operand_uses or bool(
        re.search(rf"\b{pc_name}\s*=", source)
    )
    score = (
        register_operations * 10
        + operand_uses * 4
        + control_operations
        + state_assignments * 3
    )
    if constant_return:
        score -= 100
    if integrity_references and not semantic_anchor:
        score -= integrity_references * 3
        score -= max(0, duplicate_count - 1) * 50
    return score, -len(source)


def extract_opcode_handler_candidates(
    root_function_source: str,
    opcodes: Iterable[int],
) -> dict[int, list[str]]:
    """Extract ranked dispatch-leaf candidates for each concrete opcode."""
    ast = _lua_ast()
    tree = ast.parse("return " + root_function_source)
    function = tree.body.body[0].values[0]
    loop = _direct_vm_loop(function)
    if loop is None:
        raise ValueError("root function does not contain a VM dispatch loop")
    layout = _vm_loop_layout(loop)
    if layout is None:
        raise ValueError("could not infer the VM dispatch layout")
    dispatch_candidates = [
        item for item in loop.body.body if type(item).__name__ == "If"
    ]
    if not dispatch_candidates:
        raise ValueError("VM loop does not contain an opcode dispatch tree")
    dispatch = max(
        dispatch_candidates,
        key=lambda item: _opcode_test_count(item, layout.opcode_variable),
    )
    if _opcode_test_count(dispatch, layout.opcode_variable) == 0:
        raise ValueError("VM loop does not contain opcode tests")

    handlers: dict[int, list[str]] = {}
    synthetic_block = type(loop.body)(body=[dispatch])
    for opcode in sorted(set(opcodes)):
        candidates = []
        for path in _expand_dispatch_block(
            synthetic_block,
            opcode,
            layout.opcode_variable,
        ):
            source = "\n".join(ast.to_lua_source(item).strip() for item in path)
            source = source.strip()
            if source and source not in candidates:
                candidates.append(source)
        if not candidates:
            candidates.append("-- no operation (empty dispatch leaf)")
        handlers[opcode] = candidates

    duplicate_counts = Counter(
        source for candidates in handlers.values() for source in set(candidates)
    )
    for opcode, candidates in handlers.items():
        handlers[opcode] = sorted(
            candidates,
            key=lambda source: _handler_score(
                source,
                duplicate_counts[source],
                pc_variable=layout.pc_variable,
                register_variable=layout.register_variable,
                integrity_variable=layout.integrity_variable,
            ),
            reverse=True,
        )
    return handlers


def extract_opcode_handlers(
    root_function_source: str,
    opcodes: Iterable[int],
) -> dict[int, str]:
    return {
        opcode: candidates[0] if candidates else ""
        for opcode, candidates in extract_opcode_handler_candidates(
            root_function_source,
            opcodes,
        ).items()
    }


def _operand_to_lua(value: Any) -> str:
    if value is None:
        return "nil"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, dict) and value.get("type") == "string":
        return json.dumps(value["value"], ensure_ascii=False)
    if isinstance(value, dict):
        return f"<{value.get('type', 'value')}>"
    return json.dumps(value, ensure_ascii=False)


def instantiate_handler(
    handler: str,
    instruction: dict[str, Any],
    *,
    pc_variable: str = "B",
    register_variable: str = "z",
) -> str:
    """Substitute one program row into an extracted handler template."""
    output = handler
    operands = instruction.get("operands")
    if not isinstance(operands, dict):
        operands = {
            name: instruction[name]
            for name in ("h", "O", "W", "N", "o", "e")
            if name in instruction
        }
    for operand_name, operand_value in sorted(
        operands.items(),
        key=lambda item: len(item[0]),
        reverse=True,
    ):
        literal = _operand_to_lua(operand_value)
        output = re.sub(
            rf"\b{re.escape(operand_name)}\s*\[\s*{re.escape(pc_variable)}\s*\]",
            lambda _, replacement=literal: replacement,
            output,
        )
    register_name = re.escape(register_variable)
    output = re.sub(
        rf"\(\s*{register_name}\s*\[\s*(\d+)\s*\]\s*\)",
        r"r\1",
        output,
    )
    output = re.sub(
        rf"\(\s*{register_name}\s*\)\s*\[\s*(\d+)\s*\]",
        r"r\1",
        output,
    )
    output = re.sub(rf"\b{register_name}\s*\[\s*(\d+)\s*\]", r"r\1", output)
    return output


def render_program_pseudolua(
    source_name: str,
    program: dict[str, Any],
    handlers: dict[int, str],
    *,
    pc_variable: str = "B",
    register_variable: str = "z",
) -> str:
    lines = [
        f"-- Virtual instruction recovery for {source_name}, program {program['id']}",
        "-- Register names, labels, and layout are reconstructed; original names/comments are lost.",
        "-- This listing is inert evidence, not directly executable Lua.",
        "",
    ]
    for instruction in program.get("instructions", []):
        pc = instruction["pc"]
        opcode = instruction["opcode"]
        if isinstance(opcode, dict):
            opcode = -1
        lines.append(f"::L{pc:04d}:: -- opcode {opcode}")
        handler = instantiate_handler(
            handlers.get(opcode, ""),
            instruction,
            pc_variable=pc_variable,
            register_variable=register_variable,
        )
        if handler:
            lines.extend(f"    {line}" for line in handler.splitlines())
        else:
            operand_values = instruction.get("operands", {})
            rendered_operands = ", ".join(
                f"{name}={_operand_to_lua(value)}"
                for name, value in sorted(operand_values.items())
            )
            lines.append(f"    -- UNKNOWN_HANDLER({rendered_operands})")
        lines.append("")
    return "\n".join(lines)
