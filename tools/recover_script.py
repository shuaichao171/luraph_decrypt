from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from tools.luraph_devirtualize import (
    extract_opcode_handler_candidates,
    extract_root_function_source,
    extract_vm_layout,
    render_program_pseudolua,
)
from tools.luraph_recover import (
    decode_lph_base85,
    extract_payload,
    trace_vm_fetches,
)


def _sequence(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


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


def expand_compact_trace(trace: dict[str, Any]) -> dict[str, Any]:
    if trace.get("format") != "luraph-context-ir-v2":
        return trace
    constants = trace.get("constant_pool", [])
    rows = [
        _expand_constant_references(row, constants)
        for row in trace.get("instruction_rows", [])
    ]
    for collection_name in ("program_summaries", "context_summaries"):
        for summary in _sequence(trace.get(collection_name)):
            references = summary.pop("instruction_refs", [])
            summary["instructions"] = [rows[reference - 1] for reference in references]
    trace.pop("format", None)
    trace.pop("constant_pool", None)
    trace.pop("instruction_rows", None)
    return trace


def compact_trace(trace: dict[str, Any]) -> dict[str, Any]:
    if "fetches" in trace:
        fetches = trace.pop("fetches")
        trace["fetch_prefix_omitted"] = (
            len(fetches) if isinstance(fetches, list) else 0
        )
    if trace.get("format") == "luraph-context-ir-v2":
        return trace
    constant_pool: list[Any] = []
    constants_by_json: dict[str, int] = {}
    instruction_rows: list[dict[str, Any]] = []
    rows_by_json: dict[str, int] = {}

    def intern(value: Any) -> Any:
        if isinstance(value, list):
            return [intern(item) for item in value]
        if not isinstance(value, dict):
            return value
        if value.get("type") == "string" and "value" in value:
            canonical = json.dumps(value, ensure_ascii=False, sort_keys=True)
            reference = constants_by_json.get(canonical)
            if reference is None:
                constant_pool.append(value)
                reference = len(constant_pool)
                constants_by_json[canonical] = reference
            return {"constant_ref": reference}
        return {key: intern(item) for key, item in value.items()}

    for collection_name in ("program_summaries", "context_summaries"):
        for summary in _sequence(trace.get(collection_name)):
            references = []
            for row in _sequence(summary.pop("instructions", [])):
                pooled_row = intern(row)
                canonical = json.dumps(pooled_row, ensure_ascii=False, sort_keys=True)
                reference = rows_by_json.get(canonical)
                if reference is None:
                    instruction_rows.append(pooled_row)
                    reference = len(instruction_rows)
                    rows_by_json[canonical] = reference
                references.append(reference)
            summary["instruction_refs"] = references
    trace["format"] = "luraph-context-ir-v2"
    trace["constant_pool"] = constant_pool
    trace["instruction_rows"] = instruction_rows
    return trace


def recover_script(
    source_path: Path,
    output_root: Path,
    *,
    fetch_budget: int,
    callback_limit: int,
    reuse_trace: bool = False,
    reuse_handlers: bool = False,
) -> dict[str, Any]:
    source = source_path.read_text(encoding="utf-8")
    payload = extract_payload(source)
    decoded = decode_lph_base85(payload)
    stem = source_path.stem

    decoded_path = output_root / "artifacts" / "decoded" / f"{stem}.lph.bin"
    root_source_path = (
        output_root / "artifacts" / "decompiled" / f"{stem}.root.source.lua"
    )
    programs_path = (
        output_root / "artifacts" / "programs" / f"{stem}.programs.json"
    )
    handlers_path = (
        output_root / "artifacts" / "handlers" / f"{stem}.handlers.json"
    )
    pseudolua_path = (
        output_root / "artifacts" / "pseudolua" / f"{stem}.all.pseudo.lua"
    )
    recovered_path = output_root / f"{stem}.recovered.lua"

    decoded_path.parent.mkdir(parents=True, exist_ok=True)
    decoded_path.write_bytes(decoded)
    if root_source_path.exists():
        root_source = root_source_path.read_text(encoding="utf-8")
    else:
        root_source = extract_root_function_source(source)
        root_source_path.parent.mkdir(parents=True, exist_ok=True)
        root_source_path.write_text(root_source, encoding="utf-8")
    layout = extract_vm_layout(root_source)

    trace = None
    if reuse_trace and programs_path.exists():
        cached_trace = expand_compact_trace(
            json.loads(programs_path.read_text(encoding="utf-8"))
        )
        if cached_trace.get("operand_snapshot_format") == "first-fetch-v1":
            trace = cached_trace
    if trace is None:
        trace = trace_vm_fetches(
            source,
            fetch_budget=fetch_budget,
            event_limit=10_000,
            include_programs=True,
            pass_environment=True,
            bind_missing_environment=True,
            environment_overrides={
                "env": {"modname": "workshop-3787391869"},
            },
            alias_global_environment=True,
            proxy_unknown_globals=True,
            callback_limit=callback_limit,
            instruction_upvalue_name=layout.instruction_upvalue,
            environment_upvalue_name="",
        )

    contexts = _sequence(trace.get("context_summaries"))
    opcodes = {
        row["opcode"]
        for context in contexts
        for row in _sequence(context.get("instructions"))
        if isinstance(row.get("opcode"), int)
    }
    if reuse_handlers and handlers_path.exists():
        cached_handler_report = json.loads(handlers_path.read_text(encoding="utf-8"))
        candidates = {
            int(opcode): list(value.get("candidates", []))
            for opcode, value in cached_handler_report.get("handlers", {}).items()
        }
        missing_opcodes = sorted(opcodes.difference(candidates))
        if missing_opcodes:
            raise ValueError(
                "cached handler report does not cover traced opcodes: "
                + ", ".join(map(str, missing_opcodes))
            )
    else:
        candidates = extract_opcode_handler_candidates(root_source, opcodes)
    handlers = {
        opcode: opcode_candidates[0] if opcode_candidates else ""
        for opcode, opcode_candidates in candidates.items()
    }
    _write_json(
        handlers_path,
        {
            "source": str(source_path),
            "opcode_count": len(opcodes),
            "handlers": {
                str(opcode): {
                    "selected": handlers[opcode],
                    "candidates": candidates[opcode],
                }
                for opcode in sorted(opcodes)
            },
        },
    )

    header = [
        f"-- Attempted full virtual-instruction recovery of {source_path.name}",
        "-- Constants, opcode behavior, and VM control flow are preserved in this listing.",
        "-- Original local names, comments, whitespace, and high-level block layout are unrecoverable.",
        "-- This file is inert pseudo-Lua. See artifacts/programs and artifacts/handlers for evidence.",
        "",
        f"-- root_ok={trace.get('ok')} fetches={trace.get('fetch_count')}",
        f"-- code_programs={trace.get('programs')} closure_contexts={trace.get('contexts')}",
        f"-- callbacks={trace.get('callbacks_invoked')}/{trace.get('callbacks_captured')}",
        "",
    ]
    listings = [
        render_program_pseudolua(
            f"{source_path.name} closure-context {context['id']} "
            f"(code program {context['program']})",
            context,
            handlers,
            pc_variable=layout.pc_variable,
            register_variable=layout.register_variable,
        )
        for context in contexts
    ]
    recovered = "\n".join(header + listings)
    pseudolua_path.parent.mkdir(parents=True, exist_ok=True)
    pseudolua_path.write_text(recovered, encoding="utf-8")
    recovered_path.write_text(recovered, encoding="utf-8")
    _write_json(programs_path, compact_trace(trace))

    summary = {
        "source": str(source_path),
        "encoded_size": len(payload),
        "decoded_size": len(decoded),
        "decoded_sha256": hashlib.sha256(decoded).hexdigest(),
        "root_ok": trace.get("ok"),
        "root_error": trace.get("error"),
        "fetch_count": trace.get("fetch_count"),
        "programs": trace.get("programs"),
        "contexts": trace.get("contexts"),
        "opcodes": len(opcodes),
        "callbacks_captured": trace.get("callbacks_captured"),
        "callbacks_invoked": trace.get("callbacks_invoked"),
        "global_events": len(_sequence(trace.get("global_events"))),
        "outputs": {
            "decoded": str(decoded_path),
            "root_source": str(root_source_path),
            "programs": str(programs_path),
            "handlers": str(handlers_path),
            "pseudolua": str(pseudolua_path),
            "recovered": str(recovered_path),
        },
    }
    _write_json(output_root / "artifacts" / "summaries" / f"{stem}.json", summary)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Recover one Luraph script into VM source, handler, and program IR artifacts."
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("--output-root", type=Path, default=Path("recovered"))
    parser.add_argument("--fetch-budget", type=int, default=2_000_000)
    parser.add_argument("--callback-limit", type=int, default=200)
    parser.add_argument("--reuse-trace", action="store_true")
    parser.add_argument("--reuse-handlers", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    summary = recover_script(
        args.source,
        args.output_root,
        fetch_budget=args.fetch_budget,
        callback_limit=args.callback_limit,
        reuse_trace=args.reuse_trace,
        reuse_handlers=args.reuse_handlers,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
