from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
from typing import Any

from tools.luraph_recover import trace_vm_fetches


def _json_object(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        try:
            decoded = base64.b64decode(value, validate=True).decode("utf-8")
            parsed = json.loads(decoded)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise argparse.ArgumentTypeError(
                "expected a JSON object or its Base64 encoding"
            ) from error
    if not isinstance(parsed, dict):
        raise argparse.ArgumentTypeError("expected a JSON object")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a reproducible loaded-mod probe against one Luraph script."
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("--fixture", type=_json_object, required=True)
    parser.add_argument("--environment", type=_json_object, default={})
    parser.add_argument("--fetch-budget", type=int, default=2_000_000)
    parser.add_argument("--event-limit", type=int, default=10_000)
    parser.add_argument("--callback-limit", type=int, default=20)
    parser.add_argument("--instruction-upvalue", required=True)
    parser.add_argument("--environment-upvalue", required=True)
    parser.add_argument("--full", action="store_true")
    parser.add_argument(
        "--program",
        action="append",
        type=int,
        default=[],
        help="include only the requested dynamic program details",
    )
    parser.add_argument("--keep-debug-events", action="store_true")
    return parser


def _select_programs(
    report: dict[str, Any],
    program_ids: list[int],
    *,
    visited_only: bool = True,
) -> dict[str, Any]:
    selected_ids = set(program_ids)
    selected = dict(report)
    selected_programs = []
    for program in report.get("program_summaries", []):
        if program.get("id") not in selected_ids:
            continue
        selected_program = dict(program)
        program_strings: set[str] = set()
        _collect_encoded_strings(program.get("instructions", []), program_strings)
        selected_program["interesting_strings"] = sorted(program_strings)
        if visited_only:
            visited_pcs = {
                item.get("pc")
                for item in program.get("visited_pcs", [])
                if isinstance(item, dict)
            }
            selected_program["instructions"] = [
                row
                for row in program.get("instructions", [])
                if (
                    row.get("pc") in visited_pcs
                    if visited_pcs
                    else "first_fetch_sequence" in row
                )
            ]
        selected_programs.append(selected_program)
    selected["program_summaries"] = selected_programs
    selected_contexts = []
    for context in report.get("context_summaries", []):
        if context.get("program") not in selected_ids:
            continue
        selected_context = dict(context)
        if visited_only:
            visited_pcs = set(context.get("path_pcs", []))
            selected_context["instructions"] = [
                row
                for row in context.get("instructions", [])
                if row.get("pc") in visited_pcs
            ]
        selected_contexts.append(selected_context)
    selected["context_summaries"] = selected_contexts
    return _redact_long_strings(selected)


def _collect_encoded_strings(value: Any, strings: set[str]) -> None:
    if isinstance(value, list):
        for item in value:
            _collect_encoded_strings(item, strings)
        return
    if not isinstance(value, dict):
        return

    string_value = value.get("value")
    if (
        value.get("type") == "string"
        and isinstance(string_value, str)
        and len(string_value) <= 160
    ):
        strings.add(string_value)
    for item in value.values():
        _collect_encoded_strings(item, strings)


def _redact_long_strings(value: Any, limit: int = 160) -> Any:
    if isinstance(value, list):
        return [_redact_long_strings(item, limit) for item in value]
    if not isinstance(value, dict):
        return value

    redacted = {
        key: _redact_long_strings(item, limit) for key, item in value.items()
    }
    string_value = redacted.get("value")
    if isinstance(string_value, str) and len(string_value) > limit:
        redacted.pop("value")
        redacted["value_omitted"] = True
    return redacted


def main() -> int:
    args = build_parser().parse_args()
    source = args.source.read_text(encoding="utf-8")
    report = trace_vm_fetches(
        source,
        fetch_budget=args.fetch_budget,
        event_limit=args.event_limit,
        include_programs=bool(args.program),
        pass_environment=True,
        bind_missing_environment=True,
        environment_overrides=args.environment,
        runtime_fixture=args.fixture,
        alias_global_environment=True,
        proxy_unknown_globals=True,
        callback_limit=args.callback_limit,
        instruction_upvalue_name=args.instruction_upvalue,
        environment_upvalue_name=args.environment_upvalue,
    )
    if not args.keep_debug_events:
        report["fixture_events"] = [
            event
            for event in report.get("fixture_events", [])
            if event.get("op")
            not in {
                "debug_getupvalue",
                "debug_setupvalue",
                "fixture_getfenv",
                "fixture_setfenv",
            }
        ]
    if args.program:
        report = _select_programs(report, args.program)
    if not args.full:
        report_keys = [
            "ok",
            "error",
            "fetch_count",
            "fetch_budget",
            "stopped_by_budget",
            "callbacks_captured",
            "callbacks_invoked",
            "callback_results",
            "fixture_events",
            "global_events",
        ]
        if args.program:
            report_keys.extend(("program_summaries", "context_summaries"))
        report = {key: report.get(key) for key in report_keys}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
