from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

GOTO_RE = re.compile(r"\bgoto\s+(L\d+)\b")


def audit_cfg_report(cfg_path: Path) -> dict[str, Any]:
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    readable_path = Path(cfg["outputs"]["readable"])
    source = readable_path.read_text(encoding="utf-8")
    context_errors: list[str] = []
    undefined_goto_labels: list[str] = []
    block_count = 0

    for context in cfg.get("context_reports", []):
        blocks = context.get("blocks", [])
        block_count += len(blocks)
        labels = {block["label"] for block in blocks}
        function_marker = f"local function closure_context_{context['id']:04d}(...)"
        function_start = source.find(function_marker)
        next_function = source.find("\nlocal function closure_context_", function_start + 1)
        function_source = source[
            function_start : next_function if next_function >= 0 else len(source)
        ]
        for goto_label in GOTO_RE.findall(function_source):
            if goto_label not in labels:
                undefined_goto_labels.append(
                    f"context {context['id']} -> {goto_label}"
                )
        expected_predecessors = {label: set() for label in labels}
        covered_indexes: list[int] = []

        for block in blocks:
            covered_indexes.extend(block["instruction_indexes"])
            unknown_successors = set(block["successors"]).difference(labels)
            if unknown_successors:
                context_errors.append(
                    f"context {context['id']} block {block['label']} has unknown "
                    f"successors {sorted(unknown_successors)}"
                )
            for successor in set(block["successors"]).intersection(labels):
                expected_predecessors[successor].add(block["label"])

        expected_indexes = list(range(context["instructions"]))
        if sorted(covered_indexes) != expected_indexes:
            context_errors.append(
                f"context {context['id']} block coverage is incomplete or duplicated"
            )
        for block in blocks:
            actual = set(block["predecessors"])
            expected = expected_predecessors[block["label"]]
            if actual != expected:
                context_errors.append(
                    f"context {context['id']} block {block['label']} predecessor "
                    "set does not match successors"
                )

    context_count = len(cfg.get("context_reports", []))
    return {
        "name": cfg_path.name.removesuffix(".cfg.json"),
        "contexts": context_count,
        "blocks": block_count,
        "handlers": cfg["handlers"],
        "unparsed_handler_templates": cfg["unparsed_handler_templates"],
        "integrity_trap_targets": sum(
            len(context.get("unresolved_jump_targets", []))
            for context in cfg.get("context_reports", [])
        ),
        "unresolved_handlers": cfg["unresolved_handlers"],
        "function_count_ok": source.count("local function closure_context_")
        == context_count,
        "block_count_ok": source.count("-- block L") == block_count,
        "unknown_handler_count": source.count("UNKNOWN_HANDLER"),
        "raw_unknown_opcode_count": source.count("-- unresolved opcode"),
        "empty_after_noise_count": source.count(
            "-- no operation after integrity-noise removal"
        ),
        "context_errors": context_errors,
        "undefined_goto_labels": undefined_goto_labels,
        "readable_bytes": readable_path.stat().st_size,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit readable Luraph CFG and pseudo-Lua outputs."
    )
    parser.add_argument("cfg_dir", type=Path)
    args = parser.parse_args()
    reports = [
        audit_cfg_report(path)
        for path in sorted(args.cfg_dir.glob("*.cfg.json"))
    ]
    print(json.dumps(reports, ensure_ascii=False, indent=2))
    failures = [
        report
        for report in reports
        if report["unresolved_handlers"]
        or not report["function_count_ok"]
        or not report["block_count_ok"]
        or report["unknown_handler_count"]
        or report["raw_unknown_opcode_count"]
        or report["undefined_goto_labels"]
        or report["context_errors"]
    ]
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
