from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from tools.luraph_devirtualize import extract_vm_layout


def _constant_references(value: Any) -> list[int]:
    if isinstance(value, list):
        return [reference for item in value for reference in _constant_references(item)]
    if not isinstance(value, dict):
        return []
    if set(value) == {"constant_ref"}:
        return [value["constant_ref"]]
    return [
        reference
        for item in value.values()
        for reference in _constant_references(item)
    ]


def audit_summary(summary_path: Path) -> dict[str, Any]:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    outputs = {name: Path(path) for name, path in summary["outputs"].items()}
    trace = json.loads(outputs["programs"].read_text(encoding="utf-8"))
    handler_report = json.loads(outputs["handlers"].read_text(encoding="utf-8"))
    handlers = handler_report["handlers"]
    rows = trace.get("instruction_rows", [])
    constants = trace.get("constant_pool", [])
    references = [
        reference
        for collection_name in ("program_summaries", "context_summaries")
        for item in trace.get(collection_name, [])
        for reference in item.get("instruction_refs", [])
    ]
    constant_references = [
        reference for row in rows for reference in _constant_references(row)
    ]
    opcodes = {
        str(row["opcode"])
        for row in rows
        if isinstance(row.get("opcode"), int)
    }
    layout = extract_vm_layout(outputs["root_source"].read_text(encoding="utf-8"))
    opcode_pattern = re.compile(
        rf"\b{re.escape(layout.opcode_variable)}\s*(?:==|~=|<=|>=|<|>)"
    )
    selected_handlers = [value["selected"] for value in handlers.values()]
    decoded_hash = hashlib.sha256(outputs["decoded"].read_bytes()).hexdigest()
    recovered_source = outputs["recovered"].read_text(encoding="utf-8")
    return {
        "name": summary_path.stem,
        "root_ok": summary["root_ok"],
        "fetch_count": summary["fetch_count"],
        "programs": summary["programs"],
        "contexts": summary["contexts"],
        "opcodes": summary["opcodes"],
        "callbacks": f"{summary['callbacks_invoked']}/{summary['callbacks_captured']}",
        "instruction_upvalue": trace.get("instruction_upvalue_name"),
        "environment_upvalue": trace.get("environment_upvalue_name"),
        "decoded_hash_ok": decoded_hash == summary["decoded_sha256"],
        "program_reference_ok": all(1 <= reference <= len(rows) for reference in references),
        "constant_reference_ok": all(
            1 <= reference <= len(constants) for reference in constant_references
        ),
        "missing_handlers": len(opcodes.difference(handlers)),
        "empty_handlers": sum(not handler for handler in selected_handlers),
        "unsliced_handlers": sum(
            bool(opcode_pattern.search(handler)) for handler in selected_handlers
        ),
        "unknown_listings": recovered_source.count("UNKNOWN_HANDLER"),
        "recovered_bytes": outputs["recovered"].stat().st_size,
        "program_ir_bytes": outputs["programs"].stat().st_size,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit recovered Luraph artifacts.")
    parser.add_argument("summary_dir", type=Path)
    args = parser.parse_args()
    reports = [
        audit_summary(path)
        for path in sorted(args.summary_dir.glob("*.json"))
    ]
    print(json.dumps(reports, ensure_ascii=False, indent=2))
    failures = [
        report
        for report in reports
        if not report["root_ok"]
        or not report["decoded_hash_ok"]
        or not report["program_reference_ok"]
        or not report["constant_reference_ok"]
        or report["missing_handlers"]
        or report["empty_handlers"]
        or report["unknown_listings"]
    ]
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
