from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.recover_script import _write_json, compact_trace


def main() -> int:
    parser = argparse.ArgumentParser(description="Pool duplicate values in program IR JSON.")
    parser.add_argument("inputs", nargs="+", type=Path)
    args = parser.parse_args()
    for path in args.inputs:
        trace = json.loads(path.read_text(encoding="utf-8"))
        before = path.stat().st_size
        _write_json(path, compact_trace(trace))
        after = path.stat().st_size
        print(f"{path.name}: {before} -> {after}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
