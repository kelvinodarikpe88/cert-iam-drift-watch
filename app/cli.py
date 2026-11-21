"""Demo without a server: python -m app.cli"""
from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

from . import llm
from .drift import analyse

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def main(argv: list[str]) -> int:
    as_of = date.fromisoformat(argv[1]) if len(argv) > 1 else date(2026, 11, 21)
    certs = json.loads((FIXTURES / "certs.json").read_text())["certs"]
    users = json.loads((FIXTURES / "iam.json").read_text())["users"]
    result = analyse(certs, users, as_of)
    note = llm.build_report(result, certs, users)
    result["report"] = note["text"]
    result["report_source"] = note["source"]
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
