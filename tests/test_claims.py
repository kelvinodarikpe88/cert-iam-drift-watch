"""The README makes claims. This test is what makes them true."""
import json
import re
from datetime import date
from pathlib import Path

from app.drift import analyse

ROOT = Path(__file__).resolve().parent.parent
CLAIM_RE = re.compile(r"<!--\s*claims:\s*(.*?)\s*-->")


def claims() -> dict[str, int]:
    match = CLAIM_RE.search((ROOT / "README.md").read_text())
    assert match, "README.md must carry a <!-- claims: ... --> marker"
    return {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)", match.group(1))}


def test_readme_numbers_match_the_fixtures():
    certs = json.loads((ROOT / "fixtures" / "certs.json").read_text())["certs"]
    users = json.loads((ROOT / "fixtures" / "iam.json").read_text())["users"]
    result = analyse(certs, users, date(2026, 11, 21))
    cert_findings = [f for f in result["findings"] if f["check"].startswith("cert_")]
    iam_findings = [f for f in result["findings"] if f["check"].startswith("iam_")]
    actual = {
        "findings": result["summary"]["findings"],
        "cert": len(cert_findings),
        "iam": len(iam_findings),
        "critical": result["summary"]["by_severity"]["critical"],
    }
    for key, value in claims().items():
        assert actual[key] == value, f"README claims {key}={value}, evidence says {actual[key]}"
