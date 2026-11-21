# cert-iam-drift-watch

A monthly hygiene sweep across TLS endpoints and the identity directory, with every finding tied to a field, a value and the threshold it crossed.

<!-- claims: findings=12 cert=8 iam=4 critical=4 -->

## What it checks

**Certificates**

| Check | Severity | Threshold |
|---|---|---|
| `cert_expired` | critical | not-after in the past |
| `cert_expiring` | critical / high / medium | ≤ 7 / ≤ 14 / ≤ 30 days |
| `cert_weak_key` | high | RSA < 2048, EC < 256 |
| `cert_sha1_signature` | high | SHA-1 anywhere in the signature algorithm |
| `cert_chain_incomplete` | high | chain does not build to a trusted root |
| `cert_san_mismatch` | high | expected host absent from the SAN list |
| `cert_self_signed` | medium | issuer equals subject |

**Identity**

| Check | Severity | What it means |
|---|---|---|
| `iam_standing_global_admin` | critical | permanent Global Administrator, not PIM-eligible |
| `iam_privileged_without_mfa` | critical | privileged role held with MFA disabled |
| `iam_dormant_privileged` | high | privileged role unused for more than 90 days |
| `iam_guest_privileged` | high | external guest holding a directory role |
| `iam_too_many_global_admins` | medium | more than four Global Administrators |

The PIM distinction is the point of the identity half. A Global Administrator who must activate through an eligible assignment with approval is a different risk from one who holds it permanently, and a checker that treats them the same teaches the customer to ignore it.

## One endpoint, two inventories

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt

python -m app.cli 2026-11-21

export SECOPS_API_KEYS=dev-key-change-me
uvicorn app.main:app --port 8000
curl -s localhost:8000/v1/report -H "x-api-key: dev-key-change-me" \
  -H 'content-type: application/json' \
  -d "{\"as_of\":\"2026-11-21\",\"certs\":$(python -c 'import json;print(json.dumps(json.load(open("fixtures/certs.json"))["certs"]))'),\"users\":$(python -c 'import json;print(json.dumps(json.load(open("fixtures/iam.json"))["users"]))')}"
```

`as_of` is explicit rather than implicit, so the numbers in a report can be reproduced a year later — which is what an audit asks for and what `date.today()` quietly destroys.

## Where the model is, and where it is not

The model writes the three-sentence monthly note. It cannot add a finding, change a severity or name an asset that is not in the inventory; an invented hostname discards the note and the deterministic template is used instead. Findings are sorted by severity, then asset, then check, so two runs produce byte-identical output.

## What this does not claim

The certificate data comes from an inventory file, not from a live TLS handshake — this repo does the analysis, not the collection, and pretending otherwise would hide the part that actually breaks in production (proxies with different chains, SNI-dependent certificates, and internal CAs that a public scanner cannot see). The identity export is the same: a JSON shape derived from Entra ID, not a Graph call.

Twelve checks is a floor, not a ceiling. OCSP reachability, CT log monitoring, CAA records and key-usage mismatches all belong here, and none of them is implemented.
