# SOP — Operating the certificate and identity drift watch

**Service:** `cert-iam-drift-watch`
**Owner:** security engineering
**Audience:** the analyst producing the monthly report, and the service owner
**Cadence:** monthly run, quarterly threshold review

---

## 1. Purpose and scope

This procedure covers the monthly hygiene sweep: what to collect, how to produce a reproducible report, how to interpret it, and how remediation and exceptions are closed.

**In scope:** TLS endpoint inventory, directory identity inventory, findings, report, exception handling.
**Out of scope:** issuing or deploying certificates, and changing directory roles. The tool reports; the platform teams act.

---

## 2. Roles

| Role | Owns |
|---|---|
| Analyst | collection, run, report, chase |
| Service owner | thresholds, check set, releases |
| Platform / PKI team | certificate renewal and deployment |
| Identity team | role removal, PIM conversion, MFA enforcement |
| Account owner | the customer conversation and the exception register |

---

## 3. Monthly calendar

| Day | Step |
|---|---|
| 1–3 | collect the two inventories (§4) |
| 4 | run the report with an explicit `as_of` |
| 5 | read it, spot-check three findings, resolve anything obviously stale |
| 6 | send to the customer with the exception register attached |
| 7–end | track remediation; chase anything inside its SLA window |

The run happens on the same calendar day each month. An `as_of` that drifts makes month-on-month comparison meaningless, which is most of the value.

---

## 4. Collection

### 4.1 Certificate inventory

One JSON object per endpoint:

```json
{"host": "api.example.com", "port": 443, "not_after": "2026-11-25",
 "key_alg": "RSA", "key_bits": 2048, "sig_alg": "SHA256-RSA",
 "issuer": "Example Issuing CA", "subject": "CN=api.example.com",
 "chain_ok": true, "expected_host": "api.example.com",
 "sans": ["api.example.com"]}
```

Rules for a collection that is worth anything:

- Collect **from two vantage points**: one inside the estate, one external. A certificate served through a WAF is not the certificate on the origin, and the difference is the finding.
- `expected_host` comes from the asset inventory, not from the certificate. Copying the SAN into `expected_host` guarantees the mismatch check never fires.
- `chain_ok` must be decided by an independent client, not by the same stack that serves the certificate.
- Record the collecting tool and the date. A finding you cannot reproduce is an argument, not evidence.

### 4.2 Identity inventory

One object per principal:

```json
{"principal": "admin@example.com", "roles": ["Global Administrator"],
 "assignment": "permanent", "mfa_enabled": true,
 "last_sign_in_days": 2, "enabled": true}
```

- `assignment` is `permanent` or `eligible`. Eligible means PIM with activation; this is the difference between a finding and an acceptable design.
- `last_sign_in_days` for a service account that authenticates with a certificate will read as never — that is absence of interactive sign-in, not absence of use. Check the workload before removing a role.
- Guests are identifiable by `#EXT#` in the principal. Do not normalise that away.

---

## 5. Standard run

```bash
export SECOPS_API_KEYS="$(openssl rand -hex 24)"
uvicorn app.main:app --port 8000

curl -s localhost:8000/v1/report -H "x-api-key: $SECOPS_API_KEYS" \
  -H 'content-type: application/json' \
  -d "{\"as_of\":\"2026-11-21\",
       \"certs\": $(python -c 'import json;print(json.dumps(json.load(open("certs.json"))["certs"]))'),
       \"users\": $(python -c 'import json;print(json.dumps(json.load(open("iam.json"))["users"]))')}"
```

1. Confirm `as_of` matches the date you collected, not the date you remembered to run it.
2. Read `summary.by_check`. A zero on a check for three consecutive months is worth a question: either the estate is genuinely clean or the collector stopped populating that field.
3. Spot-check three findings against the source data before sending. Certificates are the easiest thing in security to collect wrongly.
4. Send the report with the `report` text and the findings table together. The prose explains; the table is what the platform team works from.

---

## 6. Findings and remediation windows

| Check | Severity | Window |
|---|---|---|
| `cert_expired` | critical | same day |
| `cert_expiring` ≤ 7 days | critical | before expiry, escalate daily |
| `iam_privileged_without_mfa` | critical | 24 hours |
| `iam_standing_global_admin` | critical | 7 days (convert to eligible) |
| `cert_expiring` ≤ 14 days | high | before expiry |
| `cert_weak_key`, `cert_sha1_signature`, `cert_chain_incomplete`, `cert_san_mismatch` | high | 30 days |
| `iam_dormant_privileged`, `iam_guest_privileged` | high | 30 days |
| `cert_expiring` ≤ 30 days | medium | 60 days |
| `cert_self_signed`, `iam_too_many_global_admins` | medium | 90 days |

A renewal that needs a third-party CA has a lead time. If a certificate inside the 30-day band is not renewing on schedule, escalate it as critical now rather than discovering it at 7 days.

---

## 7. The PIM distinction

`iam_standing_global_admin` fires only on `assignment: permanent`.

A Global Administrator who must activate an eligible assignment, with approval and a time bound, is a different risk and is **not** a finding. If you start treating eligible assignment as a finding, the customer will disable the report rather than the access.

When converting: the target state is `eligible`, not "removed". Removing the role without a working activation path produces a break-glass incident two weeks later.

---

## 8. Exceptions

Some findings are correct and accepted: a self-signed certificate on an internal appliance with no public trust requirement, or a dormant privileged account held for a contractual handover.

1. Record the check, the asset, the owner, the justification and an **expiry date**.
2. The report carries the finding until the exception expires; the exception is noted next to it.
3. At expiry the finding returns at full severity.

An exception without an expiry is an accepted risk nobody is tracking. Do not allow one into the register.

---

## 9. Failure modes

| Symptom | Likely cause | First response |
|---|---|---|
| `422 as_of must be YYYY-MM-DD` | wrong date format | use ISO dates only |
| `422 every certificate needs 'host' and 'not_after'` | incomplete collector output | fix the collector; do not patch the data by hand |
| `0 findings` with a known bad certificate | collector did not reach that endpoint | verify from the external vantage point before reporting clean |
| a check has been zero for months | field no longer populated | audit the collector against the schema in §4 |
| `report_source: template` | no provider, or model named an unknown asset | normal; the template report is complete |
| findings differ from last month with no change | `as_of` moved, or inventory scope changed | reconcile scope before sending |

---

## 10. Data handling

The identity inventory contains names and role assignments. It is personal data.

- Keep `certs.json` and `iam.json` in the customer's case folder, not on a laptop or in a repo.
- Fixtures in this repo are synthetic.
- Reports go to the named customer contact, not a distribution list.
- Retention follows the customer's policy; the default case-folder retention is 12 months.

---

## 11. Known limits

- The certificate data is an **inventory file**, not a live handshake. This repo analyses; something else must collect, and the collector is where most errors are introduced.
- No OCSP reachability, no CT log monitoring, no CAA checks, no key-usage validation. Twelve checks is a floor.
- Internal CAs and split-horizon DNS will produce findings that a public scanner cannot see and cannot explain. Collect internally as well.
- MFA state is read as a boolean. It does not distinguish enforced-by-policy from registered-but-bypassable, and that gap has hidden real exposure in real estates.
- `iam_too_many_global_admins` counts eligible holders too. That is a design choice: a large eligible population is a governance finding in its own right.

---

## 12. Escalation

| Situation | Route |
|---|---|
| Certificate expires within 7 days and no renewal is booked | customer platform lead today, account owner same day |
| Privileged account without MFA | identity team immediately; treat as an active exposure |
| Suspected collector error on a "clean" month | service owner; re-collect from both vantage points |
| Customer disputes a threshold | threshold is a policy decision — take it to the service owner, not the customer |
| Inventory file found outside the case folder | customer security contact; delete; incident record |
