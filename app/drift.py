"""Certificate and identity drift checks. Every finding has a deterministic cause.

The report is the product; the checks are the evidence. Nothing here is
heuristic: each finding names the field, the value and the threshold that
crossed, so a customer can disagree with the threshold and still trust the data.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

PRIVILEGED_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
    "User Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Security Administrator",
    "Application Administrator",
    "Conditional Access Administrator",
}

EXPIRY_BANDS = ((7, "critical"), (14, "high"), (30, "medium"))


@dataclass
class Finding:
    asset: str
    check: str
    severity: str
    detail: str
    remediation: str

    def as_dict(self) -> dict:
        return {
            "asset": self.asset,
            "check": self.check,
            "severity": self.severity,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class Summary:
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def ordered(self) -> list[Finding]:
        return sorted(
            self.findings, key=lambda f: (SEVERITY_RANK[f.severity], f.asset, f.check)
        )

    def counts(self) -> dict:
        by_check: dict[str, int] = {}
        for finding in self.findings:
            by_check[finding.check] = by_check.get(finding.check, 0) + 1
        return {
            "findings": len(self.findings),
            "by_severity": {
                level: sum(1 for f in self.findings if f.severity == level)
                for level in ("critical", "high", "medium", "low")
            },
            "by_check": by_check,
        }


def _days_until(not_after: str, today: date) -> int:
    return (date.fromisoformat(not_after) - today).days


def check_certificate(cert: dict, today: date) -> list[Finding]:
    host = cert.get("host", "unknown")
    findings: list[Finding] = []

    days = _days_until(cert["not_after"], today)
    if days < 0:
        findings.append(
            Finding(
                host,
                "cert_expired",
                "critical",
                f"expired {abs(days)} day(s) ago on {cert['not_after']}",
                "Reissue and deploy; check whether clients are already failing closed.",
            )
        )
    else:
        for threshold, severity in EXPIRY_BANDS:
            if days <= threshold:
                findings.append(
                    Finding(
                        host,
                        "cert_expiring",
                        severity,
                        f"expires in {days} day(s) on {cert['not_after']}",
                        "Renew and deploy inside the next maintenance window.",
                    )
                )
                break

    key = str(cert.get("key_alg", "RSA")).upper()
    bits = int(cert.get("key_bits", 0) or 0)
    if key == "RSA" and bits and bits < 2048:
        findings.append(
            Finding(
                host,
                "cert_weak_key",
                "high",
                f"RSA {bits}-bit key below the 2048-bit floor",
                "Reissue on a 2048-bit or larger key.",
            )
        )
    if key == "EC" and bits and bits < 256:
        findings.append(
            Finding(
                host,
                "cert_weak_key",
                "high",
                f"EC {bits}-bit key below the 256-bit floor",
                "Reissue on P-256 or stronger.",
            )
        )

    signature = str(cert.get("sig_alg", "")).upper().replace("_", "-").replace(" ", "-")
    if "SHA1" in signature or "SHA-1" in signature:
        findings.append(
            Finding(
                host,
                "cert_sha1_signature",
                "high",
                f"signature algorithm {cert.get('sig_alg')}",
                "Reissue with SHA-256.",
            )
        )

    if cert.get("chain_ok") is False:
        findings.append(
            Finding(
                host,
                "cert_chain_incomplete",
                "high",
                "chain does not build to a trusted root",
                "Serve the full intermediate chain and re-verify with an independent client.",
            )
        )

    expected = cert.get("expected_host")
    sans = [str(s).lower() for s in cert.get("sans", [])]
    if expected and expected.lower() not in sans:
        findings.append(
            Finding(
                host,
                "cert_san_mismatch",
                "high",
                f"expected {expected} not present in SAN {sans}",
                "Reissue with the correct subject alternative names.",
            )
        )

    if cert.get("issuer") and cert.get("subject") and cert["issuer"] == cert["subject"]:
        findings.append(
            Finding(
                host,
                "cert_self_signed",
                "medium",
                "self-signed certificate",
                "Issue from the managed CA unless the endpoint is explicitly exempt.",
            )
        )

    return findings


def check_identity(user: dict) -> list[Finding]:
    principal = user.get("principal", "unknown")
    roles = set(user.get("roles", []))
    privileged = roles & PRIVILEGED_ROLES
    permanent = str(user.get("assignment", "permanent")).lower() == "permanent"
    findings: list[Finding] = []

    if "Global Administrator" in roles and permanent:
        findings.append(
            Finding(
                principal,
                "iam_standing_global_admin",
                "critical",
                "permanent Global Administrator with no eligible-only assignment",
                "Move to PIM eligible assignment with approval and a time bound.",
            )
        )

    if privileged and user.get("mfa_enabled") is False:
        findings.append(
            Finding(
                principal,
                "iam_privileged_without_mfa",
                "critical",
                f"privileged role {sorted(privileged)} held without MFA",
                "Require MFA in Conditional Access before the next sign-in.",
            )
        )

    if privileged and int(user.get("last_sign_in_days", 0) or 0) > 90:
        findings.append(
            Finding(
                principal,
                "iam_dormant_privileged",
                "high",
                f"privileged role unused for {user.get('last_sign_in_days')} days",
                "Remove the role; re-grant through the request process if it is needed again.",
            )
        )

    if "#ext#" in principal.lower() and privileged:
        findings.append(
            Finding(
                principal,
                "iam_guest_privileged",
                "high",
                f"external guest holds {sorted(privileged)}",
                "Confirm the business need; guests should not hold directory roles.",
            )
        )

    return findings


def analyse(certs: list[dict], users: list[dict], today: date) -> dict:
    summary = Summary()
    for cert in certs:
        for finding in check_certificate(cert, today):
            summary.add(finding)
    for user in users:
        for finding in check_identity(user):
            summary.add(finding)

    global_admins = [
        u for u in users if "Global Administrator" in set(u.get("roles", []))
    ]
    if len(global_admins) > 4:
        summary.add(
            Finding(
                "tenant",
                "iam_too_many_global_admins",
                "medium",
                f"{len(global_admins)} Global Administrators",
                "Reduce to four or fewer permanent holders; use eligible assignment for the rest.",
            )
        )

    return {
        "as_of": today.isoformat(),
        "summary": summary.counts(),
        "findings": [f.as_dict() for f in summary.ordered()],
    }
