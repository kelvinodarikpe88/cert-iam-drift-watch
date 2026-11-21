import json
from datetime import date
from pathlib import Path

from app.drift import analyse, check_certificate, check_identity

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
TODAY = date(2026, 11, 21)


def cert(**overrides) -> dict:
    base = {
        "host": "api.example.com",
        "not_after": "2027-06-01",
        "key_alg": "RSA",
        "key_bits": 2048,
        "sig_alg": "SHA256-RSA",
        "issuer": "Example CA",
        "subject": "CN=api.example.com",
        "chain_ok": True,
        "expected_host": "api.example.com",
        "sans": ["api.example.com"],
    }
    return {**base, **overrides}


def checks(findings) -> set[str]:
    return {f.check for f in findings}


def test_healthy_certificate_produces_nothing():
    assert check_certificate(cert(), TODAY) == []


def test_expired_certificate_is_critical():
    assert checks(check_certificate(cert(not_after="2026-10-01"), TODAY)) == {"cert_expired"}


def test_expiry_bands():
    assert checks(check_certificate(cert(not_after="2026-11-25"), TODAY)) == {"cert_expiring"}
    assert [
        f.severity for f in check_certificate(cert(not_after="2026-11-25"), TODAY)
    ] == ["critical"]
    assert [
        f.severity for f in check_certificate(cert(not_after="2026-12-03"), TODAY)
    ] == ["high"]
    assert [
        f.severity for f in check_certificate(cert(not_after="2026-12-20"), TODAY)
    ] == ["medium"]


def test_weak_key_and_deprecated_signature():
    found = checks(check_certificate(cert(key_bits=1024, sig_alg="SHA1-RSA"), TODAY))
    assert found == {"cert_weak_key", "cert_sha1_signature"}


def test_chain_and_san_and_self_signed():
    assert checks(check_certificate(cert(chain_ok=False), TODAY)) == {"cert_chain_incomplete"}
    assert checks(
        check_certificate(cert(expected_host="vpn.example.com"), TODAY)
    ) == {"cert_san_mismatch"}
    assert checks(
        check_certificate(cert(issuer="CN=api.example.com", subject="CN=api.example.com"), TODAY)
    ) == {"cert_self_signed"}


def test_permanent_global_admin_is_standing_access():
    user = {
        "principal": "a@example.com",
        "roles": ["Global Administrator"],
        "assignment": "permanent",
        "mfa_enabled": True,
        "last_sign_in_days": 1,
    }
    assert checks(check_identity(user)) == {"iam_standing_global_admin"}


def test_eligible_global_admin_is_not_standing_access():
    user = {
        "principal": "a@example.com",
        "roles": ["Global Administrator"],
        "assignment": "eligible",
        "mfa_enabled": True,
        "last_sign_in_days": 1,
    }
    assert check_identity(user) == []


def test_privileged_without_mfa_and_dormant():
    user = {
        "principal": "svc@example.com",
        "roles": ["Privileged Role Administrator"],
        "assignment": "permanent",
        "mfa_enabled": False,
        "last_sign_in_days": 200,
    }
    assert checks(check_identity(user)) == {
        "iam_privileged_without_mfa",
        "iam_dormant_privileged",
    }


def test_guest_with_a_role_is_flagged():
    user = {
        "principal": "x_y.com#EXT#@example.com",
        "roles": ["User Administrator"],
        "assignment": "permanent",
        "mfa_enabled": True,
        "last_sign_in_days": 3,
    }
    assert checks(check_identity(user)) == {"iam_guest_privileged"}


def test_non_privileged_user_is_not_flagged():
    user = {
        "principal": "u@example.com",
        "roles": ["User"],
        "assignment": "permanent",
        "mfa_enabled": False,
        "last_sign_in_days": 1,
    }
    assert check_identity(user) == []


def test_too_many_global_admins():
    users = [
        {
            "principal": f"a{i}@example.com",
            "roles": ["Global Administrator"],
            "assignment": "eligible",
            "mfa_enabled": True,
            "last_sign_in_days": 1,
        }
        for i in range(5)
    ]
    result = analyse([], users, TODAY)
    assert "iam_too_many_global_admins" in result["summary"]["by_check"]


def test_fixture_counts():
    certs = json.loads((FIXTURES / "certs.json").read_text())["certs"]
    users = json.loads((FIXTURES / "iam.json").read_text())["users"]
    summary = analyse(certs, users, TODAY)["summary"]
    assert summary["findings"] == 12
    assert summary["by_severity"]["critical"] == 4


def test_analysis_is_reproducible():
    certs = json.loads((FIXTURES / "certs.json").read_text())["certs"]
    users = json.loads((FIXTURES / "iam.json").read_text())["users"]
    assert analyse(certs, users, TODAY) == analyse(certs, users, TODAY)
