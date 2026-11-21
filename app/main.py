import os

os.environ.setdefault("SERVICE_NAME", "cert-iam-drift-watch")
os.environ.setdefault("SERVICE_VERSION", "1.0.0")

from datetime import date  # noqa: E402

from fastapi import FastAPI, HTTPException  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from . import llm  # noqa: E402
from .drift import analyse  # noqa: E402
from .runtime import configure_logging, install_runtime  # noqa: E402

CHECKS = [
    "cert_expired",
    "cert_expiring",
    "cert_weak_key",
    "cert_sha1_signature",
    "cert_chain_incomplete",
    "cert_san_mismatch",
    "cert_self_signed",
    "iam_standing_global_admin",
    "iam_privileged_without_mfa",
    "iam_dormant_privileged",
    "iam_guest_privileged",
    "iam_too_many_global_admins",
]

configure_logging()
app = FastAPI(title="cert-iam-drift-watch", version="1.0.0")
install_runtime(app)


class ReportRequest(BaseModel):
    certs: list[dict] = Field(default_factory=list)
    users: list[dict] = Field(default_factory=list)
    as_of: str | None = None
    use_model: bool = False


@app.get("/v1/checks")
def checks():
    return {"checks": CHECKS, "count": len(CHECKS)}


@app.post("/v1/report")
def report(request: ReportRequest):
    try:
        today = date.fromisoformat(request.as_of) if request.as_of else date.today()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="as_of must be YYYY-MM-DD") from exc

    for cert in request.certs:
        if "host" not in cert or "not_after" not in cert:
            raise HTTPException(
                status_code=422, detail="every certificate needs 'host' and 'not_after'"
            )

    result = analyse(request.certs, request.users, today)
    provider = llm.provider_from_env() if request.use_model else None
    note = llm.build_report(result, request.certs, request.users, provider)
    result["report"] = note["text"]
    result["report_source"] = note["source"]
    if note["rejected"]:
        result["report_rejected"] = note["rejected"]
    return result
