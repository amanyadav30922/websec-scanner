"""
FastAPI backend for the on-demand security dashboard.

Run with:  uvicorn dashboard.app:app --reload --port 8787
Then open: http://127.0.0.1:8787

Every /api/* route (other than login) requires a valid session; the
dashboard page itself redirects to a login screen when not authenticated.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from core import db, alerts, scheduler, auth
from core.orchestrator import run_scan, run_scan_with_subdomains, list_scans, get_scan
from core.allowlist_compat import normalize_domain
from checks.nuclei import is_available as nuclei_available
from checks import subdomains as subdomain_checker

app = FastAPI(title="WebSec Scanner")

STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.on_event("startup")
async def startup():
    db.init_db()
    auth.bootstrap_admin()
    alerts.bootstrap_from_env()
    scheduler.start()


@app.on_event("shutdown")
async def shutdown():
    scheduler.shutdown()


# ---------- models ----------

class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    is_admin: bool = False


class ChangePasswordRequest(BaseModel):
    new_password: str
    current_password: str | None = None  # required for non-admin self-change


class AddDomainRequest(BaseModel):
    target: str
    label: str = ""
    confirmed: bool = False


class ScanRequest(BaseModel):
    target: str
    use_nuclei: bool = True
    include_subdomains: bool = False


class ScheduleRequest(BaseModel):
    target: str
    interval_minutes: int = 1440
    use_nuclei: bool = True
    include_subdomains: bool = False


class AlertConfigRequest(BaseModel):
    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_user: str | None = None
    smtp_password: str | None = None
    from_addr: str | None = None
    to_addr: str | None = None
    use_tls: bool | None = None
    alert_on_new_critical_high: bool | None = None
    alert_on_any_new_finding: bool | None = None
    alert_on_scan_failure: bool | None = None


# ---------- pages ----------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    token = request.cookies.get(auth.SESSION_COOKIE)
    user = db.get_session_user(token) if token else None
    page = "index.html" if user else "login.html"
    html_path = Path(__file__).resolve().parent / "templates" / page
    return HTMLResponse(html_path.read_text())


# ---------- auth ----------

@app.post("/api/auth/login")
async def api_login(req: LoginRequest):
    user = db.get_user(req.username)
    if not user or not auth.verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = auth.create_session_for(req.username)
    resp = JSONResponse({"username": user["username"], "is_admin": bool(user["is_admin"])})
    resp.set_cookie(
        auth.SESSION_COOKIE, token,
        httponly=True, secure=auth.is_cookie_secure(), samesite="lax",
        max_age=60 * 60 * 24 * 14,
    )
    return resp


@app.post("/api/auth/logout")
async def api_logout(request: Request):
    token = request.cookies.get(auth.SESSION_COOKIE)
    if token:
        db.delete_session(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth.SESSION_COOKIE)
    return resp


@app.get("/api/auth/me")
async def api_me(user: dict = Depends(auth.get_current_user)):
    return user


@app.post("/api/auth/change-password")
async def api_change_password(req: ChangePasswordRequest, user: dict = Depends(auth.get_current_user)):
    full_user = db.get_user(user["username"])
    if not user.get("is_admin"):
        if not req.current_password or not auth.verify_password(req.current_password, full_user["password_hash"]):
            raise HTTPException(status_code=401, detail="Current password is incorrect")
    if len(req.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
    db.update_user_password(user["username"], auth.hash_password(req.new_password))
    return {"ok": True}


# ---------- user management (admin only) ----------

@app.get("/api/users")
async def api_list_users(admin: dict = Depends(auth.get_current_admin)):
    return db.list_users()


@app.post("/api/users")
async def api_create_user(req: CreateUserRequest, admin: dict = Depends(auth.get_current_admin)):
    if db.get_user(req.username):
        raise HTTPException(status_code=400, detail="Username already exists")
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    db.create_user(req.username, auth.hash_password(req.password), is_admin=req.is_admin)
    return {"ok": True}


@app.delete("/api/users/{username}")
async def api_delete_user(username: str, admin: dict = Depends(auth.get_current_admin)):
    if username == admin["username"]:
        raise HTTPException(status_code=400, detail="You can't delete your own account while logged in as it.")
    db.delete_user(username)
    return {"ok": True}


# ---------- domains ----------

@app.get("/api/domains")
async def api_list_domains(user: dict = Depends(auth.get_current_user)):
    return db.list_domains()


@app.post("/api/domains")
async def api_add_domain(req: AddDomainRequest, user: dict = Depends(auth.get_current_user)):
    domain = normalize_domain(req.target)
    if not domain:
        raise HTTPException(status_code=400, detail=f"Could not parse a domain from: {req.target}")
    return db.add_domain(domain, confirmed=req.confirmed, label=req.label)


@app.delete("/api/domains/{domain}")
async def api_remove_domain(domain: str, user: dict = Depends(auth.get_current_user)):
    db.remove_domain(domain)
    return {"ok": True}


# ---------- subdomains ----------

@app.post("/api/domains/{domain}/discover-subdomains")
async def api_discover_subdomains(domain: str, user: dict = Depends(auth.get_current_user)):
    entry = db.get_domain(domain)
    if not entry or not entry["confirmed"]:
        raise HTTPException(status_code=400, detail="Domain must be added and confirmed first.")
    found = await subdomain_checker.discover(domain)
    db.add_subdomains(domain, found)
    return {"domain": domain, "discovered": found, "count": len(found)}


@app.get("/api/domains/{domain}/subdomains")
async def api_list_subdomains(domain: str, user: dict = Depends(auth.get_current_user)):
    return db.list_subdomains(domain)


# ---------- status ----------

@app.get("/api/status")
async def api_status(user: dict = Depends(auth.get_current_user)):
    return {"nuclei_available": nuclei_available()}


# ---------- scanning ----------

@app.post("/api/scan")
async def api_scan(req: ScanRequest, user: dict = Depends(auth.get_current_user)):
    if req.include_subdomains:
        results = await run_scan_with_subdomains(
            req.target, use_nuclei=req.use_nuclei, include_subdomains=True
        )
        return {"primary": results[0], "subdomain_scans": results[1:]}
    result = await run_scan(req.target, use_nuclei=req.use_nuclei)
    return result


@app.get("/api/scans")
async def api_list_scans(target: str | None = None, user: dict = Depends(auth.get_current_user)):
    return list_scans(target)


@app.get("/api/scans/{scan_id}")
async def api_get_scan(scan_id: str, user: dict = Depends(auth.get_current_user)):
    result = get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


# ---------- schedules ----------

@app.get("/api/schedules")
async def api_list_schedules(user: dict = Depends(auth.get_current_user)):
    return db.list_schedules()


@app.post("/api/schedules")
async def api_create_schedule(req: ScheduleRequest, user: dict = Depends(auth.get_current_user)):
    hostname = normalize_domain(req.target)
    if not db.is_domain_confirmed(hostname):
        raise HTTPException(
            status_code=400,
            detail=f"'{hostname}' must be added and confirmed before scheduling scans.",
        )
    if req.interval_minutes < 5:
        raise HTTPException(status_code=400, detail="Minimum interval is 5 minutes.")
    return scheduler.create_schedule(
        req.target, req.interval_minutes, req.use_nuclei, req.include_subdomains
    )


@app.post("/api/schedules/{schedule_id}/toggle")
async def api_toggle_schedule(schedule_id: str, enabled: bool, user: dict = Depends(auth.get_current_user)):
    scheduler.toggle_schedule(schedule_id, enabled)
    return db.get_schedule(schedule_id)


@app.post("/api/schedules/{schedule_id}/run-now")
async def api_run_schedule_now(schedule_id: str, user: dict = Depends(auth.get_current_user)):
    sched = db.get_schedule(schedule_id)
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    results = await run_scan_with_subdomains(
        sched["target"], use_nuclei=bool(sched["use_nuclei"]),
        include_subdomains=bool(sched["include_subdomains"]),
    )
    if results:
        db.mark_schedule_run(schedule_id, results[0]["id"])
    return {"ran": True, "scan_id": results[0]["id"] if results else None}


@app.delete("/api/schedules/{schedule_id}")
async def api_delete_schedule(schedule_id: str, user: dict = Depends(auth.get_current_user)):
    scheduler.remove_schedule(schedule_id)
    return {"ok": True}


# ---------- alert config ----------

@app.get("/api/alerts/config")
async def api_get_alert_config(user: dict = Depends(auth.get_current_user)):
    cfg = db.get_alert_config()
    cfg.pop("smtp_password", None)  # never echo the password back
    cfg["smtp_password_set"] = bool(db.get_alert_config().get("smtp_password"))
    return cfg


@app.post("/api/alerts/config")
async def api_update_alert_config(req: AlertConfigRequest, user: dict = Depends(auth.get_current_user)):
    cfg = db.update_alert_config(**req.model_dump(exclude_none=True))
    cfg.pop("smtp_password", None)
    return cfg


@app.post("/api/alerts/test")
async def api_test_alert(user: dict = Depends(auth.get_current_user)):
    ok, detail = alerts.send_test_alert()
    return {"sent": ok, "detail": detail}
