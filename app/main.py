import logging
import uuid
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, JSONResponse
from contextlib import asynccontextmanager
from app.models import LoginEvent, EventResponse, UserBaseline
from app.anomaly import evaluate_login_event
from app.alerting import send_alert
from app.redis_client import (
    get_redis, close_redis,
    get_risk_score, reset_risk_score, is_account_locked,
    get_alert_history, unlock_account,
    get_known_hours, get_known_ips, get_known_user_agents,
    get_active_sessions, get_login_frequency,
    get_failed_attempts,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("login-monitor")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 Starting LoginShield API v3.1.0…")
    yield
    logger.info("🛑 Shutting down — closing Redis…")
    await close_redis()
    logger.info("✅ Shutdown complete")


app = FastAPI(
    title="LoginShield – Anomaly Detector",
    version="3.1.0",
    lifespan=lifespan,
)

try:
    app.mount("/static", StaticFiles(directory="static"), name="static")
except Exception as e:
    logger.warning(f"Could not mount static files: {e}")


# ──────────────────────────────────────────────
# PUBLIC ENDPOINTS
# ──────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/static/index.html", status_code=301)


@app.get("/health", tags=["health"])
async def health():
    try:
        r = await get_redis()
        await r.ping()
        return {"status": "ok", "redis": "connected", "version": "3.1.0"}
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {"status": "degraded", "redis": "disconnected"}


@app.post("/login", response_model=EventResponse, tags=["login"])
async def login_event(event: LoginEvent, request: Request):
    """Process a login event with comprehensive anomaly detection."""
    client_ip = event.ip_address or (request.client.host if request.client else "unknown")
    client_ua = event.user_agent or request.headers.get("user-agent", "unknown")

    alerts, risk_score, blocked = await evaluate_login_event(
        username=event.username,
        password=event.password,
        success=event.success,
        timestamp=event.timestamp,
        ip_address=client_ip,
        user_agent=client_ua,
        location_lat=event.location_lat,
        location_lon=event.location_lon,
        location_country=event.location_country,
    )

    for alert in alerts:
        send_alert(alert)

    if blocked:
        response_status, http_status = "blocked", 403
    elif event.success:
        response_status, http_status = "processed", 200
    else:
        response_status, http_status = "failed", 401

    response_data = EventResponse(
        status=response_status,
        alerts_generated=len(alerts),
        alerts=alerts,
        risk_score=risk_score,
        blocked=blocked,
        message="Account locked due to excessive risk score" if blocked else None,
    )
    return JSONResponse(status_code=http_status, content=response_data.dict())


@app.get("/baseline/{username}", tags=["user-info"])
async def get_baseline(username: str) -> UserBaseline:
    """Get user behaviour baseline and security profile."""
    try:
        r = await get_redis()
        hours = await get_known_hours(username)
        ips = await get_known_ips(username)
        uas = await get_known_user_agents(username)
        total = await r.get(f"logins:{username}")
        risk = await get_risk_score(username)
        is_locked = await is_account_locked(username)
        last_login = await r.get(f"last_login:{username}")

        return UserBaseline(
            username=username,
            total_logins=int(total) if total else 0,
            known_hours=hours,
            known_ips=ips,
            known_user_agents=uas,
            risk_score=risk,
            is_blocked=is_locked,
            last_login=last_login,
        )
    except Exception as e:
        logger.error(f"Error getting baseline for {username}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/alerts/{username}", tags=["alerts"])
async def get_alerts(username: str, limit: int = 50):
    """Get alert history for a specific user."""
    try:
        alerts = await get_alert_history(username, limit)
        return {"username": username, "alerts_count": len(alerts), "alerts": alerts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/sessions/{username}", tags=["sessions"])
async def get_sessions(username: str):
    """Get active sessions for a user."""
    try:
        sessions = await get_active_sessions(username)
        return {"username": username, "active_sessions": len(sessions), "sessions": sessions}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ──────────────────────────────────────────────
# ADMIN ENDPOINTS
# ──────────────────────────────────────────────

@app.post("/admin/reset_risk/{username}", tags=["admin"])
async def reset_risk(username: str):
    """Admin: Reset a user's risk score."""
    try:
        await reset_risk_score(username)
        return {"status": "success", "username": username, "message": "Risk score reset to 0"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/admin/unlock_account/{username}", tags=["admin"])
async def admin_unlock_account(username: str):
    """Admin: Unlock a locked account."""
    try:
        await unlock_account(username)
        return {"status": "success", "username": username, "message": "Account unlocked"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/admin/stats/{username}", tags=["admin"])
async def get_user_stats(username: str):
    """Admin: Get detailed user statistics."""
    try:
        return {
            "username": username,
            "risk_score": await get_risk_score(username),
            "failed_attempts": await get_failed_attempts(username),
            "login_frequency": await get_login_frequency(username),
            "active_sessions": len(await get_active_sessions(username)),
            "is_locked": await is_account_locked(username),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/admin/dashboard-data", tags=["admin"])
async def dashboard_data():
    """
    NEW – Admin dashboard aggregate endpoint.
    Returns system-wide stats consumed by the Splunk-style admin dashboard.
    """
    try:
        r = await get_redis()

        # Collect all usernames that have any data
        all_keys = []
        async for key in r.scan_iter("logins:*"):
            all_keys.append(key.replace("logins:", ""))
        async for key in r.scan_iter("failed:*"):
            uname = key.replace("failed:", "")
            if uname not in all_keys:
                all_keys.append(uname)

        users_data = []
        total_alerts = 0
        high_risk_users = []
        locked_users = []
        recent_alerts = []
        alert_type_counts: dict = {}

        for username in all_keys:
            risk = await get_risk_score(username)
            failed = await get_failed_attempts(username)
            is_locked = await is_account_locked(username)
            logins = await r.get(f"logins:{username}")
            alerts = await get_alert_history(username, 100)
            total_alerts += len(alerts)

            for a in alerts:
                atype = a.get("type", "unknown")
                alert_type_counts[atype] = alert_type_counts.get(atype, 0) + 1
                recent_alerts.append({**a, "username": username})

            user_row = {
                "username": username,
                "risk_score": risk,
                "failed_attempts": failed,
                "is_locked": is_locked,
                "total_logins": int(logins) if logins else 0,
                "alert_count": len(alerts),
            }
            users_data.append(user_row)

            if risk >= 5:
                high_risk_users.append(user_row)
            if is_locked:
                locked_users.append(username)

        # Sort recent alerts by timestamp desc, cap at 200
        recent_alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        recent_alerts = recent_alerts[:200]

        # Alert type breakdown for pie chart
        alert_breakdown = [{"type": k, "count": v} for k, v in sorted(
            alert_type_counts.items(), key=lambda x: -x[1]
        )]

        return {
            "summary": {
                "total_users": len(all_keys),
                "total_alerts": total_alerts,
                "high_risk_users": len(high_risk_users),
                "locked_accounts": len(locked_users),
            },
            "high_risk_users": sorted(high_risk_users, key=lambda x: -x["risk_score"])[:20],
            "locked_accounts": locked_users,
            "recent_alerts": recent_alerts,
            "alert_breakdown": alert_breakdown,
            "all_users": sorted(users_data, key=lambda x: -x["risk_score"]),
        }
    except Exception as e:
        logger.error(f"Dashboard data error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/admin/splunk-status", tags=["admin"])
async def splunk_status():
    """NEW – Check Splunk HEC connectivity and configuration."""
    from app.config import SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN
    is_configured = bool(SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN)

    if not is_configured:
        return {
            "configured": False,
            "connected": False,
            "status": "not_configured",
            "message": "Set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN in .env to enable Splunk integration",
        }

    # Try a live ping
    try:
        import httpx
        from datetime import timezone
        payload = {
            "time": __import__("datetime").datetime.now(timezone.utc).timestamp(),
            "host": "login-shield-monitor",
            "source": "health_check",
            "sourcetype": "login_shield:alert",
            "event": {"test": True, "message": "LoginShield connectivity check"},
        }
        headers = {
            "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            resp = await client.post(SPLUNK_HEC_URL, json=payload, headers=headers)

        ok = resp.status_code in (200, 201)
        return {
            "configured": True,
            "connected": ok,
            "url": SPLUNK_HEC_URL,
            "status": "ok" if ok else "connection_failed",
            "http_status": resp.status_code,
        }
    except Exception as e:
        return {
            "configured": True,
            "connected": False,
            "url": SPLUNK_HEC_URL,
            "status": "connection_failed",
            "error": str(e),
        }
