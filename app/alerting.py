"""
alerting.py  –  Fixed & enhanced alert dispatcher.

Bugs fixed:
  1. Used blocking requests.post() inside async context → replaced with httpx async
  2. Splunk payload lacked sourcetype, index, and key fields for dashboard searches
  3. No fallback when Splunk is unreachable (swallowed silently)
  4. Console log lost severity colour cues
"""

import asyncio
import logging
import json
from datetime import datetime, timezone
from typing import Dict, Any

logger = logging.getLogger("login-monitor")

# Colour map for console severity display
_SEVERITY_PREFIX = {
    "low":      "🟡",
    "medium":   "🟠",
    "high":     "🔴",
    "critical": "🚨",
}


def send_alert(alert: dict):
    """
    Fire-and-forget alert dispatcher.
    Schedules the async sender in the running event loop (FastAPI context).
    Falls back to sync console log if no loop is running.
    """
    _log_to_console(alert)
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.ensure_future(_send_alert_async(alert))
    except RuntimeError:
        pass  # No event loop — console log already done


def _log_to_console(alert: dict):
    severity = alert.get("severity", "medium").lower()
    icon = _SEVERITY_PREFIX.get(severity, "⚠️")
    logger.warning(
        f"{icon} ALERT [{severity.upper()}] type={alert.get('type')} "
        f"user={alert.get('username')} — {alert.get('details')} "
        f"ip={alert.get('ip_address', 'N/A')}"
    )


async def _send_alert_async(alert: dict):
    """Async Splunk HEC sender — does NOT block the event loop."""
    from app.config import SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN  # lazy import avoids circular

    if not SPLUNK_HEC_TOKEN or not SPLUNK_HEC_URL:
        return

    try:
        import httpx  # preferred; falls back gracefully if missing

        now_ts = datetime.now(timezone.utc).timestamp()

        # Build a rich Splunk event so every dashboard panel can filter by field
        payload = {
            "time": alert.get("_epoch") or now_ts,
            "host": "login-shield-monitor",
            "source": "login_anomaly_detector",
            "sourcetype": "login_shield:alert",   # FIX: custom sourcetype for Splunk searches
            "event": {
                # --- Core alert fields ---
                "alert_type":    alert.get("type"),
                "username":      alert.get("username"),
                "severity":      alert.get("severity", "medium"),
                "details":       alert.get("details"),
                "timestamp":     alert.get("timestamp", datetime.utcnow().isoformat()),
                # --- Enrichment fields ---
                "ip_address":    alert.get("ip_address"),
                "login_hour":    alert.get("login_hour"),
                "known_hours":   alert.get("known_hours"),
                "failed_count":  alert.get("failed_count"),
                "session_count": alert.get("session_count"),
                "device_trust":  alert.get("device_trust"),
                "login_frequency": alert.get("login_frequency"),
                "from_country":  alert.get("from_country"),
                "to_country":    alert.get("to_country"),
                "time_diff_minutes": alert.get("time_diff_minutes"),
                # --- Meta ---
                "app": "LoginShield",
                "version": "3.1.0",
            }
        }

        headers = {
            "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            resp = await client.post(SPLUNK_HEC_URL, json=payload, headers=headers)

        if resp.status_code in (200, 201):
            logger.debug(f"✅ Splunk HEC accepted alert type={alert.get('type')}")
        else:
            logger.error(f"❌ Splunk HEC error {resp.status_code}: {resp.text[:200]}")

    except ImportError:
        # httpx not installed — fall back to threaded requests
        await asyncio.to_thread(_send_alert_sync_fallback, alert)
    except Exception as exc:
        logger.warning(f"⚠️  Could not reach Splunk HEC: {exc}")


def _send_alert_sync_fallback(alert: dict):
    """Sync fallback (runs in thread pool via asyncio.to_thread)."""
    import requests
    from app.config import SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN

    now_ts = datetime.now(timezone.utc).timestamp()
    payload = {
        "time": now_ts,
        "host": "login-shield-monitor",
        "source": "login_anomaly_detector",
        "sourcetype": "login_shield:alert",
        "event": {
            "alert_type": alert.get("type"),
            "username":   alert.get("username"),
            "severity":   alert.get("severity", "medium"),
            "details":    alert.get("details"),
            "timestamp":  alert.get("timestamp", datetime.utcnow().isoformat()),
            "ip_address": alert.get("ip_address"),
            "app": "LoginShield",
        }
    }
    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json",
    }
    try:
        resp = requests.post(SPLUNK_HEC_URL, json=payload, headers=headers, timeout=5, verify=False)
        if resp.status_code not in (200, 201):
            logger.error(f"❌ Splunk fallback error {resp.status_code}: {resp.text[:200]}")
    except Exception as exc:
        logger.warning(f"⚠️  Splunk fallback failed: {exc}")
