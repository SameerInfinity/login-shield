import hashlib
from datetime import datetime
from app.config import (
    FAILED_ATTEMPTS_THRESHOLD, MIN_LOGINS_FOR_BASELINE, RISK_SCORE_THRESHOLD,
    MAX_LOGINS_IN_WINDOW, LOGIN_FREQUENCY_WINDOW_SECONDS,
    MAX_CONCURRENT_SESSIONS, GEO_TIME_THRESHOLD_MINUTES,
    DEVICE_TRUST_LOGINS_THRESHOLD,
    RISK_POINTS_BRUTE_FORCE, RISK_POINTS_UNUSUAL_TIMING,
    RISK_POINTS_NEW_IP, RISK_POINTS_NEW_DEVICE, RISK_POINTS_NEW_LOCATION,
    RISK_POINTS_RAPID_LOGINS, RISK_POINTS_CONCURRENT_SESSION,
    RISK_POINTS_WEAK_PASSWORD,
)
from app.redis_client import (
    get_redis,                          # FIX: was missing — caused NameError at runtime
    incr_failed_attempts, get_failed_attempts, reset_failed_attempts,
    record_successful_login, is_hour_unusual, get_known_hours,
    record_ip, is_ip_new, get_known_ips,
    record_user_agent, is_ua_new, get_known_user_agents,
    record_location, get_last_location,
    start_session, get_active_sessions,
    record_login_attempt, get_login_frequency,
    record_device_login, get_device_trust_level,
    incr_risk_score, get_risk_score, is_account_locked,
    store_alert, user_exists, store_password_hash, get_password_hash,
    lock_account,                       # FIX: needed for auto-locking high-risk accounts
)
from app.password_utils import validate_password_strength
from app.geolocation_utils import is_new_location_suspicious, get_location_name


async def evaluate_login_event(
    username: str,
    password: str,
    success: bool,
    timestamp: datetime,
    ip_address: str = None,
    user_agent: str = None,
    location_lat: float = None,
    location_lon: float = None,
    location_country: str = None,
):
    """
    Comprehensive login event evaluation with pattern recognition.
    Returns: (alerts, risk_score, blocked_flag)
    """
    alerts = []
    risk_before = await get_risk_score(username)

    # ===== CHECK IF ACCOUNT IS LOCKED =====
    if await is_account_locked(username):
        return [
            {
                "type": "account_locked",
                "username": username,
                "details": "Account is locked due to suspicious activity",
                "severity": "critical",
                "ip_address": ip_address,
                "timestamp": timestamp.isoformat(),
            }
        ], risk_before, True

    # ===== PASSWORD VALIDATION (regardless of success) =====
    is_weak_password = False
    if password:
        is_strong, pwd_message, pwd_risk = validate_password_strength(password)
        if not is_strong:
            is_weak_password = True
            alerts.append({
                "type": "weak_password",
                "username": username,
                "details": f"Weak password detected: {pwd_message}",
                "severity": "medium",
                "ip_address": ip_address,
                "timestamp": timestamp.isoformat(),
            })

    # ===== NEW USER REGISTRATION =====
    if not await user_exists(username):
        if success and password:
            password_hash = hashlib.sha256(f"{username}:{password}".encode()).hexdigest()
            await store_password_hash(username, password_hash)
            alerts.append({
                "type": "new_user_registered",
                "username": username,
                "details": "New user registered",
                "severity": "low",
                "ip_address": ip_address,
                "timestamp": timestamp.isoformat(),
            })
        elif not success:
            alerts.append({
                "type": "account_enumeration_attempt",
                "username": username,
                "details": "Failed login attempt on non-existent account (possible enumeration)",
                "severity": "high",
                "ip_address": ip_address,
                "timestamp": timestamp.isoformat(),
            })
            # Store alert and return early
            for alert in alerts:
                await store_alert(username, alert["type"], alert["details"], alert.get("severity", "medium"))
            risk_after = await incr_risk_score(username, 2)
            return alerts, risk_after, risk_after >= RISK_SCORE_THRESHOLD

    # ===== PASSWORD VERIFICATION (for successful logins) =====
    if success and password:
        stored_hash = await get_password_hash(username)
        if stored_hash:
            password_hash = hashlib.sha256(f"{username}:{password}".encode()).hexdigest()
            if password_hash != stored_hash:
                alerts.append({
                    "type": "password_mismatch",
                    "username": username,
                    "details": "Provided password does not match stored credentials",
                    "severity": "high",
                    "ip_address": ip_address,
                    "timestamp": timestamp.isoformat(),
                })
                success = False  # Treat as failed

    if not success:
        # ===== FAILED LOGIN ANALYSIS =====
        failed_count = await incr_failed_attempts(username)

        if failed_count >= FAILED_ATTEMPTS_THRESHOLD:
            alerts.append({
                "type": "brute_force",
                "username": username,
                "details": f"Brute-force threshold reached: {failed_count}/{FAILED_ATTEMPTS_THRESHOLD} consecutive failures",
                "severity": "critical",
                "ip_address": ip_address,
                "timestamp": timestamp.isoformat(),
                "failed_count": failed_count,
            })
            risk_points = RISK_POINTS_BRUTE_FORCE
        else:
            alerts.append({
                "type": "failed_login",
                "username": username,
                "details": f"Failed login attempt ({failed_count}/{FAILED_ATTEMPTS_THRESHOLD})",
                "severity": "low" if failed_count < 3 else "medium",
                "ip_address": ip_address,
                "timestamp": timestamp.isoformat(),
                "failed_count": failed_count,
            })
            risk_points = 1

        for alert in alerts:
            await store_alert(username, alert["type"], alert["details"], alert.get("severity", "medium"))

        risk_after = await incr_risk_score(username, risk_points)
        blocked = risk_after >= RISK_SCORE_THRESHOLD

        # FIX: Auto-lock account when risk threshold is crossed
        if blocked:
            await lock_account(username, reason=f"Risk score {risk_after} exceeded threshold {RISK_SCORE_THRESHOLD}")

        return alerts, risk_after, blocked

    # ===== SUCCESSFUL LOGIN ANALYSIS =====
    await reset_failed_attempts(username)

    hour = timestamp.hour
    device_id = None
    if user_agent:
        device_id = hashlib.md5(user_agent.encode()).hexdigest()

    # Check anomalies BEFORE recording current login
    hour_unusual = await is_hour_unusual(username, hour, MIN_LOGINS_FOR_BASELINE)

    # FIX: Use get_redis() correctly — was called without awaiting the helper
    r = await get_redis()
    total_logins_before = int(await r.get(f"logins:{username}") or 0)

    # Record the current login
    total_logins = await record_successful_login(username, hour)
    total_risk_increment = 0

    # 1. UNUSUAL TIMING
    if hour_unusual and total_logins_before >= MIN_LOGINS_FOR_BASELINE - 1:
        known_hours = await get_known_hours(username)
        alerts.append({
            "type": "unusual_timing",
            "username": username,
            "details": f"Login at {hour:02d}:00 UTC — outside known activity hours {known_hours}",
            "severity": "medium",
            "ip_address": ip_address,
            "timestamp": timestamp.isoformat(),
            "login_hour": hour,
            "known_hours": known_hours,
        })
        total_risk_increment += RISK_POINTS_UNUSUAL_TIMING

    # 2. RAPID LOGIN FREQUENCY
    login_freq = await record_login_attempt(username)
    if login_freq > MAX_LOGINS_IN_WINDOW:
        alerts.append({
            "type": "rapid_login_attempts",
            "username": username,
            "details": f"Excessive login rate: {login_freq} attempts in 5-minute window (limit: {MAX_LOGINS_IN_WINDOW})",
            "severity": "high",
            "ip_address": ip_address,
            "timestamp": timestamp.isoformat(),
            "login_frequency": login_freq,
        })
        total_risk_increment += RISK_POINTS_RAPID_LOGINS

    # 3. NEW IP ADDRESS
    if ip_address:
        ip_new = await is_ip_new(username, ip_address, MIN_LOGINS_FOR_BASELINE)
        await record_ip(username, ip_address)
        if ip_new and total_logins_before >= MIN_LOGINS_FOR_BASELINE - 1:
            known_ips = await get_known_ips(username)
            alerts.append({
                "type": "new_ip",
                "username": username,
                "details": f"Login from previously unseen IP: {ip_address}",
                "severity": "medium",
                "ip_address": ip_address,
                "timestamp": timestamp.isoformat(),
                "known_ips": known_ips,
            })
            total_risk_increment += RISK_POINTS_NEW_IP

    # 4. NEW DEVICE / USER-AGENT
    if user_agent and device_id:
        ua_new = await is_ua_new(username, user_agent, MIN_LOGINS_FOR_BASELINE)
        await record_user_agent(username, user_agent)
        device_logins = await record_device_login(username, device_id)

        if ua_new and total_logins_before >= MIN_LOGINS_FOR_BASELINE - 1:
            if device_logins < DEVICE_TRUST_LOGINS_THRESHOLD:
                alerts.append({
                    "type": "new_device",
                    "username": username,
                    "details": f"Login from unrecognised device (trust level: {device_logins}/{DEVICE_TRUST_LOGINS_THRESHOLD})",
                    "severity": "medium",
                    "ip_address": ip_address,
                    "timestamp": timestamp.isoformat(),
                    "device_trust": device_logins,
                })
                total_risk_increment += RISK_POINTS_NEW_DEVICE

    # 5. CONCURRENT SESSIONS
    sessions = await get_active_sessions(username)
    if len(sessions) > MAX_CONCURRENT_SESSIONS:
        alerts.append({
            "type": "excessive_concurrent_sessions",
            "username": username,
            "details": f"Concurrent session limit exceeded: {len(sessions)}/{MAX_CONCURRENT_SESSIONS}",
            "severity": "high",
            "ip_address": ip_address,
            "timestamp": timestamp.isoformat(),
            "session_count": len(sessions),
        })
        total_risk_increment += RISK_POINTS_CONCURRENT_SESSION

    # 6. IMPOSSIBLE TRAVEL / GEOGRAPHIC ANOMALY
    if location_lat and location_lon:
        last_location = await get_last_location(username)

        if last_location and last_location.get("lat") and last_location.get("lon"):
            last_time = datetime.fromisoformat(last_location["timestamp"])
            time_diff = (timestamp - last_time).total_seconds() / 60

            # FIX: guard against negative time_diff (clock skew / replay)
            if time_diff < 0:
                time_diff = 0

            if is_new_location_suspicious(
                location_lat, location_lon,
                last_location["lat"], last_location["lon"],
                int(time_diff)
            ):
                last_country = get_location_name(last_location.get("country"))
                current_country = get_location_name(location_country)
                alerts.append({
                    "type": "impossible_travel",
                    "username": username,
                    "details": f"Impossible travel detected: {last_country} → {current_country} in {int(time_diff)} minutes",
                    "severity": "critical",
                    "ip_address": ip_address,
                    "timestamp": timestamp.isoformat(),
                    "from_country": last_country,
                    "to_country": current_country,
                    "time_diff_minutes": int(time_diff),
                })
                total_risk_increment += RISK_POINTS_NEW_LOCATION

        await record_location(username, location_lat, location_lon, location_country)

    # 7. WEAK PASSWORD RISK INCREMENT
    if is_weak_password:
        total_risk_increment += RISK_POINTS_WEAK_PASSWORD

    # Store all alerts
    for alert in alerts:
        await store_alert(username, alert["type"], alert["details"], alert.get("severity", "medium"))

    # Calculate final risk
    risk_after = risk_before
    if total_risk_increment > 0:
        risk_after = await incr_risk_score(username, total_risk_increment)

    blocked = risk_after >= RISK_SCORE_THRESHOLD

    # FIX: Auto-lock on threshold breach
    if blocked:
        await lock_account(username, reason=f"Risk score {risk_after} exceeded threshold {RISK_SCORE_THRESHOLD}")

    return alerts, risk_after, blocked
