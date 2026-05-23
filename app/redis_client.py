import redis.asyncio as aioredis
import json
import time
from datetime import datetime, timedelta
from app.config import (
    REDIS_HOST, REDIS_PORT, REDIS_DB, FAILED_WINDOW_SECONDS,
    SESSION_TIMEOUT_MINUTES, RISK_SCORE_DECAY_HOURS
)

redis_pool = aioredis.ConnectionPool(
    host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True
)


async def get_redis():
    return aioredis.Redis(connection_pool=redis_pool)


async def close_redis():
    """Close Redis connection pool."""
    try:
        await redis_pool.disconnect()
    except Exception as e:
        print(f"Error closing Redis: {e}")


# ========== FAILED ATTEMPTS ==========
async def incr_failed_attempts(username: str) -> int:
    r = await get_redis()
    key = f"failed:{username}"
    async with r.pipeline(transaction=True) as pipe:
        pipe.incr(key)
        pipe.expire(key, FAILED_WINDOW_SECONDS)
        results = await pipe.execute()
    return results[0]


async def get_failed_attempts(username: str) -> int:
    r = await get_redis()
    count = await r.get(f"failed:{username}")
    return int(count) if count else 0


async def reset_failed_attempts(username: str):
    r = await get_redis()
    await r.delete(f"failed:{username}")


# ========== LOGIN BASELINE: HOURS ==========
async def record_successful_login(username: str, hour: int) -> int:
    r = await get_redis()
    total_key = f"logins:{username}"
    baseline_key = f"baseline:{username}:hours"
    async with r.pipeline(transaction=True) as pipe:
        pipe.incr(total_key)
        pipe.sadd(baseline_key, hour)
        total, _ = await pipe.execute()
    return total


async def is_hour_unusual(username: str, hour: int, min_logins: int) -> bool:
    r = await get_redis()
    total = await r.get(f"logins:{username}")
    if total is None or int(total) < min_logins:
        return False
    return not await r.sismember(f"baseline:{username}:hours", hour)


async def get_known_hours(username: str) -> list:
    r = await get_redis()
    hours = await r.smembers(f"baseline:{username}:hours")
    return sorted([int(h) for h in hours])


# ========== IP BASELINE ==========
async def record_ip(username: str, ip: str) -> None:
    r = await get_redis()
    ip_key = f"baseline:{username}:ips"
    await r.sadd(ip_key, ip)


async def is_ip_new(username: str, ip: str, min_logins: int) -> bool:
    r = await get_redis()
    total = await r.get(f"logins:{username}")
    if total is None or int(total) < min_logins:
        return False
    return not await r.sismember(f"baseline:{username}:ips", ip)


async def get_known_ips(username: str) -> list:
    r = await get_redis()
    ips = await r.smembers(f"baseline:{username}:ips")
    return list(ips)


# ========== USER-AGENT BASELINE ==========
async def record_user_agent(username: str, ua: str) -> None:
    r = await get_redis()
    ua_key = f"baseline:{username}:uas"
    await r.sadd(ua_key, ua)


async def is_ua_new(username: str, ua: str, min_logins: int) -> bool:
    r = await get_redis()
    total = await r.get(f"logins:{username}")
    if total is None or int(total) < min_logins:
        return False
    return not await r.sismember(f"baseline:{username}:uas", ua)


async def get_known_user_agents(username: str) -> list:
    r = await get_redis()
    uas = await r.smembers(f"baseline:{username}:uas")
    return list(uas)


# ========== GEOLOCATION BASELINE ==========
async def record_location(username: str, lat: float, lon: float, country: str) -> None:
    """Record a successful login location."""
    r = await get_redis()
    if not lat or not lon:
        return

    location_data = json.dumps(
        {
            "lat": lat,
            "lon": lon,
            "country": country,
            "timestamp": datetime.utcnow().isoformat(),
        }
    )
    loc_key = f"baseline:{username}:locations"
    await r.lpush(loc_key, location_data)
    await r.ltrim(loc_key, 0, 99)  # Keep last 100 locations


async def get_last_location(username: str) -> dict:
    """Get the most recent login location."""
    r = await get_redis()
    loc_key = f"baseline:{username}:locations"
    last = await r.lindex(loc_key, 0)
    if last:
        return json.loads(last)
    return {}


async def get_known_locations(username: str, limit: int = 10) -> list:
    """Get known login locations."""
    r = await get_redis()
    loc_key = f"baseline:{username}:locations"
    locations = await r.lrange(loc_key, 0, limit - 1)
    return [json.loads(loc) for loc in locations]


# ========== SESSION MANAGEMENT ==========
async def start_session(username: str, ip: str, user_agent: str, session_id: str) -> None:
    """Start a new user session."""
    r = await get_redis()
    session_key = f"session:{session_id}"
    sessions_set = f"sessions:{username}"

    session_data = {
        "username": username,
        "ip": ip,
        "user_agent": user_agent,
        "start_time": datetime.utcnow().isoformat(),
    }

    async with r.pipeline(transaction=True) as pipe:
        pipe.setex(
            session_key, SESSION_TIMEOUT_MINUTES * 60, json.dumps(session_data)
        )
        pipe.sadd(sessions_set, session_id)
        await pipe.execute()


async def get_active_sessions(username: str) -> list:
    """Get all active sessions for a user."""
    r = await get_redis()
    sessions_set = f"sessions:{username}"
    session_ids = await r.smembers(sessions_set)
    
    active_sessions = []
    for session_id in session_ids:
        session_key = f"session:{session_id}"
        session_data = await r.get(session_key)
        if session_data:
            active_sessions.append(json.loads(session_data))
        else:
            # Remove expired session from set
            await r.srem(sessions_set, session_id)

    return active_sessions


async def end_session(username: str, session_id: str) -> None:
    """End a session."""
    r = await get_redis()
    session_key = f"session:{session_id}"
    sessions_set = f"sessions:{username}"
    await r.delete(session_key)
    await r.srem(sessions_set, session_id)


# ========== LOGIN FREQUENCY TRACKING ==========
async def record_login_attempt(username: str) -> int:
    """Record a login attempt and return count in current window."""
    r = await get_redis()
    key = f"login_freq:{username}"
    count = await r.incr(key)
    await r.expire(key, 300)  # 5-minute window
    return count


async def get_login_frequency(username: str) -> int:
    """Get login attempts in current window."""
    r = await get_redis()
    count = await r.get(f"login_freq:{username}")
    return int(count) if count else 0


# ========== DEVICE TRUST SCORING ==========
async def record_device_login(username: str, device_id: str) -> int:
    """Record a login from a device, return count."""
    r = await get_redis()
    key = f"device:{username}:{device_id}"
    count = await r.incr(key)
    # Keep device trust for 90 days
    await r.expire(key, 90 * 24 * 60 * 60)
    return count


async def get_device_trust_level(username: str, device_id: str) -> int:
    """Get how many times a device has been used (trust level)."""
    r = await get_redis()
    count = await r.get(f"device:{username}:{device_id}")
    return int(count) if count else 0


# ========== RISK SCORE MANAGEMENT ==========
async def incr_risk_score(username: str, points: int = 1) -> int:
    """Increment risk score by N points."""
    r = await get_redis()
    key = f"risk:{username}"
    new_score = await r.incrby(key, points)
    # Keep risk score for 24 hours with automatic decay
    await r.expire(key, RISK_SCORE_DECAY_HOURS * 60 * 60)
    return new_score


async def get_risk_score(username: str) -> int:
    r = await get_redis()
    score = await r.get(f"risk:{username}")
    return int(score) if score else 0


async def decr_risk_score(username: str, points: int = 1) -> int:
    """Decrement risk score (for good behavior recovery)."""
    r = await get_redis()
    key = f"risk:{username}"
    current = await r.get(key)
    if current:
        new_score = max(0, int(current) - points)
        if new_score == 0:
            await r.delete(key)
        else:
            await r.set(key, new_score)
        return new_score
    return 0


async def reset_risk_score(username: str):
    r = await get_redis()
    await r.delete(f"risk:{username}")


# ========== ALERT HISTORY ==========
async def store_alert(username: str, alert_type: str, details: str, severity: str = "medium") -> None:
    """Store alert in history."""
    r = await get_redis()
    alert_data = {
        "type": alert_type,
        "details": details,
        "severity": severity,
        "timestamp": datetime.utcnow().isoformat(),
    }
    history_key = f"alerts:{username}"
    await r.lpush(history_key, json.dumps(alert_data))
    # Keep last 1000 alerts
    await r.ltrim(history_key, 0, 999)


async def get_alert_history(username: str, limit: int = 50) -> list:
    """Get alert history for a user."""
    r = await get_redis()
    history_key = f"alerts:{username}"
    alerts = await r.lrange(history_key, 0, limit - 1)
    return [json.loads(alert) for alert in alerts]


# ========== PASSWORD STORAGE ==========
async def store_password_hash(username: str, password_hash: str) -> None:
    """Store password hash for user."""
    r = await get_redis()
    key = f"password:{username}"
    await r.set(key, password_hash)


async def get_password_hash(username: str) -> str:
    """Get stored password hash."""
    r = await get_redis()
    return await r.get(f"password:{username}")


async def user_exists(username: str) -> bool:
    """Check if user has an account."""
    r = await get_redis()
    return await r.exists(f"password:{username}") > 0


# ========== ACCOUNT LOCK/UNLOCK ==========
async def lock_account(username: str, reason: str = "security") -> None:
    """Lock a user account."""
    r = await get_redis()
    key = f"locked:{username}"
    await r.set(key, json.dumps({"reason": reason, "timestamp": datetime.utcnow().isoformat()}))


async def unlock_account(username: str) -> None:
    """Unlock a user account."""
    r = await get_redis()
    await r.delete(f"locked:{username}")


async def is_account_locked(username: str) -> bool:
    """Check if account is locked."""
    r = await get_redis()
    return await r.exists(f"locked:{username}") > 0


async def get_lock_reason(username: str) -> str:
    """Get reason account was locked."""
    r = await get_redis()
    lock_data = await r.get(f"locked:{username}")
    if lock_data:
        return json.loads(lock_data).get("reason", "unknown")
    return None