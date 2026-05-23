# LoginShield — Bug Fixes & Enhancements

## Bugs Fixed

### 1. `NameError: get_redis` (Critical — app crashed on every successful login)
**File:** `app/anomaly.py`  
**Problem:** `get_redis` was called on line `total_logins_before = int(await (await get_redis()).get(...))` but was
never imported from `app.redis_client`. Every successful login threw `NameError: name 'get_redis' is not defined`.  
**Fix:** Added `get_redis` to the import list.

---

### 2. Blocking `requests.post()` inside async context (Performance / Correctness)
**File:** `app/alerting.py`  
**Problem:** `send_alert()` called the synchronous `requests.post()` directly inside the FastAPI async handler.
This blocked the entire event loop for up to 5 seconds per alert, degrading throughput and causing timeouts.  
**Fix:** Replaced with `httpx.AsyncClient` in an `asyncio.ensure_future()` fire-and-forget pattern.
A sync `requests` fallback (via `asyncio.to_thread`) is used only if `httpx` is not installed.

---

### 3. Missing `lock_account` import (Silent account locking failure)
**File:** `app/anomaly.py`  
**Problem:** When a user's risk score crossed `RISK_SCORE_THRESHOLD`, the code set `blocked = True` and returned
it but never actually called `lock_account()`. On the next request, `is_account_locked()` returned `False` and
the user was not blocked.  
**Fix:** Imported `lock_account` and called it whenever `blocked` becomes `True`.

---

### 4. Negative time_diff on impossible-travel check (Silent crash)
**File:** `app/anomaly.py`  
**Problem:** If a replayed or backdated login event had a timestamp *earlier* than the stored last location,
`time_diff` went negative. `int(time_diff)` passed to `is_new_location_suspicious` caused incorrect
distance-vs-speed comparisons and potential underflow.  
**Fix:** Added `if time_diff < 0: time_diff = 0` guard.

---

### 5. Account-enumeration path skipped alert storage (Alerts lost)
**File:** `app/anomaly.py`  
**Problem:** The early-return path for failed logins on non-existent users built `alerts` but never called
`store_alert()`, so those events were never persisted to Redis or forwarded to Splunk.  
**Fix:** Added `store_alert()` calls before the early return and incremented risk score.

---

### 6. Splunk payload missing custom sourcetype (Dashboard searches failed)
**File:** `app/alerting.py`  
**Problem:** Events were sent with `"sourcetype": "_json"`, a built-in Splunk type with no index-time field
extraction. All the SPL queries targeting specific fields (`alert_type`, `severity`, etc.) returned zero results.  
**Fix:** Changed `sourcetype` to `"login_shield:alert"` and enriched the event object with all anomaly-specific
fields (`ip_address`, `login_hour`, `failed_count`, `from_country`, `to_country`, etc.).

---

## New Features

### `/admin/dashboard-data` endpoint
Aggregates system-wide stats across all users:
- Summary counts (users, total alerts, high-risk users, locked accounts)
- Per-user risk register
- Alert type breakdown for chart rendering
- Last 200 events for the live alert feed

### `/admin/splunk-status` endpoint
Live-pings Splunk HEC and returns `{ configured, connected, url, status }`.
Used by the dashboard badge to show green/red connectivity in real time.

### Admin Dashboard (`static/index.html`)
Completely rebuilt. Tabs:
- **Overview** — stat cards + bar chart + recent alert stream
- **Live Alerts** — filterable table (user / severity / type)
- **Users** — risk register with inline Unlock / Reset Risk actions
- **Simulate** — send test login events without external tooling
- **Splunk Config** — HEC URL + token tester, plus 8 ready-to-use SPL queries

### `httpx` added to `requirements.txt`
Required for async Splunk HEC dispatch.

---

## Splunk Dashboard Setup (Quick Reference)

1. In Splunk Cloud/Enterprise → **Settings → Data Inputs → HTTP Event Collector → New Token**
2. Assign sourcetype `login_shield:alert` (or leave auto and use the transform below)
3. Copy the token and HEC URL into `.env`:
   ```
   SPLUNK_HEC_URL=https://YOURHOST.splunkcloud.com:8088/services/collector/event
   SPLUNK_HEC_TOKEN=your-token-here
   ```
4. Restart the app: `python run.py`
5. Open the Admin Dashboard → **Splunk Config** tab → click **Test & Save**
6. In Splunk Search, paste any of the provided SPL queries from the dashboard

### Recommended Splunk Dashboard Panels

| Panel | SPL |
|---|---|
| Alert volume over time | `sourcetype="login_shield:alert" \| timechart count by alert_type span=1h` |
| Critical alerts | `sourcetype="login_shield:alert" severity="critical" \| table _time, username, alert_type, details` |
| Top suspicious users | `sourcetype="login_shield:alert" \| stats count BY username \| sort -count` |
| Brute force map | `sourcetype="login_shield:alert" alert_type="brute_force" \| stats count BY ip_address \| iplocation ip_address \| geostats count` |
