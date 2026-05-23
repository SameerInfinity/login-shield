import os
from dotenv import load_dotenv

load_dotenv()

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))

# ===== BRUTE FORCE DETECTION =====
FAILED_ATTEMPTS_THRESHOLD = int(os.getenv("FAILED_ATTEMPTS_THRESHOLD", 5))
FAILED_WINDOW_SECONDS = int(os.getenv("FAILED_WINDOW_SECONDS", 300))

# ===== BASELINE THRESHOLDS =====
MIN_LOGINS_FOR_BASELINE = int(os.getenv("MIN_LOGINS_FOR_BASELINE", 3))

# ===== UNUSUAL TIMING =====
# Allow login at up to N different hours before flagging unusual timing
UNUSUAL_TIMING_SENSITIVITY = int(os.getenv("UNUSUAL_TIMING_SENSITIVITY", 8))

# ===== LOGIN FREQUENCY ANOMALIES =====
# Max logins within a 5-minute window (for detecting brute-force or rapid automation)
MAX_LOGINS_IN_WINDOW = int(os.getenv("MAX_LOGINS_IN_WINDOW", 10))
LOGIN_FREQUENCY_WINDOW_SECONDS = int(os.getenv("LOGIN_FREQUENCY_WINDOW_SECONDS", 300))

# ===== CONCURRENT SESSION DETECTION =====
# Max concurrent sessions per user
MAX_CONCURRENT_SESSIONS = int(os.getenv("MAX_CONCURRENT_SESSIONS", 3))
SESSION_TIMEOUT_MINUTES = int(os.getenv("SESSION_TIMEOUT_MINUTES", 30))

# ===== GEOGRAPHIC ANOMALIES =====
# Flag if user logs in from geographically distant location within time threshold
GEO_DISTANCE_THRESHOLD_KM = int(os.getenv("GEO_DISTANCE_THRESHOLD_KM", 1000))
GEO_TIME_THRESHOLD_MINUTES = int(os.getenv("GEO_TIME_THRESHOLD_MINUTES", 120))

# ===== DEVICE TRUST SCORING =====
# Number of logins to establish device trust
DEVICE_TRUST_LOGINS_THRESHOLD = int(os.getenv("DEVICE_TRUST_LOGINS_THRESHOLD", 5))

# ===== PASSWORD POLICY =====
MIN_PASSWORD_LENGTH = int(os.getenv("MIN_PASSWORD_LENGTH", 8))
REQUIRE_UPPERCASE = os.getenv("REQUIRE_UPPERCASE", "true").lower() == "true"
REQUIRE_NUMBERS = os.getenv("REQUIRE_NUMBERS", "true").lower() == "true"
REQUIRE_SPECIAL = os.getenv("REQUIRE_SPECIAL", "true").lower() == "true"

# ===== RISK SCORING =====
# Risk thresholds and scoring
RISK_SCORE_THRESHOLD = int(os.getenv("RISK_SCORE_THRESHOLD", 7))
RISK_SCORE_DECAY_HOURS = int(os.getenv("RISK_SCORE_DECAY_HOURS", 24))

# Individual risk point values
RISK_POINTS_BRUTE_FORCE = int(os.getenv("RISK_POINTS_BRUTE_FORCE", 3))
RISK_POINTS_UNUSUAL_TIMING = int(os.getenv("RISK_POINTS_UNUSUAL_TIMING", 1))
RISK_POINTS_NEW_IP = int(os.getenv("RISK_POINTS_NEW_IP", 2))
RISK_POINTS_NEW_DEVICE = int(os.getenv("RISK_POINTS_NEW_DEVICE", 1))
RISK_POINTS_NEW_LOCATION = int(os.getenv("RISK_POINTS_NEW_LOCATION", 2))
RISK_POINTS_RAPID_LOGINS = int(os.getenv("RISK_POINTS_RAPID_LOGINS", 2))
RISK_POINTS_CONCURRENT_SESSION = int(os.getenv("RISK_POINTS_CONCURRENT_SESSION", 1))
RISK_POINTS_WEAK_PASSWORD = int(os.getenv("RISK_POINTS_WEAK_PASSWORD", 2))

# ===== ALERTING =====
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "http://localhost:8088/services/collector/event")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")