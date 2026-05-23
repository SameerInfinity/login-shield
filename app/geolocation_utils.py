import math
import logging
from typing import Optional, Tuple
from app.config import GEO_DISTANCE_THRESHOLD_KM, GEO_TIME_THRESHOLD_MINUTES

logger = logging.getLogger("login-monitor")


def calculate_distance(
    lat1: float, lon1: float, lat2: float, lon2: float
) -> float:
    """
    Calculate distance between two geographic coordinates using Haversine formula.
    Returns distance in kilometers.
    """
    if not all([lat1, lon1, lat2, lon2]):
        return 0

    R = 6371  # Earth's radius in km
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(delta_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    distance = R * c

    return distance


def is_geographically_impossible(
    lat1: float,
    lon1: float,
    lat2: float,
    lon2: float,
    time_diff_minutes: int,
) -> bool:
    """
    Check if login from location1 to location2 is geographically impossible
    given the time difference between logins.
    
    Returns True if it's impossible (suspicious), False if it's possible.
    """
    if not all([lat1, lon1, lat2, lon2]):
        return False

    distance = calculate_distance(lat1, lon1, lat2, lon2)

    # Approximate max travel speed: 900 km/h (commercial flight speed)
    max_distance_possible = (900 / 60) * time_diff_minutes

    return distance > max_distance_possible


def is_new_location_suspicious(
    lat: float,
    lon: float,
    prev_lat: Optional[float],
    prev_lon: Optional[float],
    time_diff_minutes: int,
) -> bool:
    """
    Determine if a new login location is suspicious based on:
    1. Distance from previous location
    2. Time available to travel that distance
    
    Returns True if suspicious, False if normal.
    """
    if not all([lat, lon]):
        return False

    if prev_lat is None or prev_lon is None:
        return False  # First location is never suspicious

    # Check if movement is geographically impossible
    if is_geographically_impossible(prev_lat, prev_lon, lat, lon, time_diff_minutes):
        return True

    # Check if distance is greater than threshold AND time is short
    distance = calculate_distance(prev_lat, prev_lon, lat, lon)
    if distance > GEO_DISTANCE_THRESHOLD_KM and time_diff_minutes < GEO_TIME_THRESHOLD_MINUTES:
        return True

    return False


def get_location_name(country_code: Optional[str]) -> str:
    """Get readable location name from country code."""
    try:
        import pycountry

        if country_code and len(country_code) == 2:
            country = pycountry.countries.get(alpha_2=country_code)
            return country.name if country else country_code
    except Exception as e:
        logger.warning(f"Could not resolve country code {country_code}: {e}")
    return country_code or "Unknown"
