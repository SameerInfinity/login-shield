from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List

class LoginEvent(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)  # NOW REQUIRED
    success: bool = Field(default=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    location_lat: Optional[float] = None      # Geographic location (latitude)
    location_lon: Optional[float] = None      # Geographic location (longitude)
    location_country: Optional[str] = None    # Geographic location (country code)

class EventResponse(BaseModel):
    status: str                              # "processed", "blocked", "weak_password"
    alerts_generated: int
    alerts: List[dict] = []
    risk_score: int = 0
    blocked: bool = False
    message: Optional[str] = None

class AlertDetails(BaseModel):
    alert_type: str
    username: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    details: str
    severity: str = "medium"  # low, medium, high, critical
    ip_address: Optional[str] = None
    data: dict = {}

class UserBaseline(BaseModel):
    username: str
    total_logins: int = 0
    known_hours: List[int] = []
    known_ips: List[str] = []
    known_user_agents: List[str] = []
    known_locations: List[dict] = []
    trusted_devices: List[str] = []
    risk_score: int = 0
    is_blocked: bool = False
    last_login: Optional[datetime] = None
    account_created: Optional[datetime] = None