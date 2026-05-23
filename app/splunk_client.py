import logging
import requests
import json
from datetime import datetime
from typing import Dict, List, Optional
from app.config import SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN

logger = logging.getLogger("login-monitor")


class SplunkClient:
    """Client for Splunk HEC (HTTP Event Collector) integration."""
    
    def __init__(self, hec_url: str = None, hec_token: str = None):
        """Initialize Splunk client."""
        self.hec_url = hec_url or SPLUNK_HEC_URL
        self.hec_token = hec_token or SPLUNK_HEC_TOKEN
        self.is_configured = bool(self.hec_url and self.hec_token)
        
        if self.is_configured:
            logger.info(f"✅ Splunk HEC configured: {self.hec_url}")
        else:
            logger.warning("⚠️  Splunk HEC not configured. Alerts will be logged to console only.")
    
    def send_alert(self, alert: Dict) -> bool:
        """
        Send an alert to Splunk.
        
        Returns: True if sent successfully, False otherwise.
        """
        if not self.is_configured:
            logger.debug("Splunk not configured, skipping HEC send")
            return False
        
        try:
            payload = {
                "time": datetime.utcnow().timestamp(),
                "host": "login-shield-monitor",
                "source": "login_anomaly_detector",
                "sourcetype": "json",
                "event": {
                    "alert_type": alert.get("type"),
                    "username": alert.get("username"),
                    "details": alert.get("details"),
                    "severity": alert.get("severity", "medium"),
                    "timestamp": alert.get("timestamp", datetime.utcnow().isoformat()),
                    "ip_address": alert.get("ip_address"),
                }
            }
            
            headers = {
                "Authorization": f"Splunk {self.hec_token}",
                "Content-Type": "application/json"
            }
            
            # Try sending
            logger.debug(f"Sending to Splunk: {self.hec_url}")
            response = requests.post(
                self.hec_url,
                json=payload,
                headers=headers,
                timeout=5,
                verify=False  # Disable SSL verification for development
            )
            
            if response.status_code in [200, 201]:
                logger.info(f"✅ Splunk HEC accepted: {response.json().get('text', 'OK')}")
                return True
            else:
                logger.error(f"❌ Splunk HEC error ({response.status_code}): {response.text}")
                return False
                
        except requests.exceptions.ConnectionError as e:
            logger.warning(f"⚠️  Cannot connect to Splunk: {e}")
            return False
        except requests.exceptions.Timeout:
            logger.warning("⚠️  Splunk request timeout")
            return False
        except Exception as e:
            logger.error(f"❌ Error sending to Splunk: {e}")
            return False
    
    def send_metric(self, metric_name: str, value: float, tags: Dict = None) -> bool:
        """
        Send a metric to Splunk.
        
        Usage: send_metric("login_attempts", 5, {"username": "alice"})
        """
        if not self.is_configured:
            return False
        
        try:
            payload = {
                "time": datetime.utcnow().timestamp(),
                "host": "login-shield-monitor",
                "source": "login_metrics",
                "sourcetype": "metrics",
                "event": {
                    "metric_name": metric_name,
                    "value": value,
                    "tags": tags or {},
                    "timestamp": datetime.utcnow().isoformat(),
                }
            }
            
            headers = {
                "Authorization": f"Splunk {self.hec_token}",
                "Content-Type": "application/json"
            }
            
            response = requests.post(
                self.hec_url,
                json=payload,
                headers=headers,
                timeout=5,
                verify=False
            )
            
            return response.status_code in [200, 201]
            
        except Exception as e:
            logger.debug(f"Could not send metric: {e}")
            return False
    
    def test_connection(self) -> bool:
        """Test if Splunk HEC is reachable and accepting events."""
        if not self.is_configured:
            return False
        
        try:
            test_event = {
                "time": datetime.utcnow().timestamp(),
                "host": "login-shield-monitor",
                "source": "health_check",
                "sourcetype": "json",
                "event": {
                    "test": True,
                    "message": "LoginShield health check",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            }
            
            headers = {
                "Authorization": f"Splunk {self.hec_token}",
                "Content-Type": "application/json"
            }
            
            response = requests.post(
                self.hec_url,
                json=test_event,
                headers=headers,
                timeout=5,
                verify=False
            )
            
            if response.status_code in [200, 201]:
                logger.info("✅ Splunk HEC connection test PASSED")
                return True
            else:
                logger.error(f"❌ Splunk HEC test failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Splunk connection test failed: {e}")
            return False
    
    def get_recent_alerts(self, query: str = "*", count: int = 100) -> Optional[List[Dict]]:
        """
        Query recent alerts from Splunk using REST API.
        
        Note: Requires Splunk REST API access (different from HEC).
        """
        logger.debug(f"Note: Getting alerts requires Splunk REST API configuration, not HEC")
        return None


# Global client instance
_splunk_client = None


def get_splunk_client() -> SplunkClient:
    """Get or create Splunk client."""
    global _splunk_client
    if _splunk_client is None:
        _splunk_client = SplunkClient()
    return _splunk_client


def send_alert_to_splunk(alert: Dict) -> bool:
    """Send alert to Splunk (convenience function)."""
    client = get_splunk_client()
    return client.send_alert(alert)


def test_splunk_connection() -> Dict:
    """Test Splunk connection and return status."""
    client = get_splunk_client()
    is_configured = client.is_configured
    can_connect = client.test_connection() if is_configured else False
    
    return {
        "configured": is_configured,
        "url": client.hec_url if is_configured else None,
        "connected": can_connect,
        "status": "ok" if can_connect else "not_configured" if not is_configured else "connection_failed"
    }
