from __future__ import annotations
import ipaddress, json
from datetime import datetime


def utcnow() -> datetime: return datetime.utcnow()


def jsonable(x):
    """Round-trip through JSON so the value is safe for JSON columns (datetimes etc. become strings)."""
    return json.loads(json.dumps(x, default=str))


def real_name(v) -> bool:
    """True for a real user/host value ('n/a' and empty mean 'not applicable')."""
    return bool(v) and v != "n/a"


def valid_ip(ip) -> bool:
    try: ipaddress.ip_address(ip); return True
    except (ValueError, TypeError): return False


def is_public_ip(ip) -> bool:
    try: return ipaddress.ip_address(ip).is_global
    except (ValueError, TypeError): return False
