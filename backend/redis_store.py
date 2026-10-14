"""
Redis-backed persistence for alerts.

dev_server.py used to keep alerts in a plain Python list (`_alerts`) --
gone the moment the process restarted. This module is a drop-in
replacement: same shape of data, same create/list operations, but
backed by Redis so alerts (and their review status) survive restarts
and are shared across anyone pointed at the same Redis instance


Storage layout:
    darktrace:alert:{id}      -- one JSON string per alert (a Redis "hash of alerts")
    darktrace:alerts:order    -- a Redis list of alert IDs, oldest first (RPUSH on create)
    darktrace:alert_id_seq    -- an integer counter, so IDs stay sequential like the
                                 in-memory version (alert_dev_001, alert_dev_002, ...)
"""
import json
import os
from datetime import datetime, timezone

import redis
from dotenv import load_dotenv

load_dotenv()  # reads backend/.env -- REDIS_URL

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
_redis_client = redis.from_url(REDIS_URL, decode_responses=True)

ALERT_KEY_PREFIX = "darktrace:alert:"
ORDER_KEY = "darktrace:alerts:order"
ID_SEQ_KEY = "darktrace:alert_id_seq"


def _alert_key(alert_id: str) -> str:
    return f"{ALERT_KEY_PREFIX}{alert_id}"


def create_alert(payload: dict) -> dict:
    """Creates a new alert from a POST body (title, severity, ioc, type,
    source, description) and persists it. Adds the fields the frontend
    and review flow need: id, created_at, status, and empty review fields."""
    next_id = _redis_client.incr(ID_SEQ_KEY)
    alert_id = f"alert_dev_{next_id:03d}"

    alert = {
        "id": alert_id,
        **payload,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "Active",
        "reviewed_by": None,
        "reviewed_at": None,
        "review_note": None,
    }

    _redis_client.set(_alert_key(alert_id), json.dumps(alert))
    _redis_client.rpush(ORDER_KEY, alert_id)
    return alert


def list_alerts() -> list[dict]:
    """Returns all alerts, newest first -- same ordering as the old
    in-memory `list(reversed(_alerts))`."""
    alert_ids = _redis_client.lrange(ORDER_KEY, 0, -1)
    alert_ids.reverse()

    alerts = []
    for alert_id in alert_ids:
        raw = _redis_client.get(_alert_key(alert_id))
        if raw is not None:
            alerts.append(json.loads(raw))
    return alerts


def get_alert(alert_id: str) -> dict | None:
    raw = _redis_client.get(_alert_key(alert_id))
    if raw is None:
        return None
    return json.loads(raw)


def update_alert_review(
    alert_id: str,
    status: str,
    reviewer_id: str,
    note: str | None = None,
) -> dict | None:
    """Marks an alert reviewed (or otherwise updates its status) and
    persists it. Returns the updated alert, or None if alert_id doesn't
    exist -- the caller (the PATCH route) turns that into a 404."""
    alert = get_alert(alert_id)
    if alert is None:
        return None

    alert["status"] = status
    alert["reviewed_by"] = reviewer_id
    alert["reviewed_at"] = datetime.now(timezone.utc).isoformat()
    if note is not None:
        alert["review_note"] = note

    _redis_client.set(_alert_key(alert_id), json.dumps(alert))
    return alert
