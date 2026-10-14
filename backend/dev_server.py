

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import parse_qs

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

import redis_store

app = FastAPI(title="DarkTrace development API", version="0.1.0-dev")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_users: dict[str, dict] = {}
_sessions: dict[str, str] = {}
_jobs: list[dict] = []
_sources = [
    {
        "source_id": "src_dev_001",
        "name": "Development source",
        "source_type": "forum",
        "onion_addr": None,
        "auth_ref": "development-only",
        "crawl_policy": {},
        "health": {},
        "status": "active",
        "created_by": "system",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
]


class RegisterPayload(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8)


class CrawlJobPayload(BaseModel):
    intent_id: str = Field(min_length=1)
    source_id: str
    kind: Literal["scheduled", "incremental", "manual"] = "manual"


class AlertPayload(BaseModel):
    title: str = Field(min_length=1)
    severity: Literal["critical", "high", "medium", "low"] = "medium"
    ioc: str | None = None
    type: str | None = None
    source: str | None = None
    description: str | None = None


class AlertReviewPayload(BaseModel):
    """Body for PATCH /api/v1/alerts/{alert_id} -- the route unimplimented.md
    calls out under 'Persistent alert review'."""
    status: Literal["Active", "Reviewed"] = "Reviewed"
    note: str | None = None


def _hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt, digest


def _user_out(user: dict) -> dict:
    return {
        "usr_id": user["usr_id"],
        "username": user["username"],
        "email": user["email"],
        "role": "analyst",
        "mfa_enabled": False,
        "status": "active",
        "created_at": user["created_at"],
        "last_login_at": user.get("last_login_at"),
    }


def _current_user(authorization: str = Header(default="")) -> dict:
    token = authorization.removeprefix("Bearer ").strip() if authorization.startswith("Bearer ") else ""
    username = _sessions.get(token)
    if not username or username not in _users:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")
    return _users[username]


@app.get("/health", tags=["System"])
async def health() -> dict:
    return {"status": "ok", "service": "darktrace-development-api", "storage": "memory"}


@app.post("/api/v1/auth/register", status_code=status.HTTP_201_CREATED, tags=["Auth"])
async def register(payload: RegisterPayload) -> dict:
    if payload.username in _users or any(user["email"] == payload.email for user in _users.values()):
        raise HTTPException(status_code=400, detail="Username or email already registered")
    salt, password_hash = _hash_password(payload.password)
    user = {
        "usr_id": f"usr_dev_{len(_users) + 1:03d}",
        "username": payload.username,
        "email": payload.email,
        "salt": salt,
        "password_hash": password_hash,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_login_at": None,
    }
    _users[payload.username] = user
    return _user_out(user)


@app.post("/api/v1/auth/token", tags=["Auth"])
async def login(request: Request) -> dict:
    form = parse_qs((await request.body()).decode("utf-8"))
    username = form.get("username", [""])[0]
    password = form.get("password", [""])[0]
    user = _users.get(username)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    _, candidate = _hash_password(password, user["salt"])
    if not hmac.compare_digest(candidate, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = secrets.token_urlsafe(32)
    _sessions[token] = username
    user["last_login_at"] = datetime.now(timezone.utc).isoformat()
    return {"access_token": token, "token_type": "bearer"}


@app.get("/api/v1/auth/me", tags=["Auth"])
async def me(user: dict = Depends(_current_user)) -> dict:
    return _user_out(user)


@app.get("/api/v1/alerts", tags=["Alerting"])
async def list_alerts(_: dict = Depends(_current_user)) -> list[dict]:
    return redis_store.list_alerts()


@app.post("/api/v1/alerts", status_code=status.HTTP_201_CREATED, tags=["Alerting"])
async def create_alert(payload: AlertPayload, _: dict = Depends(_current_user)) -> dict:
    return redis_store.create_alert(payload.model_dump())


@app.patch("/api/v1/alerts/{alert_id}", tags=["Alerting"])
async def review_alert(
    alert_id: str, payload: AlertReviewPayload, user: dict = Depends(_current_user)
) -> dict:
    """Persists a review decision (status, reviewer, timestamp, optional
    note) for an alert -- the route unimplimented.md marked missing."""
    updated = redis_store.update_alert_review(
        alert_id, status=payload.status, reviewer_id=user["usr_id"], note=payload.note
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return updated


@app.get("/api/v1/dashboard/summary", tags=["Dashboard"])
async def dashboard_summary(_: dict = Depends(_current_user)) -> dict:
    counts = {severity: 0 for severity in ("critical", "high", "medium", "low")}
    for alert in redis_store.list_alerts():
        counts[alert["severity"]] += 1
    return {"total_cases": 0, "open_cases": 0, "alerts_by_severity": counts}


@app.get("/api/v1/sources", tags=["Sources"])
async def list_sources(status_filter: str | None = None, _: dict = Depends(_current_user)) -> list[dict]:
    return [source for source in _sources if not status_filter or source["status"] == status_filter]


@app.get("/api/v1/crawl-jobs", tags=["Crawl Jobs"])
async def list_crawl_jobs(state: str | None = None, _: dict = Depends(_current_user)) -> list[dict]:
    return [job for job in reversed(_jobs) if not state or job["state"] == state]


@app.post("/api/v1/crawl-jobs", status_code=status.HTTP_201_CREATED, tags=["Crawl Jobs"])
async def create_crawl_job(payload: CrawlJobPayload, _: dict = Depends(_current_user)) -> dict:
    if not any(source["source_id"] == payload.source_id and source["status"] == "active" for source in _sources):
        raise HTTPException(status_code=404, detail="Active source not found")
    job = {
        "job_id": f"job_dev_{len(_jobs) + 1:03d}",
        **payload.model_dump(),
        "state": "queued",
        "attempt": 0,
        "stats": {},
        "error": None,
        "started_at": None,
        "finished_at": None,
    }
    _jobs.append(job)
    return job
