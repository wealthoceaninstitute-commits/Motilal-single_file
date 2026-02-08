"""
Auth-only backend (FastAPI): User register + login + JWT verification

What this implements (matching your existing motilal_trader.py logic):
- Stores user profile at: data/users/{userid}/profile.json (via GitHub Contents API)
- Register: POST /auth/register
- Login:    POST /auth/login  -> returns {"access_token": "<JWT>"}
- Verify:   GET  /me          -> requires Authorization: Bearer <token>

Frontend storage (browser localStorage):
- mb_auth_token_v1 = <JWT>
- mb_logged_in_userid_v1 = JSON.stringify(<userid>)
- Send header on every API request:
    Authorization: Bearer <token>
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from datetime import datetime
from typing import Any, Dict, Optional, Tuple
import re

import requests
from fastapi import Depends, FastAPI, HTTPException, Request,Body,Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


# ---------------- JWT (HS256) helpers (no external dependency) ----------------
def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)

def jwt_encode(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"

class JWTError(Exception):
    pass

def jwt_decode(token: str, secret: str) -> dict:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        raise JWTError("Invalid token format")

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(_b64url_encode(expected_sig), sig_b64):
        raise JWTError("Invalid token signature")

    payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))

    exp = payload.get("exp")
    if exp is not None:
        try:
            exp_int = int(exp)
        except Exception:
            raise JWTError("Invalid exp")
        if int(time.time()) >= exp_int:
            raise JWTError("Token expired")

    return payload


# -----------------------------
# ENV config
# -----------------------------
APP_NAME = os.getenv("APP_NAME", "Auth Backend (Multiuser)")
API_VERSION = os.getenv("API_VERSION", "1.0.0")

# CORS: set CORS_ORIGINS="https://multibroker-trader-multiuser.vercel.app,http://localhost:3000"
cors_origins_raw = (os.getenv("CORS_ORIGINS") or "").strip()
if cors_origins_raw == "*":
    allow_origins = ["*"]
    allow_credentials = False
elif cors_origins_raw:
    allow_origins = [o.strip().rstrip("/") for o in cors_origins_raw.split(",") if o.strip()]
    allow_credentials = True
else:
    allow_origins = ["http://localhost:3000", "http://127.0.0.1:3000", "https://multibroker-trader-multiuser.vercel.app"]
    allow_credentials = True

SECRET_KEY = os.getenv("SECRET_KEY") or "CHANGE_ME_PLEASE_SET_SECRET_KEY"
TOKEN_EXPIRE_HOURS = int(os.getenv("TOKEN_EXPIRE_HOURS", "24"))

GITHUB_OWNER = os.getenv("GITHUB_OWNER", "")
GITHUB_REPO = os.getenv("GITHUB_REPO", "")
GITHUB_BRANCH = os.getenv("GITHUB_BRANCH", "main")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")


# -----------------------------
# App
# -----------------------------
app = FastAPI(title=APP_NAME, version=API_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)


# -----------------------------
# Utils
# -----------------------------
def utcnow_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def normalize_userid(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        vv = v.strip()
        if (vv.startswith('"') and vv.endswith('"')) or (vv.startswith("'") and vv.endswith("'")):
            vv = vv[1:-1]
        return vv.strip()
    return str(v).strip()

def require_secret():
    # For production: ALWAYS set SECRET_KEY as an environment variable.
    # This fallback prevents runtime crashes during initial testing.
    if SECRET_KEY == "CHANGE_ME_PLEASE_SET_SECRET_KEY":
        # Only a warning; app still runs so you can test end-to-end.
        print("WARNING: SECRET_KEY is not set. Using an insecure default. Set SECRET_KEY in env for production.")

def password_hash(password: str, salt: str) -> str:
    # Same as your motilal_trader.py
    return hashlib.sha256((salt + ":" + password).encode("utf-8")).hexdigest()

def create_token(userid: str) -> str:
    require_secret()
    payload = {
        "userid": userid,
        "exp": int(time.time()) + int(TOKEN_EXPIRE_HOURS) * 3600,
    }
    return jwt_encode(payload, SECRET_KEY)


# -----------------------------
# GitHub Contents helpers
# -----------------------------
def gh_enabled() -> bool:
    return bool(GITHUB_OWNER and GITHUB_REPO and GITHUB_TOKEN)

def gh_headers() -> Dict[str, str]:
    return {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github+json"}

def gh_url(path: str) -> str:
    path = path.lstrip("/")
    return f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{path}"

def b64encode_str(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("utf-8")

def b64decode_to_str(s: str) -> str:
    return base64.b64decode(s.encode("utf-8")).decode("utf-8")

def gh_get_json(path: str) -> Tuple[Optional[Any], Optional[str]]:
    """
    Returns (json_obj_or_None, sha_or_None).
    If file doesn't exist => (None, None)
    """
    if not gh_enabled():
        return None, None
    r = requests.get(gh_url(path), headers=gh_headers(), params={"ref": GITHUB_BRANCH})
    if r.status_code == 404:
        return None, None
    r.raise_for_status()
    data = r.json()
    if isinstance(data, dict) and data.get("type") == "file":
        content = (data.get("content") or "").replace("\n", "")
        sha = data.get("sha")
        text = b64decode_to_str(content) if content else ""
        if not text:
            return {}, sha
        try:
            return json.loads(text), sha
        except Exception:
            return {"_raw": text}, sha
    return data, data.get("sha")

def gh_put_json(path: str, obj: Any, message: str) -> None:
    if not gh_enabled():
        # For local testing without GitHub, just error clearly
        raise HTTPException(500, "GitHub storage not configured (set GITHUB_OWNER/GITHUB_REPO/GITHUB_TOKEN)")
    _, sha = gh_get_json(path)
    payload = {
        "message": message,
        "content": b64encode_str(json.dumps(obj, indent=2, ensure_ascii=False)),
        "branch": GITHUB_BRANCH,
    }
    if sha:
        payload["sha"] = sha
    r = requests.put(gh_url(path), headers=gh_headers(), json=payload)
    r.raise_for_status()


# -----------------------------
# Per-user storage paths
# -----------------------------
def user_root(userid: str) -> str:
    return f"data/users/{userid}"

def user_profile_path(userid: str) -> str:
    return f"{user_root(userid)}/profile.json"


# -----------------------------
# Auth dependency
# -----------------------------
def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> str:
    require_secret()
    if credentials is None or not credentials.credentials:
        raise HTTPException(status_code=401, detail="Missing token")
    try:
        payload = jwt_decode(credentials.credentials, SECRET_KEY)
        userid = (payload.get("userid") or "").strip()
        if not userid:
            raise HTTPException(status_code=401, detail="Invalid token")
        return userid
    except JWTError as e:
        msg = str(e) or "Invalid token"
        if "expired" in msg.lower():
            raise HTTPException(status_code=401, detail="Token expired")
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user_optional(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Optional[str]:
    if not credentials:
        return None
    token = (credentials.credentials or "").strip()
    if not token:
        return None
    try:
        payload = jwt_decode(token, SECRET_KEY)
        userid = payload.get("userid") or ""
        return normalize_userid(userid) or None
    except Exception:
        return None

# -----------------------------
# Routes
# -----------------------------
@app.get("/")
def root():
    return {"ok": True, "name": APP_NAME, "version": API_VERSION}

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/auth/register")
def auth_register(payload: dict):
    """
    Payload:
      { "userid": "...", "email": "...", "password": "...", "confirm_password": "..." }
    Stores:
      data/users/{userid}/profile.json  (GitHub)
    """
    userid = normalize_userid(payload.get("userid"))
    email = (payload.get("email") or "").strip()
    password = (payload.get("password") or "").strip()
    confirm = (payload.get("confirm_password") or payload.get("confirmPassword") or "").strip()

    if not userid or not email or not password:
        return {"success": False, "error": "Missing userid/email/password"}
    if confirm and password != confirm:
        return {"success": False, "error": "Passwords do not match"}

    existing, _ = gh_get_json(user_profile_path(userid))
    if existing:
        return {"success": False, "error": "User already exists"}

    salt = base64.b64encode(os.urandom(12)).decode("utf-8")
    profile = {
        "userid": userid,
        "email": email,
        "salt": salt,
        "password_hash": password_hash(password, salt),
        "created_at": utcnow_iso(),
        "updated_at": utcnow_iso(),
    }
    gh_put_json(user_profile_path(userid), profile, message=f"register {userid}")
    return {"success": True, "userid": userid}

@app.post("/auth/login")
def auth_login(payload: dict):
    """
    Payload:
      { "userid": "...", "password": "..." }
    Returns:
      { "success": True, "userid": "...", "access_token": "<JWT>" }
    """
    userid = normalize_userid(payload.get("userid"))
    password = (payload.get("password") or "").strip()

    if not userid or not password:
        return {"success": False}

    profile, _ = gh_get_json(user_profile_path(userid))
    if not profile or not isinstance(profile, dict):
        return {"success": False}

    salt = profile.get("salt", "")
    ph = profile.get("password_hash", "")
    if not salt or not ph:
        return {"success": False}

    if password_hash(password, salt) != ph:
        return {"success": False}

    token = create_token(userid)
    return {"success": True, "userid": userid, "access_token": token}

@app.get("/me")
def me(userid: str = Depends(get_current_user)):
    return {"success": True, "userid": userid}

# -----------------------------
# Per-user storage paths
# -----------------------------
def user_root(userid: str) -> str:
    return f"data/users/{userid}"

def user_profile_path(userid: str) -> str:
    return f"{user_root(userid)}/profile.json"

def _safe_filename(s: str) -> str:
    s = (s or "").strip().replace(" ", "_")
    return re.sub(r"[^A-Za-z0-9_\-]", "_", s)[:80] or "client"

def user_clients_dir(userid: str) -> str:
    return f"{user_root(userid)}/clients"

def user_client_file(userid: str, name: str, client_id: str) -> str:
    safe = _safe_filename(name)
    cid = (client_id or "").strip()
    return f"{user_clients_dir(userid)}/{safe}_{cid}.json"


# -----------------------------
# Auth dependency
# -----------------------------
def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> str:
    require_secret()
    if credentials is None or not credentials.credentials:
        raise HTTPException(status_code=401, detail="Missing token")
    try:
        payload = jwt_decode(credentials.credentials, SECRET_KEY)
        userid = (payload.get("userid") or "").strip()
        if not userid:
            raise HTTPException(status_code=401, detail="Invalid token")
        return userid
    except JWTError as e:
        msg = str(e) or "Invalid token"
        if "expired" in msg.lower():
            raise HTTPException(status_code=401, detail="Token expired")
        raise HTTPException(status_code=401, detail="Invalid token")

def gh_list_dir(path: str):
    """
    Lists a directory via GitHub Contents API.
    Returns list entries (type/file/dir, name, path, sha, etc.)
    """
    if not gh_enabled():
        raise HTTPException(500, "GitHub storage not configured (set GITHUB_OWNER/GITHUB_REPO/GITHUB_TOKEN)")
    r = requests.get(gh_url(path), headers=gh_headers(), params={"ref": GITHUB_BRANCH})
    if r.status_code == 404:
        return []
    r.raise_for_status()
    data = r.json()
    return data if isinstance(data, list) else []


# -----------------------------
# Routes
# -----------------------------
@app.get("/")
def root():
    return {"ok": True, "name": APP_NAME, "version": API_VERSION}

@app.get("/health")
def health():
    return {"ok": True}

# ---------- AUTH ----------
@app.post("/auth/register")
def auth_register(payload: dict = Body(...)):
    """
    Payload:
      { "userid": "...", "email": "...", "password": "...", "confirm_password": "..." }
    Stores:
      data/users/{userid}/profile.json
    """
    userid = normalize_userid(payload.get("userid"))
    email = (payload.get("email") or "").strip()
    password = (payload.get("password") or "").strip()
    confirm = (payload.get("confirm_password") or payload.get("confirmPassword") or "").strip()

    if not userid or not email or not password:
        return {"success": False, "error": "Missing userid/email/password"}
    if confirm and password != confirm:
        return {"success": False, "error": "Passwords do not match"}

    existing, _ = gh_get_json(user_profile_path(userid))
    if existing:
        return {"success": False, "error": "User already exists"}

    salt = base64.b64encode(os.urandom(12)).decode("utf-8")
    profile = {
        "userid": userid,
        "email": email,
        "salt": salt,
        "password_hash": password_hash(password, salt),
        "created_at": utcnow_iso(),
        "updated_at": utcnow_iso(),
    }
    gh_put_json(user_profile_path(userid), profile, message=f"register {userid}")
    return {"success": True, "userid": userid}

@app.post("/auth/login")
def auth_login(payload: dict = Body(...)):
    """
    Payload:
      { "userid": "...", "password": "..." }
    Returns:
      { "success": True, "userid": "...", "access_token": "<JWT>" }
    """
    userid = normalize_userid(payload.get("userid"))
    password = (payload.get("password") or "").strip()

    if not userid or not password:
        return {"success": False}

    profile, _ = gh_get_json(user_profile_path(userid))
    if not profile or not isinstance(profile, dict):
        return {"success": False}

    salt = profile.get("salt", "")
    ph = profile.get("password_hash", "")
    if not salt or not ph:
        return {"success": False}

    if password_hash(password, salt) != ph:
        return {"success": False}

    token = create_token(userid)
    return {"success": True, "userid": userid, "access_token": token}

@app.get("/me")
def me(userid: str = Depends(get_current_user)):
    return {"success": True, "userid": userid}

# ---------- CLIENTS ----------
def _require_fields(d: Dict[str, Any], keys: List[str]):
    missing = [k for k in keys if not (d.get(k) or "").strip()]
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing required fields: {', '.join(missing)}")

# ✅ ADD THIS HELPER (place anywhere above @app.post("/add_client"))

def build_simple_client_record(owner_userid: str, data: dict) -> dict:
    """
    Normalizes incoming payload (either flat fields OR creds{} fields)
    into ONE clean, non-repeating storage format.
    """
    data = data or {}

    # accept both "userid" and "client_id"
    name = (data.get("name") or "").strip()
    client_id = (data.get("userid") or data.get("client_id") or "").strip()

    # allow creds to come from either top-level or inside creds{}
    in_creds = data.get("creds") if isinstance(data.get("creds"), dict) else {}

    def pick(*keys):
        for k in keys:
            v = in_creds.get(k)
            if v is None or v == "":
                v = data.get(k)
            if v is not None and v != "":
                return v
        return None

    capital = pick("capital")
    try:
        capital = float(capital) if capital not in (None, "") else 0.0
    except Exception:
        capital = 0.0

    creds = {
        "password": pick("password"),
        "pan": pick("pan"),
        "apikey": pick("apikey", "api_key"),
        "totpkey": pick("totpkey", "totp", "totp_key"),
    }
    # remove empty keys
    creds = {k: v for k, v in creds.items() if v not in (None, "")}

    record = {
        "broker": (data.get("broker") or "motilal"),
        "name": name,
        "userid": client_id,
        "capital": capital,
        "creds": creds,
        "owner_userid": owner_userid,
        "session_active": bool(data.get("session_active", True)),
    }
    return record


# ✅ REPLACE ONLY YOUR /add_client FUNCTION WITH THIS VERSION

@app.post("/add_client")
def add_client(payload: dict = Body(...), userid: str = Depends(get_current_user)):
    """
    Saves client under logged-in user:
      data/users/<userid>/clients/<safe_name>_<client_id>.json
    """
    data = payload or {}
    name = (data.get("name") or "").strip()
    client_id = (data.get("userid") or data.get("client_id") or "").strip()

    _require_fields({"name": name, "userid": client_id}, ["name", "userid"])

    # ✅ save in SIMPLE non-repeating format
    clean = build_simple_client_record(userid, data)

    path = user_client_file(userid, name=name, client_id=client_id)
    gh_put_json(path, clean, message=f"add_client {userid} {name} {client_id}")
    return {"success": True, "message": "Client saved", "path": path}

@app.get("/get_clients")
@app.get("/clients")
def get_clients(
    userid: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    ignored: Optional[str] = Query(None),
    auth_user: Optional[str] = Depends(get_current_user_optional),
):
    """
    Lists clients from:
      data/users/<userid>/clients/

    Returns:
      { success: True, userid: "...", clients: [...] }
    """
    # Resolve effective user:
    # 1) If Authorization: Bearer <token> present, use it (auth_user)
    # 2) Else fallback to query params used by older frontend (userid/user_id/ignored)
    effective = auth_user or userid or user_id or ignored
    effective = normalize_userid(effective)
    if not effective:
        raise HTTPException(status_code=401, detail="Missing token (Authorization) or userid query param")
    dir_path = user_clients_dir(effective)
    entries = gh_list_dir(dir_path)

    clients: List[Dict[str, Any]] = []
    for e in entries:
        if e.get("type") != "file":
            continue
        p = e.get("path") or ""
        if not p.endswith(".json"):
            continue
        obj, _ = gh_get_json(p)
        if not isinstance(obj, dict):
            continue
        clients.append(obj)

    return {"success": True, "userid": effective, "clients": clients}


# -----------------------------
# Error formatting
# -----------------------------
@app.exception_handler(HTTPException)
async def http_exception_handler(_: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"success": False, "error": exc.detail})
