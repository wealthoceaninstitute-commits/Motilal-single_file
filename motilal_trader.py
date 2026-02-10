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
from MOFSLOPENAPI import MOFSLOPENAPI
import pyotp
from typing import Dict, Any, List, Optional


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

# =========================
# Motilal LOGIN 
# =========================

Base_Url = "https://openapi.motilaloswal.com"
SourceID = "Desktop"
browsername = "chrome"
browserversion = "104"

# same structure as CT_FastAPI
mofsl_sessions: Dict[str, Dict[str, Any]] = {}


def motilal_login(client: dict):
    """
    EXACT CT_FastAPI login logic
    No schema change
    No GitHub write
    No extra features
    """

    name = client.get("name", "")
    userid = client.get("userid", "")
    password = client.get("password", "")
    pan = client.get("pan", "")
    apikey = client.get("apikey", "")
    totpkey = client.get("totpkey", "")

    try:

        totp = pyotp.TOTP(totpkey).now() if totpkey else ""

        mofsl = MOFSLOPENAPI(
            apikey,
            Base_Url,
            None,
            SourceID,
            browsername,
            browserversion
        )

        response = mofsl.login(userid, password, pan, totp, userid)

        if isinstance(response, dict) and response.get("status") == "SUCCESS":

            mofsl_sessions[userid] = {
                "name": name,
                "userid": userid,
                "mofsl": mofsl,
                "login_ts": int(time.time())
            }

            print(f"Login successful: {name} ({userid})")

            return True

        else:

            print(f"Login failed: {name} ({userid})")

            return False

    except Exception as e:

        print(f"Login error: {name} ({userid}) :: {e}")

        return False

@app.post("/add_client")
async def add_client(request: Request, payload: dict = Body(...)):

    owner_userid = request.headers.get("x-user-id") or payload.get("owner_userid") or payload.get("userid")
    if not owner_userid:
        raise HTTPException(status_code=401, detail="Missing owner userid")

    # normalize exactly like frontend sends
    client_userid = (
        payload.get("userid")
        or payload.get("client_id")
        or payload.get("client_code")
    )

    if not client_userid:
        raise HTTPException(status_code=400, detail="Client userid required")

    client = {
        "broker": "motilal",
        "name": payload.get("name") or payload.get("display_name") or "",
        "userid": client_userid,
        "password": payload.get("password") or payload.get("creds", {}).get("password", ""),
        "pan": payload.get("pan") or payload.get("creds", {}).get("pan", ""),
        "apikey": payload.get("apikey") or payload.get("creds", {}).get("apikey", ""),
        "totpkey": payload.get("totpkey") or payload.get("creds", {}).get("totpkey", ""),
        "capital": payload.get("capital", ""),
        "session_active": False,
        "last_login_ts": 0,
        "last_login_msg": "Not logged in"
    }

    path = f"data/users/{owner_userid}/clients/{client_userid}.json"

    print(f"Saving client -> {path}")

    gh_put_json(path, client, message=f"add client {owner_userid}:{client_userid}")

    # LOGIN using YOUR existing function
    print(f"Login start -> {client_userid}")

    ok = motilal_login(client)

    client["session_active"] = ok
    client["last_login_ts"] = int(time.time())
    client["last_login_msg"] = "Login successful" if ok else "Login failed"

    gh_put_json(path, client, message=f"update login status {owner_userid}:{client_userid}")

    print(f"Login done -> {client_userid} success={ok}")

    return {"success": True}

@app.post("/edit_client")
async def edit_client(request: Request, payload: dict = Body(...)):

    owner_userid = request.headers.get("x-user-id") or payload.get("owner_userid")
    client_userid = payload.get("userid") or payload.get("client_id")

    path = f"data/users/{owner_userid}/clients/{client_userid}.json"

    client = gh_get_json(path)

    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    client["name"] = payload.get("name", client.get("name"))
    client["password"] = payload.get("password", client.get("password"))
    client["pan"] = payload.get("pan", client.get("pan"))
    client["apikey"] = payload.get("apikey", client.get("apikey"))
    client["totpkey"] = payload.get("totpkey", client.get("totpkey"))
    client["capital"] = payload.get("capital", client.get("capital"))

    gh_put_json(path, client, message="edit client")

    ok = motilal_login(client)

    client["session_active"] = ok
    client["last_login_ts"] = int(time.time())
    client["last_login_msg"] = "Login successful" if ok else "Login failed"

    gh_put_json(path, client, message="update login")

    return {"success": True}

@app.get("/clients")
def get_clients(request: Request, userid: str = None):

    userid = request.headers.get("x-user-id") or userid
    folder = f"data/users/{userid}/clients"

    clients = []

    try:
        files = gh_list_dir(folder)

        for f in files:

            if f.get("type") != "file":
                continue

            if not f.get("name", "").endswith(".json"):
                continue

            client, sha = gh_get_json(f["path"])   # ← only difference from local

            clients.append({
                "name": client.get("name", ""),
                "client_id": client.get("userid", ""),
                "capital": client.get("capital", ""),
                "session": "Logged in" if client.get("session_active") else "Logged out"
            })

    except Exception as e:
        print("Error loading clients:", e)

    return {"clients": clients}
