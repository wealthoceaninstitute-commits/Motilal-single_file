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

        totp = pyotp.TOTP(totpkey).now()

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

# ===========================================
# Clients Routes (GitHub storage) + Login now
# ===========================================

# Uses your existing: motilal_login_one_client(client, client_path=..., userid_owner=...)
# Uses your existing GitHub helpers:
#   - gh_get_json(path) -> dict | None
#   - gh_put_json(path, obj, message="...") -> None
#   - gh_list_dir(path) -> list[dict]  (GitHub "contents" entries) OR list[str]
#   - gh_delete_file(path, message="...") -> None

# -------------------------
# path builders (NO schema change)
# -------------------------
def user_clients_dir(owner_userid: str) -> str:
    owner_userid = (owner_userid or "").strip()
    return f"data/users/{owner_userid}/clients"

def user_client_path(owner_userid: str, client_userid: str) -> str:
    owner_userid = (owner_userid or "").strip()
    client_userid = (client_userid or "").strip()
    return f"{user_clients_dir(owner_userid)}/{client_userid}.json"

def ensure_clients_folder(owner_userid: str) -> None:
    """
    GitHub doesn't store empty folders.
    We keep a .keep file so the folder exists uniformly like your register flow.
    Safe to call repeatedly.
    """
    keep_path = f"{user_clients_dir(owner_userid)}/.keep"
    try:
        existing = gh_get_json(keep_path)
        if isinstance(existing, dict) and existing.get("ok") == True:
            return
    except Exception:
        pass

    try:
        gh_put_json(
            keep_path,
            {"ok": True, "ts": int(time.time())},
            message=f"ensure clients folder {owner_userid}",
        )
        print(f"📁 ensured folder: {user_clients_dir(owner_userid)}")
    except Exception as e:
        # Not fatal (client save may still create the folder implicitly)
        print(f"⚠️ ensure_clients_folder failed: {e}")

# -------------------------
# Resolve logged-in owner userid (uniform)
# -------------------------
def resolve_owner_userid(request: Request, user: Optional[dict] = None) -> str:
    """
    Prefer JWT identity if you have it (user dict).
    Else fallback to x-user-id header.
    Else fallback to query params (userid/user_id).
    """
    # 1) from auth dependency
    if isinstance(user, dict):
        for k in ("userid", "user_id", "sub", "username"):
            v = user.get(k)
            if v:
                return str(v).strip()

    # 2) headers
    hdr = request.headers.get("x-user-id") or request.headers.get("X-User-Id")
    if hdr:
        return str(hdr).strip()

    # 3) query
    qp = request.query_params.get("userid") or request.query_params.get("user_id")
    if qp:
        return str(qp).strip()

    return ""

# -------------------------
# Normalize frontend payload into flat client JSON (NO schema change)
# -------------------------
def _pick_str(d: dict, *keys: str) -> str:
    for k in keys:
        v = d.get(k)
        if v is None:
            continue
        s = str(v).strip()
        if s != "":
            return s
    return ""

def normalize_motilal_client_payload(payload: dict) -> Dict[str, Any]:
    """
    Frontend can send:
      - flat: {name, userid, password, pan, apikey, totpkey, capital, broker}
      - OR wrapper: {client_id/userid, display_name/name, creds:{password,pan,apikey,totpkey}, capital, broker}
      - and it may send BOTH (your current Clients.jsx does)
    We convert into flat CT_FastAPI style (NO schema change).
    """
    payload = payload or {}
    creds = payload.get("creds") if isinstance(payload.get("creds"), dict) else {}

    name = _pick_str(payload, "name", "display_name")
    userid = _pick_str(payload, "userid", "client_id", "client_code")  # Motilal client user id
    password = _pick_str(payload, "password") or _pick_str(creds, "password")
    pan = _pick_str(payload, "pan") or _pick_str(creds, "pan")
    apikey = _pick_str(payload, "apikey") or _pick_str(creds, "apikey")
    totpkey = _pick_str(payload, "totpkey", "totp") or _pick_str(creds, "totpkey", "totp")

    # capital optional
    capital = payload.get("capital", "")

    out = {
        "broker": _pick_str(payload, "broker") or "motilal",
        "name": name,
        "userid": userid,
        "password": password,
        "pan": pan,
        "apikey": apikey,
        "totpkey": totpkey,
        "capital": capital,
    }

    # keep any extra fields (but do NOT nest schema changes)
    # (optional: include only if you want to preserve UI fields)
    for k, v in payload.items():
        if k in out or k == "creds":
            continue
        out[k] = v

    return out

# -------------------------
# Helper: list all clients from GitHub folder
# -------------------------
def list_user_clients(owner_userid: str) -> List[Dict[str, Any]]:
    folder = user_clients_dir(owner_userid)
    entries = []
    try:
        entries = gh_list_dir(folder) or []
    except Exception as e:
        print(f"⚠️ gh_list_dir({folder}) failed: {e}")
        return []

    files: List[str] = []

    # Support both: list[str] or list[dict] (GitHub contents items)
    for it in entries:
        if isinstance(it, str):
            if it.endswith(".json") and not it.endswith("/.keep"):
                files.append(f"{folder}/{it.split('/')[-1]}")
        elif isinstance(it, dict):
            name = (it.get("name") or "").strip()
            if name.endswith(".json") and name != ".keep":
                files.append(f"{folder}/{name}")

    clients: List[Dict[str, Any]] = []
    for path in files:
        try:
            c = gh_get_json(path)
            if isinstance(c, dict) and c.get("userid"):
                clients.append(c)
        except Exception as e:
            print(f"⚠️ read client failed {path}: {e}")
            continue

    return clients

# ==========================================================
# ROUTES (KEEP EXACT PATHS)
# ==========================================================

# NOTE: replace get_current_user with YOUR dependency if you already have one.
# If you don't have a dependency, you can set user: dict = None and it still works via x-user-id.
try:
    get_current_user  # type: ignore
except NameError:
    get_current_user = None  # fallback

def _dep_user():
    if get_current_user:
        return Depends(get_current_user)  # type: ignore
    return None

@app.post("/add_client")
async def add_client(request: Request, payload: dict = Body(...), user: Optional[dict] = _dep_user()):
    owner_userid = resolve_owner_userid(request, user)
    if not owner_userid:
        raise HTTPException(status_code=401, detail="Missing logged-in user (token/x-user-id)")

    client = normalize_motilal_client_payload(payload)

    if not client.get("userid"):
        raise HTTPException(status_code=400, detail="Client userid/client_id required")
    if not client.get("password") or not client.get("apikey"):
        raise HTTPException(status_code=400, detail="password and apikey required")

    ensure_clients_folder(owner_userid)

    path = user_client_path(owner_userid, client["userid"])

    # Save first (so UI can see it immediately)
    now = int(time.time())
    client.setdefault("created_at", now)
    client["updated_at"] = now
    client.setdefault("session_active", False)
    client.setdefault("last_login_ts", 0)
    client.setdefault("last_login_msg", "Not logged in yet")

    print(f"🧾 [ADD_CLIENT] owner={owner_userid} saving={path} payload_keys={list(payload.keys())}")
    gh_put_json(path, client, message=f"add client {owner_userid}:{client['userid']}")

    # Now login immediately + persist login result into same file
    print(f"🔐 [ADD_CLIENT] login start owner={owner_userid} client={client['userid']}")
    login_status = motilal_login_one_client(client, client_path=path, userid_owner=owner_userid)
    print(f"🔐 [ADD_CLIENT] login done owner={owner_userid} client={client['userid']} status={login_status}")

    return {
        "success": True,
        "message": "Client saved. Login attempted.",
        "login": login_status,
    }

@app.post("/edit_client")
async def edit_client(request: Request, payload: dict = Body(...), user: Optional[dict] = _dep_user()):
    owner_userid = resolve_owner_userid(request, user)
    if not owner_userid:
        raise HTTPException(status_code=401, detail="Missing logged-in user (token/x-user-id)")

    client = normalize_motilal_client_payload(payload)
    if not client.get("userid"):
        raise HTTPException(status_code=400, detail="Client userid/client_id required")

    path = user_client_path(owner_userid, client["userid"])

    # Merge with existing (preserve created_at if present)
    existing = {}
    try:
        existing = gh_get_json(path) or {}
    except Exception:
        existing = {}

    merged = dict(existing) if isinstance(existing, dict) else {}
    merged.update(client)
    merged["updated_at"] = int(time.time())
    merged.setdefault("created_at", int(time.time()))

    print(f"✏️ [EDIT_CLIENT] owner={owner_userid} saving={path}")
    gh_put_json(path, merged, message=f"edit client {owner_userid}:{client['userid']}")

    # Attempt re-login after edit (important if password/apikey/totp changed)
    print(f"🔐 [EDIT_CLIENT] login start owner={owner_userid} client={client['userid']}")
    login_status = motilal_login_one_client(merged, client_path=path, userid_owner=owner_userid)
    print(f"🔐 [EDIT_CLIENT] login done owner={owner_userid} client={client['userid']} status={login_status}")

    return {"success": True, "message": "Client updated. Login attempted.", "login": login_status}

@app.post("/delete_client")
async def delete_client(request: Request, payload: dict = Body(...), user: Optional[dict] = _dep_user()):
    owner_userid = resolve_owner_userid(request, user)
    if not owner_userid:
        raise HTTPException(status_code=401, detail="Missing logged-in user (token/x-user-id)")

    items = payload.get("items") or []
    if not isinstance(items, list) or not items:
        raise HTTPException(status_code=400, detail="items[] required")

    deleted = []
    errors = []

    for it in items:
        try:
            if not isinstance(it, dict):
                continue
            client_userid = (it.get("userid") or it.get("client_id") or "").strip()
            if not client_userid:
                continue

            path = user_client_path(owner_userid, client_userid)
            print(f"🗑️ [DELETE_CLIENT] owner={owner_userid} deleting={path}")
            gh_delete_file(path, message=f"delete client {owner_userid}:{client_userid}")
            deleted.append(client_userid)

            # clear in-memory session too (optional)
            try:
                mofsl_sessions.pop(client_userid, None)
            except Exception:
                pass

        except Exception as e:
            errors.append({"client": it, "error": str(e)})

    return {"success": True, "deleted": deleted, "errors": errors}

@app.get("/get_clients")
def get_clients(request: Request, userid: Optional[str] = None, user: Optional[dict] = _dep_user()):
    owner_userid = resolve_owner_userid(request, user) or (userid or "").strip()
    if not owner_userid:
        return {"clients": []}

    clients = list_user_clients(owner_userid)

    # shape for UI table (same style as CT_FastAPI)
    out = []
    for c in clients:
        out.append({
            "name": c.get("name", ""),
            "client_id": c.get("userid", ""),
            "userid": c.get("userid", ""),
            "capital": c.get("capital", ""),
            "session_active": bool(c.get("session_active")),
            "last_login_ts": c.get("last_login_ts", 0),
            "last_login_msg": c.get("last_login_msg", ""),
            "session": "Logged in" if c.get("session_active") else "Logged out",
        })

    return {"clients": out}

@app.get("/clients")
def clients_alias(request: Request, userid: Optional[str] = None, user: Optional[dict] = _dep_user()):
    # alias route since frontend tries /clients first
    return get_clients(request, userid=userid, user=user)

