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
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from MOFSLOPENAPI import MOFSLOPENAPI
import pyotp


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
    allow_origins = ["http://localhost:3000", "http://127.0.0.1:3000", "https://woi-mosl-trader.vercel.app"]
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
                "login_ts": int(time.time()),
                "owner_userid": client.get("owner_userid", "")  # ✅ REQUIRED for /get_orders filter
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
def get_clients(request: Request, userid: str = None, user_id: str = None):
    # 1) pick userid from header or query
    uid = request.headers.get("x-user-id") or userid or user_id or request.query_params.get("userid") or request.query_params.get("user_id") or ""
    uid = str(uid).strip()

    # 2) handle %22pra%22 and "pra"
    if (uid.startswith('"') and uid.endswith('"')) or (uid.startswith("'") and uid.endswith("'")):
        uid = uid[1:-1].strip()

    if not uid:
        return {"clients": []}

    folder = f"data/users/{uid}/clients"
    clients = []

    try:
        entries = gh_list_dir(folder)  # list of dicts from GitHub API

        for ent in entries:
            if not isinstance(ent, dict):
                continue
            if ent.get("type") != "file":
                continue
            if not (ent.get("name", "").endswith(".json") and ent.get("path")):
                continue

            try:
                client_obj, _sha = gh_get_json(ent["path"])  # returns (dict, sha)
                if not isinstance(client_obj, dict):
                    continue

                # -------------------------
                # REQUIRED CHANGE START ✅
                # -------------------------
                # Tag the client with the owner, so sessions are per-user
                client_obj["owner_userid"] = uid

                # Attempt login (same behavior as CT_FastAPI desktop flow)
                # This populates mofsl_sessions[client_id] in memory if login succeeds
                try:
                    motilal_login(client_obj)
                except Exception as login_err:
                    print(f"Login attempt failed for client {client_obj.get('userid') or client_obj.get('client_id')}: {login_err}")

                # Determine session based on ACTUAL in-memory session (not stale GitHub json)
                client_id = str(client_obj.get("userid", client_obj.get("client_id", "")) or "").strip()
                sess = mofsl_sessions.get(client_id) if client_id else None
                sa = bool(sess and sess.get("owner_userid") == uid and sess.get("mofsl"))
                # -------------------------
                # REQUIRED CHANGE END ✅
                # -------------------------

                clients.append({
                    "name": client_obj.get("name", ""),
                    "client_id": client_id,
                    "capital": client_obj.get("capital", ""),
                    "session": "Logged in" if sa else "Logged out",   # keep old
                    "session_active": sa,                              # UI needs this
                    "status": "logged_in" if sa else "logged_out",     # optional
                })

            except Exception as per_file_err:
                print(f"Error reading client file {ent.get('path')}: {per_file_err}")

    except Exception as e:
        print("Error loading clients:", e)

    return {"clients": clients}
# ============================================================
# SYMBOL SEARCH (SQLite DB creation + typeahead endpoint)
# ============================================================

import os
import sqlite3
import threading
import requests
import pandas as pd
from fastapi import Query

# --- Source CSV (your repo) ---
GITHUB_CSV_URL = "https://raw.githubusercontent.com/Pramod541988/Stock_List/main/security_id.csv"

# --- DB config ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SYMBOL_DB_PATH = os.path.join(BASE_DIR, "symbols.db")
SYMBOL_TABLE = "symbols"
_symbol_db_lock = threading.Lock()

def _ensure_dirs():
    os.makedirs(BASE_DIR, exist_ok=True)

def _symbol_db_exists() -> bool:
    return os.path.exists(SYMBOL_DB_PATH)

def refresh_symbol_db_from_github() -> str:
    """
    Download CSV and rebuild SQLite table 'symbols'.
    Keeps dtype=str to avoid float artifacts like 10666.0
    Adds indexes for faster searching.
    """
    _ensure_dirs()

    r = requests.get(GITHUB_CSV_URL, timeout=30)
    r.raise_for_status()

    csv_path = os.path.join(BASE_DIR, "security_id.csv")
    with open(csv_path, "wb") as f:
        f.write(r.content)

    # Keep everything as string to avoid .0 issues
    df = pd.read_csv(csv_path, dtype=str).fillna("")

    # Optional: strip trailing ".0" on ID-like columns if present
    for col in ("Security ID", "Min qty", "Min Qty", "MIN QTY", "MIN_QTY"):
        if col in df.columns:
            df[col] = df[col].astype(str).str.replace(r"\.0$", "", regex=True).str.strip()

    with _symbol_db_lock:
        conn = sqlite3.connect(SYMBOL_DB_PATH)
        try:
            df.to_sql(SYMBOL_TABLE, conn, index=False, if_exists="replace")

            # Indexes (safe if columns exist)
            try:
                conn.execute(f'CREATE INDEX IF NOT EXISTS idx_sym_symbol ON {SYMBOL_TABLE} ("Stock Symbol");')
            except Exception:
                pass
            try:
                conn.execute(f'CREATE INDEX IF NOT EXISTS idx_sym_exchange ON {SYMBOL_TABLE} (Exchange);')
            except Exception:
                pass
            try:
                conn.execute(f'CREATE INDEX IF NOT EXISTS idx_sym_secid ON {SYMBOL_TABLE} ("Security ID");')
            except Exception:
                pass

            conn.commit()
        finally:
            conn.close()

    print("✅ Symbol DB refreshed:", SYMBOL_DB_PATH)
    return "success"

def _lazy_init_symbol_db():
    """Build the DB once if it does not exist."""
    if not _symbol_db_exists():
        try:
            print("ℹ️ Symbol DB not found. Building from GitHub CSV...")
            refresh_symbol_db_from_github()
        except Exception as e:
            print("❌ Symbol DB init failed:", e)

@app.post("/refresh_symbols")
def refresh_symbols():
    """Force refresh the symbol master from GitHub into SQLite."""
    try:
        msg = refresh_symbol_db_from_github()
        return {"status": msg}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/search_symbols")
def search_symbols(q: str = Query(""), exchange: str = Query("")):
    """
    Typeahead search with ranking:
      0 = exact match
      1 = startswith
      2 = contains
    Returns:
      {"results":[{"id":"EX|SYMBOL|SECID","text":"EX | SYMBOL"}]}
    """
    _lazy_init_symbol_db()

    raw = (q or "").strip().lower()
    exch = (exchange or "").strip().upper()

    if not raw:
        return {"results": []}

    words = [w for w in raw.split() if w]
    if not words:
        return {"results": []}

    where_sql, where_params = [], []
    for w in words:
        where_sql.append('LOWER([Stock Symbol]) LIKE ?')
        where_params.append(f"%{w}%")

    if exch:
        where_sql.append('UPPER(Exchange) = ?')
        where_params.append(exch)

    # Ranking based on full query
    rank_params = [raw, f"{raw}%", f"%{raw}%"]

    sql = f"""
        SELECT
            Exchange,
            [Stock Symbol],
            [Security ID],
            CASE
                WHEN LOWER([Stock Symbol]) = ?     THEN 0
                WHEN LOWER([Stock Symbol]) LIKE ?  THEN 1
                WHEN LOWER([Stock Symbol]) LIKE ?  THEN 2
                ELSE 3
            END AS rank_score
        FROM {SYMBOL_TABLE}
        WHERE {' AND '.join(where_sql)}
        ORDER BY rank_score, [Stock Symbol]
        LIMIT 200
    """

    with _symbol_db_lock:
        conn = sqlite3.connect(SYMBOL_DB_PATH)
        try:
            cur = conn.execute(sql, rank_params + where_params)
            rows = cur.fetchall()
        finally:
            conn.close()

    results = [{"id": f"{r[0]}|{r[1]}|{r[2]}", "text": f"{r[0]} | {r[1]}"} for r in rows]
    return {"results": results}

# Optional: build once on server start (recommended for Render)
@app.on_event("startup")
def _startup_init_symbols():
    _lazy_init_symbol_db()


# ==========================================================
# Groups + CopyTrading + Delete Client (GitHub storage)
# ==========================================================

def gh_delete_path(path: str, sha: str, message: str = "delete file") -> bool:
    if not gh_enabled():
        raise HTTPException(500, "GitHub storage not configured (set GITHUB_OWNER/GITHUB_REPO/GITHUB_TOKEN)")
    if not sha:
        # try fetch sha
        _, sha2 = gh_get_json(path)
        sha = sha2 or ""
    if not sha:
        return False
    payload = {"message": message, "sha": sha, "branch": GITHUB_BRANCH}
    r = requests.delete(gh_url(path), headers=gh_headers(), json=payload)
    if r.status_code == 404:
        return False
    r.raise_for_status()
    return True

def resolve_owner_userid(request: Request, userid: Optional[str] = None, user_id: Optional[str] = None) -> str:
    # Prefer Bearer token userid (if present), then x-user-id header, then query/body params.
    token_user = ""
    try:
        auth = request.headers.get("authorization") or request.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
            payload = jwt_decode(token, SECRET_KEY)
            token_user = payload.get("userid") or ""
    except Exception:
        token_user = ""

    uid = (
        token_user
        or request.headers.get("x-user-id")
        or request.query_params.get("userid")
        or request.query_params.get("user_id")
        or userid
        or user_id
    )
    return normalize_userid(uid or "")

    uid = (
        token_user
        or request.headers.get("x-user-id")
        or request.query_params.get("userid")
        or request.query_params.get("user_id")
        or userid
        or user_id
    )
    return normalize_userid(uid or "")

def user_groups_dir(owner_userid: str) -> str:
    return f"data/users/{owner_userid}/groups"

def user_group_file(owner_userid: str, group_id_or_name: str) -> str:
    gid = _safe_filename(group_id_or_name or "group")
    return f"{user_groups_dir(owner_userid)}/{gid}.json"

def user_copy_dir(owner_userid: str) -> str:
    return f"data/users/{owner_userid}/copytrading"

def user_copy_file(owner_userid: str, setup_id_or_name: str) -> str:
    sid = _safe_filename(setup_id_or_name or "setup")
    return f"{user_copy_dir(owner_userid)}/{sid}.json"


@app.post("/delete_client")
async def delete_client(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(request, userid=payload.get("userid") or payload.get("owner_userid"))
    if not owner_userid:
        raise HTTPException(status_code=401, detail="Missing owner userid")

    items = payload.get("items") or []
    deleted = []
    missing = []
    errors = []

    for it in items:
        try:
            client_userid = (it or {}).get("userid") or (it or {}).get("client_id") or ""
            client_userid = str(client_userid).strip()
            if not client_userid:
                continue
            path = f"data/users/{owner_userid}/clients/{client_userid}.json"
            _obj, sha = gh_get_json(path)
            if not sha:
                missing.append(client_userid)
                continue
            ok = gh_delete_path(path, sha, message=f"delete client {owner_userid}:{client_userid}")
            (deleted if ok else missing).append(client_userid)
        except Exception as e:
            errors.append(str(e))

    return {"ok": True, "deleted": deleted, "missing": missing, "errors": errors}


@app.get("/groups")
async def get_groups(request: Request, userid: str = None, user_id: str = None):
    owner_userid = resolve_owner_userid(request, userid=userid, user_id=user_id)
    if not owner_userid:
        return {"groups": []}

    folder = user_groups_dir(owner_userid)
    groups = []
    try:
        entries = gh_list_dir(folder)
        for ent in entries:
            if not isinstance(ent, dict) or ent.get("type") != "file":
                continue
            name = ent.get("name", "")
            path = ent.get("path", "")
            if not name.endswith(".json") or not path:
                continue
            obj, _sha = gh_get_json(path)
            if isinstance(obj, dict) and obj:
                # ensure required fields
                gid = obj.get("id") or name.replace(".json", "")
                groups.append({
                    "id": gid,
                    "name": obj.get("name", gid),
                    "multiplier": obj.get("multiplier", 1),
                    "members": obj.get("members", []),
                })
    except Exception:
        groups = []

    return {"groups": groups}


@app.post("/add_group")
async def add_group(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(request, userid=payload.get("userid") or payload.get("owner_userid"))
    if not owner_userid:
        raise HTTPException(status_code=401, detail="Missing owner userid")

    name = (payload.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Group name required")
    members = payload.get("members") or []
    if not isinstance(members, list) or len(members) == 0:
        raise HTTPException(status_code=400, detail="Group members required")
    try:
        multiplier = float(payload.get("multiplier", 1) or 1)
    except Exception:
        multiplier = 1.0
    if multiplier <= 0:
        multiplier = 1.0

    gid = (payload.get("id") or name).strip()
    obj = {
        "id": gid,
        "name": name,
        "multiplier": multiplier,
        "members": members,
        "created_at": utcnow_iso(),
        "updated_at": utcnow_iso(),
    }
    path = user_group_file(owner_userid, gid)
    gh_put_json(path, obj, message=f"add group {owner_userid}:{gid}")
    return {"ok": True, "group": obj}


@app.post("/edit_group")
async def edit_group(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(request, userid=payload.get("userid") or payload.get("owner_userid"))
    if not owner_userid:
        raise HTTPException(status_code=401, detail="Missing owner userid")

    gid = (payload.get("id") or payload.get("name") or "").strip()
    if not gid:
        raise HTTPException(status_code=400, detail="Group id/name required")

    name = (payload.get("name") or gid).strip()
    members = payload.get("members") or []
    try:
        multiplier = float(payload.get("multiplier", 1) or 1)
    except Exception:
        multiplier = 1.0
    if multiplier <= 0:
        multiplier = 1.0

    path = user_group_file(owner_userid, gid)
    prev, _sha = gh_get_json(path)
    if not isinstance(prev, dict):
        prev = {}

    obj = {
        "id": prev.get("id") or gid,
        "name": name,
        "multiplier": multiplier,
        "members": members,
        "created_at": prev.get("created_at") or utcnow_iso(),
        "updated_at": utcnow_iso(),
    }
    gh_put_json(path, obj, message=f"edit group {owner_userid}:{gid}")
    return {"ok": True, "group": obj}


@app.post("/delete_group")
async def delete_group(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(request, userid=payload.get("userid") or payload.get("owner_userid"))
    if not owner_userid:
        raise HTTPException(status_code=401, detail="Missing owner userid")

    ids = payload.get("ids") or payload.get("names") or payload.get("groups") or []
    if not isinstance(ids, list):
        ids = [ids]

    deleted, missing, errors = [], [], []
    for gid in ids:
        try:
            gid = str(gid).strip()
            if not gid:
                continue
            path = user_group_file(owner_userid, gid)
            _obj, sha = gh_get_json(path)
            if not sha:
                # try by name without safe transforms in case ids are already safe
                missing.append(gid)
                continue
            ok = gh_delete_path(path, sha, message=f"delete group {owner_userid}:{gid}")
            (deleted if ok else missing).append(gid)
        except Exception as e:
            errors.append(str(e))

    return {"ok": True, "deleted": deleted, "missing": missing, "errors": errors}


# ---------------- Copy Trading ----------------

@app.get("/list_copytrading_setups")
async def list_copytrading_setups(request: Request, userid: str = None, user_id: str = None):
    owner_userid = resolve_owner_userid(request, userid=userid, user_id=user_id)
    if not owner_userid:
        return {"setups": []}

    folder = user_copy_dir(owner_userid)
    setups = []
    try:
        entries = gh_list_dir(folder)
        for ent in entries:
            if not isinstance(ent, dict) or ent.get("type") != "file":
                continue
            name = ent.get("name", "")
            path = ent.get("path", "")
            if not name.endswith(".json") or not path:
                continue
            obj, _sha = gh_get_json(path)
            if not isinstance(obj, dict) or not obj:
                continue
            sid = obj.get("id") or obj.get("name") or name.replace(".json", "")
            setups.append({
                "id": sid,
                "name": obj.get("name", sid),
                "master": obj.get("master", obj.get("master_account", "")),
                "children": obj.get("children", obj.get("child_accounts", [])) or [],
                "multipliers": obj.get("multipliers", {}) or {},
                "enabled": bool(obj.get("enabled", False)),
            })
    except Exception:
        setups = []

    return {"setups": setups}


@app.post("/save_copytrading_setup")
async def save_copytrading_setup(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(request, userid=payload.get("userid") or payload.get("owner_userid"))
    if not owner_userid:
        raise HTTPException(status_code=401, detail="Missing owner userid")

    name = (payload.get("name") or payload.get("setup_name") or "").strip()
    sid = (payload.get("id") or name).strip()
    if not sid:
        raise HTTPException(status_code=400, detail="Setup name required")

    master = (payload.get("master") or payload.get("master_account") or "").strip()
    children = payload.get("children") or payload.get("child_accounts") or []
    multipliers = payload.get("multipliers") or {}

    if not master or not isinstance(children, list) or len(children) == 0:
        raise HTTPException(status_code=400, detail="Master + at least one child required")

    path = user_copy_file(owner_userid, sid)
    prev, _sha = gh_get_json(path)
    if not isinstance(prev, dict):
        prev = {}

    enabled = payload.get("enabled")
    if enabled is None:
        enabled = prev.get("enabled", False)

    obj = {
        "id": sid,
        "name": name or sid,
        "master": master,
        "children": children,
        "multipliers": multipliers if isinstance(multipliers, dict) else {},
        "enabled": bool(enabled),
        "created_at": prev.get("created_at") or utcnow_iso(),
        "updated_at": utcnow_iso(),
    }
    gh_put_json(path, obj, message=f"save copy setup {owner_userid}:{sid}")
    return {"ok": True, "setup": obj}


@app.post("/enable_copy")
async def enable_copy(request: Request, payload: dict = Body(...)):
    return await _set_copy_enabled(request, payload, True)


@app.post("/disable_copy")
async def disable_copy(request: Request, payload: dict = Body(...)):
    return await _set_copy_enabled(request, payload, False)


async def _set_copy_enabled(request: Request, payload: dict, value: bool):
    owner_userid = resolve_owner_userid(request, userid=payload.get("userid") or payload.get("owner_userid"))
    if not owner_userid:
        raise HTTPException(status_code=401, detail="Missing owner userid")
    ids = payload.get("ids") or []
    if not isinstance(ids, list):
        ids = [ids]
    # Backward/forward compatibility: accept single 'id'/'setup_id'/'name'
    if not ids:
        one = payload.get("id") or payload.get("setup_id") or payload.get("name")
        if one:
            ids = [one]
    updated, missing, errors = [], [], []
    for sid in ids:
        try:
            sid = str(sid).strip()
            if not sid:
                continue
            path = user_copy_file(owner_userid, sid)
            obj, _sha = gh_get_json(path)
            if not isinstance(obj, dict) or not obj:
                missing.append(sid)
                continue
            obj["enabled"] = bool(value)
            obj["updated_at"] = utcnow_iso()
            gh_put_json(path, obj, message=f"{'enable' if value else 'disable'} copy {owner_userid}:{sid}")
            updated.append(sid)
        except Exception as e:
            errors.append(str(e))
    return {"ok": True, "updated": updated, "missing": missing, "errors": errors}


@app.post("/delete_copy_setup")
async def delete_copy_setup(request: Request, payload: dict = Body(...)):
    return await _delete_copy_setup(request, payload)


@app.post("/delete_copytrading_setup")
async def delete_copytrading_setup(request: Request, payload: dict = Body(...)):
    # compatibility alias
    return await _delete_copy_setup(request, payload)


async def _delete_copy_setup(request: Request, payload: dict):
    owner_userid = resolve_owner_userid(request, userid=payload.get("userid") or payload.get("owner_userid"))
    if not owner_userid:
        raise HTTPException(status_code=401, detail="Missing owner userid")
    ids = payload.get("ids") or []
    if not isinstance(ids, list):
        ids = [ids]
    # Backward/forward compatibility: accept single 'id'/'setup_id'/'name'
    if not ids:
        one = payload.get("id") or payload.get("setup_id") or payload.get("name")
        if one:
            ids = [one]
    deleted, missing, errors = [], [], []
    for sid in ids:
        try:
            sid = str(sid).strip()
            if not sid:
                continue
            path = user_copy_file(owner_userid, sid)
            _obj, sha = gh_get_json(path)
            if not sha:
                missing.append(sid)
                continue
            ok = gh_delete_path(path, sha, message=f"delete copy setup {owner_userid}:{sid}")
            (deleted if ok else missing).append(sid)
        except Exception as e:
            errors.append(str(e))
    return {"ok": True, "deleted": deleted, "missing": missing, "errors": errors}


# =========================
# Orders (same logic as CT_FastAPI, only per-user client filtering differs)
# =========================
from collections import OrderedDict
@app.get("/get_orders")
def get_orders(request: Request, userid: str = None, user_id: str = None):
    owner_userid = resolve_owner_userid(request, userid=userid, user_id=user_id)

    orders_data = OrderedDict({
        "pending": [],
        "traded": [],
        "rejected": [],
        "cancelled": [],
        "others": []
    })

    # ✅ sessions are stored as dicts in motilal_login()
    for client_id, sess in mofsl_sessions.items():
        try:
            if not isinstance(sess, dict):
                continue

            # multi-user filter
            if owner_userid and str(sess.get("owner_userid", "")).strip() != str(owner_userid).strip():
                continue

            name = sess.get("name", "") or client_id
            mofsl = sess.get("mofsl")
            client_userid = sess.get("userid", client_id)

            if not mofsl or not client_userid:
                continue

            today_date = datetime.now().strftime("%d-%b-%Y 09:00:00")
            order_book_info = {"clientcode": client_userid, "datetimestamp": today_date}

            response = mofsl.GetOrderBook(order_book_info)
            if response and response.get("status") != "SUCCESS":
                logging.error(f"❌ Error fetching orders for {name}: {response.get('message', 'No message')}")

            orders = response.get("data", []) if response else []
            if not isinstance(orders, list):
                orders = []

            for order in orders:
                order_data = {
                    "name": name,
                    "client_id": client_userid,
                    "symbol": order.get("symbol", ""),
                    "transaction_type": order.get("buyorsell", ""),
                    "quantity": order.get("orderqty", ""),
                    "price": order.get("price", ""),
                    "status": order.get("orderstatus", ""),
                    "order_id": order.get("uniqueorderid", "")
                }

                status = (order.get("orderstatus", "") or "").lower()
                if "confirm" in status:
                    orders_data["pending"].append(order_data)
                elif "traded" in status:
                    orders_data["traded"].append(order_data)
                elif "rejected" in status or "error" in status:
                    orders_data["rejected"].append(order_data)
                elif "cancel" in status:
                    orders_data["cancelled"].append(order_data)
                else:
                    orders_data["others"].append(order_data)

        except Exception as e:
            print(f"❌ Error fetching orders for {client_id}: {e}")

    return dict(orders_data)


@app.post("/cancel_order")
async def cancel_order(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(request, userid=payload.get("userid") or payload.get("user_id"))

    orders = (payload or {}).get("orders", [])
    if not orders:
        raise HTTPException(status_code=400, detail="❌ No orders received for cancellation.")

    response_messages = []
    threads = []
    thread_lock = threading.Lock()

    def find_session_for_order(order: dict):
        # CT_FastAPI expects name-based lookup; our sessions are keyed by client_id.
        name = (order or {}).get("name") or ""
        client_id = (order or {}).get("client_id") or (order or {}).get("userid") or ""
        if client_id:
            sess = mofsl_sessions.get(client_id)
            if sess and sess.get("owner_userid", "") == owner_userid:
                return sess
        if name:
            for sess in mofsl_sessions.values():
                if sess.get("owner_userid", "") == owner_userid and sess.get("name") == name:
                    return sess
        return None

    def cancel_single_order(order):
        name = order.get("name") or order.get("client_id") or ""
        order_id = order.get("order_id")

        if not name or not order_id:
            with thread_lock:
                response_messages.append(f"❌ Missing data in order: {order}")
            return

        session = find_session_for_order(order)
        if not session:
            with thread_lock:
                response_messages.append(f"❌ Session not found for: {name}")
            return

        Mofsl = session.get("mofsl")
        client_userid = session.get("userid")

        try:
            cancel_response = Mofsl.CancelOrder(order_id, client_userid)
            message = (cancel_response.get("message", "") or "").lower()
            with thread_lock:
                if "cancel order request sent" in message:
                    response_messages.append(f"✅ Cancelled Order {order_id} for {session.get('name') or client_userid}")
                else:
                    response_messages.append(
                        f"❌ Failed to cancel Order {order_id} for {session.get('name') or client_userid}: {cancel_response.get('message', '')}"
                    )
        except Exception as e:
            with thread_lock:
                response_messages.append(f"❌ Error cancelling {order_id} for {session.get('name') or client_userid}: {str(e)}")

    for order in orders:
        t = threading.Thread(target=cancel_single_order, args=(order,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    return {"message": response_messages}

#/////////////////////////////////////////////////////////////
#               POSITION
#////////////////////////////////////////////////////////////

@app.get("/get_positions")
def get_positions(request: Request, userid: str = None, user_id: str = None):
    owner_userid = resolve_owner_userid(request, userid=userid, user_id=user_id)

    positions_data = {"open": [], "closed": []}

    # Ensure global meta exists (safe for Render multi-worker)
    global position_meta
    if "position_meta" not in globals():
        position_meta = {}
    else:
        position_meta.clear()

    # Iterate sessions exactly like orders
    for client_id, sess in list(mofsl_sessions.items()):
        try:
            if not isinstance(sess, dict):
                continue

            # Filter per logged-in user
            if owner_userid and str(sess.get("owner_userid", "")).strip() != str(owner_userid).strip():
                continue

            name = str(sess.get("name", "") or client_id)
            mofsl = sess.get("mofsl")
            client_userid = str(sess.get("userid", client_id))

            if not mofsl or not client_userid:
                continue

            response = mofsl.GetPosition()

            if not response or response.get("status") != "SUCCESS":
                continue

            positions = response.get("data") or []

            if not isinstance(positions, list):
                continue

            for pos in positions:

                buy_qty = float(pos.get("buyquantity") or 0)
                sell_qty = float(pos.get("sellquantity") or 0)
                quantity = buy_qty - sell_qty

                booked_profit = float(pos.get("bookedprofitloss") or 0)

                buy_amt = float(pos.get("buyamount") or 0)
                sell_amt = float(pos.get("sellamount") or 0)

                buy_avg = (buy_amt / buy_qty) if buy_qty else 0.0
                sell_avg = (sell_amt / sell_qty) if sell_qty else 0.0

                ltp = float(pos.get("LTP") or 0)

                if quantity > 0:
                    net_profit = (ltp - buy_avg) * quantity
                elif quantity < 0:
                    net_profit = (sell_avg - buy_avg) * abs(quantity)
                else:
                    net_profit = booked_profit

                # SAFE string conversion (prevents strip() crash)
                symbol = str(pos.get("symbol") or "")
                exchange = str(pos.get("exchange") or "")
                symboltoken = str(pos.get("symboltoken") or "")
                producttype = str(pos.get("productname") or "")

                # Save meta for close position
                if quantity != 0 and symbol:
                    position_meta[(client_userid, symbol)] = {
                        "exchange": exchange,
                        "symboltoken": symboltoken,
                        "producttype": producttype,
                        "client_id": client_userid
                    }

                row = {
                    "name": name,
                    "client_id": client_userid,
                    "symbol": symbol,
                    "quantity": quantity,
                    "buy_avg": round(buy_avg, 2),
                    "sell_avg": round(sell_avg, 2),
                    "net_profit": round(net_profit, 2)
                }

                if quantity == 0:
                    positions_data["closed"].append(row)
                else:
                    positions_data["open"].append(row)

        except Exception as e:
            print(f"❌ Error fetching positions for {client_id}: {e}")

    return positions_data

@app.post("/close_position")
async def close_position(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(request, userid=payload.get("userid") or payload.get("user_id"))

    positions = (payload or {}).get("positions", [])
    messages = []
    threads = []
    thread_lock = threading.Lock()

    # Load min qty map once from symbols DB
    min_qty_map = {}
    try:
        conn = sqlite3.connect(SYMBOL_DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute(f"SELECT [Security ID], [Min Qty] FROM {SYMBOL_TABLE}")
            for sid, qty in cursor.fetchall():
                if sid:
                    try:
                        min_qty_map[str(sid)] = int(qty) if qty else 1
                    except Exception:
                        min_qty_map[str(sid)] = 1
        finally:
            conn.close()
    except Exception as e:
        print(f"❌ Error reading min_qty from DB: {e}")

    def find_session_by_name_and_owner(name: str, client_id_hint: str = ""):
        # Prefer explicit client_id if provided
        if client_id_hint:
            sess = mofsl_sessions.get(client_id_hint)
            if isinstance(sess, dict) and (not owner_userid or str(sess.get("owner_userid","")).strip() == str(owner_userid).strip()):
                return client_id_hint, sess

        # Fallback: search by display name
        for cid, sess in mofsl_sessions.items():
            if not isinstance(sess, dict):
                continue
            if owner_userid and str(sess.get("owner_userid", "")).strip() != str(owner_userid).strip():
                continue
            if (sess.get("name") or "").strip().lower() == (name or "").strip().lower():
                return cid, sess
        return "", None

    def close_single_position(pos):
        name = (pos or {}).get("name") or ""
        symbol = (pos or {}).get("symbol") or ""
        quantity = float((pos or {}).get("quantity", 0) or 0)
        transaction_type = (pos or {}).get("transaction_type") or ""

        meta = position_meta.get((name, symbol)) or {}
        client_id_hint = (pos or {}).get("client_id") or meta.get("client_id") or ""
        cid, sess = find_session_by_name_and_owner(name, client_id_hint=client_id_hint)

        if not meta or not sess:
            with thread_lock:
                messages.append(f"❌ Missing session/meta for {name} - {symbol}")
            return

        mofsl = sess.get("mofsl")
        userid_ = sess.get("userid") or cid
        if not mofsl or not userid_:
            with thread_lock:
                messages.append(f"❌ Invalid session for {name} - {symbol}")
            return

        symboltoken = meta.get("symboltoken")
        min_qty = min_qty_map.get(str(symboltoken), 1)
        lots = max(1, int(abs(quantity) // min_qty)) if min_qty and abs(quantity) >= min_qty else 1

        order = {
            "clientcode": userid_,
            "exchange": meta.get("exchange", ""),
            "symboltoken": symboltoken,
            "buyorsell": transaction_type.upper(),
            "ordertype": "MARKET",
            "producttype": meta.get("producttype", ""),
            "orderduration": "DAY",
            "price": 0,
            "triggerprice": 0,
            "quantityinlot": lots,
            "disclosedquantity": 0,
            "amoorder": "N",
            "algoid": "",
            "goodtilldate": "",
            "tag": ""
        }

        try:
            response = mofsl.PlaceOrder(order)
            if isinstance(response, dict) and response.get("status") == "SUCCESS":
                with thread_lock:
                    messages.append(f"✅ Close requested: {name} {symbol}")
            else:
                with thread_lock:
                    messages.append(f"❌ Close failed: {name} {symbol} - {((response or {}).get('message') if isinstance(response, dict) else response)}")
        except Exception as e:
            with thread_lock:
                messages.append(f"❌ Error closing {name} {symbol}: {str(e)}")

    for pos in positions:
        t = threading.Thread(target=close_single_position, args=(pos,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return {"message": messages}


# =========================
# HOLDINGS + SUMMARY (CT_FastAPI replica)
# =========================
# Copy exactly into motilal_trader (9).py by REPLACING your existing
# "HOLDINGS AND SUMMARY" section with this block.
#
# Logic source: CT_FastAPI.py (/get_holdings + /get_summary) :contentReference[oaicite:0]{index=0}

# cache last computed summary for /get_summary (same keyword)
summary_data_global = {}

def get_available_margin(Mofsl, clientcode):
    # CT_FastAPI keyword + logic :contentReference[oaicite:1]{index=1}
    try:
        margin_response = Mofsl.GetReportMarginSummary(clientcode)
        if margin_response.get("status") != "SUCCESS":
            return 0
        for item in margin_response.get("data", []):
            if item.get("particulars") == "Total Available Margin for Cash":
                return float(item.get("amount", 0))
    except Exception as e:
        print(f"❌ Error fetching margin for {clientcode}: {e}")
    return 0

@app.get("/get_holdings")
def get_holdings(request: Request, userid: str = None, user_id: str = None):
    owner_userid = resolve_owner_userid(request, userid=userid, user_id=user_id)

    holdings_data = []
    summary_data = {}

    # sessions are keyed by client_id, each session is a dict with mofsl + owner_userid
    for client_id, sess in list(mofsl_sessions.items()):
        try:
            if not isinstance(sess, dict):
                continue

            # per-user filter
            if owner_userid and str(sess.get("owner_userid", "")).strip() != str(owner_userid).strip():
                continue

            name = sess.get("name", "") or client_id
            Mofsl = sess.get("mofsl")
            userid_ = sess.get("userid") or client_id

            if not Mofsl or not userid_:
                continue

            response = Mofsl.GetDPHolding(userid_)
            if not response or response.get("status") != "SUCCESS":
                continue

            holdings = response.get("data", [])
            invested = 0.0
            total_pnl = 0.0

            for holding in holdings:
                symbol = (holding.get("scripname") or "").strip()
                quantity = float(holding.get("dpquantity", 0) or 0)
                buy_avg = float(holding.get("buyavgprice", 0) or 0)
                scripcode = holding.get("nsesymboltoken")

                if not scripcode or quantity <= 0:
                    continue

                ltp_request = {"clientcode": userid_, "exchange": "NSE", "scripcode": int(scripcode)}
                ltp_response = Mofsl.GetLtp(ltp_request)

                # CT_FastAPI divides by 100 :contentReference[oaicite:2]{index=2}
                ltp = float((ltp_response or {}).get("data", {}).get("ltp", 0) or 0) / 100

                pnl = round((ltp - buy_avg) * quantity, 2)
                invested += quantity * buy_avg
                total_pnl += pnl

                holdings_data.append({
                    "name": name,
                    "symbol": symbol,
                    "quantity": quantity,
                    "buy_avg": round(buy_avg, 2),
                    "ltp": round(ltp, 2),
                    "pnl": pnl
                })

            # capital same keyword (prefer session capital, else client_capital_map like desktop)
            capital = sess.get("capital", None)
            if capital is None:
                capital = (globals().get("client_capital_map", {}) or {}).get(name, 0)

            try:
                capital = float(capital)
            except Exception:
                capital = 0.0

            current_value = invested + total_pnl
            available_margin = get_available_margin(Mofsl, userid_)
            net_gain = round((current_value + available_margin) - capital, 2)

            summary_data[name] = {
                "name": name,
                "capital": round(capital, 2),
                "invested": round(invested, 2),
                "pnl": round(total_pnl, 2),
                "current_value": round(current_value, 2),
                "available_margin": round(available_margin, 2),
                "net_gain": net_gain
            }

        except Exception as e:
            print(f"❌ Error fetching holdings for {client_id}: {e}")

    global summary_data_global
    summary_data_global = summary_data

    # CT_FastAPI response shape :contentReference[oaicite:3]{index=3}
    return {"holdings": holdings_data, "summary": list(summary_data.values())}

@app.get("/get_summary")
def get_summary():
    global summary_data_global
    return {"summary": list((summary_data_global or {}).values())}


# ============================================================
# PLACE ORDER (multi-user, sessions keyed by client_id)
# ============================================================

import threading
import time
from datetime import datetime
from fastapi import Body, Request, HTTPException


def _safe_int(v, default=0):
    try:
        return int(float(v))
    except Exception:
        return default

def _safe_float(v, default=0.0):
    try:
        return float(v)
    except Exception:
        return default

def _parse_symbol_token(payload: dict):
    """
    Frontend sends symbol like: "NSE|PNB|XXXX"
    or can send symboltoken separately.
    """
    symbol = (payload.get("symbol") or "").strip()
    exchange_val = (payload.get("exchange") or "").strip().upper()

    exch = exchange_val or "NSE"
    token = payload.get("symboltoken") or payload.get("security_id") or payload.get("token")

    if symbol and "|" in symbol:
        parts = symbol.split("|")
        if len(parts) >= 3:
            exch = (parts[0] or exch).strip().upper()
            token = parts[2].strip()

    return exch, _safe_int(token, 0)

def _resolve_owner_userid_local(request: Request, payload: dict):
    # Prefer your existing resolve_owner_userid if you already have it
    if "resolve_owner_userid" in globals():
        try:
            return globals()["resolve_owner_userid"](
                request,
                userid=payload.get("userid"),
                user_id=payload.get("user_id"),
            )
        except Exception:
            pass
    return (request.headers.get("x-user-id") or payload.get("owner_userid") or payload.get("userid") or payload.get("user_id") or "").strip()

def _get_group_members(owner_userid: str, group_name: str):
    """
    Uses your per-user GitHub group file convention (already used in your backend).
    Expected group JSON:
      { "members": [...], "multiplier": 1.0 }
    """
    try:
        # if you already have a helper, use it
        if "user_group_file" in globals():
            path = globals()["user_group_file"](owner_userid, group_name)
        else:
            path = f"data/users/{owner_userid}/groups/{group_name}.json"

        obj, _sha = gh_get_json(path)
        if not isinstance(obj, dict):
            return [], 1.0

        members = obj.get("members") or []
        if not isinstance(members, list):
            members = []
        members = [str(m).strip() for m in members if str(m).strip()]

        try:
            mult = float(obj.get("multiplier", 1) or 1)
        except Exception:
            mult = 1.0
        if mult <= 0:
            mult = 1.0

        return members, mult
    except Exception:
        return [], 1.0

@app.post("/place_order")
async def place_order(request: Request, payload: dict = Body(...)):
    owner_userid = _resolve_owner_userid_local(request, payload or {})
    if not owner_userid:
        raise HTTPException(status_code=401, detail="Missing owner userid")

    data = payload or {}
    exch, symboltoken = _parse_symbol_token(data)
    if not symboltoken:
        raise HTTPException(status_code=400, detail="Missing/invalid symbol token")

    # what frontend sends
    groupacc = bool(data.get("groupacc", False))
    groups = data.get("groups", []) or []
    clients = data.get("clients", []) or []

    diffQty = bool(data.get("diffQty", False))
    multiplier_on = bool(data.get("multiplier", False))

    quantityinlot = _safe_int(data.get("quantityinlot", 0), 0)
    perClientQty = data.get("perClientQty", {}) or {}

    action = (data.get("action") or "").strip().upper()
    ordertype = (data.get("ordertype") or "").strip().upper()
    producttype = (data.get("producttype") or "").strip().upper()
    orderduration = (data.get("orderduration") or "").strip().upper()

    price = _safe_float(data.get("price", 0), 0.0)
    triggerprice = _safe_float(data.get("triggerprice", 0), 0.0)
    disclosedquantity = _safe_int(data.get("disclosedquantity", 0), 0)
    amoorder = (data.get("amoorder") or "N").strip().upper()

    # Build targets: list of (tag, client_id, qty)
    targets = []

    if groupacc:
        for g in groups:
            gname = str(g).strip()
            if not gname:
                continue
            members, gmult = _get_group_members(owner_userid, gname)
            for cid in members:
                base_qty = quantityinlot
                if diffQty:
                    base_qty = _safe_int(perClientQty.get(cid, base_qty), base_qty)
                if multiplier_on:
                    base_qty = max(1, int(round(base_qty * float(gmult))))
                targets.append((gname, cid, base_qty))
    else:
        for cid in clients:
            cid = str(cid).strip()
            if not cid:
                continue
            q = quantityinlot
            if diffQty:
                q = _safe_int(perClientQty.get(cid, q), q)
            targets.append(("", cid, q))

    if not targets:
        raise HTTPException(status_code=400, detail="No target clients/groups selected")

    responses = {}
    lock = threading.Lock()
    threads = []

    def _place_one(tag: str, client_id: str, qty: int):
        key = f"{tag}:{client_id}" if tag else client_id

        sess = mofsl_sessions.get(str(client_id))
        if not isinstance(sess, dict):
            with lock:
                responses[key] = {"status": "ERROR", "message": "Session not found"}
            return

        # ✅ important multi-user safety: allow only same owner
        sess_owner = (sess.get("owner_userid") or "").strip()
        if sess_owner and sess_owner != str(owner_userid).strip():
            with lock:
                responses[key] = {"status": "ERROR", "message": "Session belongs to another user"}
            return

        mofsl = sess.get("mofsl")
        uid = sess.get("userid") or client_id
        if not mofsl or not uid:
            with lock:
                responses[key] = {"status": "ERROR", "message": "Invalid session"}
            return

        order_payload = {
            "clientcode": str(uid),
            "exchange": exch,
            "symboltoken": int(symboltoken),
            "buyorsell": action,
            "ordertype": ordertype,
            "producttype": producttype,
            "orderduration": orderduration,
            "price": float(price),
            "triggerprice": float(triggerprice),
            "quantityinlot": int(max(1, qty)),
            "disclosedquantity": int(disclosedquantity),
            "amoorder": amoorder,
            "algoid": "",
            "goodtilldate": "",
            "tag": (tag or "")
        }

        try:
            resp = mofsl.PlaceOrder(order_payload)
        except Exception as e:
            resp = {"status": "ERROR", "message": str(e)}

        with lock:
            responses[key] = resp

    for (tag, cid, q) in targets:
        t = threading.Thread(target=_place_one, args=(tag, cid, q))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return {"success": True, "responses": responses}


# ============================================================
# COPY TRADING ENGINE (multi-user GitHub setups)
# Order placement + cancel propagation
# ============================================================

import sqlite3

# maps: {setup_key: {master_order_id: {child_id: child_order_id}}}
order_mapping = {}
processed_order_ids_placed = {}     # {setup_key: set()}
processed_order_ids_canceled = {}   # {setup_key: set()}

def normalize_ordertype_copytrade(s: str) -> str:
    s = (s or "").upper()
    collapsed = s.replace("_", "").replace(" ", "").replace("-", "")
    return "STOPLOSS" if collapsed == "STOPLOSS" else s

def _list_all_owner_userids():
    """
    Looks at GitHub folder: data/users
    and returns directory names (userids).
    """
    owners = []
    try:
        entries = gh_list_dir("data/users")
        for ent in entries or []:
            if isinstance(ent, dict) and ent.get("type") == "dir":
                nm = (ent.get("name") or "").strip()
                if nm:
                    owners.append(nm)
    except Exception:
        owners = []
    return owners

def load_active_copy_setups_all():
    """
    Returns list of setups across all users:
      each setup dict includes: owner_userid, id, name, master, children, multipliers
    """
    setups = []
    for owner in _list_all_owner_userids():
        folder = user_copy_dir(owner)
        try:
            entries = gh_list_dir(folder)
            for ent in entries or []:
                if not isinstance(ent, dict) or ent.get("type") != "file":
                    continue
                path = ent.get("path") or ""
                name = ent.get("name") or ""
                if not path or not str(name).endswith(".json"):
                    continue
                obj, _sha = gh_get_json(path)
                if not isinstance(obj, dict) or not obj:
                    continue
                if not bool(obj.get("enabled", False)):
                    continue
                sid = (obj.get("id") or obj.get("name") or name.replace(".json", "")).strip()
                setups.append({
                    "owner_userid": owner,
                    "id": sid,
                    "name": obj.get("name", sid),
                    "master": (obj.get("master") or obj.get("master_account") or "").strip(),
                    "children": obj.get("children") or obj.get("child_accounts") or [],
                    "multipliers": obj.get("multipliers") or {},
                })
        except Exception:
            continue
    return setups

def get_session_by_clientid(client_id: str):
    """
    Sessions are keyed by client_id (userid).
    Returns (name, mofsl, userid, owner_userid) or (None,...)
    """
    sess = mofsl_sessions.get(str(client_id).strip())
    if not isinstance(sess, dict):
        return None, None, None, None
    return sess.get("name"), sess.get("mofsl"), sess.get("userid"), sess.get("owner_userid")

def fetch_master_orders(mofsl_master, master_userid: str):
    """
    Match your /get_orders logic: GetOrderBook({clientcode, datetimestamp})
    """
    try:
        today_date = datetime.now().strftime("%d-%b-%Y 09:00:00")
        order_book_info = {"clientcode": str(master_userid), "datetimestamp": today_date}
        resp = mofsl_master.GetOrderBook(order_book_info)
        if not resp or resp.get("status") != "SUCCESS":
            return []
        data = resp.get("data") or []
        return data if isinstance(data, list) else []
    except Exception:
        return []

def _min_qty_from_symbol_db(symboltoken):
    """
    Optional: if your symbols sqlite exists and has Min Qty.
    Falls back to 1.
    """
    try:
        # These globals exist in CT_FastAPI-style code. If missing, fallback.
        SQLITE_DB = globals().get("SQLITE_DB")
        symbol_db_lock = globals().get("symbol_db_lock")

        if not SQLITE_DB:
            return 1

        conn = None
        if symbol_db_lock:
            with symbol_db_lock:
                conn = sqlite3.connect(SQLITE_DB)
                cur = conn.cursor()
                cur.execute("SELECT [Min Qty] FROM symbols WHERE [Security ID]=?", (str(symboltoken),))
                row = cur.fetchone()
                conn.close()
        else:
            conn = sqlite3.connect(SQLITE_DB)
            cur = conn.cursor()
            cur.execute("SELECT [Min Qty] FROM symbols WHERE [Security ID]=?", (str(symboltoken),))
            row = cur.fetchone()
            conn.close()

        if row and row[0]:
            return max(1, int(row[0]))
    except Exception:
        pass
    return 1

def process_copy_order(order: dict, setup: dict):
    """
    Copies NEW master orders to children and propagates CANCEL.
    """
    owner = setup.get("owner_userid") or ""
    setup_name = setup.get("name") or setup.get("id") or "setup"
    setup_key = f"{owner}:{setup.get('id') or setup_name}"

    master_order_id = order.get("uniqueorderid")
    order_time_str = order.get("recordinserttime")

    if (not master_order_id or str(master_order_id) == "0" or
        not order_time_str or order_time_str in ("", "0", None)):
        return

    # parse order time and AMO flag
    try:
        order_time_dt = datetime.strptime(order_time_str, "%d-%b-%Y %H:%M:%S")
        order_time = int(order_time_dt.timestamp())
        if order_time_dt.time() < datetime.strptime("09:00:00", "%H:%M:%S").time() or \
           order_time_dt.time() > datetime.strptime("15:30:00", "%H:%M:%S").time():
            amo_flag = "Y"
        else:
            amo_flag = "N"
    except Exception:
        return

    order_status = (order.get("orderstatus") or "").upper()
    order_type = (order.get("ordertype") or "").upper()

    processed_order_ids_placed.setdefault(setup_key, set())
    processed_order_ids_canceled.setdefault(setup_key, set())
    order_mapping.setdefault(setup_key, {})

    current_time = int(time.time())

    # -----------------------
    # Placement copy
    # -----------------------
    if order_type == "MARKET" or order_status in ("CONFIRM", "TRADED"):
        if master_order_id in processed_order_ids_placed[setup_key]:
            return
        if (current_time - order_time) > 5:
            return  # too old, skip copy

        children = setup.get("children") or []
        multipliers = setup.get("multipliers") or {}

        for child_id in children:
            child_id = str(child_id).strip()
            if not child_id:
                continue

            # child must be logged-in and belong to same owner
            cname, mofsl_child, uid_child, owner_child = get_session_by_clientid(child_id)
            if not mofsl_child or str(owner_child).strip() != str(owner).strip():
                continue

            try:
                mult = int(multipliers.get(child_id, 1) or 1)
            except Exception:
                mult = 1
            if mult <= 0:
                mult = 1

            min_qty = _min_qty_from_symbol_db(order.get("symboltoken"))
            master_qty = _safe_int(order.get("orderqty", 1), 1)
            total_qty = max(1, master_qty * mult)

            # keep lot alignment like CT logic (simple)
            adjusted_qty = max(1, int(total_qty // max(1, min_qty)))

            child_order_details = {
                "clientcode": str(uid_child or child_id),
                "exchange": (order.get("exchange") or "NSE"),
                "symboltoken": _safe_int(order.get("symboltoken"), 0),
                "buyorsell": (order.get("buyorsell") or ""),
                "ordertype": normalize_ordertype_copytrade(order.get("ordertype", "")),
                "producttype": (order.get("producttype") or "CNC"),
                "orderduration": (order.get("validity") or order.get("orderduration") or "DAY"),
                "price": _safe_float(order.get("price", 0), 0.0),
                "triggerprice": _safe_float(order.get("triggerprice", 0), 0.0),
                "quantityinlot": int(adjusted_qty),
                "disclosedquantity": 0,
                "amoorder": amo_flag,
                "algoid": "",
                "goodtilldate": "",
                "tag": setup_name
            }

            try:
                resp = mofsl_child.PlaceOrder(child_order_details)
                child_order_id = (resp or {}).get("uniqueorderid")
                if child_order_id:
                    order_mapping[setup_key].setdefault(master_order_id, {})[child_id] = child_order_id
            except Exception:
                pass

        processed_order_ids_placed[setup_key].add(master_order_id)
        return

    # -----------------------
    # Cancel propagation
    # -----------------------
    if order_status == "CANCEL":
        if master_order_id in processed_order_ids_canceled[setup_key]:
            return
        if (current_time - order_time) > 5:
            processed_order_ids_canceled[setup_key].add(master_order_id)
            return

        child_map = order_mapping.get(setup_key, {}).get(master_order_id, {})
        if not child_map:
            processed_order_ids_canceled[setup_key].add(master_order_id)
            return

        for child_id, child_order_id in (child_map or {}).items():
            cname, mofsl_child, uid_child, owner_child = get_session_by_clientid(child_id)
            if not mofsl_child or str(owner_child).strip() != str(owner).strip():
                continue
            try:
                mofsl_child.CancelOrder(child_order_id, str(uid_child or child_id))
            except Exception:
                pass

        processed_order_ids_canceled[setup_key].add(master_order_id)

def synchronize_copy_trading():
    setups = load_active_copy_setups_all()
    if not setups:
        return

    threads = []

    def handle_setup(setup):
        owner = setup.get("owner_userid") or ""
        master_id = (setup.get("master") or "").strip()
        if not master_id:
            return

        mname, mofsl_master, uid_master, owner_master = get_session_by_clientid(master_id)
        if not mofsl_master or str(owner_master).strip() != str(owner).strip():
            return

        master_orders = fetch_master_orders(mofsl_master, uid_master or master_id)
        for order in master_orders or []:
            try:
                process_copy_order(order, setup)
            except Exception:
                continue

    for setup in setups:
        t = threading.Thread(target=handle_setup, args=(setup,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

def motilal_copy_trading_loop():
    print("✅ Motilal Copy Trading Engine started")
    while True:
        try:
            synchronize_copy_trading()
        except Exception as e:
            print("❌ Copy trading sync error:", str(e))
        time.sleep(1)

# Call this once from your existing startup (or add a startup event below)
_copy_thread_started = False
def start_copy_trading_thread():
    global _copy_thread_started
    if _copy_thread_started:
        return
    _copy_thread_started = True
    threading.Thread(target=motilal_copy_trading_loop, daemon=True).start()

# If you already have @app.on_event("startup") in your file, do NOT add another.
# Instead, call start_copy_trading_thread() inside your existing startup.
@app.on_event("startup")
def _startup_copy_trading():
    start_copy_trading_thread()
