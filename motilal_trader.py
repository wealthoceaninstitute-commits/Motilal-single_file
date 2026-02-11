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

                sa = bool(client_obj.get("session_active", False))
                clients.append({
                    "name": client_obj.get("name", ""),
                    "client_id": client_obj.get("userid", client_obj.get("client_id", "")),
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


# ============================================================
# ORDERS (per-user)  | frontend: Orders.jsx
# ============================================================
from collections import OrderedDict

@app.get("/get_orders")
async def get_orders(request: Request, userid: str = None, user_id: str = None):
    owner_userid = resolve_owner_userid(request, userid=userid, user_id=user_id)
    if not owner_userid:
        return {"pending": [], "traded": [], "rejected": [], "cancelled": [], "others": []}

    orders_data = OrderedDict({
        "pending": [],
        "traded": [],
        "rejected": [],
        "cancelled": [],
        "others": []
    })

    # only this user's active sessions
    sessions = [s for s in mofsl_sessions.values() if (s or {}).get("owner_userid") == owner_userid]

    for sess in sessions:
        try:
            mofsl = sess.get("mofsl")
            client_id = sess.get("userid")
            name = sess.get("name") or client_id

            if not mofsl or not client_id:
                continue

            today_date = datetime.now().strftime("%d-%b-%Y 09:00:00")
            order_book_info = {"clientcode": client_id, "datetimestamp": today_date}
            resp = mofsl.GetOrderBook(order_book_info)

            orders = (resp or {}).get("data", [])
            if not isinstance(orders, list):
                orders = []

            for order in orders:
                order_data = {
                    "broker": "motilal",
                    "client_id": client_id,
                    "name": name,
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
            print(f"❌ Error fetching orders for {sess.get('userid')}: {e}")

    return dict(orders_data)


@app.post("/cancel_order")
async def cancel_order(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(request, userid=payload.get("userid") or payload.get("owner_userid"))
    if not owner_userid:
        raise HTTPException(status_code=401, detail="Missing owner userid")

    orders = payload.get("orders", [])
    if not orders:
        raise HTTPException(status_code=400, detail="No orders received for cancellation.")

    messages = []
    threads = []
    thread_lock = threading.Lock()

    def cancel_one(order: dict):
        order_id = (order or {}).get("order_id") or ""
        client_id = (order or {}).get("client_id") or (order or {}).get("userid") or (order or {}).get("clientcode") or ""
        client_id = str(client_id).strip()

        if not order_id or not client_id:
            with thread_lock:
                messages.append(f"❌ Missing order_id/client_id in: {order}")
            return

        sess = mofsl_sessions.get(client_id)
        if not sess or sess.get("owner_userid") != owner_userid:
            with thread_lock:
                messages.append(f"❌ Session not found for client: {client_id}")
            return

        mofsl = sess.get("mofsl")
        name = sess.get("name") or client_id
        try:
            cancel_resp = mofsl.CancelOrder(order_id, client_id)
            msg = ((cancel_resp or {}).get("message", "") or "")
            if "cancel order request sent" in msg.lower():
                out = f"✅ Cancelled Order {order_id} for {name}"
            else:
                out = f"❌ Failed to cancel Order {order_id} for {name}: {msg}"
            with thread_lock:
                messages.append(out)
        except Exception as e:
            with thread_lock:
                messages.append(f"❌ Error cancelling {order_id} for {name}: {e}")

    for o in orders:
        t = threading.Thread(target=cancel_one, args=(o,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    return {"message": messages}


@app.post("/modify_order")
async def modify_order(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(request, userid=payload.get("userid") or payload.get("owner_userid"))
    if not owner_userid:
        raise HTTPException(status_code=401, detail="Missing owner userid")

    order = payload.get("order") or {}
    order_id = order.get("order_id")
    client_id = (order.get("client_id") or order.get("userid") or "").strip()
    if not order_id or not client_id:
        raise HTTPException(status_code=400, detail="order_id and client_id required")

    sess = mofsl_sessions.get(client_id)
    if not sess or sess.get("owner_userid") != owner_userid:
        raise HTTPException(status_code=404, detail="Session not found for client")

    mofsl = sess.get("mofsl")

    # Build a flexible modify payload. Motilal SDK variants differ, so we try a few.
    mod_payload = {
        "clientcode": client_id,
        "uniqueorderid": order_id,
    }
    if "ordertype" in order:
        mod_payload["ordertype"] = order.get("ordertype")
    if "quantity" in order:
        mod_payload["quantityinlot"] = order.get("quantity")
    if "price" in order:
        mod_payload["price"] = order.get("price")
    if "triggerprice" in order:
        mod_payload["triggerprice"] = order.get("triggerprice")

    # Try common method names
    resp = None
    last_err = None
    for fn_name in ["ModifyOrder", "modify_order", "ModifyEquityOrder", "ModifyOrderBook"]:
        fn = getattr(mofsl, fn_name, None)
        if callable(fn):
            try:
                resp = fn(mod_payload)
                break
            except Exception as e:
                last_err = e

    if resp is None:
        # As a last fallback, some SDKs take (order_id, client_id, payload)
        fn = getattr(mofsl, "ModifyOrder", None)
        if callable(fn):
            try:
                resp = fn(order_id, client_id, mod_payload)
            except Exception as e:
                last_err = e

    if resp is None and last_err:
        raise HTTPException(status_code=500, detail=f"Modify failed: {last_err}")

    return {"ok": True, "response": resp}


# Optional: Orders.jsx tries /ltp but ignores failures.
@app.get("/ltp")
async def ltp(request: Request, symbol: str = "", userid: str = None, user_id: str = None):
    # Not implemented in this backend yet; kept for frontend compatibility.
    raise HTTPException(status_code=404, detail="LTP not available")
