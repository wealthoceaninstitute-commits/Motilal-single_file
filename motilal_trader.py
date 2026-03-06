"""
Motilal Single File - Railway Backend (FIXED)

BUGS FIXED vs previous Railway version:
  FIX 1: _safe_int / _safe_float moved to top (were defined AFTER place_order → NameError on Railway)
  FIX 2: startup now logs in ALL clients from GitHub (matching local desktop on_startup behavior)
  FIX 3: Removed duplicate _load_client_from_github inside place_order (used module-level one instead)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import requests
from fastapi import Depends, FastAPI, HTTPException, Request, Body, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from MOFSLOPENAPI import MOFSLOPENAPI
import pyotp


# ─────────────────────────────────────────────────────────────
# JWT helpers
# ─────────────────────────────────────────────────────────────
def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)

def jwt_encode(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"

class JWTError(Exception):
    pass

def jwt_decode(token: str, secret: str) -> dict:
    try:
        h, p, s = token.split(".")
    except ValueError:
        raise JWTError("Invalid token format")
    expected = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(_b64url_encode(expected), s):
        raise JWTError("Invalid token signature")
    payload = json.loads(_b64url_decode(p).decode())
    exp = payload.get("exp")
    if exp and int(time.time()) >= int(exp):
        raise JWTError("Token expired")
    return payload


# ─────────────────────────────────────────────────────────────
# FIX 1: _safe_int / _safe_float AT THE TOP
# In the old Railway file these were defined ~800 lines in, AFTER
# place_order already called them → NameError on cold start.
# ─────────────────────────────────────────────────────────────
def _safe_int(x, default=0):
    try:
        if x is None:
            return default
        s = str(x).strip()
        return default if s == "" else int(float(s))
    except Exception:
        return default

def _safe_float(x, default=0.0):
    try:
        if x is None:
            return default
        s = str(x).strip()
        return default if s == "" else float(s)
    except Exception:
        return default


# ─────────────────────────────────────────────────────────────
# ENV config
# ─────────────────────────────────────────────────────────────
APP_NAME         = os.getenv("APP_NAME", "Auth Backend (Multiuser)")
API_VERSION      = os.getenv("API_VERSION", "1.0.0")
SECRET_KEY       = os.getenv("SECRET_KEY") or "CHANGE_ME_PLEASE_SET_SECRET_KEY"
TOKEN_EXPIRE_HOURS = int(os.getenv("TOKEN_EXPIRE_HOURS", "24"))
GITHUB_OWNER     = os.getenv("GITHUB_OWNER", "")
GITHUB_REPO      = os.getenv("GITHUB_REPO", "")
GITHUB_BRANCH    = os.getenv("GITHUB_BRANCH", "main")
GITHUB_TOKEN     = os.getenv("GITHUB_TOKEN", "")

cors_origins_raw = (os.getenv("CORS_ORIGINS") or "").strip()
if cors_origins_raw == "*":
    allow_origins    = ["*"]
    allow_credentials = False
elif cors_origins_raw:
    allow_origins    = [o.strip().rstrip("/") for o in cors_origins_raw.split(",") if o.strip()]
    allow_credentials = True
else:
    allow_origins    = ["http://localhost:3000", "http://127.0.0.1:3000",
                        "https://woi-mosl-trader.vercel.app"]
    allow_credentials = True


# ─────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────
app = FastAPI(title=APP_NAME, version=API_VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)
security = HTTPBearer(auto_error=False)


# ─────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────
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

def _norm_uid(uid: str) -> str:
    uid = str(uid or "").strip()
    if (uid.startswith('"') and uid.endswith('"')) or (uid.startswith("'") and uid.endswith("'")):
        uid = uid[1:-1].strip()
    return uid

def require_secret():
    if SECRET_KEY == "CHANGE_ME_PLEASE_SET_SECRET_KEY":
        print("WARNING: SECRET_KEY not set — using insecure default.")

def password_hash(password: str, salt: str) -> str:
    return hashlib.sha256((salt + ":" + password).encode()).hexdigest()

def create_token(userid: str) -> str:
    require_secret()
    return jwt_encode({"userid": userid, "exp": int(time.time()) + TOKEN_EXPIRE_HOURS * 3600}, SECRET_KEY)

def _safe_filename(s: str) -> str:
    s = (s or "").strip().replace(" ", "_")
    return re.sub(r"[^A-Za-z0-9_\-]", "_", s)[:80] or "client"


# ─────────────────────────────────────────────────────────────
# GitHub storage helpers
# ─────────────────────────────────────────────────────────────
def gh_enabled() -> bool:
    return bool(GITHUB_OWNER and GITHUB_REPO and GITHUB_TOKEN)

def gh_headers() -> Dict[str, str]:
    return {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github+json"}

def gh_url(path: str) -> str:
    return f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{path.lstrip('/')}"

def b64encode_str(s: str) -> str:
    return base64.b64encode(s.encode()).decode()

def b64decode_to_str(s: str) -> str:
    return base64.b64decode(s.encode()).decode()

class GitHubStorageError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        super().__init__(f"GitHub API {status_code}: {message}")

def gh_get_json(path: str) -> Tuple[Optional[Any], Optional[str]]:
    if not gh_enabled():
        return None, None
    r = requests.get(gh_url(path), headers=gh_headers(), params={"ref": GITHUB_BRANCH})
    if r.status_code == 404:
        return None, None
    if r.status_code == 401:
        raise GitHubStorageError(401, "GitHub token invalid.")
    if r.status_code == 403:
        raise GitHubStorageError(403, "GitHub token forbidden/rate-limited.")
    if not r.ok:
        raise GitHubStorageError(r.status_code, r.text[:200])
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

def gh_put_json(path: str, obj: Any, message: str, sha: Optional[str] = None) -> None:
    if not gh_enabled():
        raise HTTPException(500, "GitHub storage not configured.")
    if sha is None:
        _, sha = gh_get_json(path)
    payload: dict = {
        "message": message,
        "content": b64encode_str(json.dumps(obj, indent=2, ensure_ascii=False)),
        "branch": GITHUB_BRANCH,
    }
    if sha:
        payload["sha"] = sha
    r = requests.put(gh_url(path), headers=gh_headers(), json=payload)
    if r.status_code == 401:
        raise GitHubStorageError(401, "GitHub token invalid.")
    if r.status_code == 403:
        raise GitHubStorageError(403, "GitHub token forbidden/rate-limited.")
    if not r.ok:
        raise GitHubStorageError(r.status_code, r.text[:200])

def gh_list_dir(path: str) -> list:
    if not gh_enabled():
        raise HTTPException(500, "GitHub storage not configured.")
    r = requests.get(gh_url(path), headers=gh_headers(), params={"ref": GITHUB_BRANCH})
    if r.status_code == 404:
        return []
    if r.status_code == 401:
        raise GitHubStorageError(401, "GitHub token invalid.")
    if r.status_code == 403:
        raise GitHubStorageError(403, "GitHub token forbidden/rate-limited.")
    if not r.ok:
        raise GitHubStorageError(r.status_code, r.text[:200])
    data = r.json()
    return data if isinstance(data, list) else []

def gh_delete_path(path: str, sha: str, message: str = "delete file") -> bool:
    if not gh_enabled():
        raise HTTPException(500, "GitHub storage not configured.")
    if not sha:
        _, sha2 = gh_get_json(path)
        sha = sha2 or ""
    if not sha:
        return False
    r = requests.delete(gh_url(path), headers=gh_headers(),
                        json={"message": message, "sha": sha, "branch": GITHUB_BRANCH})
    if r.status_code == 404:
        return False
    if r.status_code == 401:
        raise GitHubStorageError(401, "GitHub token invalid.")
    if r.status_code == 403:
        raise GitHubStorageError(403, "GitHub token forbidden/rate-limited.")
    if not r.ok:
        raise GitHubStorageError(r.status_code, r.text[:200])
    return True

# In-memory GitHub read cache
_gh_cache: Dict[str, Any] = {}
_gh_cache_ts: Dict[str, float] = {}
_gh_cache_lock = threading.Lock()
GH_CACHE_TTL = 30

def gh_get_json_cached(path: str, ttl: int = GH_CACHE_TTL) -> Tuple[Optional[Any], Optional[str]]:
    now = time.time()
    with _gh_cache_lock:
        if path in _gh_cache and (now - _gh_cache_ts.get(path, 0)) < ttl:
            return _gh_cache[path]
    result = gh_get_json(path)
    with _gh_cache_lock:
        _gh_cache[path] = result
        _gh_cache_ts[path] = time.time()
    return result

def gh_cache_invalidate(path: str):
    with _gh_cache_lock:
        _gh_cache.pop(path, None)
        _gh_cache_ts.pop(path, None)


# ─────────────────────────────────────────────────────────────
# Path helpers
# ─────────────────────────────────────────────────────────────
def user_root(userid: str) -> str:           return f"data/users/{userid}"
def user_profile_path(userid: str) -> str:   return f"{user_root(userid)}/profile.json"
def user_clients_dir(userid: str) -> str:    return f"{user_root(userid)}/clients"
def user_groups_dir(owner: str) -> str:      return f"data/users/{owner}/groups"
def user_copy_dir(owner: str) -> str:        return f"data/users/{owner}/copytrading"

def user_group_file(owner: str, gid: str) -> str:
    return f"{user_groups_dir(owner)}/{_safe_filename(gid)}.json"

def user_copy_file(owner: str, sid: str) -> str:
    return f"{user_copy_dir(owner)}/{_safe_filename(sid)}.json"

def _client_dir(owner: str) -> str:
    return f"data/users/{owner}/clients"


# ─────────────────────────────────────────────────────────────
# Copy-trading setup cache
# ─────────────────────────────────────────────────────────────
_copy_setups_cache: list = []
_copy_setups_cache_ts: float = 0.0
COPY_SETUPS_CACHE_TTL = 60
_copy_setups_403_until: float = 0.0


# ─────────────────────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────────────────────
def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> str:
    require_secret()
    if not credentials or not credentials.credentials:
        raise HTTPException(401, "Missing token")
    try:
        payload = jwt_decode(credentials.credentials, SECRET_KEY)
        userid = (payload.get("userid") or "").strip()
        if not userid:
            raise HTTPException(401, "Invalid token")
        return userid
    except JWTError as e:
        msg = str(e)
        raise HTTPException(401, "Token expired" if "expired" in msg.lower() else "Invalid token")

def resolve_owner_userid(request: Request, userid: Optional[str] = None, user_id: Optional[str] = None) -> str:
    token_user = ""
    try:
        auth = request.headers.get("authorization") or request.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            payload = jwt_decode(auth.split(" ", 1)[1].strip(), SECRET_KEY)
            token_user = payload.get("userid") or ""
    except Exception:
        pass
    uid = (
        token_user
        or request.headers.get("x-user-id")
        or request.query_params.get("userid")
        or request.query_params.get("user_id")
        or userid
        or user_id
    )
    return normalize_userid(uid or "")


# ─────────────────────────────────────────────────────────────
# Motilal session store
# ─────────────────────────────────────────────────────────────
Base_Url       = "https://openapi.motilaloswal.com"
SourceID       = "Desktop"
browsername    = "chrome"
browserversion = "104"

mofsl_sessions: Dict[str, Dict[str, Any]] = {}
position_meta:  Dict = {}
_position_meta_lock = threading.Lock()

_SESSION_TTL_SECONDS = int(os.getenv("MO_SESSION_TTL_SECONDS", "21600"))
_login_locks: Dict[str, threading.Lock] = {}

def _lock_for(userid: str) -> threading.Lock:
    _login_locks.setdefault(str(userid or "").strip(), threading.Lock())
    return _login_locks[str(userid or "").strip()]

def _session_fresh(sess: dict) -> bool:
    try:
        if not isinstance(sess, dict) or not sess.get("mofsl"):
            return False
        ts = int(sess.get("login_ts") or 0)
        return ts > 0 and (int(time.time()) - ts) < _SESSION_TTL_SECONDS
    except Exception:
        return False

def motilal_login(client: dict) -> bool:
    """Login a client and store session in mofsl_sessions. Reuses fresh session."""
    name        = client.get("name", "")
    userid      = str(client.get("userid", "") or client.get("client_id", "") or "").strip()
    password    = client.get("password", "")
    pan         = client.get("pan", "")
    apikey      = client.get("apikey", "")
    totpkey     = client.get("totpkey", "")
    owner_userid = _norm_uid(client.get("owner_userid", "") or "")

    if not userid:
        print("Login skipped: missing userid")
        return False

    existing = mofsl_sessions.get(userid)
    if existing and _session_fresh(existing) and _norm_uid(existing.get("owner_userid", "")) == owner_userid:
        return True

    lk = _lock_for(userid)
    with lk:
        existing = mofsl_sessions.get(userid)
        if existing and _session_fresh(existing) and _norm_uid(existing.get("owner_userid", "")) == owner_userid:
            return True
        try:
            totp  = pyotp.TOTP(totpkey).now() if totpkey else ""
            mofsl = MOFSLOPENAPI(apikey, Base_Url, None, SourceID, browsername, browserversion)
            resp  = mofsl.login(userid, password, pan, totp, userid)
            if isinstance(resp, dict) and resp.get("status") == "SUCCESS":
                mofsl_sessions[userid] = {
                    "name": name, "userid": userid, "mofsl": mofsl,
                    "login_ts": int(time.time()), "owner_userid": owner_userid,
                }
                print(f"✅ Logged in: {name} ({userid})")
                return True
            print(f"❌ Login failed: {name} ({userid}) → {resp.get('message','')}")
            return False
        except Exception as e:
            print(f"❌ Login error: {name} ({userid}) :: {e}")
            return False


# ─────────────────────────────────────────────────────────────
# FIX 2: Module-level _load_client_from_github (used by both
#         place_order AND the copy-trading engine)
# ─────────────────────────────────────────────────────────────
def _load_client_from_github(owner: str, client_id: str) -> Optional[dict]:
    """
    Load a client JSON from GitHub for a given owner.
    Injects owner_userid so motilal_login can tag the session.
    Returns None if not found.
    """
    owner     = str(owner or "").strip()
    client_id = str(client_id or "").strip()
    if not owner or not client_id:
        return None

    folder = _client_dir(owner)
    preferred = f"{client_id}.json"
    candidates = []

    try:
        entries = gh_list_dir(folder) or []
    except Exception:
        entries = []

    for ent in entries:
        if not isinstance(ent, dict) or ent.get("type") != "file":
            continue
        nm   = (ent.get("name") or "").strip()
        path = (ent.get("path") or "").strip()
        if not nm.endswith(".json") or not path:
            continue
        if nm == preferred:
            candidates = [path]
            break
        candidates.append(path)

    for path in candidates:
        try:
            obj, _ = gh_get_json(path)
            if not isinstance(obj, dict) or not obj:
                continue
            uid = str(obj.get("userid") or obj.get("client_id") or "").strip()
            if uid == client_id or path.endswith(f"/{preferred}"):
                obj = dict(obj)
                obj["owner_userid"] = owner   # runtime-only, NOT persisted
                return obj
        except Exception:
            continue
    return None


def _ensure_session_for_copy(owner: str, client_id: str) -> Optional[dict]:
    """Ensure a fresh session exists for copy-trading; auto-login if needed."""
    owner     = str(owner or "").strip()
    client_id = str(client_id or "").strip()
    if not owner or not client_id:
        return None

    sess = mofsl_sessions.get(client_id)
    if (isinstance(sess, dict) and _session_fresh(sess)
            and _norm_uid(sess.get("owner_userid", "")) == owner and sess.get("mofsl")):
        return sess

    client_obj = _load_client_from_github(owner, client_id)
    if not client_obj:
        print(f"❌ [COPY] Client not found owner={owner} client_id={client_id}")
        return None

    try:
        ok = bool(motilal_login(client_obj))
    except Exception as e:
        print(f"❌ [COPY] Login exception owner={owner} client_id={client_id}: {e}")
        return None

    if not ok:
        print(f"❌ [COPY] Login failed owner={owner} client_id={client_id}")
        return None

    return mofsl_sessions.get(client_id)


# ─────────────────────────────────────────────────────────────
# Symbol DB (SQLite)
# ─────────────────────────────────────────────────────────────
GITHUB_CSV_URL = "https://raw.githubusercontent.com/Pramod541988/Stock_List/main/security_id.csv"
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
SYMBOL_DB_PATH  = os.path.join(BASE_DIR, "symbols.db")
SYMBOL_TABLE    = "symbols"
_symbol_db_lock = threading.Lock()

def _symbol_db_exists() -> bool:
    return os.path.exists(SYMBOL_DB_PATH)

def refresh_symbol_db_from_github() -> str:
    os.makedirs(BASE_DIR, exist_ok=True)
    r = requests.get(GITHUB_CSV_URL, timeout=30)
    r.raise_for_status()
    csv_path = os.path.join(BASE_DIR, "security_id.csv")
    with open(csv_path, "wb") as f:
        f.write(r.content)
    df = pd.read_csv(csv_path, dtype=str).fillna("")
    for col in ("Security ID", "Min qty", "Min Qty", "MIN QTY", "MIN_QTY"):
        if col in df.columns:
            df[col] = df[col].astype(str).str.replace(r"\.0$", "", regex=True).str.strip()
    with _symbol_db_lock:
        conn = sqlite3.connect(SYMBOL_DB_PATH)
        try:
            df.to_sql(SYMBOL_TABLE, conn, index=False, if_exists="replace")
            for idx_sql in [
                f'CREATE INDEX IF NOT EXISTS idx_sym_symbol ON {SYMBOL_TABLE} ("Stock Symbol");',
                f'CREATE INDEX IF NOT EXISTS idx_sym_exchange ON {SYMBOL_TABLE} (Exchange);',
                f'CREATE INDEX IF NOT EXISTS idx_sym_secid ON {SYMBOL_TABLE} ("Security ID");',
            ]:
                try:
                    conn.execute(idx_sql)
                except Exception:
                    pass
            conn.commit()
        finally:
            conn.close()
    print("✅ Symbol DB refreshed:", SYMBOL_DB_PATH)
    return "success"

def _lazy_init_symbol_db():
    if not _symbol_db_exists():
        try:
            print("ℹ️ Symbol DB not found — building from GitHub CSV…")
            refresh_symbol_db_from_github()
        except Exception as e:
            print("❌ Symbol DB init failed:", e)

def _min_qty_from_symbol_db(symboltoken) -> int:
    try:
        token = str(symboltoken).strip()
        if not token or not _symbol_db_exists():
            return 1
        with _symbol_db_lock:
            conn = sqlite3.connect(SYMBOL_DB_PATH)
            cur  = conn.cursor()
            cur.execute(f'SELECT [Min Qty] FROM {SYMBOL_TABLE} WHERE [Security ID]=?', (token,))
            row = cur.fetchone()
            conn.close()
        return max(1, int(row[0])) if row and row[0] else 1
    except Exception:
        return 1


# ─────────────────────────────────────────────────────────────
# FIX 2 (continued): Startup — login ALL clients from GitHub
# This is the exact equivalent of local on_startup() which calls
# load_all_clients() + login_client() for every client file.
# Without this, Railway sessions are empty after every restart.
# ─────────────────────────────────────────────────────────────
def _startup_login_all_clients():
    """
    Scan ALL users in data/users/ and login every client found.
    Mirrors the local desktop's on_startup() load_all_clients() behaviour.
    Runs in a background thread so it doesn't delay server readiness.
    """
    print("🔄 [STARTUP] Beginning login of all clients from GitHub…")
    try:
        users = gh_list_dir("data/users") or []
    except Exception as e:
        print(f"❌ [STARTUP] Could not list users: {e}")
        return

    all_client_pairs = []  # [(owner, client_json), ...]
    for user_ent in users:
        if user_ent.get("type") != "dir":
            continue
        owner = user_ent.get("name", "")
        if not owner:
            continue
        try:
            client_files = gh_list_dir(f"data/users/{owner}/clients") or []
        except Exception:
            continue
        for cf in client_files:
            if cf.get("type") != "file" or not (cf.get("name", "")).endswith(".json"):
                continue
            try:
                client_obj, _ = gh_get_json(cf["path"])
                if isinstance(client_obj, dict) and client_obj:
                    client_obj = dict(client_obj)
                    client_obj["owner_userid"] = owner  # runtime-only
                    all_client_pairs.append(client_obj)
            except Exception as e:
                print(f"❌ [STARTUP] Could not read {cf.get('path')}: {e}")

    if not all_client_pairs:
        print("⚠️  [STARTUP] No clients found to login.")
        return

    print(f"🔑 [STARTUP] Logging in {len(all_client_pairs)} clients…")

    def _login_one(c):
        try:
            motilal_login(c)
        except Exception as e:
            print(f"❌ [STARTUP] Login error for {c.get('userid','?')}: {e}")

    with ThreadPoolExecutor(max_workers=20) as ex:
        list(ex.map(_login_one, all_client_pairs))

    logged = sum(1 for s in mofsl_sessions.values() if _session_fresh(s))
    print(f"✅ [STARTUP] {logged}/{len(all_client_pairs)} clients logged in.")


# ─────────────────────────────────────────────────────────────
# Startup event
# ─────────────────────────────────────────────────────────────
@app.on_event("startup")
def _startup():
    _lazy_init_symbol_db()
    # Login all clients in background (non-blocking)
    threading.Thread(target=_startup_login_all_clients, daemon=True).start()
    # Start copy trading engine
    start_copy_trading_thread()


# ─────────────────────────────────────────────────────────────
# Routes — Health / Auth
# ─────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"ok": True, "name": APP_NAME, "version": API_VERSION}

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/auth/register")
def auth_register(payload: dict = Body(...)):
    userid   = normalize_userid(payload.get("userid"))
    email    = (payload.get("email") or "").strip()
    password = (payload.get("password") or "").strip()
    confirm  = (payload.get("confirm_password") or payload.get("confirmPassword") or "").strip()

    if not userid or not email or not password:
        return {"success": False, "error": "Missing userid/email/password"}
    if confirm and password != confirm:
        return {"success": False, "error": "Passwords do not match"}

    try:
        existing, _ = gh_get_json(user_profile_path(userid))
    except GitHubStorageError as e:
        return {"success": False, "error": f"Storage unavailable: {e}"}

    if existing:
        return {"success": False, "error": "User already exists"}

    salt = base64.b64encode(os.urandom(12)).decode()
    profile = {
        "userid": userid, "email": email, "salt": salt,
        "password_hash": password_hash(password, salt),
        "created_at": utcnow_iso(), "updated_at": utcnow_iso(),
    }
    try:
        gh_put_json(user_profile_path(userid), profile, message=f"register {userid}")
    except GitHubStorageError as e:
        return {"success": False, "error": f"Storage unavailable: {e}"}
    return {"success": True, "userid": userid}

@app.post("/auth/login")
def auth_login(payload: dict = Body(...)):
    userid   = normalize_userid(payload.get("userid"))
    password = (payload.get("password") or "").strip()
    if not userid or not password:
        return {"success": False}
    try:
        profile, _ = gh_get_json(user_profile_path(userid))
    except GitHubStorageError as e:
        return {"success": False, "error": f"Storage unavailable: {e}"}
    if not isinstance(profile, dict) or not profile:
        return {"success": False}
    salt = profile.get("salt", "")
    ph   = profile.get("password_hash", "")
    if not salt or not ph or password_hash(password, salt) != ph:
        return {"success": False}
    return {"success": True, "userid": userid, "access_token": create_token(userid)}

@app.get("/me")
def me(userid: str = Depends(get_current_user)):
    return {"success": True, "userid": userid}


# ─────────────────────────────────────────────────────────────
# Client CRUD
# ─────────────────────────────────────────────────────────────
@app.post("/add_client")
async def add_client(request: Request, payload: dict = Body(...)):
    owner_userid = _norm_uid(request.headers.get("x-user-id") or payload.get("owner_userid") or payload.get("userid") or "")
    if not owner_userid:
        raise HTTPException(401, "Missing owner userid")

    client_userid = str(payload.get("userid") or payload.get("client_id") or payload.get("client_code") or "").strip()
    if not client_userid:
        raise HTTPException(400, "Client userid required")

    client = {
        "broker": "motilal",
        "name":     payload.get("name") or payload.get("display_name") or "",
        "userid":   client_userid,
        "password": payload.get("password") or "",
        "pan":      payload.get("pan") or "",
        "apikey":   payload.get("apikey") or "",
        "totpkey":  payload.get("totpkey") or "",
        "capital":  payload.get("capital", ""),
        "session_active": False,
        "last_login_ts":  0,
        "last_login_msg": "Not logged in",
    }

    path = f"data/users/{owner_userid}/clients/{client_userid}.json"
    try:
        gh_put_json(path, client, message=f"add client {owner_userid}:{client_userid}")
        gh_cache_invalidate(path)
    except GitHubStorageError as e:
        raise HTTPException(503, f"Storage unavailable: {e}")

    login_client = dict(client)
    login_client["owner_userid"] = owner_userid
    ok = motilal_login(login_client)

    client["session_active"]  = ok
    client["last_login_ts"]   = int(time.time())
    client["last_login_msg"]  = "Login successful" if ok else "Login failed"
    gh_put_json(path, client, message=f"update login status {owner_userid}:{client_userid}")
    gh_cache_invalidate(path)
    return {"success": True}

@app.post("/edit_client")
async def edit_client(request: Request, payload: dict = Body(...)):
    owner_userid  = _norm_uid(request.headers.get("x-user-id") or payload.get("owner_userid") or "")
    client_userid = str(payload.get("userid") or payload.get("client_id") or "").strip()
    if not owner_userid or not client_userid:
        raise HTTPException(400, "Missing owner_userid or client_userid")

    path = f"data/users/{owner_userid}/clients/{client_userid}.json"
    client, _ = gh_get_json(path)
    if not isinstance(client, dict) or not client:
        raise HTTPException(404, "Client not found")

    for field in ("name", "password", "pan", "apikey", "totpkey", "capital"):
        if payload.get(field) is not None:
            client[field] = payload[field]

    gh_put_json(path, client, message="edit client")
    gh_cache_invalidate(path)

    login_client = dict(client)
    login_client["owner_userid"] = owner_userid
    ok = motilal_login(login_client)

    client["session_active"]  = ok
    client["last_login_ts"]   = int(time.time())
    client["last_login_msg"]  = "Login successful" if ok else "Login failed"
    gh_put_json(path, client, message="update login")
    gh_cache_invalidate(path)
    return {"success": True}

@app.get("/clients")
def get_clients(request: Request, userid: str = None, user_id: str = None):
    uid = _norm_uid(request.headers.get("x-user-id") or userid or user_id or
                    request.query_params.get("userid") or request.query_params.get("user_id") or "")
    if not uid:
        return {"clients": []}

    folder  = f"data/users/{uid}/clients"
    clients = []
    try:
        entries = gh_list_dir(folder) or []
    except GitHubStorageError as e:
        return {"clients": [], "error": str(e)}

    for ent in entries:
        if not isinstance(ent, dict) or ent.get("type") != "file":
            continue
        if not ent.get("name", "").endswith(".json") or not ent.get("path"):
            continue
        try:
            client_obj, _ = gh_get_json_cached(ent["path"])
            if not isinstance(client_obj, dict):
                continue

            client_obj_local = dict(client_obj)
            client_obj_local["owner_userid"] = uid
            try:
                motilal_login(client_obj_local)
            except Exception:
                pass

            client_id = str(client_obj.get("userid") or client_obj.get("client_id") or "").strip()
            sess = mofsl_sessions.get(client_id) if client_id else None
            sa   = bool(sess and _norm_uid(sess.get("owner_userid","")) == uid
                        and _session_fresh(sess) and sess.get("mofsl"))

            clients.append({
                "name":           client_obj.get("name", ""),
                "client_id":      client_id,
                "capital":        client_obj.get("capital", ""),
                "session":        "Logged in" if sa else "Logged out",
                "session_active": sa,
                "status":         "logged_in" if sa else "logged_out",
            })
        except Exception as e:
            print(f"Error reading {ent.get('path')}: {e}")

    return {"clients": clients}

@app.post("/delete_client")
async def delete_client(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(request, userid=payload.get("userid") or payload.get("owner_userid"))
    if not owner_userid:
        raise HTTPException(401, "Missing owner userid")

    deleted, missing, errors = [], [], []
    for it in (payload.get("items") or []):
        try:
            cuid = str((it or {}).get("userid") or (it or {}).get("client_id") or "").strip()
            if not cuid:
                continue
            path     = f"data/users/{owner_userid}/clients/{cuid}.json"
            _, sha   = gh_get_json(path)
            if not sha:
                missing.append(cuid); continue
            ok = gh_delete_path(path, sha, message=f"delete client {owner_userid}:{cuid}")
            if ok:
                deleted.append(cuid)
                mofsl_sessions.pop(cuid, None)
            else:
                missing.append(cuid)
        except Exception as e:
            errors.append(str(e))
    return {"ok": True, "deleted": deleted, "missing": missing, "errors": errors}


# ─────────────────────────────────────────────────────────────
# Symbol search
# ─────────────────────────────────────────────────────────────
@app.post("/refresh_symbols")
def refresh_symbols():
    try:
        return {"status": refresh_symbol_db_from_github()}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/search_symbols")
def search_symbols(q: str = Query(""), exchange: str = Query("")):
    _lazy_init_symbol_db()
    raw  = (q or "").strip().lower()
    exch = (exchange or "").strip().upper()
    if not raw:
        return {"results": []}

    words      = [w for w in raw.split() if w]
    where_sql  = ['LOWER([Stock Symbol]) LIKE ?' for w in words]
    where_params = [f"%{w}%" for w in words]
    if exch:
        where_sql.append('UPPER(Exchange) = ?')
        where_params.append(exch)

    sql = f"""
        SELECT Exchange, [Stock Symbol], [Security ID],
               CASE WHEN LOWER([Stock Symbol])=? THEN 0
                    WHEN LOWER([Stock Symbol]) LIKE ? THEN 1
                    WHEN LOWER([Stock Symbol]) LIKE ? THEN 2 ELSE 3 END AS rank_score
        FROM {SYMBOL_TABLE}
        WHERE {' AND '.join(where_sql)}
        ORDER BY rank_score, [Stock Symbol] LIMIT 200
    """
    with _symbol_db_lock:
        conn = sqlite3.connect(SYMBOL_DB_PATH)
        try:
            rows = conn.execute(sql, [raw, f"{raw}%", f"%{raw}%"] + where_params).fetchall()
        finally:
            conn.close()
    return {"results": [{"id": f"{r[0]}|{r[1]}|{r[2]}", "text": f"{r[0]} | {r[1]}"} for r in rows]}


# ─────────────────────────────────────────────────────────────
# Groups
# ─────────────────────────────────────────────────────────────
import re as _re

def _extract_uid_from_member(m) -> str:
    if isinstance(m, dict):
        return str(m.get("userid") or m.get("client_id") or m.get("client_code") or "").strip()
    if isinstance(m, str):
        s = m.strip()
        if s.startswith("{"):
            try:
                d = json.loads(s)
                return str(d.get("userid") or d.get("client_id") or "").strip()
            except Exception:
                pass
            hit = _re.search(r"(?:userid|client_id)['\"]?\s*:\s*['\"]([^'\"]+)['\"]", s)
            if hit:
                return hit.group(1).strip()
        return s
    return str(m or "").strip()

@app.get("/groups")
async def get_groups(request: Request, userid: str = None, user_id: str = None):
    owner_userid = resolve_owner_userid(request, userid=userid, user_id=user_id)
    if not owner_userid:
        return {"groups": []}
    groups = []
    try:
        for ent in (gh_list_dir(user_groups_dir(owner_userid)) or []):
            if not isinstance(ent, dict) or ent.get("type") != "file":
                continue
            if not ent.get("name", "").endswith(".json") or not ent.get("path"):
                continue
            obj, _ = gh_get_json(ent["path"])
            if isinstance(obj, dict) and obj:
                gid = obj.get("id") or ent["name"].replace(".json", "")
                groups.append({"id": gid, "name": obj.get("name", gid),
                               "multiplier": obj.get("multiplier", 1),
                               "members": obj.get("members", [])})
    except Exception:
        pass
    return {"groups": groups}

@app.post("/add_group")
async def add_group(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(request, userid=payload.get("userid") or payload.get("owner_userid"))
    if not owner_userid:
        raise HTTPException(401, "Missing owner userid")
    name = (payload.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "Group name required")
    members = payload.get("members") or []
    if not isinstance(members, list) or not members:
        raise HTTPException(400, "Group members required")
    mult = max(0.01, float(payload.get("multiplier", 1) or 1))
    gid  = (payload.get("id") or name).strip()
    obj  = {"id": gid, "name": name, "multiplier": mult, "members": members,
            "created_at": utcnow_iso(), "updated_at": utcnow_iso()}
    gh_put_json(user_group_file(owner_userid, gid), obj, message=f"add group {owner_userid}:{gid}")
    return {"ok": True, "group": obj}

@app.post("/edit_group")
async def edit_group(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(request, userid=payload.get("userid") or payload.get("owner_userid"))
    if not owner_userid:
        raise HTTPException(401, "Missing owner userid")
    gid  = (payload.get("id") or payload.get("name") or "").strip()
    if not gid:
        raise HTTPException(400, "Group id required")
    path = user_group_file(owner_userid, gid)
    prev, _ = gh_get_json(path)
    if not isinstance(prev, dict):
        prev = {}
    mult = max(0.01, float(payload.get("multiplier", 1) or 1))
    obj  = {"id": prev.get("id") or gid, "name": payload.get("name") or gid,
            "multiplier": mult, "members": payload.get("members") or [],
            "created_at": prev.get("created_at") or utcnow_iso(), "updated_at": utcnow_iso()}
    gh_put_json(path, obj, message=f"edit group {owner_userid}:{gid}")
    return {"ok": True, "group": obj}

@app.post("/delete_group")
async def delete_group(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(request, userid=payload.get("userid") or payload.get("owner_userid"))
    if not owner_userid:
        raise HTTPException(401, "Missing owner userid")
    ids = payload.get("ids") or payload.get("names") or []
    if not isinstance(ids, list):
        ids = [ids]
    deleted, missing, errors = [], [], []
    for gid in ids:
        try:
            gid  = str(gid).strip()
            path = user_group_file(owner_userid, gid)
            _, sha = gh_get_json(path)
            if not sha:
                missing.append(gid); continue
            (deleted if gh_delete_path(path, sha, f"delete group {owner_userid}:{gid}") else missing).append(gid)
        except Exception as e:
            errors.append(str(e))
    return {"ok": True, "deleted": deleted, "missing": missing, "errors": errors}


# ─────────────────────────────────────────────────────────────
# Copy Trading CRUD
# ─────────────────────────────────────────────────────────────
@app.get("/list_copytrading_setups")
async def list_copytrading_setups(request: Request, userid: str = None, user_id: str = None):
    owner_userid = resolve_owner_userid(request, userid=userid, user_id=user_id)
    if not owner_userid:
        return {"setups": []}
    setups = []
    try:
        for ent in (gh_list_dir(user_copy_dir(owner_userid)) or []):
            if not isinstance(ent, dict) or ent.get("type") != "file":
                continue
            if not ent.get("name", "").endswith(".json") or not ent.get("path"):
                continue
            obj, _ = gh_get_json(ent["path"])
            if not isinstance(obj, dict) or not obj:
                continue
            sid = obj.get("id") or obj.get("name") or ent["name"].replace(".json", "")
            setups.append({"id": sid, "name": obj.get("name", sid),
                           "master":      obj.get("master", ""),
                           "children":    obj.get("children", []) or [],
                           "multipliers": obj.get("multipliers", {}) or {},
                           "enabled":     bool(obj.get("enabled", False))})
    except Exception:
        pass
    return {"setups": setups}

@app.post("/save_copytrading_setup")
async def save_copytrading_setup(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(request, userid=payload.get("userid") or payload.get("owner_userid"))
    if not owner_userid:
        raise HTTPException(401, "Missing owner userid")
    name = (payload.get("name") or "").strip()
    sid  = (payload.get("id") or name).strip()
    if not sid:
        raise HTTPException(400, "Setup name required")
    master   = (payload.get("master") or "").strip()
    children = payload.get("children") or []
    if not master or not isinstance(children, list) or not children:
        raise HTTPException(400, "Master + at least one child required")
    path     = user_copy_file(owner_userid, sid)
    prev, _  = gh_get_json(path)
    if not isinstance(prev, dict):
        prev = {}
    enabled  = payload.get("enabled")
    if enabled is None:
        enabled = prev.get("enabled", False)
    obj = {"id": sid, "name": name or sid, "master": master, "children": children,
           "multipliers": payload.get("multipliers") or {},
           "enabled": bool(enabled),
           "created_at": prev.get("created_at") or utcnow_iso(), "updated_at": utcnow_iso()}
    gh_put_json(path, obj, message=f"save copy setup {owner_userid}:{sid}")
    gh_cache_invalidate(path)
    global _copy_setups_cache_ts
    _copy_setups_cache_ts = 0.0
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
        raise HTTPException(401, "Missing owner userid")
    ids = payload.get("ids") or []
    if not isinstance(ids, list):
        ids = [ids]
    if not ids:
        one = payload.get("id") or payload.get("setup_id") or payload.get("name")
        if one:
            ids = [one]
    updated, missing, errors = [], [], []
    for sid in ids:
        try:
            sid  = str(sid).strip()
            path = user_copy_file(owner_userid, sid)
            obj, _ = gh_get_json(path)
            if not isinstance(obj, dict) or not obj:
                missing.append(sid); continue
            obj["enabled"]    = bool(value)
            obj["updated_at"] = utcnow_iso()
            gh_put_json(path, obj, message=f"{'enable' if value else 'disable'} copy {owner_userid}:{sid}")
            gh_cache_invalidate(path)
            _copy_setups_cache_ts = 0.0
            updated.append(sid)
        except Exception as e:
            errors.append(str(e))
    return {"ok": True, "updated": updated, "missing": missing, "errors": errors}

@app.post("/delete_copy_setup")
@app.post("/delete_copytrading_setup")
async def delete_copy_setup(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(request, userid=payload.get("userid") or payload.get("owner_userid"))
    if not owner_userid:
        raise HTTPException(401, "Missing owner userid")
    ids = payload.get("ids") or []
    if not isinstance(ids, list):
        ids = [ids]
    if not ids:
        one = payload.get("id") or payload.get("setup_id") or payload.get("name")
        if one:
            ids = [one]
    deleted, missing, errors = [], [], []
    for sid in ids:
        try:
            sid  = str(sid).strip()
            path = user_copy_file(owner_userid, sid)
            _, sha = gh_get_json(path)
            if not sha:
                missing.append(sid); continue
            (deleted if gh_delete_path(path, sha, f"delete copy setup {owner_userid}:{sid}") else missing).append(sid)
        except Exception as e:
            errors.append(str(e))
    return {"ok": True, "deleted": deleted, "missing": missing, "errors": errors}


# ─────────────────────────────────────────────────────────────
# Orders
# ─────────────────────────────────────────────────────────────
@app.get("/get_orders")
def get_orders(request: Request, userid: str = None, user_id: str = None):
    owner_userid = resolve_owner_userid(request, userid=userid, user_id=user_id)
    orders_data  = OrderedDict(pending=[], traded=[], rejected=[], cancelled=[], others=[])

    for client_id, sess in list(mofsl_sessions.items()):
        try:
            if not isinstance(sess, dict):
                continue
            if owner_userid and str(sess.get("owner_userid","")).strip() != str(owner_userid).strip():
                continue
            name  = sess.get("name","") or client_id
            mofsl = sess.get("mofsl")
            uid   = sess.get("userid", client_id)
            if not mofsl or not uid:
                continue

            today = datetime.now().strftime("%d-%b-%Y 09:00:00")
            resp  = mofsl.GetOrderBook({"clientcode": uid, "datetimestamp": today})
            if resp and resp.get("status") != "SUCCESS":
                logging.error(f"Error fetching orders for {name}: {resp.get('message','')}")
            orders = (resp.get("data", []) if resp else [])
            if not isinstance(orders, list):
                orders = []

            for order in orders:
                od = {"name": name, "client_id": uid,
                      "symbol": order.get("symbol",""),
                      "transaction_type": order.get("buyorsell",""),
                      "quantity": order.get("orderqty",""),
                      "price":    order.get("price",""),
                      "status":   order.get("orderstatus",""),
                      "order_id": order.get("uniqueorderid","")}
                st = (order.get("orderstatus","") or "").lower()
                if "confirm" in st:       orders_data["pending"].append(od)
                elif "traded" in st:      orders_data["traded"].append(od)
                elif "rejected" in st or "error" in st: orders_data["rejected"].append(od)
                elif "cancel" in st:      orders_data["cancelled"].append(od)
                else:                     orders_data["others"].append(od)
        except Exception as e:
            print(f"❌ Error fetching orders for {client_id}: {e}")

    return dict(orders_data)

@app.post("/cancel_order")
async def cancel_order(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(request, userid=payload.get("userid") or payload.get("user_id"))
    orders = (payload or {}).get("orders", [])
    if not orders:
        raise HTTPException(400, "No orders received.")

    messages, threads, lock = [], [], threading.Lock()

    def find_sess(order):
        cid = (order or {}).get("client_id") or (order or {}).get("userid") or ""
        if cid:
            s = mofsl_sessions.get(cid)
            if s and s.get("owner_userid","") == owner_userid:
                return s
        nm = (order or {}).get("name","")
        for s in mofsl_sessions.values():
            if s.get("owner_userid","") == owner_userid and s.get("name") == nm:
                return s
        return None

    def cancel_one(order):
        oid  = order.get("order_id")
        sess = find_sess(order)
        if not sess:
            with lock: messages.append(f"❌ Session not found for {order.get('name','?')}")
            return
        try:
            resp = sess["mofsl"].CancelOrder(oid, sess["userid"])
            msg  = (resp.get("message","") or "").lower()
            with lock:
                messages.append(f"{'✅' if 'cancel order request sent' in msg else '❌'} {oid} for {sess.get('name','')}: {resp.get('message','')}")
        except Exception as e:
            with lock: messages.append(f"❌ Error cancelling {oid}: {e}")

    for o in orders:
        t = threading.Thread(target=cancel_one, args=(o,)); t.start(); threads.append(t)
    for t in threads: t.join()
    return {"message": messages}


# ─────────────────────────────────────────────────────────────
# Positions
# ─────────────────────────────────────────────────────────────
@app.get("/get_positions")
def get_positions(request: Request, userid: str = None, user_id: str = None):
    owner_userid   = resolve_owner_userid(request, userid=userid, user_id=user_id)
    positions_data = {"open": [], "closed": []}
    new_meta: Dict = {}
    global position_meta

    for client_id, sess in list(mofsl_sessions.items()):
        try:
            if not isinstance(sess, dict): continue
            if owner_userid and str(sess.get("owner_userid","")).strip() != str(owner_userid).strip(): continue
            name  = str(sess.get("name","") or client_id)
            mofsl = sess.get("mofsl")
            uid   = str(sess.get("userid", client_id))
            if not mofsl or not uid: continue

            resp = mofsl.GetPosition()
            if not resp or resp.get("status") != "SUCCESS": continue
            positions = resp.get("data") or []
            if not isinstance(positions, list): continue

            for pos in positions:
                bq = float(pos.get("buyquantity") or 0)
                sq = float(pos.get("sellquantity") or 0)
                qty = bq - sq
                ba = float(pos.get("buyamount") or 0)
                sa = float(pos.get("sellamount") or 0)
                buy_avg  = (ba / bq) if bq else 0.0
                sell_avg = (sa / sq) if sq else 0.0
                ltp = float(pos.get("LTP") or 0)
                bp  = float(pos.get("bookedprofitloss") or 0)
                net = (ltp - buy_avg)*qty if qty > 0 else (sell_avg - buy_avg)*abs(qty) if qty < 0 else bp

                symbol    = str(pos.get("symbol") or "")
                exchange  = str(pos.get("exchange") or "")
                token     = str(pos.get("symboltoken") or "")
                product   = str(pos.get("productname") or "")

                if qty != 0 and symbol:
                    new_meta[(uid, symbol)] = {"exchange": exchange, "symboltoken": token,
                                               "producttype": product, "client_id": uid}

                row = {"name": name, "client_id": uid, "symbol": symbol, "quantity": qty,
                       "buy_avg": round(buy_avg, 2), "sell_avg": round(sell_avg, 2),
                       "net_profit": round(net, 2)}
                (positions_data["closed"] if qty == 0 else positions_data["open"]).append(row)
        except Exception as e:
            print(f"❌ Error fetching positions for {client_id}: {e}")

    with _position_meta_lock:
        position_meta = new_meta
    return positions_data

@app.post("/close_position")
async def close_position(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(request, userid=payload.get("userid") or payload.get("user_id"))
    positions    = (payload or {}).get("positions", [])
    messages, threads, lock = [], [], threading.Lock()

    min_qty_map = {}
    try:
        conn = sqlite3.connect(SYMBOL_DB_PATH)
        cur  = conn.cursor()
        cur.execute(f"SELECT [Security ID], [Min Qty] FROM {SYMBOL_TABLE}")
        for sid, qty in cur.fetchall():
            if sid:
                try: min_qty_map[str(sid)] = int(qty) if qty else 1
                except Exception: min_qty_map[str(sid)] = 1
        conn.close()
    except Exception as e:
        print(f"❌ Error reading min_qty: {e}")

    def find_sess(name, cid_hint=""):
        if cid_hint:
            s = mofsl_sessions.get(cid_hint)
            if isinstance(s, dict) and (not owner_userid or str(s.get("owner_userid","")).strip() == str(owner_userid).strip()):
                return cid_hint, s
        for cid, s in mofsl_sessions.items():
            if not isinstance(s, dict): continue
            if owner_userid and str(s.get("owner_userid","")).strip() != str(owner_userid).strip(): continue
            if (s.get("name") or "").strip().lower() == (name or "").strip().lower():
                return cid, s
        return "", None

    def close_one(pos):
        name    = (pos or {}).get("name") or ""
        symbol  = (pos or {}).get("symbol") or ""
        qty     = float((pos or {}).get("quantity", 0) or 0)
        txtype  = (pos or {}).get("transaction_type") or ""
        cid_hint = (pos or {}).get("client_id") or ""
        with _position_meta_lock:
            meta = position_meta.get((cid_hint, symbol)) or position_meta.get((name, symbol)) or {}
        cid, sess = find_sess(name, cid_hint=cid_hint)
        if not meta or not sess:
            with lock: messages.append(f"❌ Missing session/meta for {name} - {symbol}"); return
        mofsl_ = sess.get("mofsl"); uid_ = sess.get("userid") or cid
        if not mofsl_ or not uid_:
            with lock: messages.append(f"❌ Invalid session for {name} - {symbol}"); return
        token   = meta.get("symboltoken")
        min_qty = min_qty_map.get(str(token), 1)
        lots    = max(1, int(abs(qty) // min_qty)) if min_qty and abs(qty) >= min_qty else 1
        order   = {"clientcode": uid_, "exchange": meta.get("exchange",""),
                   "symboltoken": token, "buyorsell": txtype.upper(),
                   "ordertype": "MARKET", "producttype": meta.get("producttype",""),
                   "orderduration": "DAY", "price": 0, "triggerprice": 0,
                   "quantityinlot": lots, "disclosedquantity": 0,
                   "amoorder": "N", "algoid": "", "goodtilldate": "", "tag": ""}
        try:
            resp = mofsl_.PlaceOrder(order)
            ok   = isinstance(resp, dict) and resp.get("status") == "SUCCESS"
            with lock: messages.append(f"{'✅' if ok else '❌'} {'Close requested' if ok else 'Close failed'}: {name} {symbol}")
        except Exception as e:
            with lock: messages.append(f"❌ Error closing {name} {symbol}: {e}")

    for p in positions:
        t = threading.Thread(target=close_one, args=(p,)); t.start(); threads.append(t)
    for t in threads: t.join()
    return {"message": messages}


# ─────────────────────────────────────────────────────────────
# Holdings + Summary
# ─────────────────────────────────────────────────────────────
summary_data_global: Dict = {}

def get_available_margin(Mofsl, clientcode):
    try:
        r = Mofsl.GetReportMarginSummary(clientcode)
        if r.get("status") != "SUCCESS": return 0
        for item in r.get("data", []):
            if item.get("particulars") == "Total Available Margin for Cash":
                return float(item.get("amount", 0))
    except Exception as e:
        print(f"❌ Margin error for {clientcode}: {e}")
    return 0

@app.get("/get_holdings")
def get_holdings(request: Request, userid: str = None, user_id: str = None):
    owner_userid = resolve_owner_userid(request, userid=userid, user_id=user_id)
    if not owner_userid:
        return {"ok": False, "error": "userid missing"}

    holdings_data, summary_data = [], {}
    client_capital_map: Dict = {}

    try:
        for ent in (gh_list_dir(f"data/users/{owner_userid}/clients") or []):
            if not isinstance(ent, dict) or ent.get("type") != "file": continue
            if not str(ent.get("name","")).endswith(".json") or not ent.get("path"): continue
            co, _ = gh_get_json_cached(ent["path"])
            if not isinstance(co, dict): continue
            cid = str(co.get("userid") or co.get("client_id") or "").strip()
            nm  = str(co.get("name","") or cid).strip()
            cap = co.get("capital") or co.get("base_amount") or 0
            if cid: client_capital_map[cid] = cap
            if nm:  client_capital_map[nm]  = cap
    except Exception as e:
        print("Capital map error:", e)

    for client_id, sess in list(mofsl_sessions.items()):
        try:
            if not isinstance(sess, dict): continue
            if str(sess.get("owner_userid","")).strip() != str(owner_userid).strip(): continue
            name  = sess.get("name","") or client_id
            Mofsl = sess.get("mofsl")
            uid_  = sess.get("userid") or client_id
            if not Mofsl or not uid_: continue

            resp = Mofsl.GetDPHolding(uid_)
            if not resp or resp.get("status") != "SUCCESS": continue
            holdings   = resp.get("data", [])
            invested   = 0.0; total_pnl = 0.0

            for h in holdings:
                symbol   = (h.get("scripname") or "").strip()
                qty      = float(h.get("dpquantity", 0) or 0)
                buy_avg  = float(h.get("buyavgprice", 0) or 0)
                scripcode = h.get("nsesymboltoken")
                if not scripcode or qty <= 0: continue

                ltp_resp = Mofsl.GetLtp({"clientcode": uid_, "exchange": "NSE", "scripcode": int(scripcode)})
                ltp      = float((ltp_resp or {}).get("data", {}).get("ltp", 0) or 0) / 100
                pnl      = round((ltp - buy_avg) * qty, 2)
                invested += qty * buy_avg; total_pnl += pnl
                holdings_data.append({"name": name, "symbol": symbol, "quantity": qty,
                                       "buy_avg": round(buy_avg,2), "ltp": round(ltp,2), "pnl": pnl})

            capital = float(client_capital_map.get(uid_) or client_capital_map.get(name) or 0)
            current_value    = invested + total_pnl
            available_margin = get_available_margin(Mofsl, uid_)
            summary_data[name] = {"name": name, "capital": round(capital,2),
                                   "invested": round(invested,2), "pnl": round(total_pnl,2),
                                   "current_value": round(current_value,2),
                                   "available_margin": round(available_margin,2),
                                   "net_gain": round((current_value + available_margin) - capital, 2)}
        except Exception as e:
            print(f"❌ Holdings error for {client_id}: {e}")

    global summary_data_global
    summary_data_global[str(owner_userid).strip()] = summary_data
    return {"holdings": holdings_data, "summary": list(summary_data.values())}

@app.get("/get_summary")
def get_summary(request: Request, userid: str = None, user_id: str = None):
    owner_userid = resolve_owner_userid(request, userid=userid, user_id=user_id)
    if not owner_userid:
        return {"ok": False, "error": "userid missing", "summary": []}
    data = (summary_data_global or {}).get(str(owner_userid).strip(), {}) or {}
    return {"summary": list(data.values())}


# ─────────────────────────────────────────────────────────────
# Place Order
# FIX 3: _load_client_from_github is now the MODULE-LEVEL one
#         (no duplicate local definition inside place_order)
# ─────────────────────────────────────────────────────────────
def _parse_symbol_token(payload: dict):
    symbol   = (payload.get("symbol") or "").strip()
    exch     = (payload.get("exchange") or "NSE").strip().upper()
    token    = payload.get("symboltoken") or payload.get("security_id") or payload.get("token")
    if symbol and "|" in symbol:
        parts = symbol.split("|")
        if len(parts) >= 3:
            exch  = (parts[0] or exch).strip().upper()
            token = parts[2].strip()
    return exch, _safe_int(token, 0)

def _get_group_members(owner_userid: str, group_name: str):
    try:
        obj, _ = gh_get_json(user_group_file(owner_userid, group_name))
        if not isinstance(obj, dict):
            return [], 1.0
        members = [str(m).strip() for m in (obj.get("members") or []) if str(m).strip()]
        mult    = max(0.01, float(obj.get("multiplier", 1) or 1))
        return members, mult
    except Exception:
        return [], 1.0

@app.post("/place_order")
async def place_order(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(request, userid=payload.get("userid"), user_id=payload.get("user_id"))
    if not owner_userid:
        raise HTTPException(401, "Missing owner userid")

    data = payload or {}
    try:
        print("📦 /place_order RAW =", json.dumps(data, ensure_ascii=False, default=str))
    except Exception:
        print("📦 /place_order RAW =", data)

    exch, symboltoken = _parse_symbol_token(data)
    if not symboltoken:
        raise HTTPException(400, "Missing/invalid symbol token")

    groupacc       = bool(data.get("groupacc", False))
    groups_raw     = data.get("groups", []) or []
    clients_raw    = data.get("clients", []) or []
    diffQty        = bool(data.get("diffQty", False))
    multiplier_on  = bool(data.get("multiplier", False))
    quantityinlot  = _safe_int(data.get("quantityinlot", 0), 0)
    perClientQty_raw = data.get("perClientQty", {}) or {}
    action         = (data.get("action") or "").strip().upper()
    ordertype      = (data.get("ordertype") or "").strip().upper()
    producttype    = (data.get("producttype") or "").strip().upper()
    orderduration  = (data.get("orderduration") or "").strip().upper()
    price          = _safe_float(data.get("price", 0), 0.0)
    triggerprice   = _safe_float(data.get("triggerprice", 0), 0.0)
    disclosedquantity = _safe_int(data.get("disclosedquantity", 0), 0)
    amoorder       = (data.get("amoorder") or "N").strip().upper()

    _re_uid1 = re.compile(r"(?:userid|client_id|client_code)'\s*:\s*'([^']+)'")
    _re_uid2 = re.compile(r'(?:userid|client_id|client_code)"\s*:\s*"([^"]+)"')

    def _extract_client_id(x) -> str:
        if isinstance(x, dict):
            return str(x.get("userid") or x.get("client_id") or x.get("client_code") or "").strip()
        if isinstance(x, str):
            s = x.strip()
            if "{" in s and "}" in s and any(k in s for k in ("userid","client_id","client_code")):
                m = _re_uid1.search(s) or _re_uid2.search(s)
                if m: return m.group(1).strip()
            return s
        return str(x or "").strip()

    def _extract_group_name(x) -> str:
        if isinstance(x, dict):
            return str(x.get("name") or x.get("group") or x.get("group_name") or "").strip()
        return str(x or "").strip()

    groups  = [_extract_group_name(g) for g in (groups_raw if isinstance(groups_raw, list) else []) if _extract_group_name(g)]
    clients = [_extract_client_id(c) for c in (clients_raw if isinstance(clients_raw, list) else []) if _extract_client_id(c)]
    perClientQty = {_extract_client_id(k): _safe_int(v, quantityinlot)
                    for k, v in (perClientQty_raw or {}).items() if _extract_client_id(k)}

    print("✅ Normalized groups:", groups)
    print("✅ Normalized clients:", clients)

    # FIX 3: use module-level _load_client_from_github (no local redefinition)
    def _ensure_session(client_id: str) -> dict:
        cid = str(client_id or "").strip()
        if not cid: return {}
        sess = mofsl_sessions.get(cid)
        if isinstance(sess, dict) and sess.get("mofsl"):
            return sess
        # Railway restart recovery — reload from GitHub and re-login
        cobj = _load_client_from_github(owner_userid, cid)   # ← module-level function
        if not isinstance(cobj, dict) or not cobj: return {}
        local_client = dict(cobj)
        local_client["owner_userid"] = str(owner_userid).strip()
        return mofsl_sessions.get(cid) or {} if motilal_login(local_client) else {}

    targets = []
    if groupacc:
        for gname in groups:
            members, gmult = _get_group_members(owner_userid, gname)
            members_norm   = [_extract_client_id(m) for m in members if _extract_client_id(m)]
            print(f"👥 group '{gname}' members={members_norm} gmult={gmult}")
            for cid in members_norm:
                q = quantityinlot
                if diffQty:     q = _safe_int(perClientQty.get(cid, q), q)
                if multiplier_on:
                    try: q = max(1, int(round(float(q) * float(gmult))))
                    except Exception: q = max(1, int(q))
                targets.append((gname, cid, int(max(1, q))))
    else:
        for cid in clients:
            q = quantityinlot
            if diffQty: q = _safe_int(perClientQty.get(cid, q), q)
            targets.append(("", cid, int(max(1, q))))

    print("🎯 targets:", targets)
    if not targets:
        raise HTTPException(400, "No target clients/groups selected")

    responses: Dict = {}
    lock    = threading.Lock()
    threads = []

    def _place_one(tag: str, client_id: str, qty: int):
        key  = f"{tag}:{client_id}" if tag else client_id
        sess = _ensure_session(client_id)
        if not isinstance(sess, dict) or not sess.get("mofsl"):
            with lock: responses[key] = {"status": "ERROR", "message": "Session not found"}
            return
        sess_owner = (sess.get("owner_userid") or "").strip()
        if sess_owner and sess_owner != str(owner_userid).strip():
            with lock: responses[key] = {"status": "ERROR", "message": "Session belongs to another user"}
            return
        mofsl_ = sess.get("mofsl")
        uid_   = sess.get("userid") or client_id
        order_payload = {
            "clientcode": str(uid_), "exchange": exch, "symboltoken": int(symboltoken),
            "buyorsell": action, "ordertype": ordertype, "producttype": producttype,
            "orderduration": orderduration, "price": float(price),
            "triggerprice": float(triggerprice), "quantityinlot": int(max(1, qty)),
            "disclosedquantity": int(disclosedquantity), "amoorder": amoorder,
            "algoid": "", "goodtilldate": "", "tag": tag or "",
        }
        print(f"🧾 Order payload for {key} =", order_payload)
        try:
            resp = mofsl_.PlaceOrder(order_payload)
        except Exception as e:
            resp = {"status": "ERROR", "message": str(e)}
        with lock: responses[key] = resp

    for (tag, cid, q) in targets:
        t = threading.Thread(target=_place_one, args=(tag, cid, q)); t.start(); threads.append(t)
    for t in threads: t.join()
    return {"success": True, "responses": responses}


# ─────────────────────────────────────────────────────────────
# Modify Order
# ─────────────────────────────────────────────────────────────
def now_ist_str() -> str:
    from datetime import timedelta
    return (datetime.utcnow() + timedelta(hours=5, minutes=30)).strftime("%d-%b-%Y %H:%M:%S")

@app.post("/modify_order")
def modify_order(request: Request, payload: dict = Body(...)) -> Dict[str, Any]:
    owner_userid = resolve_owner_userid(request, userid=(payload or {}).get("userid"),
                                        user_id=(payload or {}).get("user_id"))
    if not owner_userid:
        raise HTTPException(401, "Missing owner userid")

    data   = payload or {}
    orders = data.get("orders")
    if not isinstance(orders, list) or not orders:
        one = data.get("order")
        orders = [one] if isinstance(one, dict) else None
    if not orders:
        raise HTTPException(400, "Missing order(s)")

    messages: List[str] = []

    def _ni(x, d=None):
        try: return d if str(x).strip()=="" else int(float(str(x).strip()))
        except: return d
    def _nf(x, d=None):
        try: return d if str(x).strip()=="" else float(str(x).strip())
        except: return d
    def _pos(x):
        try: return x is not None and float(x) > 0
        except: return False

    def _ui_to_mo(ot):
        u = (ot or "").strip().upper().replace("-","_").replace(" ","_")
        return {"LIMIT":"LIMIT","MARKET":"MARKET","STOP_LOSS":"STOPLOSS","STOPLOSS":"STOPLOSS",
                "SL_LIMIT":"STOPLOSS","SL":"STOPLOSS","STOP_LOSS_MARKET":"SL-M",
                "STOPLOSS_MARKET":"SL-M","SL_MARKET":"SL-M"}.get(u,"")

    def _snap_to_mo(ot):
        u = (ot or "").strip().upper().replace("-","_").replace(" ","_")
        if u in ("SL_LIMIT","SL_L","STOPLOSS_LIMIT"): return "STOPLOSS"
        if u in ("SL_MARKET","SL_M","STOPLOSS_MARKET"): return "SL-M"
        return u if u in ("LIMIT","MARKET","STOPLOSS","SL-M") else ""

    def _infer_type(s):
        for k in ("newordertype","ordertype","orderType","OrderType"):
            t = _snap_to_mo(s.get(k))
            if t: return t
        has_p = any(_pos(_nf(s.get(k))) for k in ("newprice","orderprice","price","Price"))
        has_t = any(_pos(_nf(s.get(k))) for k in ("newtriggerprice","triggerprice","triggerPrice"))
        if has_t and has_p: return "STOPLOSS"
        if has_t: return "SL-M"
        if has_p: return "LIMIT"
        return "MARKET"

    def _get_session_for_row(r):
        cid = str(r.get("client_id") or "").strip()
        if cid:
            s = mofsl_sessions.get(cid)
            if isinstance(s, dict) and str(s.get("owner_userid","")).strip() == str(owner_userid).strip():
                return s
            for _, s in list(mofsl_sessions.items()):
                if not isinstance(s, dict): continue
                if str(s.get("owner_userid","")).strip() != str(owner_userid).strip(): continue
                if str(s.get("userid") or "").strip() == cid: return s
        nm = (r.get("name") or "").strip().lower()
        if nm:
            for _, s in list(mofsl_sessions.items()):
                if not isinstance(s, dict): continue
                if str(s.get("owner_userid","")).strip() != str(owner_userid).strip(): continue
                if (s.get("name") or "").strip().lower() == nm: return s
        return None

    for row in (orders or []):
        try:
            name = (row.get("name") or "").strip() or "<unknown>"
            oid  = str(row.get("order_id") or row.get("orderId") or "").strip()
            if not oid:
                messages.append(f"ℹ️ {name}: skipped (missing order_id)"); continue
            sess = _get_session_for_row(row)
            if not sess:
                messages.append(f"❌ {name} ({oid}): session not available"); continue
            uid  = str(sess.get("userid") or "").strip()
            sdk  = sess.get("mofsl")
            if not uid or not sdk:
                messages.append(f"❌ {name} ({oid}): session not available"); continue

            price_in = row.get("price")
            trig_in  = row.get("triggerPrice", row.get("triggerprice"))
            qty_in   = _ni(row.get("quantity"))

            # Try to get live order details
            snap = None
            try:
                resp = sdk.GetOrderDetails({"clientcode": uid, "uniqueorderid": oid})
                if isinstance(resp, dict) and resp.get("status") == "SUCCESS":
                    d = resp.get("data")
                    snap = d[0] if isinstance(d, list) and d else (d if isinstance(d, dict) else None)
            except Exception: pass
            if not snap:
                try:
                    ts = now_ist_str().split(" ")[0] + " 09:00:00"
                    ob = sdk.GetOrderBook({"clientcode": uid, "datetimestamp": ts})
                    for r2 in ((ob.get("data") or []) if isinstance(ob, dict) else []):
                        if str(r2.get("uniqueorderid","")) == str(oid): snap = r2; break
                except Exception: pass
            snap = snap or {}

            shares = qty_in if _pos(qty_in) else (_ni(snap.get("orderqty")) or 0)
            lots   = int(shares) if _pos(shares) else 0
            if lots <= 0:
                messages.append(f"❌ {name} ({oid}): cannot determine quantity"); continue

            last_mod = next((v for k in ("lastmodifiedtime","lastmodifieddatetime","recordinsertime",
                                          "recordinserttime","modifydatetime")
                             if isinstance(snap.get(k), str) and snap[k].strip()
                             for v in [snap[k].strip()]), now_ist_str())

            ui_type = _ui_to_mo(row.get("orderType") or row.get("ordertype")) or _infer_type(snap)
            out = {"clientcode": uid, "uniqueorderid": oid,
                   "newordertype": ui_type or "MARKET",
                   "neworderduration": str(row.get("validity") or "DAY").upper(),
                   "newdisclosedquantity": 0, "lastmodifiedtime": last_mod,
                   "newquantityinlot": lots}
            if _pos(_nf(price_in)): out["newprice"]        = float(price_in)
            if _pos(_nf(trig_in)):  out["newtriggerprice"] = float(trig_in)

            if out["newordertype"] == "LIMIT" and "newprice" not in out:
                messages.append(f"❌ {name} ({oid}): LIMIT requires Price > 0"); continue
            if out["newordertype"] == "STOPLOSS" and not ("newprice" in out and "newtriggerprice" in out):
                messages.append(f"❌ {name} ({oid}): STOPLOSS requires Price & Trigger > 0"); continue
            if out["newordertype"] == "SL-M" and "newtriggerprice" not in out:
                messages.append(f"❌ {name} ({oid}): SL-M requires Trigger > 0"); continue

            resp = sdk.ModifyOrder(out)
            ok, msg = False, ""
            if isinstance(resp, dict):
                status = str(resp.get("Status") or resp.get("status") or "").lower()
                code   = str(resp.get("ErrorCode") or resp.get("errorCode") or "")
                msg    = resp.get("Message") or resp.get("message") or code
                ok     = "success" in status or resp.get("Success") is True or code in ("0","200","201")
            else:
                ok = bool(resp)
            messages.append(f"{'✅' if ok else '❌'} {name} ({oid}): {'Modified' if ok else (msg or 'modify failed')}")
        except Exception as e:
            messages.append(f"❌ {row.get('name','?')} ({row.get('order_id','?')}): {e}")

    return {"message": messages}


# ─────────────────────────────────────────────────────────────
# Copy Trading Engine
# ─────────────────────────────────────────────────────────────
order_mapping:               Dict = {}
processed_order_ids_placed:  Dict = {}
processed_order_ids_canceled: Dict = {}
COPY_WINDOW_SECONDS = 120

def load_active_copy_setups_all():
    global _copy_setups_403_until, _copy_setups_cache, _copy_setups_cache_ts
    if time.time() < _copy_setups_403_until:
        return _copy_setups_cache
    if _copy_setups_cache and (time.time() - _copy_setups_cache_ts) < COPY_SETUPS_CACHE_TTL:
        return _copy_setups_cache

    setups = []
    try:
        users = gh_list_dir("data/users") or []
        for user in users:
            if user.get("type") != "dir": continue
            owner = user.get("name")
            try:
                files = gh_list_dir(f"data/users/{owner}/copytrading") or []
            except GitHubStorageError as e:
                if e.status_code == 403:
                    _copy_setups_403_until = time.time() + 60
                continue
            except Exception: continue
            for f in files:
                if f.get("type") != "file" or not f.get("name","").endswith(".json"): continue
                try:
                    setup, _ = gh_get_json(f["path"])
                except Exception: continue
                if not setup or not setup.get("enabled", False): continue
                setup["owner_userid"] = owner
                setups.append(setup)
    except GitHubStorageError as e:
        if e.status_code == 403: _copy_setups_403_until = time.time() + 60
    except Exception as e:
        logging.error(f"load_active_copy_setups_all error: {e}")

    if setups:
        _copy_setups_cache    = setups
        _copy_setups_cache_ts = time.time()
    return setups

def process_copy_order(order: dict, setup: dict):
    owner      = str(setup.get("owner_userid") or "").strip()
    setup_name = setup.get("name") or setup.get("id") or "setup"
    setup_key  = f"{owner}:{setup.get('id') or setup_name}"
    master_oid = str(order.get("uniqueorderid") or "").strip()
    if not master_oid or master_oid == "0": return

    try:
        dt_obj = datetime.strptime(order.get("recordinserttime",""), "%d-%b-%Y %H:%M:%S")
    except Exception: return
    if (int(time.time()) - int(dt_obj.timestamp())) > COPY_WINDOW_SECONDS: return

    order_status = str(order.get("orderstatus") or "").upper()
    processed_order_ids_placed.setdefault(setup_key, set())
    processed_order_ids_canceled.setdefault(setup_key, set())
    order_mapping.setdefault(setup_key, {})

    if order_status in ("CONFIRM", "TRADED"):
        if master_oid in processed_order_ids_placed[setup_key]: return
        children    = setup.get("children") or []
        multipliers = setup.get("multipliers") or {}
        print(f"🧬 COPY triggered master={setup.get('master')} order={master_oid}")

        for child_id in children:
            child_id = str(child_id)
            sess     = mofsl_sessions.get(child_id)
            if not sess or not sess.get("mofsl"):
                print(f"🔁 re-logging child {child_id}")
                cobj = _load_client_from_github(owner, child_id)
                if cobj: motilal_login(cobj)
                sess = mofsl_sessions.get(child_id)
            if not sess or not sess.get("mofsl"):
                print(f"❌ child session missing {child_id}"); continue

            mult     = int(multipliers.get(child_id, 1))
            master_q = int(order.get("orderqty", 1))
            min_qty  = _min_qty_from_symbol_db(order.get("symboltoken"))
            qty_lot  = max(1, int(max(1, master_q * mult) // max(1, min_qty)))

            ot  = str(order.get("ordertype") or "").upper().strip()
            if ot == "SL": ot = "STOPLOSS"
            dur = str(order.get("orderduration") or order.get("validity") or "DAY").upper().strip()
            if dur in ("DAY","NORMAL"): dur = "DAY"
            pt  = str(order.get("producttype") or "CNC").upper().strip()
            amo = str(order.get("amoorder") or "N").upper().strip()
            if amo not in ("Y","N"): amo = "N"

            child_order = {
                "clientcode": sess["userid"], "exchange": order.get("exchange","NSE"),
                "symboltoken": int(order.get("symboltoken") or 0),
                "buyorsell": str(order.get("buyorsell") or "").upper().strip(),
                "ordertype": ot, "producttype": pt, "orderduration": dur,
                "price": float(order.get("price") or 0),
                "triggerprice": float(order.get("triggerprice") or 0),
                "quantityinlot": qty_lot, "disclosedquantity": 0,
                "amoorder": amo, "algoid": "", "goodtilldate": "", "tag": setup_name,
            }
            try:
                print(f"📦 [COPY] child {child_id}: {child_order}")
                resp = sess["mofsl"].PlaceOrder(child_order)
                print(f"📨 [COPY] child resp {child_id}: {resp}")
                coid = (resp or {}).get("uniqueorderid")
                if coid: order_mapping[setup_key].setdefault(master_oid, {})[child_id] = coid
                else: print(f"❌ child FAILED {child_id} resp={resp}")
            except Exception as e:
                print(f"❌ child error {child_id}: {e}")

        processed_order_ids_placed[setup_key].add(master_oid)

    elif "CANCEL" in order_status:
        if master_oid in processed_order_ids_canceled[setup_key]: return
        for child_id, coid in (order_mapping.get(setup_key, {}).get(master_oid, {}) or {}).items():
            sess = mofsl_sessions.get(child_id)
            if not sess or not sess.get("mofsl"): continue
            try: sess["mofsl"].CancelOrder(coid, sess["userid"]); print(f"✅ cancel propagated {child_id}")
            except Exception as e: print("❌ cancel error:", e)
        processed_order_ids_canceled[setup_key].add(master_oid)

def synchronize_copy_trading():
    setups = load_active_copy_setups_all()
    if not setups: return

    def handle_setup(setup):
        owner     = str(setup.get("owner_userid") or "").strip()
        master_id = str(setup.get("master") or "").strip()
        if not owner or not master_id: return
        sess = _ensure_session_for_copy(owner, master_id)
        if not isinstance(sess, dict) or not sess.get("mofsl"):
            print(f"❌ [COPY] master session missing master={master_id}"); return
        today = datetime.now().strftime("%d-%b-%Y 09:00:00")
        try:
            resp = sess["mofsl"].GetOrderBook({"clientcode": str(sess.get("userid") or master_id), "datetimestamp": today})
            for order in ((resp.get("data") or []) if resp and isinstance(resp, dict) else []):
                try: process_copy_order(order, setup)
                except Exception as e: print(f"❌ [COPY] process_copy_order: {e}")
        except Exception as e:
            print(f"❌ [COPY] GetOrderBook error master={master_id}: {e}")

    threads = [threading.Thread(target=handle_setup, args=(s,)) for s in setups]
    for t in threads: t.start()
    for t in threads: t.join()

def motilal_copy_trading_loop():
    print("✅ Copy Trading Engine running…")
    while True:
        try: synchronize_copy_trading()
        except Exception as e: print("❌ Copy trading sync error:", e)
        time.sleep(10)

_copy_thread_started = False
def start_copy_trading_thread():
    global _copy_thread_started
    if _copy_thread_started: return
    _copy_thread_started = True
    threading.Thread(target=motilal_copy_trading_loop, daemon=True).start()
