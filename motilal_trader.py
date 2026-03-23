"""
Motilal Single File - Railway Backend
Storage: PostgreSQL
Copy Engine: Pure polling, 1s loop, 5s order window
Symbol Master: Motilal OpenAPI scrip CSVs (8 exchanges) -> PostgreSQL, daily 8:00 AM IST refresh
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta
from io import BytesIO, StringIO
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import psycopg2
import psycopg2.extras
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
# Safe type helpers
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
APP_NAME           = os.getenv("APP_NAME", "Motilal Trader Backend")
API_VERSION        = os.getenv("API_VERSION", "2.0.0")
SECRET_KEY         = os.getenv("SECRET_KEY") or "CHANGE_ME_PLEASE_SET_SECRET_KEY"
TOKEN_EXPIRE_HOURS = int(os.getenv("TOKEN_EXPIRE_HOURS", "24"))
DATABASE_URL       = os.getenv("DATABASE_URL", "")

cors_origins_raw = (os.getenv("CORS_ORIGINS") or "").strip()
if cors_origins_raw == "*":
    allow_origins     = ["*"]
    allow_credentials = False
elif cors_origins_raw:
    allow_origins     = [o.strip().rstrip("/") for o in cors_origins_raw.split(",") if o.strip()]
    allow_credentials = True
else:
    allow_origins     = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://woi-mosl-trader.vercel.app",
    ]
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
        print("WARNING: SECRET_KEY not set. Using insecure default.")


def password_hash(password: str, salt: str) -> str:
    return hashlib.sha256((salt + ":" + password).encode()).hexdigest()


def create_token(userid: str) -> str:
    require_secret()
    return jwt_encode(
        {"userid": userid, "exp": int(time.time()) + TOKEN_EXPIRE_HOURS * 3600},
        SECRET_KEY,
    )


def _safe_filename(s: str) -> str:
    s = (s or "").strip().replace(" ", "_")
    return re.sub(r"[^A-Za-z0-9_\-]", "_", s)[:80] or "item"


# ─────────────────────────────────────────────────────────────
# PostgreSQL connection pool
# ─────────────────────────────────────────────────────────────
_pg_lock      = threading.Lock()
_pg_pool: List = []
_PG_POOL_SIZE  = 5


def _make_pg_conn():
    url = DATABASE_URL
    if not url:
        raise RuntimeError("DATABASE_URL environment variable not set")
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    conn = psycopg2.connect(url, cursor_factory=psycopg2.extras.RealDictCursor)
    conn.autocommit = False
    return conn


@contextmanager
def get_db():
    with _pg_lock:
        conn = _pg_pool.pop() if _pg_pool else None
    if conn is None:
        conn = _make_pg_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        try:
            conn.cursor().execute("SELECT 1")
            with _pg_lock:
                if len(_pg_pool) < _PG_POOL_SIZE:
                    _pg_pool.append(conn)
                    return
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


def db_execute(sql: str, params=None, fetch: str = "none"):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(sql, params or ())
        if fetch == "one":
            return cur.fetchone()
        if fetch == "all":
            return cur.fetchall()
        return None


# ─────────────────────────────────────────────────────────────
# DB schema bootstrap
# ─────────────────────────────────────────────────────────────
_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    userid        TEXT PRIMARY KEY,
    email         TEXT NOT NULL,
    salt          TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ DEFAULT NOW(),
    updated_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS clients (
    id             SERIAL PRIMARY KEY,
    owner_userid   TEXT NOT NULL,
    userid         TEXT NOT NULL,
    name           TEXT DEFAULT '',
    password       TEXT DEFAULT '',
    pan            TEXT DEFAULT '',
    apikey         TEXT DEFAULT '',
    totpkey        TEXT DEFAULT '',
    capital        NUMERIC DEFAULT 0,
    session_active BOOLEAN DEFAULT FALSE,
    last_login_ts  BIGINT DEFAULT 0,
    last_login_msg TEXT DEFAULT '',
    UNIQUE(owner_userid, userid)
);

CREATE TABLE IF NOT EXISTS groups (
    id           SERIAL PRIMARY KEY,
    owner_userid TEXT NOT NULL,
    name         TEXT NOT NULL,
    multiplier   NUMERIC DEFAULT 1,
    members      JSONB DEFAULT '[]',
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    updated_at   TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(owner_userid, name)
);

CREATE TABLE IF NOT EXISTS copy_setups (
    id           SERIAL PRIMARY KEY,
    owner_userid TEXT NOT NULL,
    name         TEXT NOT NULL,
    master       TEXT NOT NULL,
    children     JSONB DEFAULT '[]',
    multipliers  JSONB DEFAULT '{}',
    enabled      BOOLEAN DEFAULT FALSE,
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    updated_at   TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(owner_userid, name)
);

CREATE TABLE IF NOT EXISTS symbol_master (
    security_id  TEXT NOT NULL PRIMARY KEY,
    exchange     TEXT NOT NULL,
    stock_symbol TEXT NOT NULL,
    min_qty      INTEGER NOT NULL DEFAULT 1,
    updated_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sm_exchange
    ON symbol_master (exchange);
CREATE INDEX IF NOT EXISTS idx_sm_symbol
    ON symbol_master (stock_symbol);
CREATE INDEX IF NOT EXISTS idx_sm_symbol_lower
    ON symbol_master ((LOWER(stock_symbol)));

CREATE TABLE IF NOT EXISTS app_meta (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
"""


def _init_db():
    try:
        with get_db() as conn:
            conn.cursor().execute(_SCHEMA_SQL)
        print("✅ PostgreSQL schema ready")
    except Exception as e:
        print(f"❌ DB schema init failed: {e}")
        raise


# ─────────────────────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────────────────────
def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> str:
    require_secret()
    if not credentials or not credentials.credentials:
        raise HTTPException(401, "Missing token")
    try:
        payload = jwt_decode(credentials.credentials, SECRET_KEY)
        userid  = (payload.get("userid") or "").strip()
        if not userid:
            raise HTTPException(401, "Invalid token")
        return userid
    except JWTError as e:
        msg = str(e)
        raise HTTPException(401, "Token expired" if "expired" in msg.lower() else "Invalid token")


def resolve_owner_userid(
    request: Request, userid: Optional[str] = None, user_id: Optional[str] = None
) -> str:
    token_user = ""
    try:
        auth = request.headers.get("authorization") or request.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            payload    = jwt_decode(auth.split(" ", 1)[1].strip(), SECRET_KEY)
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
    name         = client.get("name", "")
    userid       = str(client.get("userid", "") or client.get("client_id", "") or "").strip()
    password     = client.get("password", "")
    pan          = client.get("pan", "")
    apikey       = client.get("apikey", "")
    totpkey      = client.get("totpkey", "")
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
                    "name":         name,
                    "userid":       userid,
                    "mofsl":        mofsl,
                    "login_ts":     int(time.time()),
                    "owner_userid": owner_userid,
                }
                print(f"✅ Logged in: {name} ({userid})")
                return True
            print(f"❌ Login failed: {name} ({userid}) → {resp.get('message', '')}")
            return False
        except Exception as e:
            print(f"❌ Login error: {name} ({userid}) :: {e}")
            return False


def _load_client_from_db(owner: str, client_userid: str) -> Optional[dict]:
    row = db_execute(
        "SELECT * FROM clients WHERE owner_userid=%s AND userid=%s",
        (owner, client_userid),
        fetch="one",
    )
    if not row:
        return None
    d = dict(row)
    d["owner_userid"] = owner
    return d


def _ensure_session_for_copy(owner: str, client_id: str) -> Optional[dict]:
    owner     = str(owner or "").strip()
    client_id = str(client_id or "").strip()
    if not owner or not client_id:
        return None

    sess = mofsl_sessions.get(client_id)
    if (
        isinstance(sess, dict)
        and _session_fresh(sess)
        and _norm_uid(sess.get("owner_userid", "")) == owner
        and sess.get("mofsl")
    ):
        return sess

    client_obj = _load_client_from_db(owner, client_id)
    if not client_obj:
        print(f"❌ [COPY] Client not found owner={owner} client_id={client_id}")
        return None

    try:
        ok = bool(motilal_login(client_obj))
    except Exception as e:
        print(f"❌ [COPY] Login exception: {e}")
        return None

    return mofsl_sessions.get(client_id) if ok else None


# ─────────────────────────────────────────────────────────────
# Symbol Master — Motilal OpenAPI scrip CSVs
#
# Download URL: https://openapi.motilaloswal.com/getscripmastercsv?name=<EXCHANGE>
#
# 8 exchanges downloaded in parallel every day at 08:00 IST:
#   NSE, BSE, NSEFO, NSECD, MCX, BSEFO, BSECD, NCDEX
#
# Column mapping from Motilal CSV:
#   exchangename  → exchange      (already correct — no translation needed)
#   scripcode     → security_id
#   scripname     → stock_symbol
#   marketlot     → min_qty
#
# No complex instrument-type mapping needed at all.
# ─────────────────────────────────────────────────────────────

MOSL_SCRIP_BASE_URL = "https://openapi.motilaloswal.com/getscripmastercsv?name="

# All 8 exchanges. NCDEX is kept — the UI dropdown already shows it (image 4).
MOSL_EXCHANGES = ["NSE", "BSE", "NSEFO", "NSECD", "MCX", "BSEFO", "BSECD", "NCDEX"]

_SYMBOL_REFRESH_LOCK      = threading.Lock()
_SYMBOL_REFRESH_META_KEY  = "mosl_scrip_master"
_SYMBOL_SCHEDULER_STARTED = False

IST_OFFSET_SECONDS = 5 * 3600 + 30 * 60


def _utc_now_ts() -> int:
    return int(time.time())


def _ist_datetime_now() -> datetime:
    return datetime.utcfromtimestamp(_utc_now_ts() + IST_OFFSET_SECONDS)


def _today_ist_str() -> str:
    return _ist_datetime_now().strftime("%Y-%m-%d")


def _next_8am_ist_epoch() -> int:
    now_ist = _ist_datetime_now()
    target  = now_ist.replace(hour=8, minute=0, second=0, microsecond=0)
    if now_ist >= target:
        target += timedelta(days=1)
    return int(target.timestamp()) - IST_OFFSET_SECONDS


def _ensure_symbol_tables():
    with get_db() as conn:
        conn.cursor().execute("""
            CREATE TABLE IF NOT EXISTS symbol_master (
                security_id  TEXT NOT NULL PRIMARY KEY,
                exchange     TEXT NOT NULL,
                stock_symbol TEXT NOT NULL,
                min_qty      INTEGER NOT NULL DEFAULT 1,
                updated_at   TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_sm_exchange
                ON symbol_master (exchange);
            CREATE INDEX IF NOT EXISTS idx_sm_symbol
                ON symbol_master (stock_symbol);
            CREATE INDEX IF NOT EXISTS idx_sm_symbol_lower
                ON symbol_master ((LOWER(stock_symbol)));
            CREATE TABLE IF NOT EXISTS app_meta (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)


def _get_symbol_refresh_meta() -> dict:
    try:
        row = db_execute(
            "SELECT value FROM app_meta WHERE key=%s",
            (_SYMBOL_REFRESH_META_KEY,),
            fetch="one",
        )
        if not row:
            return {}
        return json.loads(row["value"] or "{}") or {}
    except Exception:
        return {}


def _set_symbol_refresh_meta(meta: dict):
    db_execute(
        """
        INSERT INTO app_meta (key, value, updated_at)
        VALUES (%s, %s, NOW())
        ON CONFLICT (key) DO UPDATE
            SET value=EXCLUDED.value, updated_at=NOW()
        """,
        (_SYMBOL_REFRESH_META_KEY, json.dumps(meta or {})),
    )


def _symbols_are_fresh_for_today_ist() -> bool:
    return _get_symbol_refresh_meta().get("trade_date_ist") == _today_ist_str()


def _download_exchange_csv(exchange: str) -> pd.DataFrame:
    """
    Download one Motilal exchange scrip CSV.
    Returns clean DataFrame with columns: security_id, exchange, stock_symbol, min_qty
    Returns empty DataFrame on any error so the caller can continue with other exchanges.
    """
    url = f"{MOSL_SCRIP_BASE_URL}{exchange}"
    try:
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()

        text = resp.content.decode("utf-8", errors="replace")
        df   = pd.read_csv(StringIO(text), dtype=str, low_memory=False).fillna("")

        if df.empty:
            print(f"⚠️  [{exchange}] Empty CSV")
            return pd.DataFrame()

        # Case-insensitive column lookup
        col_lower = {c.strip().lower(): c for c in df.columns}

        def _col(*names) -> Optional[str]:
            for n in names:
                if n.lower() in col_lower:
                    return col_lower[n.lower()]
            return None

        scrip_col = _col("scripcode", "security_id", "securityid", "token")
        name_col  = _col("scripname",  "stock_symbol", "symbol", "name")
        lot_col   = _col("marketlot",  "min_qty", "lotsize", "lot_size", "lot")
        exch_col  = _col("exchangename", "exchange", "exch")

        if not scrip_col or not name_col:
            print(f"⚠️  [{exchange}] Missing required columns. Got: {list(df.columns)}")
            return pd.DataFrame()

        result = pd.DataFrame()
        result["security_id"]  = (
            df[scrip_col].astype(str).str.strip()
            .str.replace(r"\.0$", "", regex=True)
        )
        result["stock_symbol"] = df[name_col].astype(str).str.strip()
        result["exchange"]     = (
            df[exch_col].astype(str).str.strip().str.upper()
            if exch_col else exchange.upper()
        )
        result["min_qty"]      = (
            df[lot_col].apply(lambda x: max(1, _safe_int(x, 1)))
            if lot_col else 1
        )

        # Drop rows with blank / zero security_id or stock_symbol
        result = result[
            (result["security_id"]  != "") &
            (result["security_id"]  != "0") &
            (result["stock_symbol"] != "")
        ].copy()

        print(f"   [{exchange}] {len(result):,} rows")
        return result

    except Exception as e:
        print(f"❌ [{exchange}] Download failed: {e}")
        return pd.DataFrame()


def refresh_symbol_db_from_dhan(force: bool = False) -> Dict[str, Any]:
    """
    Entry point (name kept for API backward-compat with /refresh_symbols).
    Downloads all 8 Motilal exchange CSVs in parallel, merges, deduplicates,
    and atomically replaces symbol_master in PostgreSQL.
    """
    with _SYMBOL_REFRESH_LOCK:
        _ensure_symbol_tables()

        if not force and _symbols_are_fresh_for_today_ist():
            row = db_execute("SELECT COUNT(*) AS c FROM symbol_master", fetch="one")
            return {
                "status":         "already_fresh",
                "message":        "Already fresh for today",
                "rows":           int((row or {}).get("c") or 0),
                "trade_date_ist": _today_ist_str(),
            }

        print(f"⬇️  [SYMBOLS] Downloading {len(MOSL_EXCHANGES)} Motilal exchange CSVs in parallel…")
        t0 = time.time()

        # ── Parallel downloads ───────────────────────────────
        frames:      List[pd.DataFrame] = []
        dl_counts:   Dict[str, int]     = {}
        dl_errors:   List[str]          = []
        frames_lock  = threading.Lock()

        def _dl(exch: str):
            df = _download_exchange_csv(exch)
            with frames_lock:
                if df.empty:
                    dl_errors.append(exch)
                else:
                    dl_counts[exch] = len(df)
                    frames.append(df)

        threads = [threading.Thread(target=_dl, args=(e,), daemon=True) for e in MOSL_EXCHANGES]
        for t in threads: t.start()
        for t in threads: t.join()

        elapsed = time.time() - t0
        print(f"   Downloads finished in {elapsed:.1f}s")
        if dl_errors:
            print(f"   ⚠️  Failed: {dl_errors}")
        if not frames:
            raise RuntimeError("All exchange downloads failed — aborting")

        # ── Merge ────────────────────────────────────────────
        combined = pd.concat(frames, ignore_index=True)
        raw_count = len(combined)

        # Deduplicate on security_id (keep first occurrence)
        combined = combined.drop_duplicates(subset=["security_id"], keep="first")
        final_count = len(combined)
        if raw_count != final_count:
            print(f"   Removed {raw_count - final_count:,} duplicate security_ids")

        print(f"   Total rows to insert: {final_count:,}")

        records = list(zip(
            combined["security_id"],
            combined["exchange"],
            combined["stock_symbol"],
            combined["min_qty"].astype(int),
        ))

        # ── Atomic TRUNCATE + INSERT ─────────────────────────
        print("   Writing to PostgreSQL…")
        t1 = time.time()
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("TRUNCATE TABLE symbol_master")
            if records:
                psycopg2.extras.execute_batch(
                    cur,
                    """
                    INSERT INTO symbol_master
                        (security_id, exchange, stock_symbol, min_qty, updated_at)
                    VALUES (%s, %s, %s, %s, NOW())
                    """,
                    records,
                    page_size=5000,
                )
        print(f"   DB write done in {time.time() - t1:.1f}s")

        meta = {
            "trade_date_ist":   _today_ist_str(),
            "refreshed_at_utc": utcnow_iso(),
            "row_count":        final_count,
            "by_exchange":      dl_counts,
            "failed_exchanges": dl_errors,
            "source":           MOSL_SCRIP_BASE_URL,
        }
        _set_symbol_refresh_meta(meta)

        print(
            f"✅ [SYMBOLS] Done — {final_count:,} rows  "
            f"by_exchange={dl_counts}  date={meta['trade_date_ist']}"
        )
        return {"status": "success", **meta}


def _ensure_symbols_ready():
    _ensure_symbol_tables()
    if not _symbols_are_fresh_for_today_ist():
        try:
            refresh_symbol_db_from_dhan(force=False)
        except Exception as e:
            print(f"❌ Symbol refresh failed: {e}")


def _min_qty_from_symbol_db(symboltoken) -> int:
    try:
        token = str(symboltoken).strip()
        if not token:
            return 1
        row = db_execute(
            "SELECT min_qty FROM symbol_master WHERE security_id=%s",
            (token,),
            fetch="one",
        )
        return max(1, int((row or {}).get("min_qty") or 1))
    except Exception:
        return 1


def _seconds_until_next_8am_ist() -> int:
    return max(5, _next_8am_ist_epoch() - _utc_now_ts())


def symbol_refresh_scheduler_loop():
    print("🕗 [SYMBOLS] Scheduler started — daily refresh at 08:00 IST")
    while True:
        try:
            secs    = _seconds_until_next_8am_ist()
            next_dt = _ist_datetime_now() + timedelta(seconds=secs)
            print(f"⏳ [SYMBOLS] Next refresh at {next_dt.strftime('%Y-%m-%d %H:%M')} IST ({secs/3600:.1f}h away)")
            time.sleep(secs)
            print("🔄 [SYMBOLS] Daily 08:00 IST refresh starting…")
            refresh_symbol_db_from_dhan(force=True)
        except Exception as e:
            print(f"❌ [SYMBOLS] Daily refresh error: {e}")
            time.sleep(300)


def start_symbol_refresh_thread():
    global _SYMBOL_SCHEDULER_STARTED
    if _SYMBOL_SCHEDULER_STARTED:
        return
    _SYMBOL_SCHEDULER_STARTED = True
    threading.Thread(
        target=symbol_refresh_scheduler_loop,
        daemon=True,
        name="symbol-refresh-8am-ist",
    ).start()


# ─────────────────────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────────────────────
def _startup_login_all_clients():
    print("🔄 [STARTUP] Logging in all clients from PostgreSQL…")
    try:
        rows = db_execute("SELECT * FROM clients", fetch="all") or []
    except Exception as e:
        print(f"❌ [STARTUP] DB error: {e}")
        return

    if not rows:
        print("⚠️ [STARTUP] No clients found.")
        return

    print(f"🔑 [STARTUP] Logging in {len(rows)} clients…")

    def _login_one(row):
        try:
            motilal_login(dict(row))
        except Exception as e:
            print(f"❌ [STARTUP] Login error {row.get('userid', '?')}: {e}")

    with ThreadPoolExecutor(max_workers=20) as ex:
        list(ex.map(_login_one, rows))

    logged = sum(1 for s in mofsl_sessions.values() if _session_fresh(s))
    print(f"✅ [STARTUP] {logged}/{len(rows)} clients logged in.")


@app.on_event("startup")
def _startup():
    _init_db()
    _ensure_symbols_ready()
    start_symbol_refresh_thread()
    threading.Thread(target=_startup_login_all_clients, daemon=True).start()
    start_copy_trading_thread()


# ─────────────────────────────────────────────────────────────
# Health / Auth routes
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
        existing = db_execute("SELECT userid FROM users WHERE userid=%s", (userid,), fetch="one")
        if existing:
            return {"success": False, "error": "User already exists"}
        salt = base64.b64encode(os.urandom(12)).decode()
        ph   = password_hash(password, salt)
        db_execute(
            "INSERT INTO users (userid, email, salt, password_hash) VALUES (%s,%s,%s,%s)",
            (userid, email, salt, ph),
        )
        return {"success": True, "userid": userid}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/auth/login")
def auth_login(payload: dict = Body(...)):
    userid   = normalize_userid(payload.get("userid"))
    password = (payload.get("password") or "").strip()
    if not userid or not password:
        return {"success": False}
    try:
        row = db_execute("SELECT * FROM users WHERE userid=%s", (userid,), fetch="one")
        if not row:
            return {"success": False}
        salt = row["salt"]
        ph   = row["password_hash"]
        if not salt or not ph or password_hash(password, salt) != ph:
            return {"success": False}
        return {"success": True, "userid": userid, "access_token": create_token(userid)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/me")
def me(userid: str = Depends(get_current_user)):
    return {"success": True, "userid": userid}

@app.get("/debug_sessions")
def debug_sessions(request: Request, userid: str = None, user_id: str = None):
    owner_userid = resolve_owner_userid(request, userid=userid, user_id=user_id)
    result = []
    for client_id, sess in list(mofsl_sessions.items()):
        if not isinstance(sess, dict): continue
        sess_owner = str(sess.get("owner_userid", "")).strip()
        matched = (sess_owner == str(owner_userid).strip())
        result.append({
            "client_id":    client_id,
            "name":         sess.get("name"),
            "sess_owner":   sess_owner,
            "req_owner":    owner_userid,
            "match":        matched,
            "has_mofsl":    bool(sess.get("mofsl")),
        })
    return {"resolved_owner": owner_userid, "sessions": result}


# ─────────────────────────────────────────────────────────────
# Client CRUD
# ─────────────────────────────────────────────────────────────
@app.post("/add_client")
async def add_client(request: Request, payload: dict = Body(...)):
    owner_userid = _norm_uid(
        request.headers.get("x-user-id") or payload.get("owner_userid") or payload.get("userid") or ""
    )
    client_userid = str(
        payload.get("userid") or payload.get("client_id") or payload.get("client_code") or ""
    ).strip()
    if not owner_userid:
        raise HTTPException(401, "Missing owner userid")
    if not client_userid:
        raise HTTPException(400, "Client userid required")

    name    = payload.get("name") or ""
    capital = _safe_float(payload.get("capital", 0), 0.0)

    try:
        db_execute(
            """
            INSERT INTO clients (owner_userid, userid, name, password, pan, apikey, totpkey, capital)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (owner_userid, userid) DO UPDATE SET
                name=%s, password=%s, pan=%s, apikey=%s, totpkey=%s, capital=%s
            """,
            (
                owner_userid, client_userid, name,
                payload.get("password", ""), payload.get("pan", ""),
                payload.get("apikey", ""), payload.get("totpkey", ""), capital,
                name, payload.get("password", ""), payload.get("pan", ""),
                payload.get("apikey", ""), payload.get("totpkey", ""), capital,
            ),
        )
    except Exception as e:
        raise HTTPException(503, f"DB error: {e}")

    client_obj = {
        "name": name, "userid": client_userid,
        "password": payload.get("password", ""), "pan": payload.get("pan", ""),
        "apikey": payload.get("apikey", ""), "totpkey": payload.get("totpkey", ""),
        "owner_userid": owner_userid,
    }
    ok  = motilal_login(client_obj)
    msg = "Login successful" if ok else "Login failed"
    try:
        db_execute(
            "UPDATE clients SET session_active=%s, last_login_ts=%s, last_login_msg=%s "
            "WHERE owner_userid=%s AND userid=%s",
            (ok, int(time.time()), msg, owner_userid, client_userid),
        )
    except Exception:
        pass
    return {"success": True}


@app.post("/edit_client")
async def edit_client(request: Request, payload: dict = Body(...)):
    owner_userid  = _norm_uid(request.headers.get("x-user-id") or payload.get("owner_userid") or "")
    client_userid = str(payload.get("userid") or payload.get("client_id") or "").strip()
    if not owner_userid or not client_userid:
        raise HTTPException(400, "Missing owner_userid or client_userid")

    row = db_execute(
        "SELECT * FROM clients WHERE owner_userid=%s AND userid=%s",
        (owner_userid, client_userid), fetch="one",
    )
    if not row:
        raise HTTPException(404, "Client not found")

    fields = {}
    for f in ("name", "password", "pan", "apikey", "totpkey"):
        if payload.get(f) is not None:
            fields[f] = payload[f]
    if payload.get("capital") is not None:
        fields["capital"] = _safe_float(payload["capital"], 0.0)

    if fields:
        set_clause = ", ".join(f"{k}=%s" for k in fields)
        db_execute(
            f"UPDATE clients SET {set_clause} WHERE owner_userid=%s AND userid=%s",
            list(fields.values()) + [owner_userid, client_userid],
        )

    updated_row = db_execute(
        "SELECT * FROM clients WHERE owner_userid=%s AND userid=%s",
        (owner_userid, client_userid), fetch="one",
    )
    client_obj = dict(updated_row)
    client_obj["owner_userid"] = owner_userid
    mofsl_sessions.pop(client_userid, None)
    ok  = motilal_login(client_obj)
    msg = "Login successful" if ok else "Login failed"
    db_execute(
        "UPDATE clients SET session_active=%s, last_login_ts=%s, last_login_msg=%s "
        "WHERE owner_userid=%s AND userid=%s",
        (ok, int(time.time()), msg, owner_userid, client_userid),
    )
    return {"success": True}


@app.get("/clients")
def get_clients(request: Request, userid: str = None, user_id: str = None):
    uid = _norm_uid(
        request.headers.get("x-user-id") or userid or user_id
        or request.query_params.get("userid") or request.query_params.get("user_id") or ""
    )
    if not uid:
        return {"clients": []}

    try:
        rows = db_execute(
            "SELECT * FROM clients WHERE owner_userid=%s ORDER BY name",
            (uid,), fetch="all",
        ) or []
    except Exception as e:
        return {"clients": [], "error": str(e)}

    clients = []
    for row in rows:
        client_id = row["userid"]
        sess = mofsl_sessions.get(client_id)
        sa   = bool(
            sess
            and _norm_uid(sess.get("owner_userid", "")) == uid
            and _session_fresh(sess)
            and sess.get("mofsl")
        )
        clients.append({
            "name":           row["name"],
            "client_id":      client_id,
            "capital":        float(row.get("capital") or 0),
            "session":        "Logged in" if sa else "Logged out",
            "session_active": sa,
            "status":         "logged_in" if sa else "logged_out",
        })
    return {"clients": clients}


@app.post("/delete_client")
async def delete_client(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(
        request, userid=payload.get("userid") or payload.get("owner_userid")
    )
    if not owner_userid:
        raise HTTPException(401, "Missing owner userid")

    deleted, missing, errors = [], [], []
    for it in (payload.get("items") or []):
        cuid = str((it or {}).get("userid") or (it or {}).get("client_id") or "").strip()
        if not cuid:
            continue
        try:
            row = db_execute(
                "SELECT id FROM clients WHERE owner_userid=%s AND userid=%s",
                (owner_userid, cuid), fetch="one",
            )
            if not row:
                missing.append(cuid); continue
            db_execute("DELETE FROM clients WHERE owner_userid=%s AND userid=%s", (owner_userid, cuid))
            mofsl_sessions.pop(cuid, None)
            deleted.append(cuid)
        except Exception as e:
            errors.append(str(e))
    return {"ok": True, "deleted": deleted, "missing": missing, "errors": errors}


# ─────────────────────────────────────────────────────────────
# Symbol search endpoints
# ─────────────────────────────────────────────────────────────
@app.post("/refresh_symbols")
def refresh_symbols():
    try:
        return refresh_symbol_db_from_dhan(force=True)
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.get("/symbols_status")
def symbols_status():
    _ensure_symbol_tables()
    total = db_execute("SELECT COUNT(*) AS c FROM symbol_master", fetch="one")
    by_exchange = db_execute(
        "SELECT exchange, COUNT(*) AS c FROM symbol_master GROUP BY exchange ORDER BY exchange",
        fetch="all",
    ) or []
    meta = _get_symbol_refresh_meta()
    return {
        "total":           int((total or {}).get("c") or 0),
        "by_exchange":     {r["exchange"]: int(r["c"]) for r in by_exchange},
        "meta":            meta,
        "today_ist":       _today_ist_str(),
        "fresh_for_today": _symbols_are_fresh_for_today_ist(),
    }


@app.get("/search_symbols")
def search_symbols(q: str = Query(""), exchange: str = Query("")):
    _ensure_symbols_ready()

    raw  = (q or "").strip().lower()
    exch = (exchange or "").strip().upper()
    if not raw:
        return {"results": []}

    words = [w.strip() for w in raw.split() if w.strip()]
    if not words:
        return {"results": []}

    where_clauses: List[str] = []
    filter_params: List[Any] = []

    for w in words:
        where_clauses.append("LOWER(stock_symbol) LIKE %s")
        filter_params.append(f"%{w}%")

    if exch:
        where_clauses.append("exchange = %s")
        filter_params.append(exch)

    sql = f"""
        SELECT exchange, stock_symbol, security_id,
            CASE
                WHEN LOWER(stock_symbol) = %s         THEN 0
                WHEN LOWER(stock_symbol) LIKE %s       THEN 1
                WHEN LOWER(stock_symbol) LIKE %s       THEN 2
                ELSE 3
            END AS rank_score
        FROM symbol_master
        WHERE {' AND '.join(where_clauses)}
        ORDER BY rank_score, exchange, stock_symbol
        LIMIT 200
    """

    rows = db_execute(
        sql,
        (raw, f"{raw}%", f"%{raw}%") + tuple(filter_params),
        fetch="all",
    ) or []

    return {
        "results": [
            {
                "id":   f"{r['exchange']}|{r['stock_symbol']}|{r['security_id']}",
                "text": f"{r['exchange']} | {r['stock_symbol']}",
            }
            for r in rows
        ]
    }


# ─────────────────────────────────────────────────────────────
# Groups
# ─────────────────────────────────────────────────────────────
@app.get("/groups")
async def get_groups(request: Request, userid: str = None, user_id: str = None):
    owner_userid = resolve_owner_userid(request, userid=userid, user_id=user_id)
    if not owner_userid:
        return {"groups": []}
    try:
        rows = db_execute(
            "SELECT * FROM groups WHERE owner_userid=%s ORDER BY name",
            (owner_userid,), fetch="all",
        ) or []
    except Exception:
        return {"groups": []}
    return {
        "groups": [
            {
                "id":         row["name"],
                "name":       row["name"],
                "multiplier": float(row.get("multiplier") or 1),
                "members":    row.get("members") or [],
            }
            for row in rows
        ]
    }


@app.post("/add_group")
async def add_group(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(
        request, userid=payload.get("userid") or payload.get("owner_userid")
    )
    if not owner_userid:
        raise HTTPException(401, "Missing owner userid")
    name    = (payload.get("name") or "").strip()
    members = payload.get("members") or []
    if not name:
        raise HTTPException(400, "Group name required")
    if not members:
        raise HTTPException(400, "Group members required")
    mult = max(0.01, float(payload.get("multiplier", 1) or 1))
    try:
        db_execute(
            """
            INSERT INTO groups (owner_userid, name, multiplier, members)
            VALUES (%s,%s,%s,%s)
            ON CONFLICT (owner_userid, name)
            DO UPDATE SET multiplier=%s, members=%s, updated_at=NOW()
            """,
            (owner_userid, name, mult, json.dumps(members), mult, json.dumps(members)),
        )
    except Exception as e:
        raise HTTPException(503, str(e))
    return {"ok": True, "group": {"id": name, "name": name, "multiplier": mult, "members": members}}


@app.post("/edit_group")
async def edit_group(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(
        request, userid=payload.get("userid") or payload.get("owner_userid")
    )
    if not owner_userid:
        raise HTTPException(401, "Missing owner userid")
    name    = (payload.get("id") or payload.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "Group name required")
    members = payload.get("members") or []
    mult    = max(0.01, float(payload.get("multiplier", 1) or 1))
    try:
        db_execute(
            "UPDATE groups SET multiplier=%s, members=%s, updated_at=NOW() "
            "WHERE owner_userid=%s AND name=%s",
            (mult, json.dumps(members), owner_userid, name),
        )
    except Exception as e:
        raise HTTPException(503, str(e))
    return {"ok": True, "group": {"id": name, "name": name, "multiplier": mult, "members": members}}


@app.post("/delete_group")
async def delete_group(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(
        request, userid=payload.get("userid") or payload.get("owner_userid")
    )
    if not owner_userid:
        raise HTTPException(401, "Missing owner userid")
    ids = payload.get("ids") or payload.get("names") or []
    if not isinstance(ids, list):
        ids = [ids]
    deleted, missing, errors = [], [], []
    for gid in ids:
        gid = str(gid).strip()
        try:
            row = db_execute(
                "SELECT id FROM groups WHERE owner_userid=%s AND name=%s",
                (owner_userid, gid), fetch="one",
            )
            if not row:
                missing.append(gid); continue
            db_execute("DELETE FROM groups WHERE owner_userid=%s AND name=%s", (owner_userid, gid))
            deleted.append(gid)
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
    try:
        rows = db_execute(
            "SELECT * FROM copy_setups WHERE owner_userid=%s ORDER BY name",
            (owner_userid,), fetch="all",
        ) or []
    except Exception:
        return {"setups": []}
    return {
        "setups": [
            {
                "id":          row["name"],
                "name":        row["name"],
                "master":      row["master"],
                "children":    row.get("children") or [],
                "multipliers": row.get("multipliers") or {},
                "enabled":     bool(row.get("enabled", False)),
            }
            for row in rows
        ]
    }


@app.post("/save_copytrading_setup")
async def save_copytrading_setup(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(
        request, userid=payload.get("userid") or payload.get("owner_userid")
    )
    if not owner_userid:
        raise HTTPException(401, "Missing owner userid")
    name        = (payload.get("name") or payload.get("id") or "").strip()
    master      = (payload.get("master") or "").strip()
    children    = payload.get("children") or []
    if not name:
        raise HTTPException(400, "Setup name required")
    if not master or not children:
        raise HTTPException(400, "Master + at least one child required")
    multipliers = payload.get("multipliers") or {}
    enabled     = bool(payload.get("enabled", False))
    try:
        db_execute(
            """
            INSERT INTO copy_setups (owner_userid, name, master, children, multipliers, enabled)
            VALUES (%s,%s,%s,%s,%s,%s)
            ON CONFLICT (owner_userid, name) DO UPDATE SET
                master=%s, children=%s, multipliers=%s, enabled=%s, updated_at=NOW()
            """,
            (
                owner_userid, name, master,
                json.dumps(children), json.dumps(multipliers), enabled,
                master, json.dumps(children), json.dumps(multipliers), enabled,
            ),
        )
    except Exception as e:
        raise HTTPException(503, str(e))
    return {
        "ok": True,
        "setup": {
            "id": name, "name": name, "master": master,
            "children": children, "multipliers": multipliers, "enabled": enabled,
        },
    }


@app.post("/enable_copy")
async def enable_copy(request: Request, payload: dict = Body(...)):
    return await _set_copy_enabled(request, payload, True)


@app.post("/disable_copy")
async def disable_copy(request: Request, payload: dict = Body(...)):
    return await _set_copy_enabled(request, payload, False)


async def _set_copy_enabled(request: Request, payload: dict, value: bool):
    owner_userid = resolve_owner_userid(
        request, userid=payload.get("userid") or payload.get("owner_userid")
    )
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
        sid = str(sid).strip()
        try:
            row = db_execute(
                "SELECT id FROM copy_setups WHERE owner_userid=%s AND name=%s",
                (owner_userid, sid), fetch="one",
            )
            if not row:
                missing.append(sid); continue
            db_execute(
                "UPDATE copy_setups SET enabled=%s, updated_at=NOW() "
                "WHERE owner_userid=%s AND name=%s",
                (value, owner_userid, sid),
            )
            updated.append(sid)
        except Exception as e:
            errors.append(str(e))
    return {"ok": True, "updated": updated, "missing": missing, "errors": errors}


@app.post("/delete_copy_setup")
@app.post("/delete_copytrading_setup")
async def delete_copy_setup(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(
        request, userid=payload.get("userid") or payload.get("owner_userid")
    )
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
        sid = str(sid).strip()
        try:
            row = db_execute(
                "SELECT id FROM copy_setups WHERE owner_userid=%s AND name=%s",
                (owner_userid, sid), fetch="one",
            )
            if not row:
                missing.append(sid); continue
            db_execute(
                "DELETE FROM copy_setups WHERE owner_userid=%s AND name=%s",
                (owner_userid, sid),
            )
            deleted.append(sid)
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
            if not isinstance(sess, dict): continue
            if owner_userid and str(sess.get("owner_userid", "")).strip() != str(owner_userid).strip():
                continue
            name  = sess.get("name", "") or client_id
            mofsl = sess.get("mofsl")
            uid   = sess.get("userid", client_id)
            if not mofsl or not uid: continue

            today = datetime.now().strftime("%d-%b-%Y 09:00:00")
            resp  = mofsl.GetOrderBook({"clientcode": uid, "datetimestamp": today})
            orders = resp.get("data", []) if resp else []
            if not isinstance(orders, list):
                orders = []

            for order in orders:
                od = {
                    "name":             name,
                    "client_id":        uid,
                    "symbol":           order.get("symbol", ""),
                    "transaction_type": order.get("buyorsell", ""),
                    "quantity":         order.get("orderqty", ""),
                    "price":            order.get("price", ""),
                    "status":           order.get("orderstatus", ""),
                    "order_id":         order.get("uniqueorderid", ""),
                }
                st = (order.get("orderstatus", "") or "").lower()
                if "confirm" in st:
                    orders_data["pending"].append(od)
                elif "traded" in st:
                    orders_data["traded"].append(od)
                elif "rejected" in st or "error" in st:
                    orders_data["rejected"].append(od)
                elif "cancel" in st:
                    orders_data["cancelled"].append(od)
                else:
                    orders_data["others"].append(od)
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
        cid = (order or {}).get("client_id") or ""
        if cid:
            s = mofsl_sessions.get(cid)
            if s and s.get("owner_userid", "") == owner_userid:
                return s
        nm = (order or {}).get("name", "")
        for s in mofsl_sessions.values():
            if s.get("owner_userid", "") == owner_userid and s.get("name") == nm:
                return s
        return None

    def cancel_one(order):
        oid  = order.get("order_id")
        sess = find_sess(order)
        if not sess:
            with lock: messages.append(f"❌ Session not found for {order.get('name', '?')}"); return
        try:
            resp = sess["mofsl"].CancelOrder(oid, sess["userid"])
            msg  = (resp.get("message", "") or "").lower()
            with lock:
                messages.append(
                    f"{'✅' if 'cancel order request sent' in msg else '❌'} "
                    f"{oid} for {sess.get('name', '')}: {resp.get('message', '')}"
                )
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
            if not isinstance(sess, dict):
                continue
            if owner_userid and str(sess.get("owner_userid", "")).strip() != str(owner_userid).strip():
                continue
            name  = str(sess.get("name", "") or client_id)
            mofsl = sess.get("mofsl")
            uid   = str(sess.get("userid", client_id))
            if not mofsl or not uid:
                continue

            response = mofsl.GetPosition()
            if not response or response.get("status") != "SUCCESS":
                continue
            positions = response.get("data", []) if response else []
            if not isinstance(positions, list):
                positions = []

            for pos in positions:
                try:
                    symbol      = str(pos.get("symbol")      or "")
                    exchange    = str(pos.get("exchange")     or "")
                    token       = str(pos.get("symboltoken")  or "")
                    producttype = str(pos.get("productname")  or "")

                    if not symbol:
                        continue

                    # ── Use gross buy/sell quantities (includes CF + day) ──
                    bq = _safe_float(pos.get("buyquantity"),  0.0)
                    sq = _safe_float(pos.get("sellquantity"), 0.0)
                    ba = _safe_float(pos.get("buyamount"),    0.0)
                    sa = _safe_float(pos.get("sellamount"),   0.0)

                    # Fallback to day quantities if gross fields are missing/zero
                    if bq == 0 and sq == 0:
                        bq = _safe_float(pos.get("daybuyquantity"),  0.0)
                        sq = _safe_float(pos.get("daysellquantity"), 0.0)
                        ba = _safe_float(pos.get("daybuyamount"),    0.0)
                        sa = _safe_float(pos.get("daysellamount"),   0.0)

                    quantity = int(round(bq - sq))

                    buy_avg  = (ba / bq) if bq > 0 else 0.0
                    sell_avg = (sa / sq) if sq > 0 else 0.0

                    ltp = _safe_float(pos.get("LTP"), 0.0)

                    # ── P&L calculation per bucket ──
                    if quantity > 0:
                        # Long open position
                        net_profit = (ltp - buy_avg) * quantity if ltp else _safe_float(
                            pos.get("actualmarktomarket") or pos.get("marktomarket"), 0.0
                        )
                    elif quantity < 0:
                        # Short open position
                        net_profit = (sell_avg - ltp) * abs(quantity) if ltp else _safe_float(
                            pos.get("actualmarktomarket") or pos.get("marktomarket"), 0.0
                        )
                    else:
                        # Fully squared off — use booked P&L directly
                        net_profit = _safe_float(
                            pos.get("actualbookedprofitloss")
                            or pos.get("bookedprofitloss"),
                            0.0
                        )
                        # Secondary fallback: compute from avg prices
                        if net_profit == 0 and bq > 0 and sq > 0:
                            traded_qty = min(bq, sq)
                            net_profit = (sell_avg - buy_avg) * traded_qty

                    bucket = "closed" if quantity == 0 else "open"

                    print(
                        f"   {name} | {symbol} | bq={bq} sq={sq} | "
                        f"qty={quantity} → {bucket} | pnl={round(net_profit, 2)}"
                    )

                    new_meta[(uid, symbol)] = {
                        "exchange":    exchange,
                        "symboltoken": token,
                        "producttype": producttype,
                        "client_id":   uid,
                    }

                    positions_data[bucket].append({
                        "name":       name,
                        "client_id":  uid,
                        "symbol":     symbol,
                        "quantity":   quantity,
                        "buy_avg":    round(buy_avg,    2),
                        "sell_avg":   round(sell_avg,   2),
                        "net_profit": round(net_profit, 2),
                    })

                except Exception as row_e:
                    print(f"❌ Row error {name} {pos.get('symbol', '?')}: {row_e}")

        except Exception as e:
            print(f"❌ Error fetching positions for {client_id}: {e}")

    print(f"[POS] open={len(positions_data['open'])} closed={len(positions_data['closed'])}")
    with _position_meta_lock:
        position_meta = new_meta
    return positions_data

# ─────────────────────────────────────────────────────────────
# DEBUG — remove after diagnosis
# ─────────────────────────────────────────────────────────────
@app.get("/debug_positions_raw")
def debug_positions_raw(request: Request, userid: str = None, user_id: str = None):
    owner_userid = resolve_owner_userid(request, userid=userid, user_id=user_id)
    result = []

    for client_id, sess in list(mofsl_sessions.items()):
        try:
            if not isinstance(sess, dict): continue
            if owner_userid and str(sess.get("owner_userid", "")).strip() != str(owner_userid).strip():
                continue
            name  = str(sess.get("name", "") or client_id)
            mofsl = sess.get("mofsl")
            uid   = str(sess.get("userid", client_id))
            if not mofsl or not uid: continue

            resp = mofsl.GetPosition()
            positions = (resp or {}).get("data") or []

            for pos in (positions if isinstance(positions, list) else []):
                symbol = str(pos.get("symbol") or "")
                # Only show Reliance to keep output small
                if "RELIANCE" not in symbol.upper():
                    continue
                result.append({
                    "client":          name,
                    "uid":             uid,
                    "symbol":          symbol,
                    # ── the key quantity fields ──
                    "buyquantity":     pos.get("buyquantity"),
                    "sellquantity":    pos.get("sellquantity"),
                    "daybuyquantity":  pos.get("daybuyquantity"),
                    "daysellquantity": pos.get("daysellquantity"),
                    "cfbuyquantity":   pos.get("cfbuyquantity"),
                    "cfsellquantity":  pos.get("cfsellquantity"),
                    # ── amounts ──
                    "buyamount":       pos.get("buyamount"),
                    "sellamount":      pos.get("sellamount"),
                    "daybuyamount":    pos.get("daybuyamount"),
                    "daysellamount":   pos.get("daysellamount"),
                    # ── P&L fields ──
                    "bookedprofitloss":       pos.get("bookedprofitloss"),
                    "actualbookedprofitloss": pos.get("actualbookedprofitloss"),
                    "marktomarket":           pos.get("marktomarket"),
                    "actualmarktomarket":     pos.get("actualmarktomarket"),
                    "LTP":                    pos.get("LTP"),
                    # ── raw full record ──
                    "_raw": dict(pos),
                })
        except Exception as e:
            result.append({"client": client_id, "error": str(e)})

    return {"count": len(result), "positions": result}

    

@app.post("/close_position")
async def close_position(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(request, userid=payload.get("userid") or payload.get("user_id"))
    positions    = (payload or {}).get("positions", [])
    messages, threads, lock = [], [], threading.Lock()

    min_qty_map = {}
    try:
        rows = db_execute("SELECT security_id, min_qty FROM symbol_master", fetch="all") or []
        for row in rows:
            sid = str(row.get("security_id") or "").strip()
            qty = row.get("min_qty")
            if sid:
                try:    min_qty_map[sid] = max(1, int(qty or 1))
                except: min_qty_map[sid] = 1
    except Exception as e:
        print(f"❌ Error reading min_qty: {e}")

    def find_sess(name, cid_hint=""):
        if cid_hint:
            s = mofsl_sessions.get(cid_hint)
            if isinstance(s, dict) and (
                not owner_userid
                or str(s.get("owner_userid", "")).strip() == str(owner_userid).strip()
            ):
                return cid_hint, s
        for cid, s in mofsl_sessions.items():
            if not isinstance(s, dict): continue
            if owner_userid and str(s.get("owner_userid", "")).strip() != str(owner_userid).strip(): continue
            if (s.get("name") or "").strip().lower() == (name or "").strip().lower():
                return cid, s
        return "", None

    def close_one(pos):
        name     = (pos or {}).get("name") or ""
        symbol   = (pos or {}).get("symbol") or ""
        qty      = float((pos or {}).get("quantity", 0) or 0)
        txtype   = (pos or {}).get("transaction_type") or ""
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
        order   = {
            "clientcode": uid_, "exchange": meta.get("exchange", ""),
            "symboltoken": token, "buyorsell": txtype.upper(),
            "ordertype": "MARKET", "producttype": meta.get("producttype", ""),
            "orderduration": "DAY", "price": 0, "triggerprice": 0,
            "quantityinlot": lots, "disclosedquantity": 0,
            "amoorder": "N", "algoid": "", "goodtilldate": "", "tag": "",
        }
        try:
            resp = mofsl_.PlaceOrder(order)
            ok   = isinstance(resp, dict) and resp.get("status") == "SUCCESS"
            with lock:
                messages.append(f"{'✅' if ok else '❌'} {'Close requested' if ok else 'Close failed'}: {name} {symbol}")
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
        if r.get("status") != "SUCCESS":
            return 0
        for item in r.get("data", []):
            if item.get("particulars") == "Total Available Margin for Cash":
                return float(item.get("amount", 0))
    except Exception as e:
        print(f"❌ Margin error for {clientcode}: {e}")
    return 0


def _build_client_capital_map(owner_userid: str) -> Dict:
    capital_map: Dict = {}
    try:
        rows = db_execute(
            "SELECT userid, name, capital FROM clients WHERE owner_userid=%s",
            (owner_userid,), fetch="all",
        ) or []
        for row in rows:
            cid = str(row["userid"] or "").strip()
            nm  = str(row["name"] or cid).strip()
            cap = float(row.get("capital") or 0)
            if cid: capital_map[cid] = cap
            if nm:  capital_map[nm]  = cap
    except Exception as e:
        print(f"Capital map error: {e}")
    return capital_map


def _fetch_summary_for_owner(owner_userid: str) -> Dict:
    capital_map   = _build_client_capital_map(owner_userid)
    summary_data: Dict = {}

    for client_id, sess in list(mofsl_sessions.items()):
        try:
            if not isinstance(sess, dict): continue
            if str(sess.get("owner_userid", "")).strip() != str(owner_userid).strip(): continue
            name  = sess.get("name", "") or client_id
            Mofsl = sess.get("mofsl")
            uid_  = sess.get("userid") or client_id
            if not Mofsl or not uid_: continue

            invested = 0.0; total_pnl = 0.0
            try:
                resp = Mofsl.GetDPHolding(uid_)
                if resp and resp.get("status") == "SUCCESS":
                    for h in (resp.get("data") or []):
                        qty     = float(h.get("dpquantity", 0) or 0)
                        buy_avg = float(h.get("buyavgprice", 0) or 0)
                        sc      = h.get("nsesymboltoken")
                        if not sc or qty <= 0: continue
                        try:
                            ltp_resp = Mofsl.GetLtp({"clientcode": uid_, "exchange": "NSE", "scripcode": int(sc)})
                            ltp = float((ltp_resp or {}).get("data", {}).get("ltp", 0) or 0) / 100
                        except Exception:
                            ltp = 0.0
                        invested  += qty * buy_avg
                        total_pnl += (ltp - buy_avg) * qty
            except Exception as e:
                print(f"⚠️ Holdings fetch skipped for {name}: {e}")

            available_margin = get_available_margin(Mofsl, uid_)
            capital          = float(capital_map.get(uid_) or capital_map.get(name) or 0)
            current_value    = invested + total_pnl
            summary_data[name] = {
                "name":             name,
                "capital":          round(capital, 2),
                "invested":         round(invested, 2),
                "pnl":              round(total_pnl, 2),
                "current_value":    round(current_value, 2),
                "available_margin": round(available_margin, 2),
                "net_gain":         round((current_value + available_margin) - capital, 2),
            }
        except Exception as e:
            print(f"❌ Summary error for {client_id}: {e}")
    return summary_data


@app.get("/get_holdings")
def get_holdings(request: Request, userid: str = None, user_id: str = None):
    owner_userid = resolve_owner_userid(request, userid=userid, user_id=user_id)
    if not owner_userid:
        return {"ok": False, "error": "userid missing"}

    holdings_data: List = []
    capital_map   = _build_client_capital_map(owner_userid)
    summary_data: Dict = {}

    for client_id, sess in list(mofsl_sessions.items()):
        try:
            if not isinstance(sess, dict): continue
            if str(sess.get("owner_userid", "")).strip() != str(owner_userid).strip(): continue
            name  = sess.get("name", "") or client_id
            Mofsl = sess.get("mofsl")
            uid_  = sess.get("userid") or client_id
            if not Mofsl or not uid_: continue

            resp = Mofsl.GetDPHolding(uid_)
            if not resp or resp.get("status") != "SUCCESS": continue

            invested = 0.0; total_pnl = 0.0
            for h in (resp.get("data") or []):
                symbol    = (h.get("scripname") or "").strip()
                qty       = float(h.get("dpquantity", 0) or 0)
                buy_avg   = float(h.get("buyavgprice", 0) or 0)
                scripcode = h.get("nsesymboltoken")
                if not scripcode or qty <= 0: continue
                try:
                    ltp_resp = Mofsl.GetLtp({"clientcode": uid_, "exchange": "NSE", "scripcode": int(scripcode)})
                    ltp = float((ltp_resp or {}).get("data", {}).get("ltp", 0) or 0) / 100
                except Exception:
                    ltp = 0.0
                pnl        = round((ltp - buy_avg) * qty, 2)
                invested  += qty * buy_avg
                total_pnl += pnl
                holdings_data.append({
                    "name": name, "symbol": symbol, "quantity": qty,
                    "buy_avg": round(buy_avg, 2), "ltp": round(ltp, 2), "pnl": pnl,
                })

            available_margin = get_available_margin(Mofsl, uid_)
            capital          = float(capital_map.get(uid_) or capital_map.get(name) or 0)
            current_value    = invested + total_pnl
            summary_data[name] = {
                "name":             name,
                "capital":          round(capital, 2),
                "invested":         round(invested, 2),
                "pnl":              round(total_pnl, 2),
                "current_value":    round(current_value, 2),
                "available_margin": round(available_margin, 2),
                "net_gain":         round((current_value + available_margin) - capital, 2),
            }
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
    try:
        summary_data = _fetch_summary_for_owner(owner_userid)
    except Exception as e:
        print(f"❌ get_summary fetch error: {e}")
        summary_data = {}
    if summary_data:
        global summary_data_global
        summary_data_global[str(owner_userid).strip()] = summary_data
        return {"summary": list(summary_data.values())}
    cached = (summary_data_global or {}).get(str(owner_userid).strip(), {}) or {}
    if cached:
        return {"summary": list(cached.values()), "stale": True}
    return {"summary": []}


# ─────────────────────────────────────────────────────────────
# Place Order
# ─────────────────────────────────────────────────────────────
def _parse_symbol_token(payload: dict):
    symbol = (payload.get("symbol") or "").strip()
    exch   = (payload.get("exchange") or "NSE").strip().upper()
    token  = payload.get("symboltoken") or payload.get("security_id") or payload.get("token")
    if symbol and "|" in symbol:
        parts = symbol.split("|")
        if len(parts) >= 3:
            exch  = (parts[0] or exch).strip().upper()
            token = parts[2].strip()
    return exch, _safe_int(token, 0)


def _get_group_members_from_db(owner_userid: str, group_name: str):
    try:
        row = db_execute(
            "SELECT multiplier, members FROM groups WHERE owner_userid=%s AND name=%s",
            (owner_userid, group_name), fetch="one",
        )
        if not row:
            return [], 1.0
        members = row["members"] or []
        mult    = max(0.01, float(row.get("multiplier") or 1))
        return members, mult
    except Exception:
        return [], 1.0


@app.post("/place_order")
async def place_order(request: Request, payload: dict = Body(...)):
    owner_userid = resolve_owner_userid(
        request, userid=payload.get("userid"), user_id=payload.get("user_id")
    )
    if not owner_userid:
        raise HTTPException(401, "Missing owner userid")

    data = payload or {}
    exch, symboltoken = _parse_symbol_token(data)
    if not symboltoken:
        raise HTTPException(400, "Missing/invalid symbol token")

    groupacc          = bool(data.get("groupacc", False))
    groups_raw        = data.get("groups", []) or []
    clients_raw       = data.get("clients", []) or []
    diffQty           = bool(data.get("diffQty", False))
    multiplier_on     = bool(data.get("multiplier", False))
    quantityinlot     = _safe_int(data.get("quantityinlot", 0), 0)
    perClientQty_raw  = data.get("perClientQty", {}) or {}
    action            = (data.get("action") or "").strip().upper()
    ordertype         = (data.get("ordertype") or "").strip().upper()
    producttype       = (data.get("producttype") or "").strip().upper()
    orderduration     = (data.get("orderduration") or "").strip().upper()
    price             = _safe_float(data.get("price", 0), 0.0)
    triggerprice      = _safe_float(data.get("triggerprice", 0), 0.0)
    disclosedquantity = _safe_int(data.get("disclosedquantity", 0), 0)
    amoorder          = (data.get("amoorder") or "N").strip().upper()

    def _extract_client_id(x) -> str:
        if isinstance(x, dict):
            return str(x.get("userid") or x.get("client_id") or x.get("client_code") or "").strip()
        return str(x or "").strip()

    def _extract_group_name(x) -> str:
        if isinstance(x, dict):
            return str(x.get("name") or x.get("group") or x.get("group_name") or "").strip()
        return str(x or "").strip()

    groups       = [_extract_group_name(g) for g in groups_raw  if _extract_group_name(g)]
    clients      = [_extract_client_id(c)  for c in clients_raw if _extract_client_id(c)]
    perClientQty = {
        _extract_client_id(k): _safe_int(v, quantityinlot)
        for k, v in perClientQty_raw.items() if _extract_client_id(k)
    }

    def _ensure_session(client_id: str) -> dict:
        cid = str(client_id or "").strip()
        if not cid: return {}
        sess = mofsl_sessions.get(cid)
        if isinstance(sess, dict) and sess.get("mofsl"): return sess
        cobj = _load_client_from_db(owner_userid, cid)
        if not cobj: return {}
        cobj["owner_userid"] = owner_userid
        return mofsl_sessions.get(cid) or {} if motilal_login(cobj) else {}

    targets = []
    if groupacc:
        for gname in groups:
            members, gmult = _get_group_members_from_db(owner_userid, gname)
            members_norm   = [_extract_client_id(m) for m in members if _extract_client_id(m)]
            for cid in members_norm:
                q = quantityinlot
                if diffQty:      q = _safe_int(perClientQty.get(cid, q), q)
                if multiplier_on:
                    try:    q = max(1, int(round(float(q) * float(gmult))))
                    except: q = max(1, int(q))
                targets.append((gname, cid, int(max(1, q))))
    else:
        for cid in clients:
            q = quantityinlot
            if diffQty: q = _safe_int(perClientQty.get(cid, q), q)
            targets.append(("", cid, int(max(1, q))))

    if not targets:
        raise HTTPException(400, "No target clients/groups selected")

    responses: Dict = {}
    lock = threading.Lock(); threads = []

    def _place_one(tag: str, client_id: str, qty: int):
        key  = f"{tag}:{client_id}" if tag else client_id
        sess = _ensure_session(client_id)
        if not isinstance(sess, dict) or not sess.get("mofsl"):
            with lock: responses[key] = {"status": "ERROR", "message": "Session not found"}; return
        sess_owner = (sess.get("owner_userid") or "").strip()
        if sess_owner and sess_owner != str(owner_userid).strip():
            with lock: responses[key] = {"status": "ERROR", "message": "Session belongs to another user"}; return
        order_payload = {
            "clientcode":        str(sess.get("userid") or client_id),
            "exchange":          exch,
            "symboltoken":       int(symboltoken),
            "buyorsell":         action,
            "ordertype":         ordertype,
            "producttype":       producttype,
            "orderduration":     orderduration,
            "price":             float(price),
            "triggerprice":      float(triggerprice),
            "quantityinlot":     int(max(1, qty)),
            "disclosedquantity": int(disclosedquantity),
            "amoorder":          amoorder,
            "algoid":            "",
            "goodtilldate":      "",
            "tag":               tag or "",
        }
        try:
            resp = sess["mofsl"].PlaceOrder(order_payload)
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
    return (datetime.utcnow() + timedelta(hours=5, minutes=30)).strftime("%d-%b-%Y %H:%M:%S")


@app.post("/modify_order")
def modify_order(request: Request, payload: dict = Body(...)) -> Dict[str, Any]:
    owner_userid = resolve_owner_userid(
        request, userid=(payload or {}).get("userid"), user_id=(payload or {}).get("user_id")
    )
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
        try:    return d if str(x).strip() == "" else int(float(str(x).strip()))
        except: return d

    def _nf(x, d=None):
        try:    return d if str(x).strip() == "" else float(str(x).strip())
        except: return d

    def _pos(x):
        try:    return x is not None and float(x) > 0
        except: return False

    def _ui_to_mo(ot):
        u = (ot or "").strip().upper().replace("-", "_").replace(" ", "_")
        return {
            "LIMIT": "LIMIT", "MARKET": "MARKET",
            "STOP_LOSS": "STOPLOSS", "STOPLOSS": "STOPLOSS",
            "SL_LIMIT": "STOPLOSS", "SL": "STOPLOSS",
            "STOP_LOSS_MARKET": "SL-M", "STOPLOSS_MARKET": "SL-M", "SL_MARKET": "SL-M",
        }.get(u, "")

    def _snap_to_mo(ot):
        u = (ot or "").strip().upper().replace("-", "_").replace(" ", "_")
        if u in ("SL_LIMIT", "SL_L", "STOPLOSS_LIMIT"):   return "STOPLOSS"
        if u in ("SL_MARKET", "SL_M", "STOPLOSS_MARKET"): return "SL-M"
        return u if u in ("LIMIT", "MARKET", "STOPLOSS", "SL-M") else ""

    def _infer_type(s):
        for k in ("newordertype", "ordertype", "orderType", "OrderType"):
            t = _snap_to_mo(s.get(k))
            if t: return t
        has_p = any(_pos(_nf(s.get(k))) for k in ("newprice", "orderprice", "price", "Price"))
        has_t = any(_pos(_nf(s.get(k))) for k in ("newtriggerprice", "triggerprice", "triggerPrice"))
        if has_t and has_p: return "STOPLOSS"
        if has_t:           return "SL-M"
        if has_p:           return "LIMIT"
        return "MARKET"

    def _get_session_for_row(r):
        cid = str(r.get("client_id") or "").strip()
        if cid:
            s = mofsl_sessions.get(cid)
            if isinstance(s, dict) and str(s.get("owner_userid", "")).strip() == str(owner_userid).strip():
                return s
        nm = (r.get("name") or "").strip().lower()
        if nm:
            for _, s in list(mofsl_sessions.items()):
                if not isinstance(s, dict): continue
                if str(s.get("owner_userid", "")).strip() != str(owner_userid).strip(): continue
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
            uid = str(sess.get("userid") or "").strip()
            sdk = sess.get("mofsl")
            if not uid or not sdk:
                messages.append(f"❌ {name} ({oid}): session not available"); continue

            price_in = row.get("price")
            trig_in  = row.get("triggerPrice", row.get("triggerprice"))
            qty_in   = _ni(row.get("quantity"))

            snap = None
            try:
                resp = sdk.GetOrderDetails({"clientcode": uid, "uniqueorderid": oid})
                if isinstance(resp, dict) and resp.get("status") == "SUCCESS":
                    d    = resp.get("data")
                    snap = d[0] if isinstance(d, list) and d else (d if isinstance(d, dict) else None)
            except Exception: pass
            if not snap:
                try:
                    ts = now_ist_str().split(" ")[0] + " 09:00:00"
                    ob = sdk.GetOrderBook({"clientcode": uid, "datetimestamp": ts})
                    for r2 in ((ob.get("data") or []) if isinstance(ob, dict) else []):
                        if str(r2.get("uniqueorderid", "")) == str(oid):
                            snap = r2; break
                except Exception: pass
            snap = snap or {}

            shares = qty_in if _pos(qty_in) else (_ni(snap.get("orderqty")) or 0)
            lots   = int(shares) if _pos(shares) else 0
            if lots <= 0:
                messages.append(f"❌ {name} ({oid}): cannot determine quantity"); continue

            last_mod = next(
                (
                    v for k in (
                        "lastmodifiedtime", "lastmodifieddatetime",
                        "recordinsertime", "recordinserttime", "modifydatetime",
                    )
                    if isinstance(snap.get(k), str) and snap[k].strip()
                    for v in [snap[k].strip()]
                ),
                now_ist_str(),
            )

            ui_type = _ui_to_mo(row.get("orderType") or row.get("ordertype")) or _infer_type(snap)
            out = {
                "clientcode":           uid,
                "uniqueorderid":        oid,
                "newordertype":         ui_type or "MARKET",
                "neworderduration":     str(row.get("validity") or "DAY").upper(),
                "newdisclosedquantity": 0,
                "lastmodifiedtime":     last_mod,
                "newquantityinlot":     lots,
            }
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
                ok     = "success" in status or resp.get("Success") is True or code in ("0", "200", "201")
            else:
                ok = bool(resp)
            messages.append(f"{'✅' if ok else '❌'} {name} ({oid}): {'Modified' if ok else (msg or 'modify failed')}")
        except Exception as e:
            messages.append(f"❌ {row.get('name', '?')} ({row.get('order_id', '?')}): {e}")

    return {"message": messages}


# ─────────────────────────────────────────────────────────────
# Copy Trading Engine — pure polling, 1s loop, 5s order window
# ─────────────────────────────────────────────────────────────
order_mapping:                Dict = {}
processed_order_ids_placed:   Dict = {}
processed_order_ids_canceled: Dict = {}

COPY_ORDER_WINDOW_SECONDS = 5
COPY_SETUPS_CACHE_TTL     = 30
POLL_INTERVAL_SECONDS     = 1

_copy_setups_cache:    list  = []
_copy_setups_cache_ts: float = 0.0
_copy_setups_lock = threading.Lock()


def _norm_ordertype(s: str) -> str:
    s         = (s or "").strip().upper()
    collapsed = s.replace("_", "").replace(" ", "").replace("-", "")
    return "STOPLOSS" if collapsed == "STOPLOSS" else s


def _norm_producttype(raw: str) -> str:
    v       = str(raw or "").strip().upper()
    allowed = {"NORMAL", "DELIVERY", "SELLFROMDP", "VALUEPLUS", "BTST", "MTF"}
    legacy  = {"CNC": "DELIVERY", "MIS": "NORMAL", "INTRADAY": "NORMAL", "MARGIN": "NORMAL"}
    return v if v in allowed else legacy.get(v, "DELIVERY")


def _norm_duration(raw: str) -> str:
    v = str(raw or "").strip().upper()
    return "DAY" if v in ("DAY", "NORMAL", "D", "") else v


def load_active_copy_setups_all() -> list:
    global _copy_setups_cache, _copy_setups_cache_ts
    with _copy_setups_lock:
        if _copy_setups_cache and (time.time() - _copy_setups_cache_ts) < COPY_SETUPS_CACHE_TTL:
            return list(_copy_setups_cache)
    try:
        rows   = db_execute("SELECT * FROM copy_setups WHERE enabled=TRUE", fetch="all") or []
        setups = [dict(r) for r in rows]
        with _copy_setups_lock:
            _copy_setups_cache    = setups
            _copy_setups_cache_ts = time.time()
        return setups
    except Exception as e:
        print(f"❌ load_active_copy_setups_all: {e}")
        return _copy_setups_cache


def _fetch_master_orders(master_id: str, owner: str) -> list:
    sess = _ensure_session_for_copy(owner, master_id)
    if not isinstance(sess, dict) or not sess.get("mofsl"):
        return []
    try:
        today = datetime.now().strftime("%d-%b-%Y 09:00:00")
        resp  = sess["mofsl"].GetOrderBook(
            {"clientcode": str(sess.get("userid") or master_id), "datetimestamp": today}
        )
        if not resp or resp.get("status") != "SUCCESS":
            return []
        orders = resp.get("data") or []
        return orders if isinstance(orders, list) else []
    except Exception as e:
        print(f"❌ [COPY] GetOrderBook exception master={master_id}: {e}")
        return []


def process_copy_order(order: dict, setup: dict):
    owner      = str(setup.get("owner_userid") or "").strip()
    setup_name = str(setup.get("name") or "setup")
    setup_key  = f"{owner}:{setup_name}"
    master_oid = str(order.get("uniqueorderid") or "").strip()

    if not master_oid or master_oid == "0":
        return

    order_time_str = order.get("recordinserttime") or ""
    if not order_time_str or order_time_str in ("", "0", None):
        return

    try:
        order_time_dt = datetime.strptime(order_time_str, "%d-%b-%Y %H:%M:%S")
        order_time    = int(order_time_dt.timestamp())
        t             = order_time_dt.time()
        market_open   = datetime.strptime("09:00:00", "%H:%M:%S").time()
        market_close  = datetime.strptime("15:30:00", "%H:%M:%S").time()
        amo_flag      = "N" if market_open <= t <= market_close else "Y"
    except Exception as e:
        print(f"⚠️ [COPY] Bad recordinserttime='{order_time_str}' oid={master_oid}: {e}")
        return

    age = int(time.time()) - order_time
    if age > COPY_ORDER_WINDOW_SECONDS:
        return

    processed_order_ids_placed.setdefault(setup_key, set())
    processed_order_ids_canceled.setdefault(setup_key, set())
    order_mapping.setdefault(setup_key, {})

    order_status = str(order.get("orderstatus") or "").strip().upper()
    order_type   = _norm_ordertype(order.get("ordertype") or "")

    _PLACE_STATUSES = {
        "CONFIRM", "CONFIRMED", "TRADED", "SENT", "OPEN", "PENDING",
        "TRIGGER PENDING", "TRIGGERPENDING",
        "AMO REQ RECEIVED", "PUT ORDER REQ RECEIVED",
        "AFTER MARKET ORDER REQ RECEIVED", "MODIFIED", "MODIFY CONFIRM",
    }

    if order_type == "MARKET" or order_status in _PLACE_STATUSES:
        if master_oid in processed_order_ids_placed[setup_key]:
            return

        children    = setup.get("children") or []
        multipliers = setup.get("multipliers") or {}

        side     = str(order.get("buyorsell") or "").upper().strip()
        ot       = order_type
        pt       = _norm_producttype(order.get("producttype") or "")
        dur      = _norm_duration(order.get("orderduration") or order.get("validity") or "")
        price    = float(order.get("price") or 0)
        trig     = float(order.get("triggerprice") or 0)
        exchange = str(order.get("exchange") or "NSE").upper()
        symtok   = int(order.get("symboltoken") or 0)

        if not side or not symtok:
            processed_order_ids_placed[setup_key].add(master_oid)
            return

        master_qty = int(order.get("orderqty") or 1)
        min_qty    = max(1, _min_qty_from_symbol_db(symtok))

        print(
            f"🧬 [COPY] TRIGGERED setup={setup_name} oid={master_oid} "
            f"side={side} ot={ot} pt={pt} status={order_status} "
            f"master_qty={master_qty} min_qty={min_qty} age={age}s"
        )

        for child_id in children:
            child_id = str(child_id).strip()
            if not child_id: continue

            sess = mofsl_sessions.get(child_id)
            if not (isinstance(sess, dict) and sess.get("mofsl") and _session_fresh(sess)):
                print(f"🔁 [COPY] Re-logging child={child_id}")
                cobj = _load_client_from_db(owner, child_id)
                if cobj: motilal_login(cobj)
                sess = mofsl_sessions.get(child_id)

            if not (isinstance(sess, dict) and sess.get("mofsl")):
                print(f"❌ [COPY] No session child={child_id} — skipping"); continue

            mult      = float(multipliers.get(child_id, 1) or 1)
            total_qty = master_qty * mult
            qty_lot   = max(1, int(total_qty // min_qty))

            child_order = {
                "clientcode":        sess["userid"],
                "exchange":          exchange,
                "symboltoken":       symtok,
                "buyorsell":         side,
                "ordertype":         ot,
                "producttype":       pt,
                "orderduration":     dur,
                "price":             price,
                "triggerprice":      trig,
                "quantityinlot":     qty_lot,
                "disclosedquantity": 0,
                "amoorder":          amo_flag,
                "algoid":            "",
                "goodtilldate":      "",
                "tag":               setup_name,
            }

            print(f"📦 [COPY] child={child_id} qty={qty_lot} payload={child_order}")
            try:
                resp = sess["mofsl"].PlaceOrder(child_order)
                print(f"📨 [COPY] child={child_id} resp={resp}")
                coid = (resp or {}).get("uniqueorderid")
                if coid:
                    order_mapping[setup_key].setdefault(master_oid, {})[child_id] = coid
                else:
                    print(f"❌ [COPY] PlaceOrder FAILED child={child_id} resp={resp}")
            except Exception as e:
                print(f"❌ [COPY] PlaceOrder exception child={child_id}: {e}")

        processed_order_ids_placed[setup_key].add(master_oid)

    elif "CANCEL" in order_status:
        if master_oid in processed_order_ids_canceled[setup_key]:
            return
        child_map = order_mapping.get(setup_key, {}).get(master_oid, {}) or {}
        if not child_map:
            print(f"ℹ️ [COPY] Cancel: no child mapping for oid={master_oid}")
            processed_order_ids_canceled[setup_key].add(master_oid)
            return
        for child_id, coid in child_map.items():
            sess = mofsl_sessions.get(child_id)
            if not (isinstance(sess, dict) and sess.get("mofsl")): continue
            try:
                resp = sess["mofsl"].CancelOrder(coid, sess["userid"])
                print(f"✅ [COPY] Cancel propagated child={child_id} coid={coid} resp={resp}")
            except Exception as e:
                print(f"❌ [COPY] Cancel error child={child_id}: {e}")
        processed_order_ids_canceled[setup_key].add(master_oid)


def synchronize_copy_trading():
    setups = load_active_copy_setups_all()
    if not setups:
        return

    def handle_setup(setup):
        master_id = str(setup.get("master") or "").strip()
        owner     = str(setup.get("owner_userid") or "").strip()
        if not master_id or not owner: return
        orders = _fetch_master_orders(master_id, owner)
        if not orders: return
        order_threads = []
        for order in orders:
            t = threading.Thread(target=process_copy_order, args=(order, setup), daemon=True)
            t.start(); order_threads.append(t)
        for t in order_threads: t.join()

    setup_threads = []
    for setup in setups:
        t = threading.Thread(target=handle_setup, args=(setup,), daemon=True)
        t.start(); setup_threads.append(t)
    for t in setup_threads: t.join()


def motilal_copy_trading_loop():
    print("✅ Copy Trading Engine running (1s polling loop)…")
    last_enabled: set = set()
    while True:
        try:
            setups      = load_active_copy_setups_all()
            enabled_now = {s.get("name", "") for s in setups}
            for sname in enabled_now - last_enabled:
                print(f"[COPY] Setup ENABLED: {sname}")
            for sname in last_enabled - enabled_now:
                print(f"[COPY] Setup DISABLED: {sname}")
            last_enabled = enabled_now
            synchronize_copy_trading()
        except Exception as e:
            print(f"❌ Copy trading sync error: {e}")
        time.sleep(POLL_INTERVAL_SECONDS)


_copy_thread_started = False


def start_copy_trading_thread():
    global _copy_thread_started
    if _copy_thread_started:
        return
    _copy_thread_started = True
    threading.Thread(
        target=motilal_copy_trading_loop,
        daemon=True,
        name="copy-trading-main",
    ).start()
