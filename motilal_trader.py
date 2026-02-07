# motilal_trader.py
"""
Motilal Multiuser Trader (FastAPI) - single broker (Motilal) multiuser webapp.

This consolidates CT_FastAPI Motilal endpoints into the new token-based multiuser system.

Frontend contract:
- Stores:
    mb_auth_token_v1 = <JWT>
    mb_logged_in_userid_v1 = JSON.stringify(<userid>)
- Sends:
    Authorization: Bearer <token>

Data storage (GitHub Contents API):
- data/users/{userid}/profile.json
- data/users/{userid}/clients/{client_id}.json
- data/users/{userid}/groups.json   (list of groups)
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time

# ---------------- JWT (HS256) helpers (no external dependency) ----------------
import base64
import hmac
import hashlib

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

    # exp may be int timestamp (seconds)
    exp = payload.get("exp")
    if exp is not None:
        try:
            exp_int = int(exp)
        except Exception:
            raise JWTError("Invalid exp")
        if int(time.time()) >= exp_int:
            raise JWTError("Token expired")

    return payload

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import requests
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from MOFSLOPENAPI import MOFSLOPENAPI  # type: ignore


# -----------------------------
# ENV config (env only)
# -----------------------------
APP_NAME = os.getenv("APP_NAME", "Motilal Multiuser Trader")
API_VERSION = os.getenv("API_VERSION", "1.1.0")

ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
if not ALLOWED_ORIGINS:
    ALLOWED_ORIGINS = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://localhost:3000",
        "https://multibroker-trader-multiuser.vercel.app",
    ]

SECRET_KEY = os.getenv("SECRET_KEY", "")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
TOKEN_EXPIRE_HOURS = int(os.getenv("TOKEN_EXPIRE_HOURS", "24"))

GITHUB_OWNER = os.getenv("GITHUB_OWNER", "")
GITHUB_REPO = os.getenv("GITHUB_REPO", "")
GITHUB_BRANCH = os.getenv("GITHUB_BRANCH", "main")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

SYMBOLS_PATH = os.getenv("SYMBOLS_PATH", "symbols.json")
SYMBOLS_GH_PATH = os.getenv("SYMBOLS_GH_PATH", "")


# -----------------------------
# App
# -----------------------------
app = FastAPI(title=APP_NAME, version=API_VERSION)

# ---------------- CORS (env-driven) ----------------
# Set CORS_ORIGINS as comma-separated origins, e.g.
# CORS_ORIGINS=https://multibroker-trader-multiuser.vercel.app,http://localhost:3000
# If you set CORS_ORIGINS=*, we will allow all origins but disable credentials (required by browsers).
cors_origins_raw = (os.getenv("CORS_ORIGINS") or "").strip()

if cors_origins_raw == "*":
    allow_origins = ["*"]
    allow_credentials = False
elif cors_origins_raw:
    allow_origins = [o.strip().rstrip("/") for o in cors_origins_raw.split(",") if o.strip()]
    allow_credentials = True
else:
    # Safe default for dev; in prod please set CORS_ORIGINS explicitly.
    allow_origins = ["http://localhost:3000", "http://127.0.0.1:3000"]
    allow_credentials = True

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)


security = HTTPBearer(auto_error=False)


# -----------------------------
# Time + misc
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


def safe_int_token(val: Any) -> int:
    """Accept 3, "3", "3.0", "3 lots"..."""
    if val is None:
        return 0
    if isinstance(val, (int, float)):
        return int(val)
    s = str(val).strip()
    if not s:
        return 0
    out = ""
    for ch in s:
        if ch.isdigit():
            out += ch
        elif out:
            break
    return int(out) if out else 0


# -----------------------------
# Auth helpers
# -----------------------------
def require_secret():
    if not SECRET_KEY:
        raise RuntimeError("Missing SECRET_KEY env var")


def create_token(userid: str) -> str:
    require_secret()
    payload = {
        "userid": userid,
        # exp as unix timestamp (seconds)
        "exp": int(time.time()) + int(TOKEN_EXPIRE_HOURS) * 3600,
    }
    return jwt_encode(payload, SECRET_KEY)



def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> str:
    require_secret()

    if credentials is None or not credentials.credentials:
        raise HTTPException(status_code=401, detail="Missing token")

    token = credentials.credentials
    try:
        payload = jwt_decode(token, SECRET_KEY)
        userid = (payload.get("userid") or "").strip()
        if not userid:
            raise HTTPException(status_code=401, detail="Invalid token")
        return userid
    except JWTError as e:
        msg = str(e) or "Invalid token"
        if "expired" in msg.lower():
            raise HTTPException(status_code=401, detail="Token expired")
        raise HTTPException(status_code=401, detail="Invalid token")


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
    if not gh_enabled():
        return None, None
    url = gh_url(path)
    r = requests.get(url, headers=gh_headers(), params={"ref": GITHUB_BRANCH})
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
        return
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


def gh_delete(path: str, message: str) -> None:
    if not gh_enabled():
        return
    _, sha = gh_get_json(path)
    if not sha:
        return
    payload = {"message": message, "sha": sha, "branch": GITHUB_BRANCH}
    r = requests.delete(gh_url(path), headers=gh_headers(), json=payload)
    r.raise_for_status()


def gh_list_folder(path: str) -> List[dict]:
    if not gh_enabled():
        return []
    r = requests.get(gh_url(path), headers=gh_headers(), params={"ref": GITHUB_BRANCH})
    if r.status_code == 404:
        return []
    r.raise_for_status()
    data = r.json()
    return data if isinstance(data, list) else []


# -----------------------------
# Per-user storage paths
# -----------------------------
def user_root(userid: str) -> str:
    return f"data/users/{userid}"


def user_profile_path(userid: str) -> str:
    return f"{user_root(userid)}/profile.json"


def user_clients_folder(userid: str) -> str:
    return f"{user_root(userid)}/clients"


def user_client_path(userid: str, client_id: str) -> str:
    return f"{user_clients_folder(userid)}/{client_id}.json"


def user_groups_path(userid: str) -> str:
    return f"{user_root(userid)}/groups.json"


# -----------------------------
# Password hashing (simple)
# -----------------------------
def password_hash(password: str, salt: str) -> str:
    return hashlib.sha256((salt + ":" + password).encode("utf-8")).hexdigest()


# -----------------------------
# In-memory Motilal sessions (per user)
# -----------------------------
SESSIONS: Dict[Tuple[str, str], Dict[str, Any]] = {}


def get_client_record(userid: str, client_id: str) -> Optional[dict]:
    obj, _ = gh_get_json(user_client_path(userid, client_id))
    return obj if isinstance(obj, dict) else None


def save_client_record(userid: str, client_id: str, record: dict) -> None:
    gh_put_json(user_client_path(userid, client_id), record, message=f"save client {userid}/{client_id}")


def list_clients(userid: str) -> List[dict]:
    items = gh_list_folder(user_clients_folder(userid))
    out: List[dict] = []
    for it in items:
        if it.get("type") != "file":
            continue
        rec, _ = gh_get_json(it.get("path") or "")
        if isinstance(rec, dict):
            out.append(rec)
    return out


def load_groups(userid: str) -> List[dict]:
    obj, _ = gh_get_json(user_groups_path(userid))
    if not obj:
        return []
    if isinstance(obj, dict) and isinstance(obj.get("groups"), list):
        return obj["groups"]
    if isinstance(obj, list):
        return obj
    return []


def save_groups(userid: str, groups: List[dict]) -> None:
    gh_put_json(user_groups_path(userid), {"groups": groups, "updated_at": utcnow_iso()}, message=f"save groups {userid}")


def ensure_logged_in(userid: str, client_id: str) -> Dict[str, Any]:
    key = (userid, client_id)
    sess = SESSIONS.get(key)
    if sess and sess.get("ok"):
        return sess

    rec = get_client_record(userid, client_id)
    if not rec:
        raise HTTPException(404, f"Client not found: {client_id}")

    creds = rec.get("creds") or rec.get("credentials") or {}
    password = creds.get("password") or rec.get("password")
    pan = creds.get("pan") or rec.get("pan")
    apikey = creds.get("apikey") or creds.get("api_key") or rec.get("apikey")
    totpkey = creds.get("totpkey") or creds.get("totp_key") or rec.get("totpkey")

    if not (client_id and password and pan and apikey and totpkey):
        raise HTTPException(400, "Missing Motilal creds (client_id/password/pan/apikey/totpkey)")

    api = MOFSLOPENAPI()
    try:
        resp = api.login({"userid": client_id, "password": password, "pan": pan, "apikey": apikey, "totpkey": totpkey})
        ok = True if resp else False
        sess = {"ok": ok, "api": api, "ts": time.time(), "client_id": client_id, "owner": userid}
        SESSIONS[key] = sess

        rec["session_active"] = ok
        rec["last_login_ts"] = utcnow_iso()
        rec["updated_at"] = utcnow_iso()
        save_client_record(userid, client_id, rec)
        return sess
    except Exception as e:
        rec["session_active"] = False
        rec["last_login_ts"] = utcnow_iso()
        rec["updated_at"] = utcnow_iso()
        rec["last_error"] = str(e)
        save_client_record(userid, client_id, rec)
        raise HTTPException(500, f"Motilal login failed for {client_id}: {e}")


# -----------------------------
# Basic routes
# -----------------------------
@app.get("/")
def root():
    return {"ok": True, "name": APP_NAME, "version": API_VERSION}


@app.get("/health")
def health():
    return {"ok": True}


# -----------------------------
# Auth
# -----------------------------
@app.post("/auth/register")
def auth_register(payload: dict):
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


# -----------------------------
# Symbols (shared)
# -----------------------------
@app.get("/symbols")
def symbols():
    if SYMBOLS_GH_PATH:
        data, _ = gh_get_json(SYMBOLS_GH_PATH)
        if isinstance(data, list):
            return {"success": True, "symbols": data}
        if isinstance(data, dict) and isinstance(data.get("symbols"), list):
            return {"success": True, "symbols": data["symbols"]}
    try:
        if os.path.exists(SYMBOLS_PATH):
            with open(SYMBOLS_PATH, "r", encoding="utf-8") as f:
                return {"success": True, "symbols": json.load(f)}
    except Exception:
        pass
    return {"success": True, "symbols": []}


# -----------------------------
# Clients (per-user)
# -----------------------------
@app.post("/add_client")
def add_client(payload: dict, userid: str = Depends(get_current_user)):
    broker = (payload.get("broker") or "motilal").strip().lower()
    if broker != "motilal":
        raise HTTPException(400, "Only broker=motilal is supported")

    client_id = (payload.get("client_id") or payload.get("client_code") or payload.get("userid") or "").strip()
    if not client_id:
        raise HTTPException(400, "Missing client_id")

    display_name = (payload.get("display_name") or payload.get("name") or "").strip()
    capital = payload.get("capital")

    creds = payload.get("creds") or payload.get("credentials") or {}
    record = {
        "broker": "motilal",
        "client_id": client_id,
        "name": display_name or client_id,
        "capital": capital,
        "creds": {
            "password": creds.get("password") or payload.get("password"),
            "pan": creds.get("pan") or payload.get("pan"),
            "apikey": creds.get("apikey") or creds.get("api_key") or payload.get("apikey"),
            "totpkey": creds.get("totpkey") or creds.get("totp_key") or payload.get("totpkey"),
        },
        "session_active": False,
        "created_at": utcnow_iso(),
        "updated_at": utcnow_iso(),
    }
    save_client_record(userid, client_id, record)

    try:
        ensure_logged_in(userid, client_id)
    except Exception:
        pass

    return {"success": True}


@app.get("/get_clients")
@app.get("/clients")
def get_clients(userid: str = Depends(get_current_user)):
    clients = list_clients(userid)
    for c in clients:
        cid = (c.get("client_id") or "").strip()
        if (userid, cid) in SESSIONS and SESSIONS[(userid, cid)].get("ok"):
            c["session_active"] = True
    return {"success": True, "clients": clients, "userid": userid}


@app.post("/delete_clients")
def delete_clients(payload: dict, userid: str = Depends(get_current_user)):
    ids = payload.get("client_ids") or payload.get("clients") or payload.get("ids") or []
    if isinstance(ids, str):
        ids = [ids]
    deleted = 0
    for cid in ids:
        cid = (cid or "").strip()
        if not cid:
            continue
        gh_delete(user_client_path(userid, cid), message=f"delete client {userid}/{cid}")
        SESSIONS.pop((userid, cid), None)
        deleted += 1
    return {"success": True, "deleted": deleted}


# -----------------------------
# Groups (per-user)
# -----------------------------
@app.get("/get_groups")
@app.get("/groups")
def get_groups(userid: str = Depends(get_current_user)):
    return {"success": True, "groups": load_groups(userid)}


@app.post("/save_groups")
def save_groups_api(payload: dict, userid: str = Depends(get_current_user)):
    groups = payload.get("groups", [])
    if not isinstance(groups, list):
        raise HTTPException(400, "groups must be list")
    save_groups(userid, groups)
    return {"success": True}


@app.post("/delete_groups")
def delete_groups_api(payload: dict, userid: str = Depends(get_current_user)):
    names = payload.get("group_names") or payload.get("names") or []
    if isinstance(names, str):
        names = [names]
    existing = load_groups(userid)
    keep = [g for g in existing if (g.get("name") not in names)]
    save_groups(userid, keep)
    return {"success": True}


# -----------------------------
# CT_FastAPI-compatible trading endpoints
# -----------------------------
@app.post("/place_order")
def place_order(payload: dict, userid: str = Depends(get_current_user)):
    try:
        symbol_str = (payload.get("symbol") or "").strip()
        if not symbol_str:
            raise HTTPException(400, "symbol is required")

        parts = symbol_str.split("|")
        if len(parts) >= 3:
            exchange = parts[0].strip()
            scripcode = parts[2].strip()
        else:
            exchange = (payload.get("exchange") or "NSE").strip()
            scripcode = symbol_str

        buyorsell = (payload.get("action") or "BUY").strip().upper()
        ordertype = (payload.get("ordertype") or "MARKET").strip().upper()
        producttype = (payload.get("producttype") or "MIS").strip().upper()

        diffQty = (payload.get("diffQty") or "same").strip().lower()
        multiplier = safe_int_token(payload.get("multiplier") or 1)
        qtySelection = (payload.get("qtySelection") or "auto").strip().lower()
        quantityinlot = safe_int_token(payload.get("quantityinlot") or 1)
        perClientQty = safe_int_token(payload.get("perClientQty") or 1)
        perGroupQty = safe_int_token(payload.get("perGroupQty") or 1)
        base_quantity = safe_int_token(payload.get("quantity") or 1)

        groupacc = (payload.get("groupacc") or "").strip()
        client = (payload.get("client") or "").strip()

        target_clients: List[dict] = []
        clients_records = list_clients(userid)

        if client and client != "All Clients":
            target_clients = [c for c in clients_records if c.get("client_id") == client]
        elif client == "All Clients":
            target_clients = clients_records
        elif groupacc:
            groups = load_groups(userid)
            g = next((x for x in groups if (x.get("name") or "") == groupacc), None)
            if not g:
                raise HTTPException(400, f"Group not found: {groupacc}")
            group_clients = g.get("clients") or []
            ids: List[str] = []
            for gc in group_clients:
                if isinstance(gc, str):
                    ids.append(gc)
                elif isinstance(gc, dict):
                    ids.append((gc.get("client_id") or gc.get("client") or "").strip())
            target_clients = [c for c in clients_records if c.get("client_id") in ids]
        else:
            target_clients = clients_records

        if not target_clients:
            raise HTTPException(400, "No target clients found")

        results: Dict[str, Any] = {}

        for idx, c in enumerate(target_clients):
            client_id = (c.get("client_id") or "").strip()
            if not client_id:
                continue

            if qtySelection == "manual":
                quantity = quantityinlot
            else:
                if groupacc:
                    quantity = perGroupQty
                else:
                    quantity = perClientQty or base_quantity

            if diffQty == "diff":
                quantity = max(1, quantity + idx)

            if multiplier > 1:
                quantity = quantity * multiplier

            sess = ensure_logged_in(userid, client_id)
            api = sess["api"]

            order_payload = {
                "clientcode": client_id,
                "exchange": exchange,
                "scripcode": scripcode,
                "buyorsell": buyorsell,
                "quantity": quantity,
                "producttype": producttype,
                "ordertype": ordertype,
                "price": payload.get("price") or "0",
                "triggerprice": payload.get("triggerprice") or "0",
                "disclosedqty": payload.get("disclosedqty") or "0",
                "validity": payload.get("validity") or "DAY",
                "amo": payload.get("amo") or "NO",
                "remarks": payload.get("remarks") or "",
            }

            try:
                resp = api.PlaceOrder(order_payload)
                results[client_id] = resp
            except Exception as e:
                results[client_id] = {"error": str(e)}

        return {"success": True, "results": results}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/get_orders")
def get_orders(userid: str = Depends(get_current_user)):
    data: Dict[str, Any] = {}
    for c in list_clients(userid):
        client_id = (c.get("client_id") or "").strip()
        if not client_id:
            continue
        try:
            sess = ensure_logged_in(userid, client_id)
            api = sess["api"]
            data[client_id] = api.GetOrderBook({"clientcode": client_id})
        except Exception as e:
            data[client_id] = {"error": str(e)}
    return {"success": True, "orders": data}


@app.get("/get_positions")
def get_positions(userid: str = Depends(get_current_user)):
    data: Dict[str, Any] = {}
    for c in list_clients(userid):
        client_id = (c.get("client_id") or "").strip()
        if not client_id:
            continue
        try:
            sess = ensure_logged_in(userid, client_id)
            api = sess["api"]
            data[client_id] = api.GetPosition({"clientcode": client_id})
        except Exception as e:
            data[client_id] = {"error": str(e)}
    return {"success": True, "positions": data}


@app.get("/get_holdings")
def get_holdings(userid: str = Depends(get_current_user)):
    data: Dict[str, Any] = {}
    for c in list_clients(userid):
        client_id = (c.get("client_id") or "").strip()
        if not client_id:
            continue
        try:
            sess = ensure_logged_in(userid, client_id)
            api = sess["api"]
            data[client_id] = api.GetHoldings({"clientcode": client_id})
        except Exception as e:
            data[client_id] = {"error": str(e)}
    return {"success": True, "holdings": data}


@app.get("/summary")
def summary(userid: str = Depends(get_current_user)):
    try:
        return {
            "success": True,
            "summary": {
                "orders": get_orders(userid).get("orders"),
                "positions": get_positions(userid).get("positions"),
                "holdings": get_holdings(userid).get("holdings"),
            },
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/copy_trade")
def copy_trade(payload: dict, userid: str = Depends(get_current_user)):
    order = payload.get("order") or payload
    targets = payload.get("targets") or []
    groupacc = (payload.get("groupacc") or payload.get("group") or "").strip()

    if groupacc and not targets:
        groups = load_groups(userid)
        g = next((x for x in groups if (x.get("name") or "") == groupacc), None)
        if g:
            targets = g.get("clients") or []

    results: Dict[str, Any] = {}

    if targets and isinstance(targets, list):
        for t in targets:
            if isinstance(t, str):
                cid = t.strip()
                mult = 1
            else:
                cid = (t.get("client_id") or t.get("client") or "").strip()
                mult = safe_int_token(t.get("multiplier") or 1)

            if not cid:
                continue

            o = dict(order)
            o["client"] = cid
            o.pop("groupacc", None)
            o["multiplier"] = mult
            try:
                results[cid] = place_order(o, userid).get("results", {}).get(cid)
            except Exception as e:
                results[cid] = {"error": str(e)}

        return {"success": True, "results": results}

    return place_order(order, userid)



# -----------------------------
# CT_FastAPI parity endpoints (close/cancel/convert)
# -----------------------------

@app.post("/cancel_order")
def cancel_order(payload: dict = Body(...), userid: str = Depends(get_current_user)):
    """Cancel a single order for a specific client.

    Payload:
      {"client_id": "...", "order_id": "..."}
    """
    client_id = str(payload.get("client_id") or payload.get("name") or "").strip()
    order_id = str(payload.get("order_id") or payload.get("orderid") or "").strip()

    if not client_id or not order_id:
        raise HTTPException(status_code=400, detail="client_id and order_id are required")

    sess = ensure_logged_in(userid, client_id)
    api = sess["api"]

    try:
        # Most MOFSLOPENAPI builds: CancelOrder(order_id)
        resp = api.CancelOrder(order_id)
    except TypeError:
        # Some builds: CancelOrder(order_id, client_id)
        resp = api.CancelOrder(order_id, client_id)

    return {"success": True, "data": resp}


@app.post("/close_position")
def close_position(payload: dict = Body(...), userid: str = Depends(get_current_user)):
    """Close positions by placing opposite market orders.

    Payload:
      {
        "positions": [
          {
            "client_id": "...",
            "exchange": "NSE"|"BSE"|"NFO"|"MCX",
            "symboltoken": "...",
            "buyorsell": "BUY"|"SELL",   # direction you want to PLACE (opposite of open position)
            "producttype": "CNC"|"MIS"|"NRML"|"NORMAL"|"INTRADAY",
            "quantityinlot": 1,
            "price": 0,
            "disclosedqty": 0
          }
        ]
      }

    Note: Frontend can build this using /get_positions response.
    """
    positions = payload.get("positions") or payload.get("items") or []
    if not isinstance(positions, list) or len(positions) == 0:
        raise HTTPException(status_code=400, detail="positions[] is required")

    results = []

    for pos in positions:
        client_id = str(pos.get("client_id") or pos.get("name") or "").strip()
        if not client_id:
            results.append({"success": False, "error": "client_id missing", "input": pos})
            continue

        sess = ensure_logged_in(userid, client_id)
        api = sess["api"]

        order = {
            "exchange": (pos.get("exchange") or "NSE"),
            "scripcode": pos.get("symboltoken") or pos.get("scripcode"),
            "quantity": int(pos.get("quantityinlot") or pos.get("quantity") or 0),
            "price": float(pos.get("price") or 0),
            "buyorsell": str(pos.get("buyorsell") or "").upper(),
            "producttype": str(pos.get("producttype") or "MIS").upper(),
            "ordertype": str(pos.get("ordertype") or "MARKET").upper(),
            "disclosedqty": int(pos.get("disclosedqty") or 0),
            "triggerprice": float(pos.get("triggerprice") or 0),
            "retention": str(pos.get("retention") or "DAY").upper(),
            "remarks": str(pos.get("remarks") or "close_position"),
        }

        if not order["scripcode"] or not order["quantity"] or order["quantity"] <= 0:
            results.append({"success": False, "error": "symboltoken/scripcode and quantity required", "input": pos})
            continue
        if order["buyorsell"] not in ("BUY", "SELL"):
            results.append({"success": False, "error": "buyorsell must be BUY or SELL", "input": pos})
            continue

        try:
            resp = api.PlaceOrder(order)
            results.append({"success": True, "client_id": client_id, "data": resp, "order": order})
        except Exception as e:
            results.append({"success": False, "client_id": client_id, "error": str(e), "order": order})

    return {"success": True, "results": results}


@app.post("/convert_position")
def convert_position(payload: dict = Body(...), userid: str = Depends(get_current_user)):
    """Convert position product type (e.g., MIS -> CNC).

    Payload:
      {
        "items": [
          {
            "client_id": "...",
            "exchange": "NSE"|"BSE"|"NFO"|"MCX",
            "symboltoken": "...",
            "quantityinlot": 1,
            "buyorsell": "BUY"|"SELL",
            "oldproducttype": "MIS",
            "newproducttype": "CNC"
          }
        ]
      }
    """
    items = payload.get("items") or payload.get("positions") or []
    if not isinstance(items, list) or len(items) == 0:
        raise HTTPException(status_code=400, detail="items[] is required")

    results = []

    for it in items:
        client_id = str(it.get("client_id") or it.get("name") or "").strip()
        if not client_id:
            results.append({"success": False, "error": "client_id missing", "input": it})
            continue

        sess = ensure_logged_in(userid, client_id)
        api = sess["api"]

        conv = {
            "exchange": (it.get("exchange") or "NSE"),
            "scripcode": it.get("symboltoken") or it.get("scripcode"),
            "quantity": int(it.get("quantityinlot") or it.get("quantity") or 0),
            "buyorsell": str(it.get("buyorsell") or "").upper(),
            "oldproducttype": str(it.get("oldproducttype") or it.get("old_producttype") or "MIS").upper(),
            "newproducttype": str(it.get("newproducttype") or it.get("new_producttype") or "CNC").upper(),
        }

        if not conv["scripcode"] or not conv["quantity"] or conv["quantity"] <= 0:
            results.append({"success": False, "error": "symboltoken/scripcode and quantity required", "input": it})
            continue
        if conv["buyorsell"] not in ("BUY", "SELL"):
            results.append({"success": False, "error": "buyorsell must be BUY or SELL", "input": it})
            continue

        try:
            # Most MOFSLOPENAPI builds: PositionConversion(payload)
            resp = api.PositionConversion(conv)
            results.append({"success": True, "client_id": client_id, "data": resp, "conversion": conv})
        except Exception as e:
            results.append({"success": False, "client_id": client_id, "error": str(e), "conversion": conv})

    return {"success": True, "results": results}
# -----------------------------
# Error formatting
# -----------------------------
@app.exception_handler(HTTPException)
async def http_exception_handler(_: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"success": False, "error": exc.detail})
