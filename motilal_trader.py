from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
import hashlib, json, os, jwt

# ================= CONFIG =================
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALGO = "HS256"
TOKEN_EXP_MIN = 1440

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_DIR = os.path.join(BASE_DIR, "data", "users")
os.makedirs(USERS_DIR, exist_ok=True)

# ================= APP ====================
app = FastAPI(title="Multibroker Auth")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://multibroker-trader-multiuser.vercel.app",
        "http://localhost:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================= MODELS =================
class RegisterReq(BaseModel):
    user_id: str
    email: str
    password: str

class LoginReq(BaseModel):
    user_id: str
    password: str

# ---- helpers (same behavior as old code) ----
def _norm(s: Optional[str]) -> str:
    return (s or "").strip()

def _safe(s: str) -> str:
    s = _norm(s).replace(" ", "_")
    return "".join(ch for ch in s if ch.isalnum() or ch in ("_", "-"))

def hash_password(p: str) -> str:
    return hashlib.sha256(_norm(p).encode("utf-8")).hexdigest()

# ---- GitHub raw read config ----
GITHUB_OWNER = os.getenv("GITHUB_REPO_OWNER", "wealthoceaninstitute-commits")
GITHUB_REPO  = os.getenv("GITHUB_REPO_NAME", "Multiuser_clients")
BRANCH = os.getenv("GITHUB_BRANCH", "main")

# ---- REGISTER (permissive, frontend-safe) ----
@app.post("/auth/register")
def register(payload: Dict[str, Any] = Body(...)):
    userid = _norm(payload.get("userid") or payload.get("user_id") or payload.get("username"))
    email = _norm(payload.get("email"))
    password = _norm(payload.get("password"))

    if not userid or not email or not password:
        raise HTTPException(status_code=400, detail="All fields required")

    profile = {
        "userid": userid,
        "email": email,
        "password": hash_password(password),
        "created_at": datetime.utcnow().isoformat(),
    }

    try:
        github_write_json(f"data/users/{userid}/profile.json", profile)

        safe_email = _safe(email)
        if safe_email and safe_email != userid:
            github_write_json(f"data/users/{safe_email}/profile.json", profile)

    except Exception as e:
        print("[auth] GitHub write failed:", str(e)[:200])

    return {"success": True, "message": "User created"}

# ---- LOGIN (userid OR email OR username) ----
@app.post("/auth/login")
def login(payload: Dict[str, Any] = Body(...)):
    username = _norm(
        payload.get("userid")
        or payload.get("user_id")
        or payload.get("username")
        or payload.get("email")
    )
    password = _norm(payload.get("password"))

    if not username or not password:
        raise HTTPException(status_code=400, detail="Missing credentials")

    candidates = [username]
    safe_u = _safe(username)
    if safe_u not in candidates:
        candidates.append(safe_u)

    user = None
    for key in candidates:
        path = f"data/users/{key}/profile.json"
        url = f"https://raw.githubusercontent.com/{GITHUB_OWNER}/{GITHUB_REPO}/{BRANCH}/{path}"
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                user = r.json()
                break
        except Exception:
            continue

    if not user or user.get("password") != hash_password(password):
        raise HTTPException(status_code=401, detail="Invalid login")

    return {
        "success": True,
        "userid": user.get("userid") or username
    }
