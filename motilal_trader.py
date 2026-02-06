from fastapi import FastAPI, HTTPException, Body, Depends
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from jose import jwt, JWTError
import hashlib, os, json, requests
import base64

# ======================================================
# CONFIG
# ======================================================
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALGO = "HS256"
JWT_EXP_MINUTES = 60 * 24  # 1 day

GITHUB_OWNER = os.getenv("GITHUB_REPO_OWNER", "wealthoceaninstitute-commits")
GITHUB_REPO = os.getenv("GITHUB_REPO_NAME", "Multiuser_clients")
GITHUB_BRANCH = os.getenv("GITHUB_BRANCH", "main")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

if not GITHUB_TOKEN:
    raise RuntimeError("GITHUB_TOKEN not set")

# ======================================================
# APP
# ======================================================
app = FastAPI(title="Multibroker Auth")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://multibroker-trader-multiuser.vercel.app",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ======================================================
# HELPERS
# ======================================================
def hash_password(pwd: str) -> str:
    return hashlib.sha256(pwd.encode()).hexdigest()

def create_token(userid: str) -> str:
    payload = {
        "sub": userid,
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXP_MINUTES),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def read_github_json(path: str):
    url = f"https://raw.githubusercontent.com/{GITHUB_OWNER}/{GITHUB_REPO}/{GITHUB_BRANCH}/{path}"
    r = requests.get(url, timeout=10)
    return r.json() if r.status_code == 200 else None

def write_github_json(path: str, data: dict):
    api = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{path}"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
    }

    content_bytes = json.dumps(data, indent=2).encode("utf-8")
    content_b64 = base64.b64encode(content_bytes).decode("utf-8")

    payload = {
        "message": f"create {path}",
        "content": content_b64,
        "branch": GITHUB_BRANCH,
    }

    r = requests.put(api, headers=headers, json=payload)

    if r.status_code not in (200, 201):
        raise HTTPException(
            400,
            f"GitHub write failed: {r.status_code} {r.text[:200]}"
        )

# ======================================================
# AUTH ROUTES
# ======================================================
@app.post("/auth/register")
def register(payload: dict = Body(...)):
    userid = payload.get("user_id") or payload.get("userid") or payload.get("username")
    email = payload.get("email")
    password = payload.get("password")

    if not userid or not email or not password:
        raise HTTPException(400, "All fields required")

    path = f"data/users/{userid}/profile.json"
    if read_github_json(path):
        raise HTTPException(400, "User already exists")

    profile = {
        "userid": userid,
        "email": email,
        "password_hash": hash_password(password),
        "created_at": datetime.utcnow().isoformat(),
    }

    write_github_json(path, profile)

    return {
        "success": True,
        "message": "User created",
    }

@app.post("/auth/login")
def login(payload: dict = Body(...)):
    userid = (
        payload.get("user_id")
        or payload.get("userid")
        or payload.get("username")
        or payload.get("email")
    )
    password = payload.get("password")

    if not userid or not password:
        raise HTTPException(400, "Missing credentials")

    profile = read_github_json(f"data/users/{userid}/profile.json")
    if not profile:
        raise HTTPException(401, "Invalid credentials")

    if profile["password_hash"] != hash_password(password):
        raise HTTPException(401, "Invalid credentials")

    token = create_token(profile["userid"])

    return {
        "success": True,
        "access_token": token,
        "token_type": "bearer",
        "userid": profile["userid"],
        "email": profile["email"],
    }
