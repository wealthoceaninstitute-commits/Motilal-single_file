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

# ================= HELPERS ================
def hash_password(pwd: str) -> str:
    return hashlib.sha256(pwd.encode()).hexdigest()

def user_file(user_id: str) -> str:
    return os.path.join(USERS_DIR, f"{user_id}.json")

def create_jwt(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.utcnow() + timedelta(minutes=TOKEN_EXP_MIN)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

# ================= ROUTES =================
@app.post("/auth/register")
def register(req: RegisterReq):
    if os.path.exists(user_file(req.user_id)):
        raise HTTPException(status_code=400, detail="User ID already exists")

    # ensure email uniqueness
    for f in os.listdir(USERS_DIR):
        with open(os.path.join(USERS_DIR, f), "r") as fp:
            u = json.load(fp)
            if u.get("email") == req.email:
                raise HTTPException(status_code=400, detail="Email already registered")

    user = {
        "user_id": req.user_id,
        "email": req.email,
        "password_hash": hash_password(req.password),
        "created_at": datetime.utcnow().isoformat()
    }

    with open(user_file(req.user_id), "w") as fp:
        json.dump(user, fp, indent=2)

    return {"success": True, "message": "User created"}

@app.post("/auth/login")
def login(req: LoginReq):
    path = user_file(req.user_id)
    if not os.path.exists(path):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    with open(path, "r") as fp:
        user = json.load(fp)

    if user["password_hash"] != hash_password(req.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {
        "access_token": create_jwt(req.user_id),
        "token_type": "bearer"
    }

@app.get("/")
def health():
    return {"status": "auth service running"}
