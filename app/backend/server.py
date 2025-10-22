from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
from enum import Enum

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT settings
SECRET_KEY = os.environ.get('JWT_SECRET', 'senate-secret-key-change-in-production')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

# Enums
class Role(str, Enum):
    TECH_ADMIN = "TECH_ADMIN"
    ADMIN = "ADMIN"
    SPEAKER = "SPEAKER"
    SPEAKER_ASSISTANT = "SPEAKER_ASSISTANT"
    SENATOR = "SENATOR"

class BillStatus(str, Enum):
    PENDING = "PENDING"
    VOTING = "VOTING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    VETOED = "VETOED"

class VoteType(str, Enum):
    FOR = "FOR"
    AGAINST = "AGAINST"
    ABSTAIN = "ABSTAIN"

# Models
class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    full_name: str
    roles: List[Role] = [Role.SENATOR]
    note: Optional[str] = None  # Примечание от спикера (партия/орган)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Vote(BaseModel):
    user_id: str
    user_name: str
    vote: VoteType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Bill(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    author_id: str
    author_name: str
    status: BillStatus = BillStatus.PENDING
    votes: List[Vote] = []
    speaker_decision: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class BillCreate(BaseModel):
    title: str
    description: str

class BillVote(BaseModel):
    vote: VoteType

class BillDecision(BaseModel):
    status: BillStatus
    decision: str

class Attendance(BaseModel):
    user_id: str
    user_name: str
    present: bool

class Session(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    date: datetime
    attendance: List[Attendance] = []
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SessionCreate(BaseModel):
    title: str
    description: str
    date: datetime

class News(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    content: str
    author_id: str
    author_name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class NewsCreate(BaseModel):
    title: str
    content: str

class Decree(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    content: str
    author_id: str
    author_name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class DecreeCreate(BaseModel):
    title: str
    content: str

class SiteSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")
    primary_color: str = "#1e40af"
    secondary_color: str = "#64748b"
    senate_name: str = "Сенат штата Сан-Андреас"
    logo_url: Optional[str] = None
    welcome_text: str = "Официальный портал Сената штата Сан-Андреас"

class UserUpdate(BaseModel):
    roles: Optional[List[Role]] = None
    note: Optional[str] = None

# Helper functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = await db.users.find_one({"id": user_id}, {"_id": 0})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_roles(allowed_roles: List[Role]):
    async def role_checker(user: dict = Depends(get_current_user)):
        user_roles = user.get("roles", [])
        if not any(role in user_roles for role in allowed_roles):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return role_checker

# Auth routes
@api_router.post("/auth/register")
async def register(user_data: UserCreate):
    # Check if user exists
    existing = await db.users.find_one({"email": user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user = User(
        email=user_data.email,
        full_name=user_data.full_name,
        roles=[Role.SENATOR]  # Default role
    )
    
    user_dict = user.model_dump()
    user_dict['password'] = hash_password(user_data.password)
    user_dict['created_at'] = user_dict['created_at'].isoformat()
    
    await db.users.insert_one(user_dict)
    
    token = create_access_token({"sub": user.id})
    return {"token": token, "user": user}

@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email}, {"_id": 0})
    if not user or not verify_password(credentials.password, user['password']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token({"sub": user['id']})
    user.pop('password', None)
    return {"token": token, "user": user}

@api_router.get("/auth/me")
async def get_me(user: dict = Depends(get_current_user)):
    user.pop('password', None)
    return user

# User routes
@api_router.get("/users", response_model=List[User])
async def get_users():
    users = await db.users.find({}, {"_id": 0, "password": 0}).to_list(1000)
    for user in users:
        if isinstance(user.get('created_at'), str):
            user['created_at'] = datetime.fromisoformat(user['created_at'])
    return users

@api_router.put("/users/{user_id}")
async def update_user(
    user_id: str,
    update_data: UserUpdate,
    current_user: dict = Depends(require_roles([Role.TECH_ADMIN, Role.ADMIN, Role.SPEAKER]))
):
    # Check permissions
    if update_data.roles and Role.TECH_ADMIN in update_data.roles:
        if Role.TECH_ADMIN not in current_user.get('roles', []):
            raise HTTPException(status_code=403, detail="Only tech admin can assign tech admin role")
    
    update_dict = {}
    if update_data.roles is not None:
        update_dict['roles'] = update_data.roles
    if update_data.note is not None:
        update_dict['note'] = update_data.note
    
    if update_dict:
        await db.users.update_one({"id": user_id}, {"$set": update_dict})
    
    user = await db.users.find_one({"id": user_id}, {"_id": 0, "password": 0})
    return user

@api_router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    current_user: dict = Depends(require_roles([Role.TECH_ADMIN]))
):
    await db.users.delete_one({"id": user_id})
    return {"message": "User deleted"}

# Bill routes
@api_router.get("/bills", response_model=List[Bill])
async def get_bills():
    bills = await db.bills.find({}, {"_id": 0}).to_list(1000)
    for bill in bills:
        if isinstance(bill.get('created_at'), str):
            bill['created_at'] = datetime.fromisoformat(bill['created_at'])
        for vote in bill.get('votes', []):
            if isinstance(vote.get('timestamp'), str):
                vote['timestamp'] = datetime.fromisoformat(vote['timestamp'])
    return bills

@api_router.post("/bills", response_model=Bill)
async def create_bill(
    bill_data: BillCreate,
    user: dict = Depends(require_roles([Role.SENATOR, Role.SPEAKER, Role.SPEAKER_ASSISTANT]))
):
    bill = Bill(
        title=bill_data.title,
        description=bill_data.description,
        author_id=user['id'],
        author_name=user['full_name']
    )
    
    bill_dict = bill.model_dump()
    bill_dict['created_at'] = bill_dict['created_at'].isoformat()
    
    await db.bills.insert_one(bill_dict)
    return bill

@api_router.post("/bills/{bill_id}/vote")
async def vote_on_bill(
    bill_id: str,
    vote_data: BillVote,
    user: dict = Depends(require_roles([Role.SENATOR, Role.SPEAKER, Role.SPEAKER_ASSISTANT]))
):
    bill = await db.bills.find_one({"id": bill_id}, {"_id": 0})
    if not bill:
        raise HTTPException(status_code=404, detail="Bill not found")
    
    # Remove existing vote from this user
    votes = [v for v in bill.get('votes', []) if v['user_id'] != user['id']]
    
    # Add new vote
    vote = Vote(
        user_id=user['id'],
        user_name=user['full_name'],
        vote=vote_data.vote
    )
    votes.append(vote.model_dump())
    votes[-1]['timestamp'] = votes[-1]['timestamp'].isoformat()
    
    await db.bills.update_one({"id": bill_id}, {"$set": {"votes": votes}})
    return {"message": "Vote recorded"}

@api_router.post("/bills/{bill_id}/decision")
async def make_decision(
    bill_id: str,
    decision_data: BillDecision,
    user: dict = Depends(require_roles([Role.SPEAKER]))
):
    await db.bills.update_one(
        {"id": bill_id},
        {"$set": {
            "status": decision_data.status,
            "speaker_decision": decision_data.decision
        }}
    )
    return {"message": "Decision made"}

@api_router.put("/bills/{bill_id}/status")
async def update_bill_status(
    bill_id: str,
    status: BillStatus,
    user: dict = Depends(require_roles([Role.SPEAKER, Role.SPEAKER_ASSISTANT]))
):
    await db.bills.update_one({"id": bill_id}, {"$set": {"status": status}})
    return {"message": "Status updated"}

@api_router.delete("/bills/{bill_id}")
async def delete_bill(
    bill_id: str,
    user: dict = Depends(require_roles([Role.TECH_ADMIN, Role.ADMIN, Role.SPEAKER]))
):
    await db.bills.delete_one({"id": bill_id})
    return {"message": "Bill deleted"}

# Session routes
@api_router.get("/sessions", response_model=List[Session])
async def get_sessions():
    sessions = await db.sessions.find({}, {"_id": 0}).to_list(1000)
    for session in sessions:
        if isinstance(session.get('created_at'), str):
            session['created_at'] = datetime.fromisoformat(session['created_at'])
        if isinstance(session.get('date'), str):
            session['date'] = datetime.fromisoformat(session['date'])
    return sessions

@api_router.post("/sessions", response_model=Session)
async def create_session(
    session_data: SessionCreate,
    user: dict = Depends(require_roles([Role.SPEAKER, Role.SPEAKER_ASSISTANT]))
):
    session = Session(
        title=session_data.title,
        description=session_data.description,
        date=session_data.date
    )
    
    session_dict = session.model_dump()
    session_dict['created_at'] = session_dict['created_at'].isoformat()
    session_dict['date'] = session_dict['date'].isoformat()
    
    await db.sessions.insert_one(session_dict)
    return session

@api_router.post("/sessions/{session_id}/attendance")
async def mark_attendance(
    session_id: str,
    attendance_data: List[Attendance],
    user: dict = Depends(require_roles([Role.SPEAKER]))
):
    attendance_list = [a.model_dump() for a in attendance_data]
    await db.sessions.update_one(
        {"id": session_id},
        {"$set": {"attendance": attendance_list}}
    )
    return {"message": "Attendance marked"}

@api_router.delete("/sessions/{session_id}")
async def delete_session(
    session_id: str,
    user: dict = Depends(require_roles([Role.TECH_ADMIN, Role.ADMIN, Role.SPEAKER]))
):
    await db.sessions.delete_one({"id": session_id})
    return {"message": "Session deleted"}

# News routes
@api_router.get("/news", response_model=List[News])
async def get_news():
    news = await db.news.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    for item in news:
        if isinstance(item.get('created_at'), str):
            item['created_at'] = datetime.fromisoformat(item['created_at'])
    return news

@api_router.post("/news", response_model=News)
async def create_news(
    news_data: NewsCreate,
    user: dict = Depends(require_roles([Role.TECH_ADMIN, Role.ADMIN, Role.SPEAKER, Role.SPEAKER_ASSISTANT]))
):
    news = News(
        title=news_data.title,
        content=news_data.content,
        author_id=user['id'],
        author_name=user['full_name']
    )
    
    news_dict = news.model_dump()
    news_dict['created_at'] = news_dict['created_at'].isoformat()
    
    await db.news.insert_one(news_dict)
    return news

@api_router.delete("/news/{news_id}")
async def delete_news(
    news_id: str,
    user: dict = Depends(require_roles([Role.TECH_ADMIN, Role.ADMIN, Role.SPEAKER]))
):
    await db.news.delete_one({"id": news_id})
    return {"message": "News deleted"}

# Decree routes
@api_router.get("/decrees", response_model=List[Decree])
async def get_decrees():
    decrees = await db.decrees.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    for decree in decrees:
        if isinstance(decree.get('created_at'), str):
            decree['created_at'] = datetime.fromisoformat(decree['created_at'])
    return decrees

@api_router.post("/decrees", response_model=Decree)
async def create_decree(
    decree_data: DecreeCreate,
    user: dict = Depends(require_roles([Role.SPEAKER]))
):
    decree = Decree(
        title=decree_data.title,
        content=decree_data.content,
        author_id=user['id'],
        author_name=user['full_name']
    )
    
    decree_dict = decree.model_dump()
    decree_dict['created_at'] = decree_dict['created_at'].isoformat()
    
    await db.decrees.insert_one(decree_dict)
    return decree

@api_router.delete("/decrees/{decree_id}")
async def delete_decree(
    decree_id: str,
    user: dict = Depends(require_roles([Role.TECH_ADMIN, Role.ADMIN, Role.SPEAKER]))
):
    await db.decrees.delete_one({"id": decree_id})
    return {"message": "Decree deleted"}

# Settings routes
@api_router.get("/settings", response_model=SiteSettings)
async def get_settings():
    settings = await db.settings.find_one({}, {"_id": 0})
    if not settings:
        settings = SiteSettings().model_dump()
        await db.settings.insert_one(settings)
    return settings

@api_router.put("/settings")
async def update_settings(
    settings_data: SiteSettings,
    user: dict = Depends(require_roles([Role.TECH_ADMIN]))
):
    settings_dict = settings_data.model_dump()
    await db.settings.delete_many({})
    await db.settings.insert_one(settings_dict)
    return settings_data

# Include router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
