"""Simple database endpoints that work without complex relationships."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text
from backend.models.database import get_db
from backend.utils.authentication import hash_password, verify_password, create_access_token
from pydantic import BaseModel
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/db", tags=["Simple Database"])

class SimpleUser(BaseModel):
    username: str
    password: str
    role: str = "user"

class SimpleUserResponse(BaseModel):
    id: str
    username: str
    role: str
    email: str
    is_active: bool

@router.get("/init")
async def init_simple_tables(db: Session = Depends(get_db)):
    """Initialize simple user table."""
    try:
        # Create a simple users table
        db.execute(text("""
            CREATE TABLE IF NOT EXISTS simple_users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))
        db.commit()
        
        # Check if admin exists
        result = db.execute(text("SELECT COUNT(*) FROM simple_users WHERE username = 'admin'")).scalar()
        
        if result == 0:
            # Create admin user
            import uuid
            admin_id = str(uuid.uuid4())
            admin_password = hash_password("admin123!")
            
            db.execute(text("""
                INSERT INTO simple_users (id, username, email, password_hash, role, is_active)
                VALUES (:id, :username, :email, :password_hash, :role, :is_active)
            """), {
                "id": admin_id,
                "username": "admin",
                "email": "admin@example.com", 
                "password_hash": admin_password,
                "role": "admin",
                "is_active": True
            })
            db.commit()
            
            return {"message": "Database initialized", "admin_created": True, "admin_password": "admin123!"}
        
        return {"message": "Database already initialized"}
        
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/register")
async def register_simple_user(user: SimpleUser, db: Session = Depends(get_db)):
    """Register a new user in simple table."""
    try:
        # Check if user exists
        result = db.execute(text("SELECT COUNT(*) FROM simple_users WHERE username = :username"), 
                          {"username": user.username}).scalar()
        
        if result > 0:
            raise HTTPException(status_code=400, detail="Username already exists")
        
        # Create user
        import uuid
        user_id = str(uuid.uuid4())
        password_hash = hash_password(user.password)
        email = f"{user.username}@example.com"
        
        db.execute(text("""
            INSERT INTO simple_users (id, username, email, password_hash, role, is_active)
            VALUES (:id, :username, :email, :password_hash, :role, :is_active)
        """), {
            "id": user_id,
            "username": user.username,
            "email": email,
            "password_hash": password_hash,
            "role": user.role,
            "is_active": True
        })
        db.commit()
        
        return {
            "id": user_id,
            "username": user.username,
            "email": email,
            "role": user.role,
            "is_active": True,
            "message": "User registered successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering user: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/login")
async def login_simple_user(username: str, password: str, db: Session = Depends(get_db)):
    """Login user from simple table."""
    try:
        # Get user
        result = db.execute(text("""
            SELECT id, username, password_hash, role, is_active 
            FROM simple_users 
            WHERE username = :username
        """), {"username": username}).fetchone()
        
        if not result:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        user_id, db_username, password_hash, role, is_active = result
        
        if not verify_password(password, password_hash):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        if not is_active:
            raise HTTPException(status_code=401, detail="Account disabled")
        
        # Create token
        token = create_access_token(data={"sub": username})
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "user_id": user_id,
            "username": db_username,
            "role": role
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during login: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/users")
async def get_simple_users(db: Session = Depends(get_db)):
    """Get all users from simple table."""
    try:
        results = db.execute(text("""
            SELECT id, username, email, role, is_active, created_at
            FROM simple_users
            ORDER BY created_at DESC
        """)).fetchall()
        
        users = []
        for row in results:
            users.append({
                "id": row[0],
                "username": row[1], 
                "email": row[2],
                "role": row[3],
                "is_active": bool(row[4]),
                "created_at": str(row[5]) if row[5] else None
            })
        
        return {"users": users, "count": len(users)}
        
    except Exception as e:
        logger.error(f"Error getting users: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/status")
async def db_status(db: Session = Depends(get_db)):
    """Check database status."""
    try:
        # Test connection
        test_result = db.execute(text("SELECT 1")).scalar()
        
        # Count users
        user_count = db.execute(text("SELECT COUNT(*) FROM simple_users")).scalar() if True else 0
        
        # Get database type
        db_url = str(db.bind.url)
        db_type = "mysql" if "mysql" in db_url else "sqlite" if "sqlite" in db_url else "unknown"
        
        return {
            "status": "connected",
            "database_type": db_type,
            "connection_test": test_result == 1,
            "user_count": user_count,
            "database_url_preview": db_url.split('@')[0] + '@***' if '@' in db_url else db_url.split('///')[0] + '///**'
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }
