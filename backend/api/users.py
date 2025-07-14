"""Database-powered user management endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from backend.models.database import get_db
from backend.services.user_service import UserService
from backend.schemas.user import UserRequest
from backend.utils.authentication import get_current_user, hash_password, verify_password
from backend.models.storage import user_db, username_map  # For compatibility
from backend.models.user import User as UserModel
from uuid import UUID
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v2", tags=["Database Users"])

@router.post("/register")
async def register_user_db(user: UserRequest, db: Session = Depends(get_db)):
    """Register a new user using database."""
    try:
        # Check if user already exists
        existing_user = UserService.get_user_by_username(db, user.username)
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already exists")
        
        # Create user in database
        user_data = {
            "username": user.username,
            "password": user.password,
            "role": user.role,
            "email": getattr(user, 'email', f"{user.username}@example.com")
        }
        
        db_user = UserService.create_user(db, user_data)
        roles = UserService.get_user_roles(db, db_user.id)
        
        response = UserService.to_response(db_user, roles)
        logger.info(f"User registered in database: {user.username}")
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering user: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/users")
async def get_all_users_db(db: Session = Depends(get_db)):
    """Get all users from database."""
    try:
        users = UserService.get_all_users(db)
        response = []
        
        for user in users:
            roles = UserService.get_user_roles(db, user.id)
            user_response = UserService.to_response(user, roles)
            response.append(user_response)
        
        return response
        
    except Exception as e:
        logger.error(f"Error getting users: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/users/{user_id}")
async def get_user_by_id_db(user_id: str, db: Session = Depends(get_db)):
    """Get user by ID from database."""
    try:
        user = UserService.get_user_by_id(db, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        roles = UserService.get_user_roles(db, user.id)
        response = UserService.to_response(user, roles)
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting user: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/login")
async def login_user_db(username: str, password: str, db: Session = Depends(get_db)):
    """Login user using database."""
    try:
        user = UserService.get_user_by_username(db, username)
        if not user or not verify_password(password, user.password_hash):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        if not user.is_active:
            raise HTTPException(status_code=401, detail="Account is disabled")
        
        from backend.utils.authentication import create_access_token
        token = create_access_token(data={"sub": username})
        roles = UserService.get_user_roles(db, user.id)
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "user_id": user.id,
            "role": roles[0] if roles else "user"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during login: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/status")
async def database_status(db: Session = Depends(get_db)):
    """Check database connection status."""
    try:
                # Simple query to test connection
        from sqlalchemy import text
        result = db.execute(text("SELECT 1")).scalar()
        user_count = db.query(UserModel).count()
        
        return {
            "status": "connected",
            "database": "mysql" if "mysql" in str(db.bind.url) else "sqlite",
            "user_count": user_count,
            "connection_test": result == 1
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }
