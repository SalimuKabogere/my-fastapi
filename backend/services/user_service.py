"""User service for database operations."""

from sqlalchemy.orm import Session
from backend.models.user import User as UserModel, Role, UserRole, UserProfile
from backend.schemas.user import UserCreate, UserResponse
from backend.utils.authentication import hash_password
from typing import List, Optional
import uuid

class UserService:
    
    @staticmethod
    def create_user(db: Session, user_data: dict) -> UserModel:
        """Create a new user in the database."""
        # Generate email if not provided (for backward compatibility)
        email = user_data.get('email', f"{user_data['username']}@example.com")
        
        db_user = UserModel(
            username=user_data['username'],
            email=email,
            password_hash=hash_password(user_data['password']),
            first_name=user_data.get('first_name'),
            last_name=user_data.get('last_name'),
            is_active=True,
            is_verified=False,
            failed_login_attempts=0
        )
        
        db.add(db_user)
        db.flush()  # Get the ID
        
        # Create user profile
        profile = UserProfile(
            user_id=db_user.id,
            bio=f"User {user_data['username']}",
            language="en",
            theme="light"
        )
        db.add(profile)
        
        # Assign role (backward compatibility)
        role_name = user_data.get('role', 'user')
        role = db.query(Role).filter(Role.name == role_name).first()
        if role:
            user_role = UserRole(
                user_id=db_user.id,
                role_id=role.id
            )
            db.add(user_role)
        
        db.commit()
        db.refresh(db_user)
        return db_user
    
    @staticmethod
    def get_user_by_username(db: Session, username: str) -> Optional[UserModel]:
        """Get user by username."""
        return db.query(UserModel).filter(UserModel.username == username).first()
    
    @staticmethod
    def get_user_by_id(db: Session, user_id: str) -> Optional[UserModel]:
        """Get user by ID."""
        return db.query(UserModel).filter(UserModel.id == user_id).first()
    
    @staticmethod
    def get_all_users(db: Session) -> List[UserModel]:
        """Get all users."""
        return db.query(UserModel).all()
    
    @staticmethod
    def get_user_roles(db: Session, user_id: str) -> List[str]:
        """Get user roles."""
        roles = db.query(Role).join(UserRole).filter(UserRole.user_id == user_id).all()
        return [role.name for role in roles]
    
    @staticmethod
    def to_response(user: UserModel, roles: List[str] = None) -> dict:
        """Convert user model to response format."""
        return {
            "id": user.id,
            "user_id": user.id,  # For backward compatibility
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "is_active": user.is_active,
            "is_verified": user.is_verified,
            "failed_login_attempts": user.failed_login_attempts,
            "last_login": user.last_login,
            "created_at": user.created_at,
            "updated_at": user.updated_at,
            "role": roles[0] if roles else "user"  # For backward compatibility
        }
