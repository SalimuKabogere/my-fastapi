from fastapi import FastAPI, Depends, HTTPException, Form
from backend.utils.authentication import create_access_token, get_current_user, hash_password, verify_password, role_checker
from backend.models.database import engine, SessionLocal, Base
from fastapi.security import OAuth2PasswordBearer
from typing import List, Tuple
from uuid import UUID, uuid4
from backend.schemas.user import UserRequest, UserResponse, UserStored, Token
from backend.models.storage import user_db, username_map
import re
import html
from urllib.parse import unquote
from backend.utils.sanitization import sanitize_username, validate_password, sanitize_free_text
import logging
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html, get_swagger_ui_oauth2_redirect_html
from fastapi import APIRouter
from pydantic import BaseModel


Base.metadata.create_all(bind=engine)

# logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(docs_url=None, redoc_url=None, swagger_ui_oauth2_redirect_url="/oauth2-redirect")



app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Add your frontend URLs here
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth_scheme = OAuth2PasswordBearer(tokenUrl='login')
redirect_path = app.swagger_ui_oauth2_redirect_url or "/oauth2-redirect"
openapi_url = app.openapi_url or "/openapi.json"

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Input sanitization function
def sanitize_input(input_str: str) -> str:
    """Sanitize user input to prevent XSS and injection attacks"""
    if not input_str:
        return ""
    # Decode URL encoding
    decoded = unquote(input_str)
    # Remove script tags (case-insensitive)
    no_script = re.sub(r'<script.*?</script>', '', decoded, flags=re.IGNORECASE | re.DOTALL)
    # Remove all HTML tags
    no_tags = re.sub(r'<.*?>', '', no_script)
    # Escape any remaining HTML special characters
    escaped = html.escape(no_tags)
    return escaped.strip()

# Validate UUID format
def validate_uuid(uuid_str: str) -> bool:
    """Validate if string is a valid UUID format"""
    uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
    return bool(uuid_pattern.match(uuid_str))

@app.get("/", include_in_schema=False)
async def custom_swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url= openapi_url,
        title="My API - Swagger UI",
        oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
        swagger_ui_parameters={"defaultModelsExpandDepth": -1}
    )

@app.get(redirect_path, include_in_schema=False)
async def swagger_ui_redirect():
    return get_swagger_ui_oauth2_redirect_html()

# Create an APIRouter for auth endpoints
auth_router = APIRouter(prefix="/api/auth", tags=["auth"])

# Auth endpoints grouped together in logical order
@auth_router.post("/register", response_model=UserResponse)
def register_user(user: UserRequest) -> UserResponse:
    # Sanitize input
    sanitized_username = sanitize_username(user.username)
    sanitized_role = sanitize_free_text(user.role, max_length=16)
    # Validate role
    if sanitized_role not in ["admin", "user"]:
        logging.error(f"Invalid role: {sanitized_role}")
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'user'")
    # Check for duplicate username
    if sanitized_username in username_map:
        logging.error(f"Username already exists: {sanitized_username}")
        raise HTTPException(status_code=400, detail=f"Username '{sanitized_username}' already exists")
    # Validate password
    if not validate_password(user.password):
        logging.error(f"Invalid password: {user.password}")
        raise HTTPException(status_code=400, detail="Password must be 8-128 characters and include a letter, number, and symbol.")
    # Generate user ID
    user_id = uuid4()
    username_map[sanitized_username] = user_id
    # Store user with hashed password
    stored = UserStored(
        uuid=user_id,
        username=sanitized_username,
        role=sanitized_role,
        password=hash_password(user.password)
    )
    user_db[user_id] = stored
    # Prepare response
    response = UserResponse(
        user_id=user_id,
        username=sanitized_username,
        role=sanitized_role
    )
    logging.info(f"User registered successfully: {sanitized_username}")
    return response

@auth_router.post("/login", response_model=Token)
def login_user(
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form(...)
):
    # Sanitize input
    sanitized_username = sanitize_username(username)
    sanitized_role = sanitize_free_text(role, max_length=16)
    user_id = username_map.get(sanitized_username)
    if not user_id:
        logging.error(f"User not found: {sanitized_username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user = user_db.get(user_id)
    if not user or not verify_password(password, user.password):
        logging.error(f"Invalid credentials: {sanitized_username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.role != sanitized_role:
        logging.error(f"Role does not match user: {sanitized_username}")
        raise HTTPException(status_code=401, detail="Role does not match user")
    token = create_access_token(data={"sub": sanitized_username})
    logging.info(f"User logged in successfully: {sanitized_username}")
    return {"access_token": token,"user_id": user_id, "role": sanitized_role,"token_type": "bearer"}

@auth_router.post("/logout")
def logout_user(current: Tuple[UUID, UserStored] = Depends(get_current_user)):
    # For JWT, logout is typically handled client-side by deleting the token.
    # If using token blacklisting, add token to blacklist here.
    return {"message": "Logged out successfully"}

@auth_router.post("/forgot-password")
def forgot_password(username: str = Form(...)):
    # Simulate sending a password reset link or code to the user's email.
    # In production, look up user by username/email and send email with token.
    if username not in username_map:
        raise HTTPException(status_code=404, detail="User not found")
    # Here, you would generate a reset token and send it via email.
    return {"message": f"Password reset instructions sent to the email for {username}"}

@auth_router.post("/reset-password")
def reset_password(username: str = Form(...), new_password: str = Form(...), reset_token: str = Form(...)):
    # In production, validate the reset_token and ensure it matches the user.
    if username not in username_map:
        raise HTTPException(status_code=404, detail="User not found")
    if not new_password or new_password.strip() == "":
        raise HTTPException(status_code=400, detail="Password cannot be empty.")
    if not validate_password(new_password):
        raise HTTPException(status_code=400, detail="Password must be 8-128 characters and include a letter, number, and symbol.")
    user_id = username_map[username]
    user = user_db[user_id]
    # Check if new password is the same as the current password
    if verify_password(new_password, user.password):
        raise HTTPException(status_code=400, detail="New password must be different from the current password.")
    # Optionally, add more criteria here (e.g., password history, common passwords, etc.)
    user.password = hash_password(new_password)
    # Invalidate the reset token here in production.
    return {"message": "Password reset successful"}


# --- User Management Endpoints ---

@app.get("/users/", response_model=List[UserResponse])
def get_all_users(current: Tuple[UUID, UserStored]=Depends(get_current_user)):

    _, user = current
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can view all users")
    return [
        UserResponse(
            user_id=uid,
            username=user.username,
            role=user.role
        )
        for uid, user in user_db.items()
    ]


@app.get("/users/{user_id}", response_model=UserResponse)
def get_user_by_id(user_id: UUID, current: Tuple[UUID, UserStored]=Depends(get_current_user)):
    # Validate UUID format
    if not validate_uuid(str(user_id)):
        raise HTTPException(status_code=400, detail="Invalid user ID format")
    
    user = user_db.get(user_id)
    if not user:
        logging.error(f"User not found: {user_id}")
        raise HTTPException(status_code=404, detail="User not found")
    logging.info(f"User retrieved successfully: {user.username}")
    return UserResponse(
        user_id=user_id,
        username=user.username,
        role=user.role
    )


@app.delete("/users_del/{user_id}")
def delete_user(user_id: UUID, current: Tuple[UUID, UserStored]=Depends(get_current_user)):
    # Validate UUID format
    if not validate_uuid(str(user_id)):
        raise HTTPException(status_code=400, detail="Invalid user ID format")
    
    _, user = current
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can delete users")

    if user_id not in user_db:
        raise HTTPException(status_code=404, detail="User not found")

    del user_db[user_id]
    return {"message": "User deleted successfully"}


# --- User/Profile Management Endpoints ---

# Update a user's profile (user can update own, admin can update any)
@app.put("/users/{user_id}")
def update_user_profile(user_id: UUID, user_update: UserRequest, current: Tuple[UUID, UserStored]=Depends(get_current_user)):
    current_id, current_user = current
    if current_user.role != "admin" and current_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to update this profile")
    user = user_db.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent non-admins from attempting to change their role
    if current_user.role != "admin" and user_update.role and user_update.role != user.role:
        raise HTTPException(status_code=403, detail="You are not allowed to change your role.")

    # Update username mapping if username changes
    old_username = user.username
    new_username = sanitize_username(user_update.username)
    if old_username != new_username:
        del username_map[old_username]
        username_map[new_username] = user_id
        user.username = new_username

    # Update password if changed
    if user_update.password and not verify_password(user_update.password, user.password):
        user.password = hash_password(user_update.password)

    # Only admin can update role, and must be a valid role
    if current_user.role == "admin" and user_update.role:
        sanitized_role = sanitize_free_text(user_update.role, max_length=16)
        if sanitized_role not in ["admin", "user"]:
            raise HTTPException(status_code=400, detail="Role must be 'admin' or 'user'")
        user.role = sanitized_role

    return {"message": "Profile updated successfully"}

# Get all profiles/roles assigned to a user
@app.get("/users/{user_id}/profiles")
def get_user_profiles(user_id: UUID, current: Tuple[UUID, UserStored]=Depends(get_current_user)):
    current_id, current_user = current
    if current_user.role != "admin" and current_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to view this user's roles")
    user = user_db.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"roles": [user.role], "username": user.username	}

# Assign or update profiles/roles for a user (admin only)
class RolesUpdateRequest(BaseModel):
    roles: List[str]

@app.put("/users/{user_id}/profiles")
def assign_user_profiles(user_id: UUID, req: RolesUpdateRequest, current: Tuple[UUID, UserStored]=Depends(role_checker(["admin"]))):
    roles = req.roles
    user = user_db.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # For simplicity, only one role per user in this model
    if not roles or roles[0] not in ["admin", "user"]:
        raise HTTPException(status_code=400, detail="Invalid role")
    user.role = roles[0]
    return {"message": f"Role updated to {roles[0]} for user {user_id}"}

# Unassign a specific profile/role from a user (admin only)
@app.delete("/users/{user_id}/profiles/{profile_id}")
def unassign_user_profile(user_id: UUID, profile_id: str, current: Tuple[UUID, UserStored]=Depends(role_checker(["admin"]))):
    user = user_db.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.role == profile_id:
        user.role = "user"  # Default to 'user' if role removed
        return {"message": f"Role {profile_id} removed from user {user_id}, {user.username}"}
    return {"message": f"User {user_id}, {user.username} does not have role {profile_id}"}

# --- Profile Management Endpoints ---

# List all available profiles/roles (admin only)
@app.get("/profiles")
def list_profiles(current: Tuple[UUID, UserStored]=Depends(role_checker(["admin"]))):
    return {"profiles": ["admin", "user"]}

# Get details of a specific profile/role (admin only)
@app.get("/profiles/{profile_id}")
def get_profile(profile_id: str, current: Tuple[UUID, UserStored]=Depends(role_checker(["admin"]))):
    if profile_id not in ["admin", "user"]:
        raise HTTPException(status_code=404, detail="Profile not found")
    # Example: return permissions or metadata
    return {"profile": profile_id, "permissions": ["all"] if profile_id == "admin" else ["basic"]}

# Assign a profile/role to multiple users (admin only)
class UserIDsUpdateRequest(BaseModel):
    user_ids: List[UUID]

@app.put("/profiles/{profile_id}/users")
def assign_profile_to_users(profile_id: str, req: UserIDsUpdateRequest, current: Tuple[UUID, UserStored]=Depends(role_checker(["admin"]))):
    user_ids = req.user_ids
    if profile_id not in ["admin", "user"]:
        raise HTTPException(status_code=400, detail="Invalid profile")
    updated: list[str] = []
    for uid in user_ids:
        user = user_db.get(uid)
        if user:
            user.role = profile_id
            updated.append(str(uid))
    return {"message": f"Assigned profile {profile_id} to users", "updated_users": updated}

@app.options("/test")
def options_test():
    return {"message": "OPTIONS works"}

# Include the auth_router in the main app
app.include_router(auth_router)